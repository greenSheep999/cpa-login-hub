// Package main — AuthProvider capability implementation.
//
// Four methods (ParseAuth / StartLogin / PollLogin / RefreshAuth) —
// dispatch here, per-provider details in providers.go + provider_*.go.
//
// The login flow is intentionally asynchronous:
//
//  1. Panel POSTs /prepare → we stash params in flow_registry.pendingSlot.
//  2. Panel redirects browser to CPA-native /cpa-login-hub-auth-url →
//     CPA calls our StartLogin.
//  3. StartLogin takes the pending params, spawns a worker goroutine,
//     returns immediately with a stateToken. NO worker work runs inline.
//  4. CPA polls get-auth-status → we forward to PollLogin → we check
//     whether the goroutine finished and return pending / success / error.
//
// This matches CPA's OAuth-flow expectations exactly and stops HTTP
// handlers from being blocked for minutes during Camoufox runs.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// ---------- auth.parse ---------------------------------------------------

// authParseRequest mirrors sdk/pluginapi/types.go AuthParseRequest.
//
// RawJSON is []byte (NOT json.RawMessage) because CPA's request type is
// []byte too — and Go's encoding/json marshals []byte as base64 strings.
// If we declared this as json.RawMessage we'd get "\"eyJ0eXBlIjoi…\""
// (a base64-string wrapped in JSON quotes) instead of the decoded bytes.
type authParseRequest struct {
	Provider string `json:"Provider"`
	Path     string `json:"Path"`
	FileName string `json:"FileName"`
	RawJSON  []byte `json:"RawJSON"`
}

type authParseResponse struct {
	Handled bool     `json:"Handled"`
	Auth    authData `json:"Auth"`
}

// authData mirrors sdk/pluginapi/types.go AuthData.
type authData struct {
	Provider         string            `json:"Provider"`
	ID               string            `json:"ID"`
	FileName         string            `json:"FileName"`
	Label            string            `json:"Label"`
	Prefix           string            `json:"Prefix,omitempty"`
	ProxyURL         string            `json:"ProxyURL,omitempty"`
	Disabled         bool              `json:"Disabled,omitempty"`
	StorageJSON      []byte            `json:"StorageJSON"`
	Metadata         map[string]any    `json:"Metadata,omitempty"`
	Attributes       map[string]string `json:"Attributes,omitempty"`
	NextRefreshAfter time.Time         `json:"NextRefreshAfter,omitempty"`
}

// handleAuthParse decides whether an on-disk auth file belongs to us.
// Umbrella-mode: any file whose top-level "type" matches a registered
// provider's StorageType is ours. Per-provider metadata extraction is
// delegated to the binding's parseStorage.
func handleAuthParse(request []byte) []byte {
	var req authParseRequest
	if err := decodeRequest(request, &req); err != nil {
		return errorEnvelope("bad_request", err.Error())
	}

	var probe struct {
		Type string `json:"type"`
	}
	_ = json.Unmarshal(req.RawJSON, &probe)

	binding := lookupProviderByStorageType(probe.Type)
	if binding == nil {
		// Not ours — reply Handled=false so the host tries the next parser.
		return okEnvelope(authParseResponse{Handled: false})
	}

	fileName := req.FileName
	if fileName == "" && req.Path != "" {
		fileName = filepath.Base(req.Path)
	}

	label, meta := binding.parseStorage(req.RawJSON, fileName)
	if meta == nil {
		meta = map[string]any{}
	}
	meta["provider_key"] = binding.Key
	meta["source"] = pluginName

	auth := authData{
		Provider:    pluginName,
		ID:          fileName,
		FileName:    fileName,
		Label:       stringOr(label, fileName),
		StorageJSON: req.RawJSON,
		Metadata:    meta,
	}
	return okEnvelope(authParseResponse{Handled: true, Auth: auth})
}

// ---------- auth.login.start ---------------------------------------------

type authLoginStartRequest struct {
	Provider string         `json:"Provider"`
	BaseURL  string         `json:"BaseURL"`
	Metadata map[string]any `json:"Metadata"`
}

type authLoginStartResponse struct {
	Provider  string         `json:"Provider"`
	URL       string         `json:"URL"`
	State     string         `json:"State"`
	ExpiresAt time.Time      `json:"ExpiresAt"`
	Metadata  map[string]any `json:"Metadata,omitempty"`
}

// handleLoginStart is called by CPA when the user hits
// /v0/management/cpa-login-hub-auth-url (i.e. clicks any OAuth-login
// button that maps to us).
//
// We do NOT expect the user to have visited our panel first. Instead:
//
//  1. Generate a state token and register an "awaiting_panel" flow.
//  2. Return a URL pointing at our panel with ?state=<token>.
//     CPA-side handleAuthURL forwards this URL to the browser, which
//     opens it — user lands directly on our form pre-tagged with state.
//  3. User picks provider + fills fields + submits.
//  4. Panel POST /submit-login with state → we build the worker job
//     and spawn the worker goroutine, transitioning the flow from
//     "awaiting_panel" to "running".
//  5. CPA's normal get-auth-status polling loop calls our PollLogin
//     which returns pending / success / error just like before.
//
// This way the CPA-native login button IS the natural entry point;
// the panel is a form the user fills out mid-flow, not a separate
// step they have to remember to do first.
func handleLoginStart(request []byte) []byte {
	var req authLoginStartRequest
	if err := decodeRequest(request, &req); err != nil {
		return errorEnvelope("bad_request",
			"decode auth.login.start request failed: "+err.Error())
	}

	stateToken := newStateToken()
	flow := &activeFlow{
		Provider:  "", // set on /submit-login when user picks provider
		StartedAt: time.Now(),
		done:      make(chan struct{}),
		Awaiting:  true,
	}
	registerActiveFlow(stateToken, flow)

	// Panel URL. CPA-side handleAuthURL returns this to the browser as
	// {status:"ok", url:...} — the frontend then navigates the user to
	// this URL. We serve it at /v0/resource/plugins/<plugin>/panel and
	// it reads the state param out of the URL to correlate submissions.
	panelURL := "/v0/resource/plugins/" + pluginName + "/panel?state=" + stateToken

	return okEnvelope(authLoginStartResponse{
		Provider:  req.Provider,
		URL:       panelURL,
		State:     stateToken,
		ExpiresAt: time.Now().Add(15 * time.Minute),
		Metadata: map[string]any{
			"kind": "cpa-login-hub-panel",
		},
	})
}

// panelSubmitLogin is invoked by ManagementAPI when the user submits the
// panel form. It correlates with the CPA-initiated flow via stateToken.
// This is what actually launches the worker goroutine.
func panelSubmitLogin(state string, params *pendingLogin) error {
	flow := lookupActiveFlow(state)
	if flow == nil {
		return fmt.Errorf("no active flow for state %q — the CPA login button must be clicked first (this creates the flow)", state)
	}
	if !flow.Awaiting {
		return fmt.Errorf("state %q is already running or completed", state)
	}
	binding, ok := providerRegistry[params.Provider]
	if !ok {
		return fmt.Errorf("unknown provider: %s", params.Provider)
	}
	bundle, err := pluginBundleDir()
	if err != nil {
		return fmt.Errorf("locate plugin bundle: %w", err)
	}
	outDir := filepath.Join(bundle, "worker", "runs", state)
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return fmt.Errorf("create worker output dir: %w", err)
	}

	synth := authLoginStartRequest{
		Provider: pluginName,
		Metadata: pendingToMetadata(params),
	}
	job, err := binding.buildLoginJob(synth, outDir)
	if err != nil {
		return err
	}
	if job.Timeout <= 0 {
		if params.Timeout > 0 {
			job.Timeout = params.Timeout
		} else {
			job.Timeout = 600
		}
	}

	// Transition the flow from awaiting → running.
	flow.mu.Lock()
	flow.Provider = params.Provider
	flow.Awaiting = false
	flow.mu.Unlock()

	go func() {
		result, runErr := runWorker(job)
		flow.finish(result, runErr)
	}()
	return nil
}

// pendingToMetadata converts pendingLogin into the map[string]any shape
// binding.buildLoginJob expects.
func pendingToMetadata(p *pendingLogin) map[string]any {
	if p == nil {
		return map[string]any{}
	}
	out := map[string]any{
		"provider_key":    p.Provider,
		"timeout_seconds": p.Timeout,
	}
	extras := make(map[string]any, len(p.Extras))
	for k, v := range p.Extras {
		extras[k] = v
	}
	if p.Label != "" {
		out["label"] = p.Label
	}
	if p.Proxy != "" {
		out["proxy"] = p.Proxy
	}
	out["extras"] = extras
	return out
}

// ---------- auth.login.poll ----------------------------------------------

type authLoginPollRequest struct {
	Provider string         `json:"Provider"`
	State    string         `json:"State"`
	Metadata map[string]any `json:"Metadata"`
}

type authLoginPollResponse struct {
	Status  string   `json:"Status"` // pending | success | error
	Message string   `json:"Message,omitempty"`
	Auth    authData `json:"Auth,omitempty"`
}

// handleLoginPoll returns the current state of the background worker.
// CPA polls this every 1-2s until we return success or error. The flow
// is consumed only on terminal success so transient CPA-side retries
// don't lose the result.
func handleLoginPoll(request []byte) []byte {
	var req authLoginPollRequest
	if err := decodeRequest(request, &req); err != nil {
		return errorEnvelope("bad_request", err.Error())
	}

	flow := lookupActiveFlow(req.State)
	if flow == nil {
		return errorEnvelope("unknown_state",
			fmt.Sprintf("no active flow for state %q — the login may have been abandoned or the plugin restarted", req.State))
	}

	// Flow states, in order:
	//   1. Awaiting  = true                       → user hasn't submitted the panel form yet
	//   2. Awaiting  = false, isDone() = false    → worker running
	//   3.                    isDone() = true     → worker terminated (success/error)
	flow.mu.Lock()
	awaiting := flow.Awaiting
	provider := flow.Provider
	flow.mu.Unlock()

	if awaiting {
		return okEnvelope(authLoginPollResponse{
			Status:  "pending",
			Message: "waiting for user to submit the CPA Login Hub panel form",
		})
	}

	if !flow.isDone() {
		return okEnvelope(authLoginPollResponse{
			Status:  "pending",
			Message: fmt.Sprintf("running %s login (%.0fs elapsed) — Camoufox is driving the browser", provider, time.Since(flow.StartedAt).Seconds()),
		})
	}

	// Terminal state — drain it now so a retry doesn't double-report.
	_ = consumeActiveFlow(req.State)

	if flow.ErrorMessage != "" {
		return okEnvelope(authLoginPollResponse{
			Status:  "error",
			Message: flow.ErrorMessage,
		})
	}
	if flow.Result == nil || flow.Result.FinalResult == nil {
		return okEnvelope(authLoginPollResponse{
			Status:  "error",
			Message: "worker finished without producing a result",
		})
	}

	binding, ok := providerRegistry[flow.Provider]
	if !ok {
		return errorEnvelope("unknown_provider",
			fmt.Sprintf("provider %q disappeared from registry", flow.Provider))
	}

	auth, err := buildAuthDataFromResult(binding, flow.Result)
	if err != nil {
		return errorEnvelope("bad_worker_result", err.Error())
	}
	return okEnvelope(authLoginPollResponse{
		Status: "success",
		Auth:   auth,
	})
}

// buildAuthDataFromResult reads the worker's on-disk output file and
// wraps it in an AuthData record CPA can persist. Called by both the
// PollLogin success path (initial login) and, notionally, by any future
// "resume from stored auth" path.
func buildAuthDataFromResult(binding *providerBinding, result *workerResult) (authData, error) {
	var final struct {
		OutPath  string         `json:"out_path"`
		Identity string         `json:"identity"`
		Extra    map[string]any `json:"extra"`
	}
	if err := json.Unmarshal(result.FinalResult, &final); err != nil {
		return authData{}, fmt.Errorf("unmarshal worker result: %w", err)
	}
	if final.OutPath == "" {
		return authData{}, fmt.Errorf("worker result has no out_path")
	}
	storage, err := os.ReadFile(final.OutPath)
	if err != nil {
		return authData{}, fmt.Errorf("read %s: %w", final.OutPath, err)
	}
	fileName := filepath.Base(final.OutPath)

	label, meta := binding.parseStorage(storage, fileName)
	if meta == nil {
		meta = map[string]any{}
	}
	meta["provider_key"] = binding.Key
	meta["source"] = pluginName
	// Copy worker's ``extra`` fields into metadata unchanged so downstream
	// UI code can display them (profile_arn, region, project_id, ...).
	for k, v := range final.Extra {
		if _, exists := meta[k]; !exists {
			meta[k] = v
		}
	}
	if label == "" {
		label = final.Identity
	}
	if label == "" {
		label = fileName
	}

	return authData{
		Provider:    pluginName,
		ID:          fileName,
		FileName:    fileName,
		Label:       label,
		StorageJSON: storage,
		Metadata:    meta,
	}, nil
}

// ---------- auth.refresh -------------------------------------------------

type authRefreshRequest struct {
	AuthID       string            `json:"AuthID"`
	AuthProvider string            `json:"AuthProvider"`
	StorageJSON  []byte            `json:"StorageJSON"`
	Metadata     map[string]any    `json:"Metadata"`
	Attributes   map[string]string `json:"Attributes"`
}

type authRefreshResponse struct {
	Auth             authData  `json:"Auth"`
	NextRefreshAfter time.Time `json:"NextRefreshAfter,omitempty"`
}

// handleRefresh routes to the provider binding whose StorageType matches
// the auth file's top-level "type". Pure HTTP flow inside — no browser,
// no worker.
func handleRefresh(request []byte) []byte {
	var req authRefreshRequest
	if err := decodeRequest(request, &req); err != nil {
		return errorEnvelope("bad_request", err.Error())
	}
	var probe struct {
		Type string `json:"type"`
	}
	_ = json.Unmarshal(req.StorageJSON, &probe)
	binding := lookupProviderByStorageType(probe.Type)
	if binding == nil {
		return errorEnvelope("unknown_provider",
			fmt.Sprintf("cannot refresh auth id=%q: unrecognised storage type %q", req.AuthID, probe.Type))
	}
	if binding.refreshFunc == nil {
		return errorEnvelope("not_implemented",
			fmt.Sprintf("provider %q does not support protocol-level refresh — re-login via the panel", binding.Key))
	}
	return binding.refreshFunc(req)
}
