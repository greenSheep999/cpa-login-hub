// Package main — Kiro provider (AWS IAM Identity Center + M365 external_idp).
//
// StartLogin/PollLogin run the Python worker via worker_bridge. RefreshAuth
// stays 100% in Go: it's a plain OAuth token refresh against
// oidc.<region>.amazonaws.com/token (IdC) or the M365 token_endpoint
// (external_idp) — no browser needed, no worker fork.
//
// Because these flows are synchronous today (the worker blocks the
// StartLogin RPC until the browser flow completes), StartLogin actually
// runs the whole browser flow inline and PollLogin just returns the
// cached result. This matches how muxhub scripts/login-hub/server.py
// operates. A future async refactor can move to a proper poll loop.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// kiroFlowState carries data between StartLogin (browser run) and
// PollLogin (result fetch). Keyed by an opaque state string CPA passes
// back to us verbatim.
type kiroFlowState struct {
	Provider  string
	Result    *workerResult
	StartedAt time.Time
	Metadata  map[string]any
}

var (
	kiroFlowsMu sync.Mutex
	kiroFlows   = map[string]*kiroFlowState{}
)

// kiroStartLogin drives a first-time or re-login browser flow.
//
// The CPA management panel will call StartLogin, take our returned URL
// (empty in our case since the browser opens inside the worker itself,
// not a hosted OAuth callback), then poll. We complete the login inline
// during StartLogin so the poll call is cheap.
func kiroStartLogin(req authLoginStartRequest) []byte {
	extras := parseExtras(req.Metadata)
	if extras["sso_start_url"] == "" && extras["email"] == "" {
		return errorEnvelope("missing_parameter",
			"kiro provider requires extras.sso_start_url (IdC) or extras.email (M365)")
	}
	if extras["password"] == "" {
		return errorEnvelope("missing_parameter", "kiro provider requires extras.password")
	}

	// Where should the worker drop its CPA JSON? Use a per-flow scratch
	// dir under the plugin bundle so multiple concurrent flows don't
	// stomp on each other. The Go side reads the JSON back from disk
	// then embeds it in AuthData.StorageJSON.
	bundle, err := pluginBundleDir()
	if err != nil {
		return errorEnvelope("bundle_error", err.Error())
	}
	stateToken := newStateToken()
	outDir := filepath.Join(bundle, "worker", "runs", stateToken)
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return errorEnvelope("io_error", err.Error())
	}

	job := workerJob{
		Provider: "kiro",
		Label:    stringOr(extras["label"], stateToken),
		Proxy:    extras["proxy"],
		OutDir:   outDir,
		Timeout:  intOr(req.Metadata, "timeout_seconds", 600),
		Extras:   metadataToExtras(req.Metadata),
	}

	result, runErr := runWorker(job)
	if runErr != nil {
		return errorEnvelope("worker_error", runErr.Error())
	}

	kiroFlowsMu.Lock()
	kiroFlows[stateToken] = &kiroFlowState{
		Provider:  "kiro",
		Result:    result,
		StartedAt: time.Now(),
		Metadata:  req.Metadata,
	}
	kiroFlowsMu.Unlock()

	// Return the state token so PollLogin can retrieve the result. URL
	// is empty because the Camoufox browser opened locally on the CPA
	// host — the user isn't clicking an OAuth URL in *their* browser.
	// Panels that expect a URL should treat empty as "no user action
	// required, wait for PollLogin".
	return okEnvelope(authLoginStartResponse{
		Provider:  req.Provider,
		URL:       "",
		State:     stateToken,
		ExpiresAt: time.Now().Add(15 * time.Minute),
		Metadata:  map[string]any{"provider_key": "kiro"},
	})
}

func kiroPollLogin(req authLoginPollRequest) []byte {
	kiroFlowsMu.Lock()
	flow, ok := kiroFlows[req.State]
	if ok {
		delete(kiroFlows, req.State)
	}
	kiroFlowsMu.Unlock()
	if !ok {
		return errorEnvelope("unknown_state", fmt.Sprintf("no kiro flow for state %q", req.State))
	}

	if flow.Result.ErrorMessage != "" {
		return okEnvelope(authLoginPollResponse{
			Status:  "error",
			Message: flow.Result.ErrorMessage,
		})
	}

	// The worker's ``_result`` payload includes an ``out_path`` pointing
	// at CLIProxyAPI_<id>.json. Read + embed it verbatim as
	// AuthData.StorageJSON so CPA can persist the exact file we produced.
	var final struct {
		OutPath  string `json:"out_path"`
		Identity string `json:"identity"`
		Extra    struct {
			ProfileARN string `json:"profile_arn"`
			Region     string `json:"region"`
		} `json:"extra"`
	}
	if err := json.Unmarshal(flow.Result.FinalResult, &final); err != nil {
		return errorEnvelope("bad_worker_result", err.Error())
	}
	storage, err := os.ReadFile(final.OutPath)
	if err != nil {
		return errorEnvelope("io_error", fmt.Sprintf("read %s: %v", final.OutPath, err))
	}
	fileName := filepath.Base(final.OutPath)

	auth := authData{
		Provider:    "kiro",
		ID:          fileName, // stable ID: filename (unique per email)
		FileName:    fileName,
		Label:       stringOr(final.Identity, fileName),
		StorageJSON: storage,
		Metadata: map[string]any{
			"profile_arn": final.Extra.ProfileARN,
			"region":      final.Extra.Region,
			"source":      "cpa-login-hub",
		},
	}
	return okEnvelope(authLoginPollResponse{
		Status: "success",
		Auth:   auth,
	})
}

// kiroRefresh does a protocol-level token refresh against AWS SSO OIDC
// (IdC) or the M365 token_endpoint (external_idp). No browser, no worker.
func kiroRefresh(req authRefreshRequest) []byte {
	var stored kiroStorage
	if err := json.Unmarshal(req.StorageJSON, &stored); err != nil {
		return errorEnvelope("bad_storage", err.Error())
	}
	if stored.RefreshToken == "" {
		return errorEnvelope("missing_refresh_token", "stored auth has no refresh_token")
	}
	authMethod := strings.ToLower(stored.AuthMethod)
	switch authMethod {
	case "idc":
		return kiroRefreshIdc(req, stored)
	case "external_idp":
		return kiroRefreshExternalIdp(req, stored)
	case "social", "":
		// Cognito social — supported by the same OAuth2 refresh flow but
		// against Kiro's public /oauth/token. Stub for v0.1 — most
		// production accounts run IdC or external_idp.
		return errorEnvelope("not_implemented",
			"social (Cognito) kiro refresh coming in v0.2")
	default:
		return errorEnvelope("unknown_auth_method",
			fmt.Sprintf("kiro storage has unknown auth_method=%q", stored.AuthMethod))
	}
}

// kiroParse is called when CPA sees a *.json file on disk and asks
// plugins to identify it. We claim every kiro auth file (type=="kiro").
func handleKiroParse(req authParseRequest, authMethod string) []byte {
	fileName := req.FileName
	if fileName == "" && req.Path != "" {
		fileName = filepath.Base(req.Path)
	}
	// Extract email/identity for a nicer label.
	var meta struct {
		Email      string `json:"email"`
		ProfileARN string `json:"profile_arn"`
		Region     string `json:"region"`
	}
	_ = json.Unmarshal(req.RawJSON, &meta)

	auth := authData{
		Provider:    "kiro",
		ID:          fileName,
		FileName:    fileName,
		Label:       stringOr(meta.Email, fileName),
		StorageJSON: []byte(req.RawJSON),
		Metadata: map[string]any{
			"auth_method": authMethod,
			"profile_arn": meta.ProfileARN,
			"region":      meta.Region,
			"source":      "cpa-login-hub",
		},
	}
	return okEnvelope(authParseResponse{Handled: true, Auth: auth})
}
