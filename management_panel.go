// Package main — ManagementAPI capability.
//
// This is the bridge from "user filling a form in CPA's management UI"
// to "CPA's AuthProvider StartLogin call carries the right params".
// CPA's StartLogin RPC has no user-payload channel (only Provider +
// BaseURL) so we can't push credentials through it directly. Instead:
//
//  1. Panel HTML lives at /v0/resource/plugins/cpa-login-hub/panel and
//     is served here as an embedded static bundle (see panel.go).
//  2. /v0/management/cpa-login-hub/schema returns JSON describing every
//     provider's input fields — the panel renders form controls from it.
//  3. /v0/management/cpa-login-hub/prepare receives the filled form.
//     We stash the params in flow_registry.pendingSlot and return a
//     “next_url“ the panel navigates to: /v0/management/cpa-login-hub-
//     auth-url. That URL is CPA-native — its handler calls our
//     AuthProvider.StartLogin, which pops the pending slot.
//  4. /v0/management/cpa-login-hub/status is used by the panel to poll
//     the underlying flow while CPA also polls its own get-auth-status
//     endpoint — the two coexist because get-auth-status is what actually
//     drives token persistence; our /status is just for UI feedback.
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path"
	"strings"
	"time"
)

// ---------- request/response types ---------------------------------------

// managementRegisterRequest carries the host prefixes the plugin must
// register routes under. Mirrors sdk/pluginapi/types.go
// ManagementRegistrationRequest.
type managementRegisterRequest struct {
	Plugin           metadataSummary `json:"Plugin"`
	BasePath         string          `json:"BasePath"`
	ResourceBasePath string          `json:"ResourceBasePath"`
}

type metadataSummary struct {
	Name string `json:"Name"`
}

// managementRegisterResponse mirrors ManagementRegistrationResponse.
type managementRegisterResponse struct {
	Routes    []managementRoute `json:"Routes"`
	Resources []resourceRoute   `json:"Resources"`
}

type managementRoute struct {
	Method      string `json:"Method"`
	Path        string `json:"Path"`
	Menu        string `json:"Menu,omitempty"`
	Description string `json:"Description,omitempty"`
}

type resourceRoute struct {
	Path        string `json:"Path"`
	Menu        string `json:"Menu,omitempty"`
	Description string `json:"Description,omitempty"`
}

// managementHandleRequest mirrors ManagementRequest — CPA sends the
// full HTTP context. Headers/Query/Body are what the browser sent us.
type managementHandleRequest struct {
	Method  string              `json:"Method"`
	Path    string              `json:"Path"`
	Headers map[string][]string `json:"Headers"`
	Query   map[string][]string `json:"Query"`
	Body    []byte              `json:"Body"` // encoding/json base64-decodes this
}

// managementHandleResponse mirrors ManagementResponse.
type managementHandleResponse struct {
	StatusCode int                 `json:"StatusCode"`
	Headers    map[string][]string `json:"Headers,omitempty"`
	Body       []byte              `json:"Body,omitempty"`
}

// ---------- register -----------------------------------------------------

// handleManagementRegister declares our management + resource routes.
// The panel HTML is exposed as a Resource (no auth) so the browser can
// GET it directly; the interactive endpoints are authenticated Management
// routes.
func handleManagementRegister(request []byte) []byte {
	var req managementRegisterRequest
	if err := decodeRequest(request, &req); err != nil {
		return errorEnvelope("bad_request", err.Error())
	}
	// Note: CPA host resolves relative paths under BasePath / ResourceBasePath,
	// so we pass short paths like "/schema" (not the full /v0/management/...).
	resp := managementRegisterResponse{
		Routes: []managementRoute{
			// Management routes live at /v0/management/<Path> — flat, NO
			// per-plugin prefix. We embed pluginName ourselves so paths
			// don't collide with other plugins' routes.
			{Method: http.MethodPost, Path: "/" + pluginName + "/submit-login", Description: "start worker for a state token (internal)"},
			{Method: http.MethodGet, Path: "/" + pluginName + "/status", Description: "poll pending / active flow state (internal)"},
			{Method: http.MethodPost, Path: "/" + pluginName + "/cancel", Description: "cancel a running login flow (internal)"},
		},
		Resources: []resourceRoute{
			{
				Path:        "/panel",
				Menu:        "CPA Login Hub",
				Description: "打开登录中心面板，为 kiro / openai / grok / antigravity / cursor 一键批量导入账号",
			},
			{Path: "/panel.css", Description: "panel stylesheet"},
			{Path: "/panel.js", Description: "panel client-side script"},
			{Path: "/i18n.js", Description: "panel i18n dictionary"},
			{Path: "/logo.png", Description: "plugin logo"},
			// /schema is exposed as an unauthenticated resource because it
			// contains only static field metadata — no secrets, no state.
			// This lets the panel bootstrap without needing the management
			// key. (Auth-sensitive endpoints — submit-login / status / cancel
			// — stay behind management-auth.)
			{Path: "/schema", Description: "provider input schema JSON (public)"},
		},
	}
	return okEnvelope(resp)
}

// ---------- handle -------------------------------------------------------

// handleManagementHandle dispatches an incoming HTTP request based on
// its trailing path segment. The BasePath prefix is stripped by CPA
// before we see it, so req.Path is something like "/prepare" or
// "/panel". Extremely thin router by design.
func handleManagementHandle(request []byte) []byte {
	var req managementHandleRequest
	if err := decodeRequest(request, &req); err != nil {
		return errorEnvelope("bad_request", err.Error())
	}
	// Normalise path — the plugin id is embedded in every registered
	// management route path (see handleManagementRegister) AND in the
	// resource base. Strip whichever prefix we see so downstream
	// switch-cases are simple ("/panel", "/submit-login", ...).
	p := req.Path
	prefixes := []string{
		"/v0/management/" + pluginName,
		"/v0/resource/plugins/" + pluginName,
		"/plugins/" + pluginName,
		"/" + pluginName,
	}
	for _, pref := range prefixes {
		if strings.HasPrefix(p, pref) {
			p = strings.TrimPrefix(p, pref)
			break
		}
	}
	p = "/" + strings.TrimLeft(path.Clean(p), "/")

	switch {
	case req.Method == http.MethodGet && (p == "/panel" || p == "/panel.html" || p == "/"):
		// HTML uses no-store (not just no-cache) because it embeds the
		// BUILD_STAMP that CSS/JS filenames key off — browsers must
		// re-fetch on every load to see the newest stamp.
		return respondNoStore(200, "text/html; charset=utf-8", panelIndexHTML())
	case req.Method == http.MethodGet && p == "/panel.css":
		return respondStatic(200, "text/css; charset=utf-8", panelCSS())
	case req.Method == http.MethodGet && p == "/panel.js":
		return respondStatic(200, "application/javascript; charset=utf-8", panelJS())
	case req.Method == http.MethodGet && p == "/i18n.js":
		return respondStatic(200, "application/javascript; charset=utf-8", panelI18n())
	case req.Method == http.MethodGet && p == "/logo.png":
		return respondStatic(200, "image/png", panelLogo())
	case req.Method == http.MethodGet && p == "/schema":
		return respondJSON(200, buildSchemaResponse())
	case req.Method == http.MethodPost && p == "/submit-login":
		return handleSubmitLogin(req.Body, req.Query)
	case req.Method == http.MethodGet && p == "/status":
		return handleStatus(req.Query)
	case req.Method == http.MethodPost && p == "/cancel":
		return handleCancel()
	default:
		return respondJSON(404, map[string]any{
			"error": fmt.Sprintf("unknown management path: %s %s", req.Method, p),
		})
	}
}

// ---------- helpers ------------------------------------------------------

func respondBytes(status int, contentType string, body []byte) []byte {
	resp := managementHandleResponse{
		StatusCode: status,
		Headers:    map[string][]string{"content-type": {contentType}},
		Body:       body,
	}
	return okEnvelope(resp)
}

// respondStatic wraps respondBytes with Cache-Control: no-store. We
// intentionally use no-store (not no-cache) because Cloudflare and some
// other CDNs happily rewrite no-cache into max-age=14400, defeating the
// version-query approach. no-store is a stronger directive CDNs respect.
// Combined with per-request cache-busting in index.html, deploys are
// picked up on the next reload without any manual cache clear.
func respondStatic(status int, contentType string, body []byte) []byte {
	resp := managementHandleResponse{
		StatusCode: status,
		Headers: map[string][]string{
			"content-type":  {contentType},
			"cache-control": {"no-store, no-cache, must-revalidate, max-age=0"},
			"pragma":        {"no-cache"},
			"expires":       {"0"},
			// Cloudflare-specific: refuse edge cache regardless of rules.
			"cf-cache-status": {"BYPASS"},
			"cdn-cache-control": {"no-store"},
		},
		Body: body,
	}
	return okEnvelope(resp)
}

// respondNoStore forces the browser to re-fetch on every load — used
// for the entry HTML because a stale HTML would keep referring to old
// ?v=BUILD_STAMP asset URLs.
func respondNoStore(status int, contentType string, body []byte) []byte {
	resp := managementHandleResponse{
		StatusCode: status,
		Headers: map[string][]string{
			"content-type":  {contentType},
			"cache-control": {"no-store, no-cache, must-revalidate, max-age=0"},
			"pragma":        {"no-cache"},
			"expires":       {"0"},
		},
		Body: body,
	}
	return okEnvelope(resp)
}

func respondJSON(status int, payload any) []byte {
	body, err := json.Marshal(payload)
	if err != nil {
		return errorEnvelope("marshal_error", err.Error())
	}
	return respondBytes(status, "application/json; charset=utf-8", body)
}

// ---------- /schema ------------------------------------------------------

type schemaProvider struct {
	Key          string     `json:"key"`
	Label        string     `json:"label"`
	Description  string     `json:"description"`
	StorageType  string     `json:"storage_type"`
	FilenameHint string     `json:"filename_hint"`
	Fields       []fieldDef `json:"fields"`
	Extras       []fieldDef `json:"extras"`
	CanRefresh   bool       `json:"can_refresh"`
}

func buildSchemaResponse() map[string]any {
	keys := providerKeys()
	providers := make([]schemaProvider, 0, len(keys))
	for _, k := range keys {
		b := providerRegistry[k]
		providers = append(providers, schemaProvider{
			Key:          b.Key,
			Label:        b.Label,
			Description:  b.Description,
			StorageType:  b.StorageType,
			FilenameHint: b.FilenameHint,
			Fields:       b.Fields,
			Extras:       b.Extras,
			CanRefresh:   b.refreshFunc != nil,
		})
	}
	return map[string]any{
		"plugin":    pluginName,
		"version":   pluginVersion,
		"providers": providers,
		// Client hint: after /prepare succeeds, navigate to this URL to
		// trigger CPA's AuthProvider.StartLogin dispatch. The panel doesn't
		// have to hard-code the CPA-side path — this decouples it from
		// any future path change.
		"auth_url_path": "/v0/management/" + pluginName + "-auth-url",
		"status_path":   "/v0/management/get-auth-status",
	}
}

// ---------- /prepare -----------------------------------------------------

type submitLoginRequest struct {
	Provider string            `json:"provider"`
	Label    string            `json:"label"`
	Proxy    string            `json:"proxy"`
	Timeout  int               `json:"timeout"`
	Extras   map[string]string `json:"extras"`
}

// handleSubmitLogin is called by the panel form after the user picks a
// provider and fills the fields. State was created by AuthProvider.
// StartLogin (i.e. the CPA-native login button); the panel URL was
// crafted to carry it as ?state=<token>. We correlate the panel's
// submission back to the CPA-created flow via that token.
func handleSubmitLogin(body []byte, query map[string][]string) []byte {
	state := firstQueryValue(query, "state")
	if state == "" {
		return respondJSON(400, map[string]any{
			"error": "missing ?state — the panel must be reached via CPA's Login Hub button so the state token is present in the URL",
		})
	}
	var req submitLoginRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return respondJSON(400, map[string]any{"error": "invalid JSON: " + err.Error()})
	}
	if req.Provider == "" {
		return respondJSON(400, map[string]any{"error": "provider is required"})
	}
	binding, ok := providerRegistry[req.Provider]
	if !ok {
		return respondJSON(400, map[string]any{"error": "unknown provider: " + req.Provider})
	}
	// Server-side required-field validation. UI side does its own check
	// but a malicious/curl client shouldn't be able to skip it.
	for _, f := range binding.Extras {
		if f.Required && strings.TrimSpace(req.Extras[f.Key]) == "" {
			return respondJSON(400, map[string]any{
				"error": fmt.Sprintf("provider %s requires field %q", req.Provider, f.Key),
			})
		}
	}

	err := panelSubmitLogin(state, &pendingLogin{
		Provider: req.Provider,
		Label:    req.Label,
		Proxy:    req.Proxy,
		Timeout:  req.Timeout,
		Extras:   req.Extras,
	})
	if err != nil {
		return respondJSON(400, map[string]any{"error": err.Error()})
	}

	return respondJSON(200, map[string]any{
		"status":   "running",
		"provider": req.Provider,
		"state":    state,
		"message":  "worker started; CPA's get-auth-status poll will surface the result",
	})
}

func firstQueryValue(q map[string][]string, key string) string {
	if q == nil {
		return ""
	}
	if v, ok := q[key]; ok && len(v) > 0 {
		return v[0]
	}
	return ""
}

// ---------- /status ------------------------------------------------------

// handleStatus is for panel UI feedback only. CPA's get-auth-status is
// what actually drives token persistence — /status here reports finer-
// grained plugin-side state (awaiting_submit / running / done / error)
// so the panel can show useful progress.
func handleStatus(query map[string][]string) []byte {
	state := firstQueryValue(query, "state")
	if state == "" {
		return respondJSON(200, map[string]any{"status": "idle"})
	}

	flow := lookupActiveFlow(state)
	if flow == nil {
		return respondJSON(200, map[string]any{"status": "unknown_state"})
	}
	flow.mu.Lock()
	awaiting := flow.Awaiting
	provider := flow.Provider
	flow.mu.Unlock()
	if awaiting {
		return respondJSON(200, map[string]any{
			"status":  "awaiting_submit",
			"message": "state registered; waiting for the panel form submission",
		})
	}
	if !flow.isDone() {
		return respondJSON(200, map[string]any{
			"status":       "running",
			"provider":     provider,
			"elapsed_secs": int(time.Since(flow.StartedAt).Seconds()),
		})
	}
	if flow.ErrorMessage != "" {
		return respondJSON(200, map[string]any{
			"status": "error",
			"error":  flow.ErrorMessage,
		})
	}
	return respondJSON(200, map[string]any{
		"status": "done",
	})
}

// ---------- /cancel ------------------------------------------------------

func handleCancel() []byte {
	// Best-effort: kill any in-flight workers. Individual flow entries
	// are left in place so PollLogin returning error can propagate to
	// CPA. The janitor reaps them later.
	shutdownWorkers()
	return respondJSON(200, map[string]any{"status": "cancelled"})
}
