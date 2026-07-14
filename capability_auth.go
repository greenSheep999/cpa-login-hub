// Package main — AuthProvider capability implementation.
//
// This file implements the four AuthProvider methods every plugin auth flow
// needs: ParseAuth / StartLogin / PollLogin / RefreshAuth. Per-provider
// bespoke logic lives under provider/*.go — this file only threads the
// request through the right provider.
package main

import (
	"encoding/json"
	"fmt"
	"time"
)

// ---------- auth.parse ---------------------------------------------------

// AuthParseRequest mirrors sdk/pluginapi/types.go AuthParseRequest.
type authParseRequest struct {
	Provider string          `json:"Provider"`
	Path     string          `json:"Path"`
	FileName string          `json:"FileName"`
	RawJSON  json.RawMessage `json:"RawJSON"`
}

type authParseResponse struct {
	Handled bool     `json:"Handled"`
	Auth    authData `json:"Auth"`
}

// authData mirrors sdk/pluginapi/types.go AuthData.
// StorageJSON is base64-encoded when marshalled (json.RawMessage on the
// wire is base64 for []byte fields, per encoding/json rules).
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

// handleAuthParse decides whether an on-disk auth file belongs to us. We
// recognise files whose top-level “type“ is “kiro“ (login-hub CPA
// native schema). Other providers (openai/grok/antigravity/codex) will be
// added in the PR2 milestone — for now they slot in here.
func handleAuthParse(request []byte) []byte {
	var req authParseRequest
	if err := decodeRequest(request, &req); err != nil {
		return errorEnvelope("bad_request", err.Error())
	}

	// Peek at the JSON to see which provider it belongs to.
	var probe struct {
		Type       string `json:"type"`
		AuthMethod string `json:"auth_method"`
	}
	_ = json.Unmarshal(req.RawJSON, &probe)

	if probe.Type == "kiro" {
		return handleKiroParse(req, probe.AuthMethod)
	}

	// Not ours — reply Handled=false so the host tries the next parser.
	return okEnvelope(authParseResponse{Handled: false})
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

func handleLoginStart(request []byte) []byte {
	var req authLoginStartRequest
	if err := decodeRequest(request, &req); err != nil {
		return errorEnvelope("bad_request", err.Error())
	}
	// Per-provider dispatch — Metadata.provider_key selects the flow when
	// multiple providers live behind the same plugin identifier. See
	// docs/DESIGN.md for the metadata contract.
	provider := resolveProviderKey(req.Provider, req.Metadata)
	switch provider {
	case "kiro":
		return kiroStartLogin(req)
	case "openai", "grok", "antigravity", "codex":
		return errorEnvelope("not_implemented",
			fmt.Sprintf("provider %q is scheduled for v0.2 — see roadmap in README", provider))
	default:
		return errorEnvelope("unknown_provider", fmt.Sprintf("unknown provider: %q", provider))
	}
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

func handleLoginPoll(request []byte) []byte {
	var req authLoginPollRequest
	if err := decodeRequest(request, &req); err != nil {
		return errorEnvelope("bad_request", err.Error())
	}
	provider := resolveProviderKey(req.Provider, req.Metadata)
	switch provider {
	case "kiro":
		return kiroPollLogin(req)
	default:
		return errorEnvelope("unknown_provider", fmt.Sprintf("unknown provider: %q", provider))
	}
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

func handleRefresh(request []byte) []byte {
	var req authRefreshRequest
	if err := decodeRequest(request, &req); err != nil {
		return errorEnvelope("bad_request", err.Error())
	}
	// The refresh path is 100% protocol (no browser) — dispatch by
	// inspecting the stored JSON payload to pick the right provider.
	var probe struct {
		Type string `json:"type"`
	}
	_ = json.Unmarshal(req.StorageJSON, &probe)
	if probe.Type == "kiro" {
		return kiroRefresh(req)
	}
	return errorEnvelope("unknown_provider",
		fmt.Sprintf("cannot refresh auth id=%q: unrecognised storage type", req.AuthID))
}

// resolveProviderKey extracts the concrete provider from either the top-
// level Provider field or the Metadata bag. CPA passes “Provider“ as the
// plugin identifier (e.g. "cpa-login-hub") when the plugin declares an
// umbrella identifier, so the actual per-flow provider is passed inside
// Metadata (convention: metadata["provider_key"] = "kiro" | "openai" | …).
func resolveProviderKey(topLevel string, metadata map[string]any) string {
	if metadata != nil {
		if v, ok := metadata["provider_key"].(string); ok && v != "" {
			return v
		}
	}
	// Fall back to the top-level field if it looks like a concrete provider.
	// The plugin identifier itself is never a valid provider key.
	if topLevel != "" && topLevel != pluginName {
		return topLevel
	}
	return ""
}
