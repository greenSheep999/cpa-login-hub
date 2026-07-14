// Package main — OpenAI (codex) token refresh (protocol only).
//
// POST https://auth.openai.com/oauth/token
// Content-Type: application/x-www-form-urlencoded
// Body: client_id=<CLIENT_ID>&grant_type=refresh_token&refresh_token=<...>
//
// codex is a PKCE public client — no client_secret. CLIENT_ID matches
// helpers/openai.py::CLIENT_ID exactly so refresh interoperates with any
// credential this plugin issues.
package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"time"
)

const (
	openaiTokenEndpoint = "https://auth.openai.com/oauth/token"
	openaiClientID      = "app_EMoamEEZ73f0CkXaXp7hrann" // matches helpers/openai.py:46
)

// openaiStorage is the on-disk schema. Field names match
// helpers/openai.py::_build_cpa_record exactly.
type openaiStorage struct {
	Type         string `json:"type"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	AccountID    string `json:"account_id"`
	Email        string `json:"email"`
	Expired      string `json:"expired"`
	LastRefresh  string `json:"last_refresh"`
	Disabled     bool   `json:"disabled"`
}

func openaiRefresh(req authRefreshRequest) []byte {
	var stored openaiStorage
	if err := json.Unmarshal(req.StorageJSON, &stored); err != nil {
		return errorEnvelope("bad_storage", err.Error())
	}
	if stored.RefreshToken == "" {
		return errorEnvelope("missing_refresh_token", "stored openai auth has no refresh_token")
	}

	form := url.Values{}
	form.Set("client_id", openaiClientID)
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", stored.RefreshToken)

	respBody, status, err := postForm(openaiTokenEndpoint, form)
	if err != nil {
		return errorEnvelope("network_error", err.Error())
	}
	if status < 200 || status >= 300 {
		return errorEnvelope("token_endpoint_error",
			fmt.Sprintf("HTTP %d: %s", status, truncate(string(respBody), 300)))
	}

	var tok struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
		ExpiresIn    int    `json:"expires_in"`
		TokenType    string `json:"token_type"`
	}
	if err := json.Unmarshal(respBody, &tok); err != nil {
		return errorEnvelope("bad_response", err.Error())
	}
	if tok.AccessToken == "" {
		return errorEnvelope("empty_token",
			fmt.Sprintf("token endpoint returned no access_token: %s", truncate(string(respBody), 300)))
	}

	stored.AccessToken = tok.AccessToken
	if tok.RefreshToken != "" {
		stored.RefreshToken = tok.RefreshToken
	}
	if tok.IDToken != "" {
		stored.IDToken = tok.IDToken
	}
	// Python side writes ``expired`` in Asia/Shanghai (+08:00) — mirror
	// that so a Python-written record and a Go-written record round-trip
	// identically.
	now := time.Now()
	shanghai := time.FixedZone("+08:00", 8*3600)
	if tok.ExpiresIn > 0 {
		stored.Expired = now.Add(time.Duration(tok.ExpiresIn) * time.Second).In(shanghai).Format("2006-01-02T15:04:05-07:00")
	}
	stored.LastRefresh = now.In(shanghai).Format("2006-01-02T15:04:05-07:00")

	storageBytes, err := json.MarshalIndent(stored, "", "  ")
	if err != nil {
		return errorEnvelope("marshal_error", err.Error())
	}

	auth := authData{
		Provider:    pluginName,
		ID:          req.AuthID,
		FileName:    req.AuthID,
		Label:       stringOr(stored.Email, req.AuthID),
		StorageJSON: storageBytes,
		Metadata:    req.Metadata,
		Attributes:  req.Attributes,
	}
	if auth.Metadata == nil {
		auth.Metadata = map[string]any{}
	}
	auth.Metadata["provider_key"] = "openai"
	auth.Metadata["source"] = pluginName
	auth.Metadata["account_id"] = stored.AccountID
	auth.Metadata["email"] = stored.Email

	return okEnvelope(authRefreshResponse{
		Auth:             auth,
		NextRefreshAfter: computeNextRefresh(tok.ExpiresIn),
	})
}
