// Package main — Grok (xAI) token refresh (protocol only).
//
// POST https://auth.x.ai/oauth2/token
// Content-Type: application/x-www-form-urlencoded
// Body: client_id=<CLIENT_ID>&grant_type=refresh_token&refresh_token=<...>
//
// grok is a PKCE public client — no client_secret. CLIENT_ID matches
// helpers/grok.py::CLIENT_ID exactly.
package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"time"
)

const (
	grokTokenEndpoint = "https://auth.x.ai/oauth2/token"
	grokClientID      = "b1a00492-073a-47ea-816f-4c329264a828" // matches helpers/grok.py:57
)

// grokStorage matches helpers/grok.py::_build_record.
type grokStorage struct {
	Type         string `json:"type"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token,omitempty"`
	Email        string `json:"email"`
	ExpiresIn    int    `json:"expires_in"`
	Expired      string `json:"expired,omitempty"`
	Scope        string `json:"scope"`
	Timestamp    int64  `json:"timestamp"`
	TokenType    string `json:"token_type"`
	Disabled     bool   `json:"disabled"`
}

func grokRefresh(req authRefreshRequest) []byte {
	var stored grokStorage
	if err := json.Unmarshal(req.StorageJSON, &stored); err != nil {
		return errorEnvelope("bad_storage", err.Error())
	}
	if stored.RefreshToken == "" {
		return errorEnvelope("missing_refresh_token", "stored grok auth has no refresh_token")
	}

	form := url.Values{}
	form.Set("client_id", grokClientID)
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", stored.RefreshToken)

	respBody, status, err := postForm(grokTokenEndpoint, form)
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
		Scope        string `json:"scope"`
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
	if tok.TokenType != "" {
		stored.TokenType = tok.TokenType
	}
	if tok.Scope != "" {
		stored.Scope = tok.Scope
	}
	now := time.Now()
	if tok.ExpiresIn > 0 {
		stored.ExpiresIn = tok.ExpiresIn
		stored.Expired = now.UTC().Add(time.Duration(tok.ExpiresIn) * time.Second).Format("2006-01-02T15:04:05+00:00")
	}
	stored.Timestamp = now.UnixMilli()

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
	auth.Metadata["provider_key"] = "grok"
	auth.Metadata["source"] = pluginName
	auth.Metadata["email"] = stored.Email

	return okEnvelope(authRefreshResponse{
		Auth:             auth,
		NextRefreshAfter: computeNextRefresh(tok.ExpiresIn),
	})
}
