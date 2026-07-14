// Package main — Kiro token refresh (protocol only, no browser).
//
// AWS IAM Identity Center flow:
//
//	POST https://oidc.<region>.amazonaws.com/token
//	Body: {clientId, clientSecret, grantType: "refresh_token", refreshToken}
//	Response: {accessToken, refreshToken?, expiresIn, tokenType}
//
// M365 external_idp flow:
//
//	POST <token_endpoint> (from stored AuthData)
//	Body (form-urlencoded): grant_type=refresh_token
//	                        refresh_token=<...>
//	                        client_id=<clientId>
//	                        scope=<space-delimited>
//	Response: same OAuth2 shape
//
// Both mirror what kiro.rs::src/kiro/auth/idc.rs and login-hub
// helpers/kiro.py do — we intentionally stay compatible with the JSON
// schema kiro-rs writes so credentials round-trip losslessly.
package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// kiroStorage is the on-disk schema for a kiro CPA credential file.
// Matches muxhub scripts/login-hub/helpers/kiro.py::_build_cpa_json.
type kiroStorage struct {
	Type          string `json:"type"`
	AccessToken   string `json:"access_token"`
	RefreshToken  string `json:"refresh_token"`
	ProfileARN    string `json:"profile_arn,omitempty"`
	ExpiresAt     string `json:"expires_at,omitempty"`
	AuthMethod    string `json:"auth_method"`
	Email         string `json:"email,omitempty"`
	Disabled      bool   `json:"disabled"`
	ClientID      string `json:"client_id,omitempty"`
	ClientSecret  string `json:"client_secret,omitempty"`
	Region        string `json:"region,omitempty"`
	StartURL      string `json:"start_url,omitempty"`
	IssuerURL     string `json:"issuer_url,omitempty"`
	TokenEndpoint string `json:"token_endpoint,omitempty"`
	Scopes        string `json:"scopes,omitempty"`
	Provider      string `json:"provider,omitempty"`

	// Optional metadata carried through since our first-time login
	// captured them via the state machine. Persisted so a rotated auth
	// can be re-run without re-scraping.
	GeneratedPassword   string `json:"generated_password,omitempty"`
	GeneratedTotpSecret string `json:"generated_totp_secret,omitempty"`
	SsoUsername         string `json:"sso_username,omitempty"`
}

func kiroRefreshIdc(req authRefreshRequest, stored kiroStorage) []byte {
	region := stored.Region
	if region == "" {
		region = "us-east-1"
	}
	if stored.ClientID == "" || stored.ClientSecret == "" {
		return errorEnvelope("missing_client_credentials",
			"IdC refresh requires clientId+clientSecret to be present in storage — reauthenticate to fill them")
	}
	endpoint := fmt.Sprintf("https://oidc.%s.amazonaws.com/token", region)
	body, err := json.Marshal(map[string]string{
		"clientId":     stored.ClientID,
		"clientSecret": stored.ClientSecret,
		"grantType":    "refresh_token",
		"refreshToken": stored.RefreshToken,
	})
	if err != nil {
		return errorEnvelope("marshal_error", err.Error())
	}
	respBody, status, err := postJSON(endpoint, body)
	if err != nil {
		return errorEnvelope("network_error", err.Error())
	}
	if status < 200 || status >= 300 {
		return errorEnvelope("token_endpoint_error",
			fmt.Sprintf("HTTP %d: %s", status, truncate(string(respBody), 300)))
	}
	var tok struct {
		AccessToken  string `json:"accessToken"`
		RefreshToken string `json:"refreshToken"`
		ExpiresIn    int    `json:"expiresIn"`
		TokenType    string `json:"tokenType"`
	}
	if err := json.Unmarshal(respBody, &tok); err != nil {
		return errorEnvelope("bad_response", err.Error())
	}
	if tok.AccessToken == "" {
		return errorEnvelope("empty_token",
			fmt.Sprintf("token endpoint returned no accessToken: %s", truncate(string(respBody), 300)))
	}
	stored.AccessToken = tok.AccessToken
	if tok.RefreshToken != "" {
		stored.RefreshToken = tok.RefreshToken
	}
	if tok.ExpiresIn > 0 {
		stored.ExpiresAt = time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second).UTC().Format(time.RFC3339)
	}
	return kiroBuildRefreshResponse(req, stored, tok.ExpiresIn)
}

func kiroRefreshExternalIdp(req authRefreshRequest, stored kiroStorage) []byte {
	if stored.TokenEndpoint == "" {
		return errorEnvelope("missing_token_endpoint",
			"external_idp refresh requires token_endpoint in storage")
	}
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", stored.RefreshToken)
	if stored.ClientID != "" {
		form.Set("client_id", stored.ClientID)
	}
	if stored.Scopes != "" {
		form.Set("scope", stored.Scopes)
	}
	respBody, status, err := postForm(stored.TokenEndpoint, form)
	if err != nil {
		return errorEnvelope("network_error", err.Error())
	}
	if status < 200 || status >= 300 {
		return errorEnvelope("token_endpoint_error",
			fmt.Sprintf("HTTP %d: %s", status, truncate(string(respBody), 300)))
	}
	// External IdPs return snake_case per RFC 6749.
	var tok struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
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
	if tok.ExpiresIn > 0 {
		stored.ExpiresAt = time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second).UTC().Format(time.RFC3339)
	}
	if tok.Scope != "" {
		stored.Scopes = tok.Scope
	}
	return kiroBuildRefreshResponse(req, stored, tok.ExpiresIn)
}

func kiroBuildRefreshResponse(req authRefreshRequest, stored kiroStorage, expiresIn int) []byte {
	storageBytes, err := json.MarshalIndent(stored, "", "  ")
	if err != nil {
		return errorEnvelope("marshal_error", err.Error())
	}
	// AWS access tokens live ~1h for IdC and ~5m-1h for M365. Refresh
	// aggressively: 5 minutes before expiry.
	nextRefresh := time.Now().Add(time.Duration(expiresIn-300) * time.Second)
	if expiresIn <= 300 {
		nextRefresh = time.Now().Add(30 * time.Second)
	}
	auth := authData{
		Provider:    "kiro",
		ID:          req.AuthID,
		FileName:    req.AuthID, // ID == filename by our convention
		Label:       stringOr(stored.Email, req.AuthID),
		StorageJSON: storageBytes,
		Metadata:    req.Metadata,
		Attributes:  req.Attributes,
	}
	if auth.Metadata == nil {
		auth.Metadata = map[string]any{}
	}
	auth.Metadata["profile_arn"] = stored.ProfileARN
	auth.Metadata["region"] = stored.Region
	auth.Metadata["source"] = "cpa-login-hub"
	return okEnvelope(authRefreshResponse{
		Auth:             auth,
		NextRefreshAfter: nextRefresh,
	})
}

// ---------- HTTP helpers -------------------------------------------------

var refreshHTTPClient = &http.Client{
	Timeout: 30 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	},
}

func postJSON(endpoint string, body []byte) ([]byte, int, error) {
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	// AWS SSO OIDC wants an explicit Host header even though net/http will
	// set it — being explicit doesn't hurt and matches kiro.rs.
	if u, err := url.Parse(endpoint); err == nil {
		req.Host = u.Host
	}
	resp, err := refreshHTTPClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	buf, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return buf, resp.StatusCode, nil
}

func postForm(endpoint string, form url.Values) ([]byte, int, error) {
	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := refreshHTTPClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	buf, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return buf, resp.StatusCode, nil
}
