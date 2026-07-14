// Package main — Grok (xAI) provider binding.
//
// Python worker driver: helpers/grok.py. Camoufox drives auth.x.ai OAuth
// consent flow, captures the code at http://127.0.0.1:56121/callback,
// and exchanges it against auth.x.ai/oauth2/token. Public PKCE client.
// Output file: grok-<sanitized-email>.json.
package main

import (
	"encoding/json"
	"fmt"
	"path/filepath"
)

var grokBinding = providerBinding{
	Key:          "grok",
	Label:        "Grok (xAI)",
	Description:  "Camoufox 驱动 auth.x.ai OAuth 授权页 → 拦截 :56121/callback → 换 token。PKCE public client。",
	StorageType:  "grok",
	FilenameHint: "grok-<email>.json",
	Fields:       commonFields,
	Extras: []fieldDef{
		{Key: "email", Type: "text", Title: "xAI 账号邮箱", Required: true},
		{Key: "password", Type: "password", Title: "密码", Required: true},
	},
	buildLoginJob: grokBuildLoginJob,
	parseStorage:  grokParseStorage,
	refreshFunc:   grokRefresh,
}

func init() {
	registerProvider(&grokBinding)
}

func grokBuildLoginJob(req authLoginStartRequest, outDir string) (workerJob, error) {
	extras := parseExtras(req.Metadata)
	if extras["email"] == "" {
		return workerJob{}, fmt.Errorf("grok requires email")
	}
	if extras["password"] == "" {
		return workerJob{}, fmt.Errorf("grok requires password")
	}
	return workerJob{
		Provider: "grok",
		Label:    stringOr(extras["label"], extras["email"]),
		Proxy:    extras["proxy"],
		OutDir:   outDir,
		Timeout:  intOr(req.Metadata, "timeout_seconds", 600),
		Extras:   metadataToExtras(req.Metadata),
	}, nil
}

func grokParseStorage(rawJSON []byte, fileName string) (string, map[string]any) {
	var meta struct {
		Email string `json:"email"`
		Scope string `json:"scope"`
	}
	_ = json.Unmarshal(rawJSON, &meta)
	label := meta.Email
	if label == "" {
		label = filepath.Base(fileName)
	}
	return label, map[string]any{
		"email": meta.Email,
		"scope": meta.Scope,
	}
}
