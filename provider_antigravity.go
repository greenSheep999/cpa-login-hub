// Package main — Antigravity (Google OAuth) provider binding.
//
// Python worker driver: helpers/antigravity.py. Camoufox drives Google's
// OAuth consent page, captures the code at
// http://localhost:51121/oauth-callback, and exchanges it against
// oauth2.googleapis.com/token. Uses a Google-issued installed-app
// client_secret (public-in-practice per RFC 8252). Output file:
// antigravity-<email>.json.
package main

import (
	"encoding/json"
	"fmt"
	"path/filepath"
)

var antigravityBinding = providerBinding{
	Key:          "antigravity",
	Label:        "Antigravity (Google OAuth)",
	Description:  "Camoufox 驱动 Google 同意页 → cloudcode-pa 取 project_id → 落盘 antigravity-<email>.json。",
	StorageType:  "antigravity",
	FilenameHint: "antigravity-<email>.json",
	Fields:       commonFields,
	Extras: []fieldDef{
		{Key: "email", Type: "text", Title: "Google 邮箱", Required: true},
		{Key: "password", Type: "password", Title: "密码", Required: true},
		{Key: "totp_secret", Type: "password", Title: "TOTP base32 (可选)"},
		{Key: "skip_activation", Type: "text", Title: "skip_activation (可选)", Placeholder: "填 true 只出 raw token"},
	},
	buildLoginJob: antigravityBuildLoginJob,
	parseStorage:  antigravityParseStorage,
	refreshFunc:   antigravityRefresh,
}

func init() {
	registerProvider(&antigravityBinding)
}

func antigravityBuildLoginJob(req authLoginStartRequest, outDir string) (workerJob, error) {
	extras := parseExtras(req.Metadata)
	if extras["email"] == "" {
		return workerJob{}, fmt.Errorf("antigravity requires email")
	}
	if extras["password"] == "" {
		return workerJob{}, fmt.Errorf("antigravity requires password")
	}
	return workerJob{
		Provider: "antigravity",
		Label:    stringOr(extras["label"], extras["email"]),
		Proxy:    extras["proxy"],
		OutDir:   outDir,
		Timeout:  intOr(req.Metadata, "timeout_seconds", 600),
		Extras:   metadataToExtras(req.Metadata),
	}, nil
}

func antigravityParseStorage(rawJSON []byte, fileName string) (string, map[string]any) {
	var meta struct {
		Email     string `json:"email"`
		ProjectID string `json:"project_id"`
	}
	_ = json.Unmarshal(rawJSON, &meta)
	label := meta.Email
	if label == "" {
		label = filepath.Base(fileName)
	}
	return label, map[string]any{
		"email":      meta.Email,
		"project_id": meta.ProjectID,
	}
}
