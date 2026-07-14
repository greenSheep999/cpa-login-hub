// Package main — Kiro provider binding.
//
// Kiro has two login paths that live in the same Python entry point
// (helpers/kiro.py::run):
//
//   - M365 / external_idp (default, if extras["sso_start_url"] is empty)
//   - AWS IAM Identity Center / IdC (if extras["sso_start_url"] is set)
//
// Which one runs is decided inside the worker, not here — we just pass
// the extras through and the Python side dispatches. Both produce a CPA
// JSON with “type: "kiro"“ and refresh through kiroRefresh (which itself
// picks between IdC vs external_idp by inspecting auth_method).
package main

import (
	"encoding/json"
	"fmt"
	"path/filepath"
)

var kiroBinding = providerBinding{
	Key:          "kiro",
	Label:        "Kiro (M365 SSO / AWS IdC)",
	Description:  "Camoufox 隔离启浏览器 → app.kiro.dev/signin → 按 email 域自动识别 M365 或 IdC → 拦截 :3128/oauth/callback 拿 code → 换 token → 落盘 CLIProxyAPI_<user>.json",
	StorageType:  "kiro",
	FilenameHint: "CLIProxyAPI_<user>.json",
	Fields:       commonFields,
	Extras: []fieldDef{
		{Key: "email", Type: "text", Title: "邮箱 (M365 或 IdC 的登录用户名)", Placeholder: "user@example.com", Required: true},
		{Key: "password", Type: "password", Title: "密码", Required: true},
		{Key: "totp_secret", Type: "password", Title: "TOTP base32 (可选)", Placeholder: "MYKALLU3… — 自动算 6 位"},
		{Key: "sso_start_url", Type: "text", Title: "SSO Start URL (仅 IdC)", Placeholder: "https://d-xxxx.awsapps.com/start"},
		{Key: "region", Type: "text", Title: "Region (可选，默认 us-east-1)", Placeholder: "us-east-1 / eu-central-1"},
		{Key: "username", Type: "text", Title: "Username override (可选)", Placeholder: "文件名里的用户段"},
	},
	buildLoginJob: kiroBuildLoginJob,
	parseStorage:  kiroParseStorage,
	refreshFunc:   kiroRefresh,
}

func init() {
	registerProvider(&kiroBinding)
}

// kiroBuildLoginJob turns the panel-provided request into a workerJob
// the Python runner understands. Panel input validation happens here.
func kiroBuildLoginJob(req authLoginStartRequest, outDir string) (workerJob, error) {
	extras := parseExtras(req.Metadata)
	if extras["email"] == "" {
		return workerJob{}, fmt.Errorf("kiro requires email")
	}
	if extras["password"] == "" {
		return workerJob{}, fmt.Errorf("kiro requires password")
	}
	// IdC path is entered by presence of sso_start_url; we don't
	// validate it further — the worker knows the accepted forms.
	return workerJob{
		Provider: "kiro",
		Label:    stringOr(extras["label"], extras["email"]),
		Proxy:    extras["proxy"],
		OutDir:   outDir,
		Timeout:  intOr(req.Metadata, "timeout_seconds", 600),
		Extras:   metadataToExtras(req.Metadata),
	}, nil
}

// kiroParseStorage extracts (label, metadata) from a stored kiro CPA JSON.
// Label priority: email > filename-derived.
func kiroParseStorage(rawJSON []byte, fileName string) (string, map[string]any) {
	var meta struct {
		Email      string `json:"email"`
		AuthMethod string `json:"auth_method"`
		ProfileARN string `json:"profile_arn"`
		Region     string `json:"region"`
		StartURL   string `json:"start_url"`
	}
	_ = json.Unmarshal(rawJSON, &meta)
	label := meta.Email
	if label == "" {
		label = filepath.Base(fileName)
	}
	return label, map[string]any{
		"email":       meta.Email,
		"auth_method": meta.AuthMethod,
		"profile_arn": meta.ProfileARN,
		"region":      meta.Region,
		"start_url":   meta.StartURL,
	}
}
