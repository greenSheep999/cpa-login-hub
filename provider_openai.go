// Package main — OpenAI (codex) provider binding.
//
// Python worker driver: helpers/openai.py. Uses Camoufox to complete
// the sign-in flow (email/password + optional TOTP + optional SMS OTP
// via ChongPT), captures the auth code at http://localhost:1455/auth/
// callback, and exchanges it for tokens against auth.openai.com/oauth/
// token. Output file: codex-<sanitized-email>-<plan>.json.
package main

import (
	"encoding/json"
	"fmt"
	"path/filepath"
)

var openaiBinding = providerBinding{
	Key:          "openai",
	Label:        "OpenAI / Codex",
	Description:  "邮箱密码登录 + 可选 TOTP + 可选 ChongPT 短信 OTP。落盘 codex-<email>-<plan>.json。",
	StorageType:  "codex",
	FilenameHint: "codex-<email>-<plan>.json",
	Fields:       commonFields,
	Extras: []fieldDef{
		{Key: "email", Type: "text", Title: "OpenAI 账号邮箱", Required: true},
		{Key: "password", Type: "password", Title: "密码", Required: true},
		{Key: "totp_secret", Type: "password", Title: "TOTP base32 (可选)"},
		{Key: "sms_cdk", Type: "text", Title: "ChongPT SMS CDK (可选)", Placeholder: "购买短信验证码所用的 CDK"},
	},
	buildLoginJob: openaiBuildLoginJob,
	parseStorage:  openaiParseStorage,
	refreshFunc:   openaiRefresh,
}

func init() {
	registerProvider(&openaiBinding)
}

func openaiBuildLoginJob(req authLoginStartRequest, outDir string) (workerJob, error) {
	extras := parseExtras(req.Metadata)
	if extras["email"] == "" {
		return workerJob{}, fmt.Errorf("openai requires email")
	}
	if extras["password"] == "" {
		return workerJob{}, fmt.Errorf("openai requires password")
	}
	return workerJob{
		Provider: "openai",
		Label:    stringOr(extras["label"], extras["email"]),
		Proxy:    extras["proxy"],
		OutDir:   outDir,
		Timeout:  intOr(req.Metadata, "timeout_seconds", 600),
		Extras:   metadataToExtras(req.Metadata),
	}, nil
}

func openaiParseStorage(rawJSON []byte, fileName string) (string, map[string]any) {
	var meta struct {
		Email     string `json:"email"`
		AccountID string `json:"account_id"`
	}
	_ = json.Unmarshal(rawJSON, &meta)
	label := meta.Email
	if label == "" {
		label = filepath.Base(fileName)
	}
	return label, map[string]any{
		"email":      meta.Email,
		"account_id": meta.AccountID,
	}
}
