// Package main — Cursor provider binding.
//
// Python worker driver: helpers/cursor.py. Cursor's sign-in is Email OTP
// + Cloudflare Turnstile — the worker can IMAP the OTP from a mailbox if
// mail_* extras are provided, or wait for the user to paste it manually
// via the “otp“ extra. Auth tokens are extracted from cursor.com/api/
// auth/me via authenticated cookie session, NOT via OAuth token exchange.
// Output file: cursor-<sanitized-email>.json. Refresh isn't implemented
// in Python — the module TODO notes it as follow-up work — so this
// binding returns not_implemented and asks users to re-login.
package main

import (
	"encoding/json"
	"fmt"
	"path/filepath"
)

var cursorBinding = providerBinding{
	Key:          "cursor",
	Label:        "Cursor (Email OTP)",
	Description:  "Email OTP + Turnstile。可选提供 IMAP 邮箱自动取 OTP，或在 ``otp`` 字段手动粘贴。落盘 cursor-<email>.json。",
	StorageType:  "cursor",
	FilenameHint: "cursor-<email>.json",
	Fields:       commonFields,
	Extras: []fieldDef{
		{Key: "email", Type: "text", Title: "Cursor 账号邮箱", Required: true},
		{Key: "mail_host", Type: "text", Title: "IMAP host (可选)", Placeholder: "imap.gmail.com"},
		{Key: "mail_port", Type: "text", Title: "IMAP port (可选)", Placeholder: "993"},
		{Key: "mail_user", Type: "text", Title: "IMAP 用户名 (可选)"},
		{Key: "mail_pass", Type: "password", Title: "IMAP 密码 (可选)"},
		{Key: "otp", Type: "text", Title: "手工 OTP (可选)", Placeholder: "如果不用 IMAP，可在这里手动粘贴 6 位验证码"},
		{Key: "headless", Type: "text", Title: "Headless 模式 (可选)", Placeholder: "true / false，默认 true"},
	},
	buildLoginJob: cursorBuildLoginJob,
	parseStorage:  cursorParseStorage,
	// refreshFunc intentionally nil — Cursor uses a cookie session refresh
	// path that has not been implemented on either the Python side or
	// here. Users get a clean "please re-login" message from handleRefresh.
	refreshFunc: nil,
}

func init() {
	registerProvider(&cursorBinding)
}

func cursorBuildLoginJob(req authLoginStartRequest, outDir string) (workerJob, error) {
	extras := parseExtras(req.Metadata)
	if extras["email"] == "" {
		return workerJob{}, fmt.Errorf("cursor requires email")
	}
	return workerJob{
		Provider: "cursor",
		Label:    stringOr(extras["label"], extras["email"]),
		Proxy:    extras["proxy"],
		OutDir:   outDir,
		Timeout:  intOr(req.Metadata, "timeout_seconds", 600),
		Extras:   metadataToExtras(req.Metadata),
	}, nil
}

func cursorParseStorage(rawJSON []byte, fileName string) (string, map[string]any) {
	var meta struct {
		Email       string `json:"email"`
		UserID      string `json:"user_id"`
		AuthKind    string `json:"auth_kind"`
		Refreshable bool   `json:"refreshable"`
	}
	_ = json.Unmarshal(rawJSON, &meta)
	label := meta.Email
	if label == "" {
		label = filepath.Base(fileName)
	}
	return label, map[string]any{
		"email":       meta.Email,
		"user_id":     meta.UserID,
		"auth_kind":   meta.AuthKind,
		"refreshable": meta.Refreshable,
	}
}
