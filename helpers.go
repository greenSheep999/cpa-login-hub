// Package main — small utilities.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

// newStateToken returns a URL-safe hex string used to correlate
// StartLogin / PollLogin invocations.
func newStateToken() string {
	var buf [16]byte
	_, _ = rand.Read(buf[:])
	return hex.EncodeToString(buf[:])
}

// parseExtras extracts a plain string bag from CPA's request metadata,
// mapping “extras.*“ keys down one level. CPA passes user-configured
// provider parameters under “Metadata“ — we surface a flat dict for
// callers that just want string values.
//
// Type coercion: JSON booleans and numbers are stringified rather than
// dropped, so panel inputs like “timeout_seconds: 900“ and
// “headless: true“ survive the round-trip.
func parseExtras(metadata map[string]any) map[string]string {
	out := map[string]string{}
	if metadata == nil {
		return out
	}
	assign := func(k string, v any) {
		out[k] = coerceString(v)
	}
	// Two conventions in the wild:
	//   metadata["extras"] = {..., password: ...}   (nested)
	//   metadata["password"] = ...                  (flat)
	if nested, ok := metadata["extras"].(map[string]any); ok {
		for k, v := range nested {
			assign(k, v)
		}
	}
	for k, v := range metadata {
		if k == "extras" {
			continue
		}
		assign(k, v)
	}
	return out
}

func coerceString(v any) string {
	switch n := v.(type) {
	case string:
		return n
	case bool:
		if n {
			return "true"
		}
		return "false"
	case int:
		return fmt.Sprintf("%d", n)
	case int64:
		return fmt.Sprintf("%d", n)
	case float64:
		// Prefer integer formatting when it's a whole number.
		if n == float64(int64(n)) {
			return fmt.Sprintf("%d", int64(n))
		}
		return fmt.Sprintf("%g", n)
	default:
		return ""
	}
}

// metadataToExtras flattens CPA's Metadata bag into the shape muxhub's
// login-hub helpers expect (an “extras“ dict of string→any).
func metadataToExtras(metadata map[string]any) map[string]any {
	if metadata == nil {
		return map[string]any{}
	}
	if nested, ok := metadata["extras"].(map[string]any); ok {
		out := make(map[string]any, len(nested))
		for k, v := range nested {
			out[k] = v
		}
		return out
	}
	// Flat mode: copy everything except reserved keys.
	out := make(map[string]any, len(metadata))
	for k, v := range metadata {
		if k == "provider_key" || k == "timeout_seconds" {
			continue
		}
		out[k] = v
	}
	return out
}

// stringOr returns fallback when s is empty.
func stringOr(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

// intOr reads an int from a metadata bag, falling back when missing/
// malformed. CPA's JSON deserialization gives us either float64 (real
// numbers) or int64 (some paths), so accept both.
func intOr(metadata map[string]any, key string, fallback int) int {
	if metadata == nil {
		return fallback
	}
	v, ok := metadata[key]
	if !ok {
		return fallback
	}
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	default:
		return fallback
	}
}

// computeNextRefresh picks a NextRefreshAfter timestamp that keeps CPA's
// scheduler from thrashing regardless of what the token endpoint returned.
//
//   - expiresIn ≤ 0  → 15 minutes (endpoint gave us nothing useful; be conservative)
//   - expiresIn ≤ 5m → 30 seconds (short-lived token; still let some time pass)
//   - otherwise      → expiresIn − 5 minutes (proactive refresh)
func computeNextRefresh(expiresIn int) time.Time {
	now := time.Now()
	switch {
	case expiresIn <= 0:
		return now.Add(15 * time.Minute)
	case expiresIn <= 300:
		return now.Add(30 * time.Second)
	default:
		return now.Add(time.Duration(expiresIn-300) * time.Second)
	}
}
