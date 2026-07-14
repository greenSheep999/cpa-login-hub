// Package main — plugin.register metadata + method dispatch.
//
// One dlopen binary serves five providers behind a single umbrella
// identifier. CPA sees us as one AuthProvider ("cpa-login-hub"); which
// concrete provider each auth belongs to is carried in Metadata and in
// the CPA JSON's top-level “type“ field. See providers.go for the
// registry.
package main

import (
	"encoding/json"
	"fmt"
)

// Plugin metadata — returned by plugin.register / plugin.reconfigure.
//
// pluginName IS the CPA provider identifier the management panel uses.
// Umbrella-style: a single identifier serves every provider we support.
// Per-provider routing happens inside the plugin (see providers.go).
const (
	pluginName    = "cpa-login-hub"
	pluginVersion = "0.2.0-alpha"
	pluginAuthor  = "greenSheep999"
	pluginRepo    = "https://github.com/greenSheep999/cpa-login-hub"
)

// registerPayload is what plugin.register / plugin.reconfigure return.
// Shape mirrors CLIProxyAPI/examples/plugin/auth/go/main.go:130.
//   - auth_provider=true: we implement AuthProvider (parse/start/poll/refresh).
//   - management_api=true: we implement the panel HTML + prepare endpoint.
var registerPayload = map[string]interface{}{
	"schema_version": 1,
	"metadata": map[string]interface{}{
		"Name":             pluginName,
		"Version":          pluginVersion,
		"Author":           pluginAuthor,
		"GitHubRepository": pluginRepo,
		// Logo is served by our own management API as a plugin resource.
		// CPA's UI reads Metadata.Logo when rendering plugin cards.
		"Logo":         "/v0/resource/plugins/" + pluginName + "/logo.png",
		"ConfigFields": []interface{}{},
	},
	"capabilities": map[string]interface{}{
		"auth_provider":  true,
		"management_api": true,
	},
}

// handleMethod routes a plugin RPC to the right capability handler.
// Returns the raw JSON envelope bytes ready for CPA to consume.
func handleMethod(method string, request []byte) []byte {
	switch method {
	case "plugin.register", "plugin.reconfigure":
		return okEnvelope(registerPayload)

	// --- AuthProvider capability ---

	case "auth.identifier":
		return okEnvelope(map[string]interface{}{
			"identifier": pluginName,
		})

	case "auth.parse":
		return handleAuthParse(request)

	case "auth.login.start":
		return handleLoginStart(request)

	case "auth.login.poll":
		return handleLoginPoll(request)

	case "auth.refresh":
		return handleRefresh(request)

	// --- ManagementAPI capability ---

	case "management.register":
		return handleManagementRegister(request)

	case "management.handle":
		return handleManagementHandle(request)

	default:
		return errorEnvelope("unknown_method", fmt.Sprintf("unknown method: %s", method))
	}
}

// decodeRequest is a small helper: given the raw envelope-less payload the
// host sends, unmarshal it into a typed struct. CPA passes the *request*
// struct's JSON directly — no envelope on the inbound side.
func decodeRequest(request []byte, out interface{}) error {
	if len(request) == 0 {
		return nil
	}
	return json.Unmarshal(request, out)
}
