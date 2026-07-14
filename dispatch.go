package main

import (
	"encoding/json"
	"fmt"
)

// Plugin metadata — returned by plugin.register / plugin.reconfigure.
// Kept in one place so version + description stay in sync across methods.
const (
	pluginName    = "cpa-login-hub"
	pluginVersion = "0.1.0-alpha"
	pluginAuthor  = "greenSheep999"
	pluginRepo    = "https://github.com/greenSheep999/cpa-login-hub"
)

// registerPayload is what plugin.register / plugin.reconfigure return.
// See CLIProxyAPI/examples/plugin/auth/go/main.go:130 for the reference
// shape. auth_provider=true tells the host we implement AuthProvider.
var registerPayload = map[string]interface{}{
	"schema_version": 1,
	"metadata": map[string]interface{}{
		"Name":             pluginName,
		"Version":          pluginVersion,
		"Author":           pluginAuthor,
		"GitHubRepository": pluginRepo,
		"ConfigFields":     []interface{}{},
	},
	"capabilities": map[string]interface{}{
		"auth_provider": true,
	},
}

// handleMethod routes a plugin RPC to the right capability.
// Returns the raw JSON envelope bytes ready for CPA to consume.
func handleMethod(method string, request []byte) []byte {
	switch method {
	case "plugin.register", "plugin.reconfigure":
		return okEnvelope(registerPayload)

	case "auth.identifier":
		// The host asks for our provider identifier list. We advertise a
		// virtual "cpa-login-hub" umbrella identifier plus one per real
		// provider we support — the host routes ParseAuth/StartLogin/... to
		// us for any of these.
		return okEnvelope(map[string]interface{}{
			// Field is singular per SDK; return the umbrella and let the
			// per-provider dispatch happen inside the plugin.
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
