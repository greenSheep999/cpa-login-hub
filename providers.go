// Package main — provider registry.
//
// The plugin is an umbrella that serves five providers behind a single CPA
// AuthProvider identifier. The dispatch tables live here so capability_auth.go
// stays a thin router — every provider defines its worker-spec builder, its
// storage-schema discriminator, and its refresh entry point in one place.
//
// Adding a sixth provider = drop a provider_<name>.go implementing the
// buildLoginJob / refreshFunc closures, then wire it into providerRegistry
// below.
package main

// fieldDef describes one input field the panel UI needs to render for a
// provider. Mirrors muxhub scripts/login-hub/server.py::PROVIDER_SCHEMAS so
// we can copy the field list verbatim.
type fieldDef struct {
	Key         string `json:"key"`
	Type        string `json:"type"` // text | password
	Title       string `json:"title"`
	Placeholder string `json:"placeholder,omitempty"`
	Required    bool   `json:"required,omitempty"`
}

// providerBinding is the per-provider dispatch record. capability_auth.go
// looks up each of these when it needs to route a request; keeping them all
// in one file makes it obvious what a provider owns end-to-end.
type providerBinding struct {
	// Key is the internal provider identifier ("kiro" | "openai" | ...).
	Key string
	// Label is the human-readable dropdown label on the panel.
	Label string
	// Description shows below the dropdown to remind the user what this
	// provider does.
	Description string
	// StorageType is the top-level "type" value we look for in a CPA JSON
	// file when deciding whether a parsed auth belongs to us.
	StorageType string
	// FilenameHint describes the on-disk filename pattern this provider
	// produces (used for logs / UI hints only).
	FilenameHint string
	// Fields lists provider-common inputs (label + proxy). Kept separate
	// from Extras because the panel groups them differently.
	Fields []fieldDef
	// Extras lists provider-specific inputs — the fields the state
	// machine consumes.
	Extras []fieldDef

	// buildLoginJob turns the login-start request into a workerJob spec
	// the Python runner understands. Returns a job + friendly error if
	// required fields are missing.
	buildLoginJob func(req authLoginStartRequest, outDir string) (workerJob, error)

	// parseStorage extracts (Label, Metadata) from a parsed CPA JSON file
	// for handleAuthParse.
	parseStorage func(rawJSON []byte, fileName string) (label string, metadata map[string]any)

	// refreshFunc executes a protocol-level token refresh. nil means the
	// provider cannot refresh — the plugin returns not_implemented and
	// the user must re-login via the panel.
	refreshFunc func(req authRefreshRequest) []byte
}

// providerRegistry is the source of truth. Populated by init functions in
// each provider_<name>.go file (init order in Go is deterministic per
// file — we don't depend on it; every init just registers itself).
var providerRegistry = map[string]*providerBinding{}

func registerProvider(binding *providerBinding) {
	if binding == nil || binding.Key == "" {
		return
	}
	providerRegistry[binding.Key] = binding
}

// commonFields are the label + proxy inputs shared by every provider.
// Kept in one place so all provider bindings stay consistent.
var commonFields = []fieldDef{
	{Key: "label", Type: "text", Title: "Label", Placeholder: "留空自动用邮箱作为标签"},
	{Key: "proxy", Type: "text", Title: "Proxy", Placeholder: "留空 = 系统代理 / env；填 direct 强制直连"},
}

// providerKeys returns the list of registered provider keys, sorted for
// UI stability.
func providerKeys() []string {
	out := make([]string, 0, len(providerRegistry))
	for k := range providerRegistry {
		out = append(out, k)
	}
	// small deterministic order — kiro first (most-used), then alphabetical.
	preferred := []string{"kiro", "openai", "grok", "antigravity", "cursor"}
	byKey := make(map[string]bool, len(out))
	for _, k := range out {
		byKey[k] = true
	}
	sorted := make([]string, 0, len(out))
	for _, k := range preferred {
		if byKey[k] {
			sorted = append(sorted, k)
			delete(byKey, k)
		}
	}
	for _, k := range out {
		if byKey[k] {
			sorted = append(sorted, k)
		}
	}
	return sorted
}

// lookupProviderByStorageType returns the binding whose CPA JSON top-level
// "type" field equals storageType. Used by handleAuthParse / handleRefresh
// when we only have a raw JSON blob and need to route it.
func lookupProviderByStorageType(storageType string) *providerBinding {
	for _, b := range providerRegistry {
		if b.StorageType == storageType {
			return b
		}
	}
	return nil
}
