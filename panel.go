// Package main — embedded panel assets.
//
// The panel HTML/CSS/JS/i18n + logo are compiled into the plugin binary
// via go:embed so a single .dylib/.so ships with everything it needs.
//
// Cache-busting: index.html references its CSS/JS with ?v=BUILD_STAMP,
// where BUILD_STAMP is a SHA1 of the embedded panel resources (see
// panelBuildStamp()). Content-addressed → any byte change in any asset
// yields a new URL, so browsers with a previously long-cached copy of
// panel.js?v=<old> are forced to fetch panel.js?v=<new>. This defeats
// browser HTTP cache entries populated when a CDN (Cloudflare, etc.)
// rewrote our Cache-Control to a long max-age before we noticed and
// switched to no-store.
package main

import (
	"bytes"
	"crypto/sha1"
	_ "embed"
	"encoding/hex"
	"sync"
)

//go:embed panel/index.html
var embeddedPanelHTML []byte

//go:embed panel/panel.css
var embeddedPanelCSS []byte

//go:embed panel/panel.js
var embeddedPanelJS []byte

//go:embed panel/i18n.js
var embeddedPanelI18n []byte

//go:embed panel/logo.png
var embeddedPanelLogo []byte

var (
	buildStampOnce sync.Once
	buildStampVal  string
)

// panelBuildStamp returns a short SHA1 of the embedded panel resources.
// Computed once per plugin process. Any byte change in any embedded
// asset (CSS/JS/i18n/HTML/logo) yields a different stamp, so browser
// HTTP caches keyed off ?v=<stamp> are automatically invalidated.
func panelBuildStamp() string {
	buildStampOnce.Do(func() {
		h := sha1.New()
		h.Write([]byte(pluginVersion))
		h.Write(embeddedPanelHTML)
		h.Write(embeddedPanelCSS)
		h.Write(embeddedPanelJS)
		h.Write(embeddedPanelI18n)
		h.Write(embeddedPanelLogo)
		// 10 hex chars is plenty of entropy for cache-busting and stays
		// short enough to keep the URL readable in logs.
		buildStampVal = hex.EncodeToString(h.Sum(nil))[:10]
	})
	return buildStampVal
}

// panelIndexHTML returns index.html with the BUILD_STAMP placeholder
// filled in so browser caches key off the current asset fingerprint.
func panelIndexHTML() []byte {
	return bytes.ReplaceAll(embeddedPanelHTML, []byte("BUILD_STAMP"), []byte(panelBuildStamp()))
}

func panelCSS() []byte  { return embeddedPanelCSS }
func panelJS() []byte   { return embeddedPanelJS }
func panelI18n() []byte { return embeddedPanelI18n }
func panelLogo() []byte { return embeddedPanelLogo }
