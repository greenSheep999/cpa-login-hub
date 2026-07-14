# cpa-login-hub

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/go-1.22%2B-00ADD8.svg)](go.mod)
[![Status](https://img.shields.io/badge/status-alpha-orange.svg)](#roadmap)

A [CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI) plugin that
batch-imports OAuth credentials for AI coding assistants — powered by
[Camoufox](https://github.com/daijro/camoufox) stealth automation. Point CPA
at this plugin, click a provider in the management panel, and it drives a
real browser through the sign-in flow, pulls the tokens, and hands them
back to CPA's auth pool — no manual curl-ing, no fragile hand-crafted JSON.

繁體 / 简体中文说明: [README.zh.md](README.zh.md)

## Provider support

| Provider     | First-time login | Refresh (protocol) | Notes |
|--------------|:---:|:---:|-------|
| **kiro (IdC)** | ✅ v0.2 | ✅ v0.2 | AWS IAM Identity Center — automatic MFA scrape, password rotation to a fixed constant on first login |
| **kiro (M365)** | ✅ v0.2 | ✅ v0.2 | Microsoft Entra external_idp — auto-selected when `sso_start_url` is empty |
| **openai (codex)** | ✅ v0.2 | ✅ v0.2 | Includes chongpt.xyz SMS OTP integration for phone-verified accounts. PKCE public client |
| **grok**          | ✅ v0.2 | ✅ v0.2 | auth.x.ai Camoufox-based consent flow. PKCE public client |
| **antigravity**   | ✅ v0.2 | ✅ v0.2 | Google login + cloudcode-pa `project_id` resolution |
| **cursor**        | ✅ v0.2 | 🚧 | Email OTP + Turnstile. Refresh requires cookie-session flow (not yet ported) — re-login after expiry |

All five providers ship in a single umbrella dylib. Enter parameters from the
in-panel HTML UI ("CPA Login Hub" menu item); the plugin handles Camoufox
automation, token exchange, and auth-file drop-in.

## How it works

```
CPA management panel                Go plugin                    Python worker
        │                              │                                │
1. Open "CPA Login Hub" menu →         │                                │
   fetch panel HTML                    │                                │
   ← rendered form (provider dropdown  │                                │
   + schema-driven inputs)             │                                │
        │                              │                                │
2. Submit form                      → /prepare (POST)                   │
   (email/password/proxy/…)            │ stash in pendingSlot           │
        │                              │                                │
3. Navigate to                      → /cpa-login-hub-auth-url           │
   /v0/management/                     │ (CPA-native) → StartLogin      │
   cpa-login-hub-auth-url              │ pops pendingSlot,              │
   ← {status:ok, state}                │ spawns worker goroutine ──────→│ Camoufox + Playwright
        │                              │ returns state immediately      │ (kiro / openai /
        │                              │                                │  grok / antigravity /
4. Poll /get-auth-status            → PollLogin                         │  cursor state machines)
   ← wait / wait / … / ok              │ checks flow.isDone(),          │
        │                              │ reads worker's CPA JSON file,  │
        │                              │ returns AuthData ─────→ CPA    │
        │                              │                        auth-dir/
        │                              │                        CLIProxyAPI_*.json
                                       │
                                       │ For refresh (later):
                                       │   protocol-only HTTP to
                                       │   provider's /token endpoint,
                                       │   no browser, no worker fork.
       ▼
Go plugin reads the JSON, wraps into pluginapi.AuthData
       │
       ▼
CPA persists to auth-dir — credential is live
```

Refresh (`auth.refresh`) skips the Python worker entirely — pure Go
`net/http` POST against the provider's token endpoint. See
[docs/DESIGN.md](docs/DESIGN.md) for full sequence diagrams.

## Install

### From a release (recommended)

```bash
# Pick your OS artifact from the latest release:
#   cpa-login-hub-linux-amd64.tar.gz
#   cpa-login-hub-darwin-amd64.tar.gz
#   cpa-login-hub-windows-amd64.zip

curl -L https://github.com/greenSheep999/cpa-login-hub/releases/latest/download/cpa-login-hub-darwin-amd64.tar.gz \
  | tar -xzC ~/.cli-proxy-api/plugins/
```

Then in your CPA `config.yaml`:

```yaml
plugins:
  enabled: true
  dir: ~/.cli-proxy-api/plugins
  configs:
    cpa-login-hub:
      enabled: true
      priority: 100
```

Restart CPA. The plugin auto-provisions its Python venv on the first login
(~90s the first time, instant thereafter).

### From source

```bash
git clone https://github.com/greenSheep999/cpa-login-hub.git
cd cpa-login-hub
make install CPA_PLUGIN_DIR=~/.cli-proxy-api/plugins
```

See [docs/INSTALL.md](docs/INSTALL.md) for the full runbook.

## Requirements

- **CPA (CLIProxyAPI) ≥ v0.9** — earlier versions predate the plugin ABI
- **Python 3.11+** on the host running CPA (macOS / Linux ships one; Windows
  users install from [python.org](https://python.org))
- **Camoufox** — auto-installed on first login (~150 MB Firefox binary)
- Outbound network access to the provider (AWS SSO OIDC / Microsoft Entra /
  x.ai / etc.)

## Usage

Once installed, the CPA management panel gains a **"Login Hub"** category
under *Auth Files*:

1. Pick a provider (e.g. `kiro`)
2. Fill in the parameters: `sso_start_url` + `username` + `password`
   for IdC, or `email` + `password` for M365
3. Click **Start login** — the plugin opens Camoufox and drives the flow
4. When the browser closes the auth appears in your CPA credential list

For the raw REST API, see [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md).

## Roadmap

- [x] **v0.1** — Plugin scaffolding, kiro IdC (first-time + refresh)
- [ ] **v0.2** — All five providers active in `StartLogin`:
  kiro M365, openai/codex (with SMS OTP), grok, antigravity (with QR activation)
- [ ] **v0.3** — Frontend menu resource: batch import panel inside CPA
- [ ] **v0.4** — Multi-provider SMS abstraction (currently chongpt.xyz only)

## Contributing

Bug reports and pull requests welcome. See [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md)
for the dev environment setup.

## License

Apache License 2.0 — see [LICENSE](LICENSE).

## Acknowledgements

- Python worker vendored from [muxhub](https://github.com/daniellee2015/muxhub)'s
  `scripts/login-hub/`, itself informed by
  [kiro.rs](https://github.com/router-for-me/kiro.rs)'s IdC implementation.
- Camoufox by [daijro](https://github.com/daijro/camoufox).
- CPA plugin ABI: see the excellent
  [`ag-importer-plugin` design doc](https://github.com/router-for-me/CLIProxyAPI/blob/main/docs/design/ag-importer-plugin.md).
