# Install

## Prerequisites

1. **CPA (CLIProxyAPI) already installed** — see
   [CPA install docs](https://github.com/router-for-me/CLIProxyAPI#installation).
   The plugin was built against CPA ≥ v0.9 (plugin ABI v1).
2. **Python 3.11 or newer on PATH**. Check:
   ```bash
   python3 --version   # 3.11.x, 3.12.x, or 3.13.x
   ```
3. **~1 GB free disk** for the auto-provisioned Python venv + Camoufox
   Firefox binaries.

## Option A — Prebuilt release

Download the tarball for your platform from
[Releases](https://github.com/greenSheep999/cpa-login-hub/releases):

- `cpa-login-hub-linux-amd64.tar.gz`
- `cpa-login-hub-darwin-amd64.tar.gz` (Apple Silicon: `-arm64` variant)
- `cpa-login-hub-windows-amd64.zip`

Extract into CPA's plugin directory (default `~/.cli-proxy-api/plugins`):

```bash
mkdir -p ~/.cli-proxy-api/plugins
curl -L https://github.com/greenSheep999/cpa-login-hub/releases/latest/download/cpa-login-hub-darwin-amd64.tar.gz \
  | tar -xzC ~/.cli-proxy-api/plugins/
```

The archive extracts into `~/.cli-proxy-api/plugins/cpa-login-hub/` with:

- `cpa-login-hub.dylib` (or `.so` / `.dll`)
- `worker/` — Python source tree
- `worker/requirements.txt` — pinned dependencies

## Option B — Build from source

```bash
git clone https://github.com/greenSheep999/cpa-login-hub.git
cd cpa-login-hub
make install CPA_PLUGIN_DIR=~/.cli-proxy-api/plugins
```

`make install` copies the freshly-built shared library and the `worker/`
directory into `$(CPA_PLUGIN_DIR)/cpa-login-hub/`. Override the plugin
dir if your CPA install is elsewhere.

## Configure CPA

Edit CPA's `config.yaml`:

```yaml
plugins:
  enabled: true
  dir: ~/.cli-proxy-api/plugins       # or wherever you extracted
  configs:
    cpa-login-hub:
      enabled: true
      priority: 100
```

Restart CPA. On startup you should see:

```
INFO plugin loaded  name=cpa-login-hub version=0.1.0-alpha
```

## First login — venv auto-provision

The first time you trigger a login through the management panel, the
plugin runs (once per install):

```
python3 -m venv worker/.venv
worker/.venv/bin/pip install -r worker/requirements.txt
worker/.venv/bin/python -m camoufox fetch     # ~150 MB
```

This takes ~90 seconds on a modern laptop. Subsequent logins reuse the
venv instantly.

If auto-provision fails (e.g. no network access to PyPI), run manually:

```bash
cd ~/.cli-proxy-api/plugins/cpa-login-hub
bash scripts/setup_venv.sh   # same three commands, plus better error text
```

## Troubleshooting

**Plugin doesn't load**

Check `~/.cli-proxy-api/logs/*.log` for the actual `dlopen` error.
Common causes:

- macOS Gatekeeper quarantine — `xattr -d com.apple.quarantine cpa-login-hub.dylib`
- Wrong architecture — `file cpa-login-hub.dylib` should match `uname -m`
- CPA too old — needs plugin ABI v1

**"venv setup failed: python3 not found"**

The plugin needs a system Python 3 on `PATH`. On macOS:

```bash
brew install python@3.13
```

**"camoufox fetch failed"**

Camoufox downloads Firefox from GitHub. Verify GitHub is reachable:

```bash
curl -I https://github.com/daijro/camoufox/releases
```

If behind a corporate proxy, set `HTTPS_PROXY` before running CPA.

**Login flow hangs at "opening verification URI"**

The Camoufox browser is on your CPA host's display. If CPA runs on a
headless server, set `headless: true` in the provider metadata — but
some providers (e.g. antigravity Google QR) require a visible browser
for scanning.
