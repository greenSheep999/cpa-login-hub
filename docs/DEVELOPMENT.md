# Development

## Repository layout

See [DESIGN.md](DESIGN.md) for the file-by-file rationale.

## Local dev loop

1. Clone + open the repo.
2. Point `CPA_LOGIN_HUB_DIR` at the checkout so the plugin finds
   `worker/` when it's loaded from an arbitrary path:
   ```bash
   export CPA_LOGIN_HUB_DIR="$(pwd)"
   ```
3. Build:
   ```bash
   make build
   ```
4. Symlink into a dev CPA install:
   ```bash
   ln -sf "$(pwd)/cpa-login-hub.dylib" ~/.cli-proxy-api/plugins/cpa-login-hub/
   ln -sf "$(pwd)/worker" ~/.cli-proxy-api/plugins/cpa-login-hub/
   ```
5. Restart CPA and watch its logs for the plugin load event.

## Testing changes without CPA

The plugin exposes its full JSON-RPC surface via a tiny CLI harness
(planned — v0.2 will ship `cmd/pluginctl` that shells `cliproxyPluginCall`
end-to-end). For now, unit-testing goes through Go's normal `go test`.

The Python worker can be exercised standalone, exactly as muxhub does:

```bash
cd worker
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
python -m camoufox fetch

echo '{"provider":"kiro","label":"test","extras":{"sso_start_url":"…","username":"…","password":"…","region":"eu-central-1"},"out_dir":"/tmp","timeout":600}' \
  | python -m worker.runner
```

You'll see the JSON event stream on stdout — identical to what the Go
side will consume in production.

## Provider metadata contract

CPA passes provider parameters through `AuthLoginStartRequest.Metadata`.
By convention this plugin expects:

```jsonc
{
  "provider_key": "kiro",         // selects the flow (kiro | openai | grok | antigravity | codex)
  "timeout_seconds": 600,          // optional; default 600
  "extras": {                      // forwarded verbatim to the Python worker
    "sso_start_url": "https://d-….awsapps.com/start",
    "region": "eu-central-1",
    "username": "user.foo.bar",
    "password": "…",
    "totp_secret": "…",            // optional; scraped during first login
    "headless": false               // default: false (visible browser)
  }
}
```

For flat/legacy metadata (no nested `extras` key), the plugin flattens
everything except `provider_key` and `timeout_seconds` into `extras`.

## Adding a new provider

1. Ensure `worker/helpers/<name>.py` exists with a `run(req, progress)`
   entry point returning a `LoginResult`. Steal patterns from
   `helpers/kiro_idc.py`.
2. In `worker/helpers/run_worker.py`, add the provider to the `PROVIDERS`
   dispatch dict.
3. In `capability_auth.go::handleLoginStart`, add a case that forwards
   to `runWorker` with the right `provider` field.
4. Add a case to `capability_auth.go::handleRefresh` (or, if the
   provider needs a browser to refresh, forward to `runWorker` again).
5. Update the support matrix in `README.md` / `README.zh.md`.
6. Bump the version constant in `dispatch.go`.

## Code style

- `go vet ./...` and `gofmt -l .` must be clean (`make test` enforces).
- Python side follows the existing muxhub `helpers/` style (no reformat).
- Comments explain **why**, not what — refer to design decisions or link
  to relevant upstream commits.

## Releasing

Push a tag matching `v*.*.*` — the GitHub Actions release workflow
builds three-platform artifacts and uploads them as release assets.

```bash
git tag -a v0.1.0-alpha -m "cpa-login-hub v0.1.0-alpha"
git push origin v0.1.0-alpha
```
