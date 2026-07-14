# Design

## Why a plugin, not a sidecar

CPA (`CLIProxyAPI`) implements a full plugin ABI via `dlopen` C shared
libraries (see `sdk/pluginabi/types.go`). It exposes an `AuthProvider`
capability with five methods:

- `Identifier()` — declare which provider keys we handle
- `ParseAuth(req)` — inspect an on-disk JSON, claim it if ours
- `StartLogin(req)` — begin an OAuth flow, return polling state
- `PollLogin(req)` — check the flow, return `AuthData` on success
- `RefreshAuth(req)` — swap an expiring token for a fresh one

An external sidecar HTTP service (login-hub's original shape) can't
integrate here — CPA's management panel is a static HTML that talks to
the host over REST and would need explicit routing rules to reach a
sidecar. A dlopen plugin gets first-class treatment: the panel already
routes login clicks to `host.StartLogin(provider)`.

## Two-language plugin

The plugin is Go on the outside (C ABI compatibility, dlopen loading)
and Python on the inside (browser automation via Playwright / Camoufox).

Rationale:

- **Go must be the outer shell.** CPA loads `.so`/`.dylib`/`.dll` via
  dlopen and calls C ABI functions. `python.h` bindings would work in
  theory but are far more fragile than shelling out to a subprocess.
- **Python must run the browser flows.** Playwright's Go binding is a
  minority-community port with lagging Firefox support. Camoufox's own
  stealth patches are shipped as Python-only. Reimplementing the browser
  state machines in Go would be months of work with a worse baseline.

So: Go handles the plugin contract + refresh (pure HTTP, no browser).
Python handles the browser flows. They talk over stdin/stdout JSON —
same protocol muxhub's `scripts/login-hub/server.py` has been running in
production for months.

## Directory layout

```
cpa-login-hub/
├── main.go                    # cliproxy_plugin_init + cliproxyPluginCall
├── dispatch.go                # plugin.register + method routing
├── capability_auth.go         # ParseAuth/StartLogin/PollLogin/RefreshAuth
├── provider_kiro.go           # kiro flow orchestration (fork worker)
├── provider_kiro_refresh.go   # kiro token refresh (pure Go HTTP)
├── worker_bridge.go           # Go ↔ Python IO + process-group cleanup
├── venv_setup.go              # First-run pip install
├── helpers.go                 # small utilities
├── worker/                    # Python side
│   ├── runner.py              # entry point: python -m worker.runner
│   ├── requirements.txt
│   └── helpers/               # vendored from muxhub scripts/login-hub
│       ├── _camoufox.py       # Camoufox launcher + 5 state machines
│       ├── kiro.py            # provider entry
│       ├── kiro_idc.py        # AWS SSO OIDC device flow
│       ├── openai.py
│       ├── grok.py
│       ├── antigravity.py
│       └── ...
└── Makefile
```

## Sequence: first-time kiro IdC login

```
CPA panel                Go plugin              Python worker             AWS SSO
    │                        │                        │                        │
    │ POST /plugin-login-url │                        │                        │
    ├───────────────────────>│                        │                        │
    │                        │ ensureVenv()           │                        │
    │                        │ (pip install first)    │                        │
    │                        │ fork python -m worker.runner                    │
    │                        ├───────────────────────>│                        │
    │                        │  stdin: {"provider":"kiro", "extras":{...}}     │
    │                        │                        │ RegisterClient          │
    │                        │                        ├───────────────────────>│
    │                        │                        │<───────────────────────┤
    │                        │                        │ StartDeviceAuthorization│
    │                        │                        ├───────────────────────>│
    │                        │                        │<───────────────────────┤
    │                        │                        │ launch Camoufox         │
    │                        │                        │ [signin/password/mfa/…] │
    │                        │                        │ poll CreateToken        │
    │                        │                        ├───────────────────────>│
    │                        │                        │<───── access+refresh ──┤
    │                        │                        │ ListAvailableProfiles   │
    │                        │                        ├───────────────────────>│
    │                        │                        │<─── profileArn ────────┤
    │                        │                        │ write CLIProxyAPI_*.json│
    │                        │  stdout: {"kind":"_result", "data":{"out_path":…}}
    │                        │<───────────────────────┤                        │
    │                        │ read JSON → AuthData   │                        │
    │  {Status:success, Auth}│                        │                        │
    │<───────────────────────┤                        │                        │
```

## Sequence: refresh

```
CPA scheduler         Go plugin
    │                     │
    │ auth.refresh(id, StorageJSON)
    ├────────────────────>│
    │                     │ decode StorageJSON → detect auth_method
    │                     │
    │                     │  idc:            external_idp:
    │                     │  POST oidc.<r>   POST <token_endpoint>
    │                     │  .amazonaws.com  (form-urlencoded)
    │                     │  /token          grant_type=refresh_token
    │                     │  (JSON)
    │                     │
    │                     │ patch stored.access_token + expires_at
    │  {Auth, NextRefresh}│
    │<────────────────────┤
```

The refresh path never involves Python — response times are ~150ms and
the plugin remains reliable even without a working browser installation.

## Cancel & shutdown safety

Every worker subprocess is started with `SysProcAttr.Setpgid = true`, so
`killpg(-pgid, SIGTERM)` reaps the entire tree (Python + Playwright node
driver + Camoufox / Firefox + 5+ content processes). This is essential —
without process group isolation, cancelling a login leaves ghost Firefox
windows on the user's desktop.

On `cliproxyPluginShutdown`, we broadcast SIGTERM to every tracked
worker's process group, wait 5 seconds for graceful shutdown, then
escalate to SIGKILL for survivors — same pattern muxhub's cancel
endpoint uses.

## Auth JSON schema

We produce (and consume, on `ParseAuth`) the CLIProxyAPI-native flat
snake_case schema, matching muxhub's `helpers/kiro.py::_build_cpa_json`:

```json
{
  "type": "kiro",
  "access_token": "aoaAAAAA…",
  "refresh_token": "aorAAAAA…",
  "profile_arn": "arn:aws:codewhisperer:us-east-1:…:profile/…",
  "expires_at": "2026-07-14T12:34:56Z",
  "auth_method": "idc",
  "email": "user@example.com",
  "provider": "Enterprise",
  "client_id": "…",
  "client_secret": "…",
  "region": "eu-central-1",
  "start_url": "https://d-….awsapps.com/start",
  "scopes": "codewhisperer:completions codewhisperer:…",
  "disabled": false
}
```

Fields marked required by CPA's watcher are always present. Optional
metadata (`sso_username`, `generated_password`, `generated_totp_secret`)
gets carried through if the state machine captured it — useful for
audit trails and re-login after a full session invalidation.

## What's not implemented in v0.1

- StartLogin for openai / grok / antigravity / kiro-M365 / codex —
  the worker code exists but the Go dispatch returns `not_implemented`.
  Wiring them up is a v0.2 task (mostly copying the kiro pattern).
- Custom management panel resource (a `management.register` capability
  advertising an in-panel HTML page for batch operations). v0.3.
- SMS provider abstraction (currently chongpt.xyz only). v0.4.
