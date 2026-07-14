#!/usr/bin/env python3
"""Offline smoke test for cpa-login-hub.dylib.

Loads the plugin via ctypes and exercises the RPC surface WITHOUT running
CPA — catches ABI mismatches, provider-registration bugs, and management-
route wiring in seconds. Runs on Python 3.11+.

Why Python instead of a Go smoke binary: two Go runtimes cannot share a
process (dlopen'ing a Go-built dylib from a Go program crashes in
runtime.cgocallback). ctypes gives us a language-neutral driver.

Usage:
    python3 tools/smoke/smoke.py                     # default dylib next to script
    python3 tools/smoke/smoke.py path/to/plugin.dylib
"""

from __future__ import annotations

import base64
import ctypes
import json
import os
import platform
import sys
from ctypes import (
    CFUNCTYPE, POINTER, Structure, byref, c_char_p, c_int, c_size_t,
    c_uint8, c_uint32, c_void_p, string_at,
)

# ---------- ABI structs ---------------------------------------------------


class Buffer(Structure):
    _fields_ = [("ptr", c_void_p), ("len", c_size_t)]


HOST_CALL_FN = CFUNCTYPE(c_int, c_void_p, c_char_p, POINTER(c_uint8), c_size_t, POINTER(Buffer))
HOST_FREE_FN = CFUNCTYPE(None, c_void_p, c_size_t)


class HostAPI(Structure):
    _fields_ = [
        ("abi_version", c_uint32),
        ("host_ctx", c_void_p),
        ("call", HOST_CALL_FN),
        ("free_buffer", HOST_FREE_FN),
    ]


PLUGIN_CALL_FN = CFUNCTYPE(c_int, c_char_p, POINTER(c_uint8), c_size_t, POINTER(Buffer))
PLUGIN_FREE_FN = CFUNCTYPE(None, c_void_p, c_size_t)
PLUGIN_SHUTDOWN_FN = CFUNCTYPE(None)


class PluginAPI(Structure):
    _fields_ = [
        ("abi_version", c_uint32),
        ("call", PLUGIN_CALL_FN),
        ("free_buffer", PLUGIN_FREE_FN),
        ("shutdown", PLUGIN_SHUTDOWN_FN),
    ]


# ---------- Host callback stubs ------------------------------------------


@HOST_CALL_FN
def host_call_stub(ctx, method, req, req_len, out):
    # Stub — smoke test doesn't drive host-side RPCs.
    if out:
        out.contents.ptr = None
        out.contents.len = 0
    return -1


@HOST_FREE_FN
def host_free_stub(ptr, length):
    pass


# ---------- Colour / logging ---------------------------------------------

def green(s: str) -> str: return f"\033[32m{s}\033[0m"
def red(s: str) -> str: return f"\033[31m{s}\033[0m"
def dim(s: str) -> str: return f"\033[2m{s}\033[0m"


def die(msg: str) -> None:
    print(red(f"❌ {msg}"), file=sys.stderr)
    sys.exit(1)


# ---------- Driver -------------------------------------------------------


class Plugin:
    def __init__(self, path: str) -> None:
        print(f"→ dlopen {path}")
        self.lib = ctypes.CDLL(path, mode=ctypes.RTLD_LOCAL)

        init = self.lib.cliproxy_plugin_init
        init.argtypes = [POINTER(HostAPI), POINTER(PluginAPI)]
        init.restype = c_int

        self.host = HostAPI()
        self.host.abi_version = 1
        self.host.host_ctx = None
        self.host.call = host_call_stub
        self.host.free_buffer = host_free_stub

        self.plugin = PluginAPI()
        rc = init(byref(self.host), byref(self.plugin))
        if rc != 0:
            die(f"plugin init returned rc={rc}")
        if self.plugin.abi_version != 1:
            die(f"plugin abi_version={self.plugin.abi_version}, want 1")
        if not self.plugin.call:
            die("plugin.call is nil")
        print(green("✓ plugin loaded, abi_version=1"))

    def call(self, method: str, body: bytes | str | dict = b"") -> dict:
        if isinstance(body, dict):
            body = json.dumps(body).encode("utf-8")
        elif isinstance(body, str):
            body = body.encode("utf-8")
        buf = Buffer()
        if body:
            body_arr = (c_uint8 * len(body))(*body)
            rc = self.plugin.call(method.encode("utf-8"), body_arr, len(body), byref(buf))
        else:
            rc = self.plugin.call(method.encode("utf-8"), None, 0, byref(buf))
        if rc != 0:
            die(f"plugin.call({method}) rc={rc}")
        if not buf.ptr:
            die(f"plugin.call({method}) returned empty response")
        raw = string_at(buf.ptr, buf.len)
        try:
            self.plugin.free_buffer(buf.ptr, buf.len)
        except Exception:
            pass  # Go allocs are C.malloc; free_buffer C.free's — harmless if it double-frees
        env = json.loads(raw)
        return env

    def shutdown(self) -> None:
        if self.plugin.shutdown:
            self.plugin.shutdown()


# ---------- Test cases ---------------------------------------------------


PASSED = 0
FAILED = 0


def case(title: str):
    def deco(fn):
        def wrapper(pl: Plugin):
            global PASSED, FAILED
            print(f"\n→ {title}")
            try:
                fn(pl)
                print(green("  ✓ ok"))
                PASSED += 1
            except AssertionError as e:
                print(red(f"  ✗ {e}"))
                FAILED += 1
            except Exception as e:
                print(red(f"  ✗ unexpected error: {type(e).__name__}: {e}"))
                FAILED += 1
        return wrapper
    return deco


def decode_management_body(env: dict) -> tuple[int, bytes]:
    """ManagementResponse.Body is base64-encoded []byte via encoding/json."""
    assert env.get("ok"), f"envelope not ok: {env.get('error')}"
    mgmt = env["result"]
    body_b64 = mgmt.get("Body") or ""
    body = base64.b64decode(body_b64) if body_b64 else b""
    return mgmt.get("StatusCode", 0), body


@case("plugin.register")
def test_register(pl: Plugin) -> None:
    env = pl.call("plugin.register")
    assert env.get("ok"), f"ok=false: {env.get('error')}"
    r = env["result"]
    assert r["schema_version"] == 1, f"schema_version={r['schema_version']}"
    assert r["metadata"]["Name"] == "cpa-login-hub", f"name={r['metadata']['Name']}"
    caps = r["capabilities"]
    assert caps.get("auth_provider"), "auth_provider not advertised"
    assert caps.get("management_api"), "management_api not advertised"
    print(f"  Name={r['metadata']['Name']} Version={r['metadata']['Version']}")


@case("auth.identifier")
def test_identifier(pl: Plugin) -> None:
    env = pl.call("auth.identifier")
    assert env.get("ok"), f"ok=false: {env.get('error')}"
    ident = env["result"].get("identifier")
    assert ident == "cpa-login-hub", f"identifier={ident!r}"
    print(f"  identifier={ident}")


@case("management.register")
def test_management_register(pl: Plugin) -> None:
    env = pl.call("management.register", {
        "BasePath": "/v0/management",
        "ResourceBasePath": "/v0/resource/plugins/cpa-login-hub",
    })
    assert env.get("ok"), f"ok=false: {env.get('error')}"
    r = env["result"]
    want_routes = {"POST /cpa-login-hub/submit-login", "GET /cpa-login-hub/status", "POST /cpa-login-hub/cancel"}
    got_routes = {f"{x['Method']} {x['Path']}" for x in r.get("Routes", [])}
    missing = want_routes - got_routes
    assert not missing, f"missing routes: {missing}"
    # /schema moved to Resources (public, no auth) so the panel bootstrap
    # works without the user pasting a management key first.
    want_resources = {"/panel", "/panel.css", "/panel.js", "/schema"}
    got_resources = {x["Path"] for x in r.get("Resources", [])}
    missing_r = want_resources - got_resources
    assert not missing_r, f"missing resources: {missing_r}"
    print(f"  routes={len(got_routes)} resources={len(got_resources)}")


@case("management.handle GET /schema")
def test_schema(pl: Plugin) -> None:
    env = pl.call("management.handle", {"Method": "GET", "Path": "/schema"})
    status, body = decode_management_body(env)
    assert status == 200, f"status={status}"
    schema = json.loads(body)
    assert schema["plugin"] == "cpa-login-hub"
    got_providers = {p["key"] for p in schema.get("providers", [])}
    want = {"kiro", "openai", "grok", "antigravity", "cursor"}
    missing = want - got_providers
    assert not missing, f"missing providers in schema: {missing}"
    print(f"  plugin={schema['plugin']} version={schema['version']} providers={len(got_providers)}")


@case("management.handle GET /panel  (embedded HTML)")
def test_panel_html(pl: Plugin) -> None:
    env = pl.call("management.handle", {"Method": "GET", "Path": "/panel"})
    status, body = decode_management_body(env)
    assert status == 200, f"status={status}"
    text = body.decode("utf-8", errors="replace")
    assert "<title>CPA Login Hub</title>" in text, "not the expected panel HTML"
    print(f"  panel html {len(body)} bytes")


# Shared state token across the CPA-first login flow tests.
STATE_TOKEN: str = ""


@case("auth.login.start  (CPA-native entry; returns panel URL + state)")
def test_start_login(pl: Plugin) -> None:
    global STATE_TOKEN
    env = pl.call("auth.login.start", {
        "Provider": "cpa-login-hub",
        "BaseURL": "http://127.0.0.1:8317/v0/management/oauth-callback",
    })
    assert env.get("ok"), f"ok=false: {env.get('error')}"
    r = env["result"]
    STATE_TOKEN = r.get("State", "")
    assert STATE_TOKEN, "empty state token"
    assert len(STATE_TOKEN) >= 16, f"state too short"
    url = r.get("URL", "")
    assert "/v0/resource/plugins/cpa-login-hub/panel" in url, f"URL={url!r}"
    assert "state=" + STATE_TOKEN in url, f"URL doesn't carry state: {url}"
    print(f"  state={STATE_TOKEN[:16]}… URL={url}")


@case("management.handle GET /status?state=…  (should show awaiting_submit)")
def test_status_awaiting(pl: Plugin) -> None:
    env = pl.call("management.handle", {
        "Method": "GET",
        "Path": "/status",
        "Query": {"state": [STATE_TOKEN]},
    })
    status, body = decode_management_body(env)
    assert status == 200, f"status={status}"
    resp = json.loads(body)
    assert resp["status"] == "awaiting_submit", f"status={resp['status']}"
    print(f"  awaiting_submit as expected")


@case("management.handle POST /submit-login  (missing state → 400)")
def test_submit_missing_state(pl: Plugin) -> None:
    payload = {"provider": "kiro", "extras": {"email": "a@b.com", "password": "x"}}
    env = pl.call("management.handle", {
        "Method": "POST",
        "Path": "/submit-login",
        "Body": base64.b64encode(json.dumps(payload).encode()).decode(),
    })
    status, body = decode_management_body(env)
    assert status == 400, f"expected 400 for missing state, got {status}"
    resp = json.loads(body)
    assert "state" in resp.get("error", "").lower()
    print(f"  rejected: {resp['error'][:100]}")


@case("management.handle POST /submit-login  (missing required field)")
def test_submit_missing_required(pl: Plugin) -> None:
    payload = {"provider": "kiro", "extras": {"email": "no-password@example.com"}}
    env = pl.call("management.handle", {
        "Method": "POST",
        "Path": "/submit-login",
        "Query": {"state": [STATE_TOKEN]},
        "Body": base64.b64encode(json.dumps(payload).encode()).decode(),
    })
    status, body = decode_management_body(env)
    assert status == 400, f"expected 400 for missing password, got {status}"
    resp = json.loads(body)
    assert "password" in resp.get("error", "").lower(), f"error={resp.get('error')}"
    print(f"  rejected: {resp['error']}")


@case("management.handle POST /submit-login  (valid → worker starts)")
def test_submit_login(pl: Plugin) -> None:
    payload = {
        "provider": "kiro",
        "label": "smoke-test",
        "proxy": "",
        "timeout": 600,
        "extras": {"email": "smoke@example.com", "password": "not-real"},
    }
    env = pl.call("management.handle", {
        "Method": "POST",
        "Path": "/submit-login",
        "Query": {"state": [STATE_TOKEN]},
        "Body": base64.b64encode(json.dumps(payload).encode()).decode(),
    })
    status, body = decode_management_body(env)
    assert status == 200, f"status={status}, body={body!r}"
    resp = json.loads(body)
    assert resp["status"] == "running", f"status={resp['status']}"
    assert resp["provider"] == "kiro"
    assert resp["state"] == STATE_TOKEN
    print(f"  worker started, state={resp['state'][:16]}…")


@case("management.handle POST /submit-login again  (state already running)")
def test_submit_login_twice(pl: Plugin) -> None:
    payload = {"provider": "kiro", "extras": {"email": "a@b.com", "password": "x"}}
    env = pl.call("management.handle", {
        "Method": "POST",
        "Path": "/submit-login",
        "Query": {"state": [STATE_TOKEN]},
        "Body": base64.b64encode(json.dumps(payload).encode()).decode(),
    })
    status, body = decode_management_body(env)
    resp = json.loads(body)
    assert status == 400, f"expected 400 for re-submit, got {status}"
    assert "already" in resp.get("error", "").lower()
    print(f"  correctly refused: {resp['error']}")


@case("auth.login.poll  (state is running or terminated)")
def test_poll_login(pl: Plugin) -> None:
    env = pl.call("auth.login.poll", {
        "Provider": "cpa-login-hub",
        "State": STATE_TOKEN,
    })
    assert env.get("ok"), f"ok=false: {env.get('error')}"
    r = env["result"]
    assert r["Status"] in ("pending", "error", "success"), f"Status={r['Status']}"
    print(f"  Status={r['Status']}  Message={(r.get('Message') or '')[:80]}")


@case("management.handle unknown path  (should 404)")
def test_unknown_path(pl: Plugin) -> None:
    env = pl.call("management.handle", {"Method": "GET", "Path": "/does-not-exist"})
    status, body = decode_management_body(env)
    assert status == 404, f"status={status}"
    print(f"  404 as expected")


@case("auth.parse  (should recognise kiro type)")
def test_auth_parse(pl: Plugin) -> None:
    kiro_json = {
        "type": "kiro",
        "access_token": "AAAA",
        "refresh_token": "RRRR",
        "auth_method": "idc",
        "email": "user@example.com",
        "region": "us-east-1",
        "profile_arn": "arn:aws:codewhisperer:us-east-1:1234:profile/xxx",
        "client_id": "cid",
        "client_secret": "csec",
    }
    env = pl.call("auth.parse", {
        "Provider": "cpa-login-hub",
        "Path": "/tmp/CLIProxyAPI_user_example_com.json",
        "FileName": "CLIProxyAPI_user_example_com.json",
        "RawJSON": base64.b64encode(json.dumps(kiro_json).encode()).decode(),
    })
    assert env.get("ok"), f"ok=false: {env.get('error')}"
    r = env["result"]
    assert r["Handled"] is True, f"Handled={r['Handled']}"
    auth = r["Auth"]
    assert auth["Provider"] == "cpa-login-hub", f"Provider={auth['Provider']}"
    assert auth["Label"] == "user@example.com"
    print(f"  Handled=true Provider={auth['Provider']} Label={auth['Label']}")


@case("auth.parse  (should NOT claim an alien type)")
def test_auth_parse_not_ours(pl: Plugin) -> None:
    alien = {"type": "gemini", "access_token": "..."}
    env = pl.call("auth.parse", {
        "Provider": "cpa-login-hub",
        "FileName": "gemini.json",
        "RawJSON": base64.b64encode(json.dumps(alien).encode()).decode(),
    })
    assert env.get("ok")
    r = env["result"]
    assert r["Handled"] is False, f"unexpectedly claimed alien type: {r}"
    print("  Handled=false as expected")


@case("auth.refresh  (kiro IdC — network error expected)")
def test_refresh_kiro(pl: Plugin) -> None:
    # We can exercise the dispatch path even without a live token endpoint.
    # The refresh will try to POST oidc.us-east-1.amazonaws.com and fail,
    # or return "empty_token"/"token_endpoint_error" — anything except
    # "unknown_provider" or "not_implemented" proves the dispatch is wired.
    stored = {
        "type": "kiro", "auth_method": "idc",
        "refresh_token": "not-real",
        "client_id": "cid", "client_secret": "csec",
        "region": "us-east-1",
    }
    env = pl.call("auth.refresh", {
        "AuthID": "CLIProxyAPI_x.json",
        "AuthProvider": "cpa-login-hub",
        "StorageJSON": base64.b64encode(json.dumps(stored).encode()).decode(),
    })
    if env.get("ok"):
        print("  (unexpectedly succeeded — the server must have accepted a bogus refresh, ignoring)")
        return
    code = (env.get("error") or {}).get("code", "")
    # These prove dispatch worked; anything else is a wiring bug.
    ok_codes = {"network_error", "token_endpoint_error", "empty_token", "bad_response"}
    assert code in ok_codes, f"unexpected error code={code}: {env['error']}"
    print(f"  dispatched to kiroRefreshIdc, expected downstream failure: {code}")


@case("auth.refresh  (cursor — must be not_implemented)")
def test_refresh_cursor(pl: Plugin) -> None:
    stored = {"type": "cursor", "refresh_token": "x", "email": "c@ex.com"}
    env = pl.call("auth.refresh", {
        "AuthID": "cursor-x.json",
        "AuthProvider": "cpa-login-hub",
        "StorageJSON": base64.b64encode(json.dumps(stored).encode()).decode(),
    })
    assert not env.get("ok")
    code = env["error"]["code"]
    assert code == "not_implemented", f"code={code}"
    print(f"  correctly returns not_implemented (Python worker has no refresh flow)")


# ---------- Main ----------------------------------------------------------


def default_lib() -> str:
    here = os.path.dirname(os.path.abspath(__file__))
    # tools/smoke/ → repo root is two levels up.
    root = os.path.dirname(os.path.dirname(here))
    ext = {"Darwin": "dylib", "Linux": "so"}.get(platform.system(), "so")
    return os.path.join(root, f"cpa-login-hub.{ext}")


def main() -> None:
    lib_path = sys.argv[1] if len(sys.argv) > 1 else default_lib()
    if not os.path.isfile(lib_path):
        die(f"dylib not found: {lib_path}  (run `make build` first?)")

    pl = Plugin(lib_path)

    test_register(pl)
    test_identifier(pl)
    test_management_register(pl)
    test_schema(pl)
    test_panel_html(pl)
    test_auth_parse(pl)
    test_auth_parse_not_ours(pl)
    test_unknown_path(pl)
    # Login flow in strict order — each step depends on the previous.
    test_start_login(pl)
    test_status_awaiting(pl)
    test_submit_missing_state(pl)
    test_submit_missing_required(pl)
    test_submit_login(pl)
    test_submit_login_twice(pl)
    test_poll_login(pl)
    test_refresh_kiro(pl)
    test_refresh_cursor(pl)

    print()
    if FAILED:
        print(red(f"❌ {FAILED} failed, {PASSED} passed"))
        sys.exit(1)
    print(green(f"✅ all {PASSED} cases passed"))


if __name__ == "__main__":
    main()
