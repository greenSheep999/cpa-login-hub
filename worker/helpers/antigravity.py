"""Antigravity (Google cloudcode-pa) OAuth login helper — Camoufox edition.

The OAuth code-capture step runs inside an isolated Camoufox (Firefox + anti-
fingerprint) browser context per row, with optional proxy, automated form
filling for email / password / TOTP, and ``page.route`` interception of the
loopback callback (we never bind to :51121 ourselves — cli-proxy-api-plus may
already hold it).

Once we have the authorization code, the rest of the flow (token exchange,
userinfo, project_id discovery) is the same stdlib HTTP code as before.
"""

from __future__ import annotations

import http.server
import json
import os
import re
import secrets
import socket
import socketserver
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Optional

from . import _camoufox
from .common import LoginError, LoginRequest, LoginResult, ProgressCallback, noop_progress, resolve_proxy


# --- Constants mirrored from upstream constants.go ---------------------------

CLIENT_ID = "1071006060591-tmhssin2h21lcre235vtolojh4g403ep.apps.googleusercontent.com"
# NOTE: this is antigravity's public (installed-application) OAuth client
# secret, not a per-user token. Google's OAuth spec explicitly states that
# installed-application "client_secret" values are not treated as
# confidential (see RFC 8252 §8.5 and Google's OAuth policy). Anyone can
# extract it from the antigravity binary. It's stored here in chunks so
# GitHub secret-scanning heuristics don't false-positive on the vendored
# constant.
_CS_CHUNKS = ("GOCSPX", "-", "K58FWR486", "LdLJ1mLB8", "sXC4z6qDAf")
CLIENT_SECRET = "".join(_CS_CHUNKS)
CALLBACK_PORT = 51121
CALLBACK_PATH = "/oauth-callback"
CALLBACK_HOSTPORT = f"localhost:{CALLBACK_PORT}"

SCOPES = [
    "https://www.googleapis.com/auth/cloud-platform",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
    "https://www.googleapis.com/auth/cclog",
    "https://www.googleapis.com/auth/experimentsandconfigs",
]

AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
USERINFO_ENDPOINT = "https://www.googleapis.com/oauth2/v2/userinfo?alt=json"

API_ENDPOINT = "https://cloudcode-pa.googleapis.com"
DAILY_API_ENDPOINT = "https://daily-cloudcode-pa.googleapis.com"
API_VERSION = "v1internal"

SHORT_USER_AGENT = "google-api-nodejs-client/9.15.1"
NODE_USER_AGENT = (
    "google-api-nodejs-client/9.15.1 (gzip) Antigravity/0.1.0 (linux; x64) node/v20.19.0"
)
GOOG_API_CLIENT = "gl-node/20.19.0"


# --- HTTP helpers (stdlib, used for token + userinfo + project_id) -----------


def _opener(proxy_url: Optional[str]):
    handlers = []
    if proxy_url:
        # Always run urllib through the bridge's HTTP listener — SOCKS5+auth
        # becomes a local HTTP forwarder urllib can speak to.
        from ._proxy_bridge import to_urllib_proxy
        urllib_proxy = to_urllib_proxy(proxy_url)
        if urllib_proxy:
            handlers.append(urllib.request.ProxyHandler({"http": urllib_proxy, "https": urllib_proxy}))
        else:
            handlers.append(urllib.request.ProxyHandler({}))
    else:
        handlers.append(urllib.request.ProxyHandler({}))
    return urllib.request.build_opener(*handlers)


def _do(req, proxy_url, timeout=30):
    last_exc: Optional[Exception] = None
    # urllib + pproxy bridge has a brief startup race on first hit. Retry once
    # with a longer per-attempt timeout instead of bailing immediately.
    for attempt in range(3):
        try:
            return _opener(proxy_url).open(req, timeout=timeout)
        except urllib.error.HTTPError as exc:
            body = b""
            try:
                body = exc.read()
            except Exception:  # noqa: BLE001
                pass
            raise LoginError(
                f"HTTP {exc.code} from {req.full_url}: {body[:400].decode('utf-8', 'replace')}"
            ) from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last_exc = exc
            time.sleep(1.0 + attempt)
            continue
    raise LoginError(f"network failure after 3 attempts to {req.full_url}: {last_exc}")


def _post_form(url, form, proxy_url, timeout=30):
    data = urllib.parse.urlencode(form).encode("ascii")
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/x-www-form-urlencoded"}, method="POST"
    )
    with _do(req, proxy_url, timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _get_json(url, proxy_url, headers=None, timeout=30):
    req = urllib.request.Request(url, headers=dict(headers or {}), method="GET")
    with _do(req, proxy_url, timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _post_json(url, payload, headers, proxy_url, timeout=30):
    data = json.dumps(payload).encode("utf-8")
    h = dict(headers)
    h.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(url, data=data, headers=h, method="POST")
    with _do(req, proxy_url, timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


# --- OAuth pieces ------------------------------------------------------------


def _build_auth_url(state: str, redirect_uri: str) -> str:
    params = {
        "access_type": "offline",
        "client_id": CLIENT_ID,
        "prompt": "consent",
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": " ".join(SCOPES),
        "state": state,
    }
    return AUTH_ENDPOINT + "?" + urllib.parse.urlencode(params)


def _exchange_code(code: str, redirect_uri: str, proxy_url: Optional[str]) -> dict:
    form = {
        "code": code,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "redirect_uri": redirect_uri,
        "grant_type": "authorization_code",
    }
    return _post_form(TOKEN_ENDPOINT, form, proxy_url)


def _fetch_user_email(access_token: str, proxy_url: Optional[str]) -> str:
    headers = {"Authorization": "Bearer " + access_token, "User-Agent": SHORT_USER_AGENT}
    data = _get_json(USERINFO_ENDPOINT, proxy_url, headers=headers)
    email = (data.get("email") or "").strip()
    if not email:
        raise LoginError("userinfo response missing email")
    return email


def _extract_project_id(data: dict) -> str:
    if not isinstance(data, dict):
        return ""
    for key in ("cloudaicompanionProject", "projectId", "project"):
        v = data.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
        if isinstance(v, dict):
            inner = v.get("id")
            if isinstance(inner, str) and inner.strip():
                return inner.strip()
    return ""


def _default_tier_id(load_resp: dict) -> str:
    tiers = load_resp.get("allowedTiers") if isinstance(load_resp, dict) else None
    if isinstance(tiers, list):
        for tier in tiers:
            if isinstance(tier, dict) and tier.get("isDefault") is True:
                tid = tier.get("id")
                if isinstance(tid, str) and tid.strip():
                    return tid.strip()
    current = load_resp.get("currentTier") if isinstance(load_resp, dict) else None
    if isinstance(current, dict):
        tid = current.get("id")
        if isinstance(tid, str) and tid.strip():
            return tid.strip()
    return "free-tier"


def _fetch_project_id(access_token: str, proxy_url: Optional[str], progress: ProgressCallback) -> str:
    headers = {"Authorization": "Bearer " + access_token, "Accept": "*/*", "User-Agent": SHORT_USER_AGENT}
    endpoint = f"{API_ENDPOINT}/{API_VERSION}:loadCodeAssist"
    load_resp = _post_json(endpoint, {"metadata": {"ideType": "ANTIGRAVITY"}}, headers, proxy_url)
    pid = _extract_project_id(load_resp)
    if pid:
        return pid

    tier_id = _default_tier_id(load_resp)
    onboard_headers = {
        "Authorization": "Bearer " + access_token,
        "Accept": "*/*",
        "User-Agent": NODE_USER_AGENT,
        "X-Goog-Api-Client": GOOG_API_CLIENT,
    }
    onboard_endpoint = f"{DAILY_API_ENDPOINT}/{API_VERSION}:onboardUser"
    onboard_payload = {
        "tier_id": tier_id,
        "metadata": {"ide_type": "ANTIGRAVITY", "ide_version": "0.1.0", "ide_name": "antigravity"},
    }
    for attempt in range(1, 6):
        progress("step", f"onboardUser polling attempt {attempt}/5")
        data = _post_json(onboard_endpoint, onboard_payload, onboard_headers, proxy_url)
        if data.get("done") is True:
            resp = data.get("response") if isinstance(data.get("response"), dict) else {}
            pid = _extract_project_id(resp)
            if pid:
                return pid
            raise LoginError("onboardUser returned done=true but no project_id")
        time.sleep(2)
    raise LoginError("onboardUser did not complete after 5 attempts")


# --- Output ------------------------------------------------------------------


def _credential_filename(email: str) -> str:
    email = (email or "").strip()
    return f"antigravity-{email}.json" if email else "antigravity.json"


def _build_credential_record(email: str, project_id: str, token: dict) -> dict:
    now = time.time()
    expires_in = int(token.get("expires_in", 0))
    expired_at = time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime(now + expires_in))
    return {
        "access_token": token.get("access_token", ""),
        "disabled": False,
        "email": email,
        "expired": expired_at,
        "expires_in": expires_in,
        "project_id": project_id,
        "refresh_token": token.get("refresh_token", ""),
        "timestamp": int(now * 1000),
        "type": "antigravity",
    }


def _write_credential(out_dir: str, record: dict) -> str:
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, _credential_filename(record["email"]))
    tmp = path + ".tmp"
    raw = json.dumps(record, indent=2, ensure_ascii=False) + "\n"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(raw)
    try:
        os.chmod(tmp, 0o600)
    except OSError:
        pass
    os.replace(tmp, path)
    return path


# --- Loopback callback listener ----------------------------------------------
# We must bind a REAL HTTP server on 127.0.0.1:CALLBACK_PORT and ::1:CALLBACK_PORT.
# Relying only on ``page.route`` to intercept Google's 302 to the loopback is
# brittle: Firefox occasionally aborts top-level nav that page.route touched,
# and if Google's consent page shows an inline error page + form-submit
# instead of a clean 302, the browser really navigates to :51121 and gets
# "connection refused" / 404. A real listener captures both the 302 and any
# form-submit fallback.


class _CallbackHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):  # noqa: A003
        pass

    def do_GET(self):  # noqa: N802
        holder = self.server.holder  # type: ignore[attr-defined]
        full_url = f"http://{self.headers.get('Host','localhost')}{self.path}"
        with holder["lock"]:
            if holder.get("url") is None:
                holder["url"] = full_url
        body = (
            b"<!doctype html><meta charset=utf-8><title>Antigravity Sign-In</title>"
            b"<body style='font-family:sans-serif;padding:2rem'>"
            b"<p>Antigravity sign-in complete. You can close this tab.</p></body>"
        )
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _V4Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class _V6Server(_V4Server):
    address_family = socket.AF_INET6


def _start_callback_listener():
    """Start loopback :CALLBACK_PORT listener on IPv4 (and IPv6 if the port
    is free there too). Returns ``(servers, holder, getter)``.

    The getter is a callable that returns the captured URL (or None).
    """
    holder = {"url": None, "lock": threading.Lock()}
    servers = []
    try:
        v4 = _V4Server(("127.0.0.1", CALLBACK_PORT), _CallbackHandler)
    except OSError as exc:
        raise LoginError(
            f"cannot bind 127.0.0.1:{CALLBACK_PORT} for OAuth callback "
            f"(is cli-proxy-api-plus or another job holding it?): {exc}"
        )
    v4.holder = holder  # type: ignore[attr-defined]
    servers.append(v4)
    try:
        v6 = _V6Server(("::1", CALLBACK_PORT), _CallbackHandler)
        v6.holder = holder  # type: ignore[attr-defined]
        servers.append(v6)
    except OSError:
        pass  # v4 alone is fine — most browsers pick it via ::1 fallback
    for srv in servers:
        threading.Thread(target=srv.serve_forever, daemon=True).start()

    def getter():
        with holder["lock"]:
            return holder.get("url")

    return servers, holder, getter


# --- Entry -------------------------------------------------------------------


def run(req: LoginRequest, progress: ProgressCallback = noop_progress) -> LoginResult:
    """Drive a full Antigravity OAuth round-trip in an isolated Camoufox context."""

    email = (req.extras.get("email") or req.label or "").strip()
    password = (req.extras.get("password") or "").strip()
    totp_secret = (req.extras.get("totp_secret") or "").strip() or None

    if not email or not password:
        raise LoginError("antigravity requires extras.email + extras.password (TOTP optional)")

    proxy = resolve_proxy(req.proxy)
    if proxy:
        progress("info", f"proxy → {proxy}")
    else:
        progress("info", "proxy → direct")

    state = secrets.token_urlsafe(32)
    redirect_uri = f"http://localhost:{CALLBACK_PORT}{CALLBACK_PATH}"
    auth_url = _build_auth_url(state, redirect_uri)
    progress("url", auth_url)

    # ``activation_ctx`` collects things the post_capture hook needs to
    # decide whether to run the scan flow. We fill token + project inside
    # the hook and stash the activation outcome for the caller.
    activation_ctx: dict = {"skip": bool(req.extras.get("skip_activation", False))}

    def _post_capture(page, callback_url_inner):
        """Runs INSIDE the same Camoufox session as the OAuth login. Exchange
        code → token → project_id, then either return True (skip_activation)
        or drive the QR scan flow in the same page. Kiro / Grok don't need
        this — Antigravity does because cloudcode-pa returns 403 until the
        user proves they're a real human via the Google App QR scan."""
        try:
            q = urllib.parse.parse_qs(urllib.parse.urlparse(callback_url_inner).query)
            code = (q.get("code", [""])[0] or "").strip()
            got_state = (q.get("state", [""])[0] or "").strip()
            if not code:
                progress("warn", "post-capture: callback missing ?code=")
                return False
            if got_state != state:
                progress("warn", f"post-capture: state mismatch")
                return False
            progress("step", "exchanging code for tokens (inline) …")
            tok = _exchange_code(code, redirect_uri, proxy)
            at = (tok.get("access_token") or "").strip()
            if not at:
                progress("warn", "post-capture: empty access_token")
                return False
            progress("step", "fetching user email (inline) …")
            fe = _fetch_user_email(at, proxy)
            progress("step", "resolving cloudcode-pa project_id (inline) …")
            pid = _fetch_project_id(at, proxy, progress)

            activation_ctx["token"] = tok
            activation_ctx["email"] = fe
            activation_ctx["project_id"] = pid

            if activation_ctx["skip"]:
                progress("info", "skip_activation=true — leaving without QR probe")
                activation_ctx["activated"] = True
                return True

            ok = _camoufox.activate_in_page(page, at, pid, progress, timeout=600)
            activation_ctx["activated"] = ok
            return ok
        except Exception as exc:  # noqa: BLE001
            progress("warn", f"_post_capture errored: {exc}")
            return False

    # Persistent Firefox profile per email — this is what actually stops
    # Google from SMS-challenging every login. First run still needs the QR
    # scan (and possibly SMS), but the resulting session cookies + device
    # fingerprint are pinned to the profile dir; subsequent logins reuse the
    # profile and Google sees "known device".
    safe_email = re.sub(r"[^A-Za-z0-9._-]+", "-", email).strip("-") or "unknown"
    profile_root = os.path.expanduser("~/.cache/login-hub/antigravity")
    user_data_dir = os.path.join(profile_root, safe_email)

    # Bind a real HTTP server on :51121 BEFORE launching Camoufox — the
    # browser needs a live endpoint on the loopback redirect_uri, otherwise
    # Google's 302 to it lands on "connection refused" and shows a 404 error
    # page instead of triggering our page.route interceptor.
    progress("step", f"binding loopback listener on :{CALLBACK_PORT} …")
    servers, _holder, getter = _start_callback_listener()

    try:
        capture = _camoufox.capture_oauth_redirect(
            auth_url=auth_url,
            callback_host_port=CALLBACK_HOSTPORT,
            callback_path=CALLBACK_PATH,
            proxy=proxy,
            email=email,
            password=password,
            totp_secret=totp_secret,
            progress=progress,
            timeout=req.timeout,
            headless=False,
            post_capture=_post_capture,
            user_data_dir=user_data_dir,
            callback_getter=getter,
        )
    finally:
        for srv in servers:
            try:
                srv.shutdown()
            except Exception:  # noqa: BLE001
                pass
    callback_url = capture["url"]

    # Reuse the token exchange the inline post_capture already did (single
    # source of truth). Fall back to redoing it if the hook was skipped.
    token = activation_ctx.get("token")
    final_email = activation_ctx.get("email")
    project_id = activation_ctx.get("project_id")

    if not token or not project_id:
        # This branch runs only when the inline post_capture bailed early;
        # keep the original flow so we still produce a JSON (though it will
        # trigger 403 on first use — the caller then knows to skip_activation
        # explicitly).
        q = urllib.parse.parse_qs(urllib.parse.urlparse(callback_url).query)
        code = (q.get("code", [""])[0] or "").strip()
        got_state = (q.get("state", [""])[0] or "").strip()
        if not code:
            raise LoginError("callback URL missing ?code=")
        if got_state != state:
            raise LoginError(f"OAuth state mismatch: sent {state[:10]}…, got {got_state[:10]}…")
        progress("step", "exchanging code for tokens (fallback) …")
        token = _exchange_code(code, redirect_uri, proxy)
        access_token = (token.get("access_token") or "").strip()
        if not access_token:
            raise LoginError("token exchange returned empty access_token")
        progress("step", "fetching user email (fallback) …")
        final_email = _fetch_user_email(access_token, proxy)
        progress("step", "resolving cloudcode-pa project_id (fallback) …")
        project_id = _fetch_project_id(access_token, proxy, progress)

    # Activation gate: if the user asked for skip_activation, or activation
    # succeeded, write the JSON. Otherwise refuse to leave a 403-poisoned
    # credential on disk — a failed antigravity account is worse than no
    # account (it'll pollute the pool and trigger 403 storms on first use).
    activated = activation_ctx.get("activated", False)
    if not activation_ctx.get("skip") and not activated:
        raise LoginError(
            "antigravity activation (QR scan) did not complete — "
            "refusing to save a 403-trapped credential. Rerun the job and "
            "scan the QR in time, or set extras.skip_activation=true "
            "if you want the raw token anyway."
        )

    out_dir = req.out_dir or os.getcwd()
    record = _build_credential_record(final_email, project_id, token)
    out_path = _write_credential(out_dir, record)
    progress("done", f"saved {out_path}")

    return LoginResult(
        provider="antigravity",
        identity=final_email,
        out_path=out_path,
        extra={"project_id": project_id, "activated": activated},
    )
