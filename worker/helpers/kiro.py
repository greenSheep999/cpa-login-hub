"""Kiro (AWS CodeWhisperer) M365/SSO + social login helper.

Vendored from ``~/Repositories/kiro-login-helper/kiro-login-helper.py`` and
refactored to expose a uniform ``run(req, progress)`` entrypoint driven by
``_camoufox.capture_oauth_redirect(site="kiro")`` — no local loopback listener
anymore; Playwright's ``page.route`` intercepts the :3128 callback in-process
and returns both the callback URL and (for the external_idp leg) the PKCE /
token-endpoint context needed to finish the exchange.

Two legs both terminate at the intercepted loopback :3128/oauth/callback:
- **social**: Cognito-backed Google/GitHub via ``app.kiro.dev`` (uses this
  script's own PKCE material)
- **external_idp**: Microsoft Entra ID; the route handler discovers the OIDC
  issuer, mints fresh leg-2 PKCE material, and 302s the browser onward to
  ``login.microsoftonline.com``

Both produce a CLIProxyAPI-compatible ``CLIProxyAPI_<username>.json``.

The private helpers ``_oidc_discover / _external_idp_authorize_url /
_exchange_external_idp_code / _exchange_social_code / _random_url_safe /
_pkce_challenge`` are also imported by ``_camoufox`` to drive leg-1 → leg-2
transition inside the route handler — keep their signatures stable.
"""

from __future__ import annotations

from typing import Optional

import base64
import hashlib
import http.server
import io
import json
import os
import queue
import secrets
import socket
import socketserver
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

from . import _camoufox
from .common import LoginError, LoginRequest, LoginResult, ProgressCallback, noop_progress, resolve_proxy


# --- Constants mirrored from internal/auth/kiro/constants.go ------------------

SOCIAL_SIGNIN_BASE_URL = "https://app.kiro.dev/signin"
SOCIAL_REDIRECT_URI = "http://localhost:3128"
SOCIAL_REDIRECT_PORT = 3128
SOCIAL_REDIRECT_FROM = "KiroIDE"
OAUTH_CALLBACK_PATH = "/oauth/callback"
SOCIAL_AUTH_BASE = "https://prod.us-east-1.auth.desktop.kiro.dev"
SOCIAL_TOKEN_URL = SOCIAL_AUTH_BASE + "/oauth/token"
DEFAULT_REGION = "us-east-1"
KIRO_IDE_VERSION = "0.10.32"
LIST_PROFILES_TARGET = "AmazonCodeWhispererService.ListAvailableProfiles"
SOCIAL_LOGIN_TIMEOUT_SECONDS = 10 * 60

# Allow-list of IdP issuer / endpoint host suffixes the enterprise leg may
# talk to. Leading dot anchors each suffix to a subdomain boundary so
# ``evil-microsoftonline.com`` cannot match.
ALLOWED_EXTERNAL_IDP_SUFFIXES = (
    ".microsoftonline.com",
    ".microsoftonline.us",
    ".microsoftonline.cn",
)


# --- PKCE helpers -------------------------------------------------------------


def _random_url_safe(n: int) -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(n)).rstrip(b"=").decode("ascii")


def _pkce_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


# --- SSRF guard ---------------------------------------------------------------


def _validate_external_idp_endpoint(raw_url: str) -> None:
    parsed = urllib.parse.urlparse((raw_url or "").strip())
    if parsed.scheme.lower() != "https":
        raise LoginError(f"external IdP URL must be https: {raw_url!r}")
    host = (parsed.hostname or "").lower()
    if not host:
        raise LoginError(f"external IdP URL has no host: {raw_url!r}")
    # Reject IP-literal hosts; only named, allow-listed IdP hosts pass.
    try:
        socket.inet_pton(socket.AF_INET, host)
        is_ip = True
    except OSError:
        try:
            socket.inet_pton(socket.AF_INET6, host)
            is_ip = True
        except OSError:
            is_ip = False
    if is_ip:
        raise LoginError(f"external IdP host must not be an IP literal: {host!r}")
    for suffix in ALLOWED_EXTERNAL_IDP_SUFFIXES:
        if host.endswith(suffix):
            return
    raise LoginError(f"external IdP host {host!r} is not allow-listed")


# --- Kiro portal domain → login metadata (CBOR RPC) --------------------------


# Kiro portal GetLoginMetadata is rate-limited ~1 rps per IP. We pace calls
# with a module-level lock + minimum interval so consecutive submissions
# from the same process can never fire the API two-back-to-back.
_METADATA_LOCK = threading.Lock()
_METADATA_LAST_CALL = [0.0]  # mutable holder for last-call timestamp
_METADATA_MIN_INTERVAL = 5.0  # seconds


KIRO_PORTAL_METADATA_URL = (
    "https://app.kiro.dev/service/KiroWebPortalService/operation/GetLoginMetadata"
)


def _get_login_metadata(email: str, proxy_url):
    """Ask the kiro web portal which IdP + which client_id to use for this
    email's domain. Returns ``(client_id, issuer_url, scopes: list[str])``.

    Portal exposes an AWS Smithy rpc-v2-cbor endpoint that only requires a
    self-minted visitor id — no cookies, no Turnstile. Body is a CBOR-encoded
    ``{"domainName": "<domain>"}``; response is ``{"clientId", "found",
    "issuerUrl", "scopes"}``.
    """
    try:
        import cbor2  # type: ignore
    except ImportError as exc:
        raise LoginError(
            "cbor2 not installed. In scripts/login-hub/ venv:\n  pip install cbor2"
        ) from exc

    domain = email.split("@", 1)[1] if "@" in email else email
    if not domain:
        raise LoginError(f"cannot derive domain from email {email!r}")

    visitor_id = f"{int(time.time() * 1000)}-{secrets.token_hex(6)}"
    body = cbor2.dumps({"domainName": domain})
    headers = {
        "Content-Type": "application/cbor",
        "Accept": "application/cbor",
        "smithy-protocol": "rpc-v2-cbor",
        "x-kiro-visitorid": visitor_id,
        "Cookie": f"kiro-visitor-id={visitor_id}",
        "Origin": "https://app.kiro.dev",
        "Referer": "https://app.kiro.dev/signin",
        # Kiro web SDK sends these — mirroring keeps the anti-abuse filters quiet
        "amz-sdk-invocation-id": secrets.token_hex(8),
        "amz-sdk-request": "attempt=1; max=1",
        "x-amz-user-agent": "aws-sdk-js/1.0.0 ua/2.1 os/macOS lang/js md/browser#Firefox_unknown",
        "User-Agent": (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:135.0) "
            "Gecko/20100101 Firefox/135.0"
        ),
    }

    opener = _opener(proxy_url, follow_redirects=True)
    # Global pacing — kiro portal (AWS Smithy) rate-limits ~1 rps per IP;
    # even the same IP running two flows back-to-back can hit 429. We keep
    # a module-level "last call" timestamp and delay before every request
    # so consecutive callers from the same process auto-serialize.
    with _METADATA_LOCK:
        since = time.time() - _METADATA_LAST_CALL[0]
        if since < _METADATA_MIN_INTERVAL:
            time.sleep(_METADATA_MIN_INTERVAL - since)

    # Retry with exponential backoff on 429/5xx — starts at 5s, caps 30s,
    # up to 7 attempts (5+10+20+30+30+30 ≈ 125s total), long enough to ride
    # out portal's IP freeze window.
    last_exc: Optional[Exception] = None
    for attempt in range(7):
        req = urllib.request.Request(KIRO_PORTAL_METADATA_URL, data=body, headers=headers, method="POST")
        try:
            with opener.open(req, timeout=30) as resp:
                raw = resp.read()
                _METADATA_LAST_CALL[0] = time.time()
                break
        except urllib.error.HTTPError as exc:
            try:
                err_body = exc.read().decode("utf-8", "replace")
            except Exception:  # noqa: BLE001
                err_body = ""
            if exc.code in (429, 500, 502, 503, 504) and attempt < 6:
                wait = min(5 * (2 ** attempt), 30)
                time.sleep(wait)
                last_exc = exc
                continue
            raise LoginError(f"GetLoginMetadata HTTP {exc.code}: {err_body[:300]}") from exc
        except (urllib.error.URLError, OSError) as exc:
            if attempt < 6:
                time.sleep(min(5 * (2 ** attempt), 15))
                last_exc = exc
                continue
            raise LoginError(f"GetLoginMetadata network err: {exc}") from exc
    else:
        raise LoginError(f"GetLoginMetadata failed after retries: {last_exc}")

    try:
        parsed = cbor2.loads(raw)
    except Exception as exc:  # noqa: BLE001
        raise LoginError(f"GetLoginMetadata CBOR decode failed: {exc}") from exc

    if not parsed.get("found"):
        raise LoginError(
            f"kiro portal has no IdP config for {domain!r} — "
            f"is this really an enterprise/external_idp email?"
        )
    client_id = (parsed.get("clientId") or "").strip()
    issuer_url = (parsed.get("issuerUrl") or "").strip()
    scopes = list(parsed.get("scopes") or [])
    if not client_id or not issuer_url or not scopes:
        raise LoginError(
            f"GetLoginMetadata returned incomplete config: "
            f"clientId={client_id!r} issuer={issuer_url!r} scopes={scopes!r}"
        )
    _validate_external_idp_endpoint(issuer_url)
    return client_id, issuer_url, scopes


# --- HTTP plumbing ------------------------------------------------------------


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, "redirect not allowed", headers, fp)


def _opener(proxy_url, follow_redirects=True):
    handlers = []
    if proxy_url:
        # urllib can't speak SOCKS5 natively — route SOCKS5+auth via the local
        # pproxy HTTP bridge (helpers._proxy_bridge). No-op for http(s)://.
        from . import _proxy_bridge  # local import to avoid cycles at load time
        usable = _proxy_bridge.to_urllib_proxy(proxy_url) or proxy_url
        handlers.append(urllib.request.ProxyHandler({"http": usable, "https": usable}))
    else:
        handlers.append(urllib.request.ProxyHandler())
    if not follow_redirects:
        handlers.append(_NoRedirect())
    return urllib.request.build_opener(*handlers)


def _http_get_json(url, proxy_url, follow_redirects=True, timeout=30):
    req = urllib.request.Request(url, method="GET", headers={"Accept": "application/json"})
    with _opener(proxy_url, follow_redirects).open(req, timeout=timeout) as resp:
        body = resp.read(1 << 20)
    return json.loads(body.decode("utf-8"))


def _http_post_form(url, form, proxy_url, timeout=30):
    data = urllib.parse.urlencode(form).encode("ascii")
    req = urllib.request.Request(
        url,
        data=data,
        method="POST",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        },
    )
    return _do_request(req, proxy_url, timeout)


def _http_post_json(url, payload, headers, proxy_url, timeout=30):
    data = json.dumps(payload).encode("utf-8")
    base_headers = {"Content-Type": "application/json", "Accept": "application/json"}
    base_headers.update(headers or {})
    req = urllib.request.Request(url, data=data, method="POST", headers=base_headers)
    return _do_request(req, proxy_url, timeout)


def _do_request(req, proxy_url, timeout, retries: int = 3):
    """POST/GET wrapper with retry on transient SSL/URL errors.

    Some residential proxies TLS-close mid-read (``SSL: UNEXPECTED_EOF_WHILE_READING``)
    on the first hit but recover on retry. Backoff 1s/3s/8s. HTTPError is a
    real HTTP response (e.g. 403) — return as-is, no retry."""
    import ssl as _ssl
    last_exc: Optional[Exception] = None
    for attempt in range(max(1, retries)):
        try:
            with _opener(proxy_url).open(req, timeout=timeout) as resp:
                raw = resp.read()
                status = resp.status
            break
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            status = exc.code
            break
        except (urllib.error.URLError, _ssl.SSLError, OSError) as exc:
            last_exc = exc
            if attempt >= retries - 1:
                raise
            time.sleep([1, 3, 8][min(attempt, 2)])
            continue
    text = raw.decode("utf-8", "replace")
    parsed = None
    if text.strip():
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            parsed = None
    return status, parsed, text


# --- OIDC discovery + token exchange (enterprise IdP leg) --------------------


def _oidc_discover(issuer_url, proxy_url):
    _validate_external_idp_endpoint(issuer_url)
    doc_url = issuer_url.strip().rstrip("/") + "/.well-known/openid-configuration"
    doc = _http_get_json(doc_url, proxy_url, follow_redirects=False)
    auth_endpoint = (doc.get("authorization_endpoint") or "").strip()
    token_endpoint = (doc.get("token_endpoint") or "").strip()
    if not auth_endpoint or not token_endpoint:
        raise LoginError("OIDC discovery document missing authorization_endpoint or token_endpoint")
    _validate_external_idp_endpoint(auth_endpoint)
    _validate_external_idp_endpoint(token_endpoint)
    return auth_endpoint, token_endpoint


def _external_idp_authorize_url(auth_endpoint, client_id, redirect_uri, scopes, challenge, state, login_hint):
    q = {
        "client_id": client_id,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "scope": scopes,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "response_mode": "query",
        "state": state,
    }
    if (login_hint or "").strip():
        q["login_hint"] = login_hint
    return auth_endpoint + "?" + urllib.parse.urlencode(q)


def _exchange_external_idp_code(token_endpoint, client_id, code, verifier, redirect_uri, scopes, proxy_url):
    form = {
        "client_id": client_id,
        "grant_type": "authorization_code",
        "code": code.strip(),
        "redirect_uri": redirect_uri,
        "code_verifier": verifier,
    }
    if (scopes or "").strip():
        form["scope"] = scopes
    status, parsed, text = _http_post_form(token_endpoint, form, proxy_url)
    parsed = parsed or {}
    access = parsed.get("access_token", "")
    if not (200 <= status < 300) or not access:
        err = parsed.get("error", "")
        desc = parsed.get("error_description", "")
        if err:
            raise LoginError(f"external IdP token exchange failed (status {status}): {err}: {desc}")
        raise LoginError(f"external IdP token exchange failed (status {status}): {text}")
    return access, parsed.get("refresh_token", ""), int(parsed.get("expires_in", 0) or 0), ""


# --- Social (Cognito) token exchange ----------------------------------------


def _exchange_social_code(code, verifier, proxy_url):
    payload = {"code": code.strip(), "code_verifier": verifier, "redirect_uri": SOCIAL_REDIRECT_URI}
    status, parsed, text = _http_post_json(SOCIAL_TOKEN_URL, payload, None, proxy_url)
    parsed = parsed or {}
    access = parsed.get("accessToken", "")
    if not (200 <= status < 300) or not access:
        raise LoginError(f"social token exchange failed (status {status}): {text}")
    return (
        access,
        parsed.get("refreshToken", ""),
        int(parsed.get("expiresIn", 0) or 0),
        parsed.get("profileArn", "") or "",
    )


# --- Profile ARN resolution -------------------------------------------------


def _build_machine_id(*parts):
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()


def _build_user_agent(machine_id):
    return (
        "aws-sdk-js/1.0.0 ua/2.1 os/windows#10.0.26200 lang/js md/nodejs#22.21.1 "
        f"api/codewhispererruntime#1.0.0 m/N,E KiroIDE-{KIRO_IDE_VERSION}-{machine_id}"
    )


def _build_x_amz_user_agent(machine_id):
    return f"aws-sdk-js/1.0.0 KiroIDE-{KIRO_IDE_VERSION}-{machine_id}"


def _rest_api_region_candidates(sso_region: str) -> list[str]:
    """Kiro REST API only exists in us-east-1 and eu-central-1.
    EU SSO region prefers eu-central-1 first, falls back to us-east-1;
    everything else prefers us-east-1 first. Mirrors kiro.rs
    `rest_api_region_candidates`."""
    if sso_region == "eu-central-1" or sso_region.startswith("eu-"):
        return ["eu-central-1", "us-east-1"]
    return ["us-east-1", "eu-central-1"]


def _list_available_profiles(access_token, region, external_idp, proxy_url):
    """Call AWS Q's `AmazonCodeWhispererService.ListAvailableProfiles`.

    Endpoint is `q.{region}.amazonaws.com` (NOT `codewhisperer.*`, which is a
    different service). Only us-east-1 / eu-central-1 host this API — SSO
    region determines which one to try first."""
    if not access_token.strip():
        raise LoginError("access token is empty")
    machine_id = _build_machine_id(access_token)
    candidates = _rest_api_region_candidates(region)

    last_status = 0
    last_text = ""
    last_err: Optional[Exception] = None
    for reg in candidates:
        host = f"q.{reg}.amazonaws.com"
        url = f"https://{host}/"
        headers = {
            "Content-Type": "application/x-amz-json-1.0",
            "Accept": "application/x-amz-json-1.0",
            "Authorization": "Bearer " + access_token,
            "X-Amz-Target": LIST_PROFILES_TARGET,
            "amz-sdk-invocation-id": _build_machine_id(access_token, reg, "list-profiles"),
            "amz-sdk-request": "attempt=1; max=1",
            "x-amzn-kiro-agent-mode": "vibe",
            "x-amzn-codewhisperer-optout": "true",
            "User-Agent": _build_user_agent(machine_id),
            "x-amz-user-agent": _build_x_amz_user_agent(machine_id),
            "Host": host,
        }
        if external_idp:
            headers["TokenType"] = "EXTERNAL_IDP"
        req = urllib.request.Request(url, data=b"{}", method="POST", headers=headers)
        try:
            status, parsed, text = _do_request(req, proxy_url, timeout=30)
        except Exception as exc:  # noqa: BLE001
            last_err = exc
            continue
        last_status = status
        last_text = text
        if 200 <= status < 300:
            for prof in (parsed or {}).get("profiles", []) or []:
                arn = (prof.get("arn") or "").strip()
                if arn:
                    return arn
            # 200 but empty — try the other region
            continue
    if last_err:
        raise LoginError(f"list-profiles network err (all candidates): {last_err}")
    if last_status:
        raise LoginError(f"list-profiles failed (last status {last_status}): {last_text[:300]}")
    raise LoginError("no profiles available (both regions returned empty)")


def _region_from_profile_arn(profile_arn):
    parts = (profile_arn or "").strip().split(":")
    return parts[3].strip() if len(parts) >= 4 else ""


# --- Username / filename helpers --------------------------------------------


def _decode_jwt_claims(token):
    parts = (token or "").strip().split(".")
    if len(parts) < 2:
        return {}
    seg = parts[1]
    padded = seg + "=" * (-len(seg) % 4)
    try:
        raw = base64.urlsafe_b64decode(padded)
    except (ValueError, TypeError):
        return {}
    try:
        return json.loads(raw.decode("utf-8", "replace"))
    except json.JSONDecodeError:
        return {}


def _derive_username(access_token):
    claims = _decode_jwt_claims(access_token)
    for key in ("preferred_username", "email", "upn", "unique_name", "name", "oid", "sub"):
        val = (claims.get(key) or "").strip()
        if val:
            return val
    return ""


def _sanitize_file_component(s):
    s = (s or "").strip()
    if not s:
        return ""
    out = io.StringIO()
    prev_dash = False
    for ch in s:
        safe = (ch.isalnum() and ch.isascii()) or ch in "._-"
        if safe:
            out.write(ch)
            prev_dash = False
        elif not prev_dash:
            out.write("-")
            prev_dash = True
    return out.getvalue().strip("-")


# --- Loopback callback listener ---------------------------------------------


# --- Loopback listener for the OAuth callback --------------------------------


class _CallbackHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):  # noqa: A003
        pass

    def do_GET(self):  # noqa: N802
        state_holder = self.server.holder  # type: ignore[attr-defined]
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path != OAUTH_CALLBACK_PATH:
            self.send_response(404); self.end_headers(); return
        # Whole URL (with query) is what the caller wants
        full_url = f"http://{self.headers.get('Host','localhost')}{self.path}"
        with state_holder["lock"]:
            if state_holder.get("url") is None:
                state_holder["url"] = full_url
        body = (
            b"<!doctype html><meta charset=utf-8><title>Kiro Sign-In</title>"
            b"<body style='font-family:sans-serif;padding:2rem'>"
            b"<p>Kiro sign-in complete. You can close this tab.</p></body>"
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
    """Start loopback :3128 listener on both IPv4 and IPv6 (browsers may
    resolve 'localhost' to either). Returns ``(servers, holder, getter)``.

    ``holder`` is a shared dict {"url": Optional[str], "lock": Lock}.
    ``getter`` is a callable that returns the captured URL (or None).
    """
    holder = {"url": None, "lock": threading.Lock()}
    servers = []
    try:
        v4 = _V4Server(("127.0.0.1", SOCIAL_REDIRECT_PORT), _CallbackHandler)
    except OSError as exc:
        raise LoginError(
            f"cannot bind loopback 127.0.0.1:{SOCIAL_REDIRECT_PORT} for OAuth callback "
            f"(is another kiro job still running or the port in use?): {exc}"
        )
    v4.holder = holder  # type: ignore[attr-defined]
    servers.append(v4)
    try:
        v6 = _V6Server(("::1", SOCIAL_REDIRECT_PORT), _CallbackHandler)
        v6.holder = holder  # type: ignore[attr-defined]
        servers.append(v6)
    except OSError:
        pass  # v4 alone is fine
    for srv in servers:
        threading.Thread(target=srv.serve_forever, daemon=True).start()

    def getter():
        with holder["lock"]:
            return holder.get("url")

    return servers, holder, getter


# --- Output ------------------------------------------------------------------


def _append_to_credentials(path: str, entry: dict) -> tuple[int, bool]:
    """Merge ``entry`` into a CPA-Plus credentials.kiro-rs.json array.

    Behavior:
      - If the file exists but isn't an array, it's promoted to ``[old]`` first
        (mirrors the tolerant behavior of ``convert_kiro_auth.py``).
      - Same identity (matching ``email`` — falling back to
        ``clientId+profileArn`` when email is missing) is **updated in place**
        instead of appended, so re-running a job for the same account
        refreshes tokens rather than duplicating.
      - Writes atomically via a tmp+rename, and holds an exclusive fcntl lock
        on the target during read-modify-write so concurrent kiro workers
        won't clobber each other.

    Returns ``(total_entries, was_replaced)``.
    """
    import fcntl  # POSIX only; login-hub is macOS/linux
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)

    # Open the target (create if missing) with a lock. Read entire body, then
    # rewrite from position 0 truncated.
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        with os.fdopen(fd, "r+", encoding="utf-8", closefd=False) as fh:
            raw = fh.read().strip()
            if raw:
                try:
                    data = json.loads(raw)
                except json.JSONDecodeError:
                    data = []
            else:
                data = []
            if isinstance(data, dict):
                data = [data]
            elif not isinstance(data, list):
                data = []

            new_email = (entry.get("email") or "").strip().lower()
            new_key = (entry.get("clientId", ""), entry.get("profileArn", ""))
            replaced = False
            for i, existing in enumerate(data):
                if not isinstance(existing, dict):
                    continue
                ex_email = (existing.get("email") or "").strip().lower()
                if new_email and ex_email == new_email:
                    data[i] = entry
                    replaced = True
                    break
                if not new_email and new_key == (
                    existing.get("clientId", ""), existing.get("profileArn", "")
                ):
                    data[i] = entry
                    replaced = True
                    break
            if not replaced:
                data.append(entry)

            fh.seek(0)
            fh.truncate()
            json.dump(data, fh, indent=2, ensure_ascii=False)
            fh.write("\n")
            return len(data), replaced
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        except Exception:  # noqa: BLE001
            pass
        try:
            os.close(fd)
        except OSError:
            pass


def _build_kiro_rs_json(token, region, email):
    """CLIProxyAPI-Plus kiro.rs credentials.json entry — camelCase schema
    (refreshToken/accessToken/profileArn/expiresAt/authMethod/…). Mirrors
    convert_kiro_auth.to_kiro_rs from the vendored helper."""
    if not token.get("refresh_token"):
        raise LoginError("cannot build kiro.rs entry — missing refresh_token")
    out: dict = {"refreshToken": token["refresh_token"]}
    if token.get("access_token"):
        out["accessToken"] = token["access_token"]
    if token.get("profile_arn"):
        out["profileArn"] = token["profile_arn"]
    if token.get("expires_in", 0) > 0:
        expires_at = int(time.time()) + int(token["expires_in"])
        out["expiresAt"] = datetime.fromtimestamp(
            expires_at, tz=timezone.utc
        ).strftime("%Y-%m-%dT%H:%M:%SZ")

    auth_method = token.get("auth_method", "social")
    out["authMethod"] = auth_method
    if token.get("client_id"):
        out["clientId"] = token["client_id"]
    if token.get("token_endpoint"):
        out["tokenEndpoint"] = token["token_endpoint"]
    if token.get("issuer_url"):
        out["issuerUrl"] = token["issuer_url"]
    if token.get("scopes"):
        out["scopes"] = token["scopes"]
    if region:
        out["region"] = region
    if auth_method.lower().replace("-", "_") == "external_idp":
        out.setdefault("provider", "ExternalIdp")
    if email:
        out["email"] = email
    return out


def _build_cpa_json(token, region, email):
    """CLIProxyAPI native schema — snake_case flat, ``type='kiro'``, produces
    a record CPA's ``filestore.readAuthFile`` can load directly.

    Mirrors ``convert_kiro_auth.to_cpa``. External-IdP metadata
    (issuer_url/token_endpoint/scopes) is written even though CPA doesn't
    consume it natively — some forks (CPA-Plus) do, and unknown fields are
    tolerated by the official version.
    """
    if not token.get("refresh_token"):
        raise LoginError("cannot build CPA entry — missing refresh_token")
    expires_at = ""
    if token.get("expires_in", 0) > 0:
        ts = int(time.time()) + int(token["expires_in"])
        expires_at = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    auth_method = token.get("auth_method", "social")
    out: dict = {
        "type": "kiro",
        "access_token": token.get("access_token", ""),
        "refresh_token": token["refresh_token"],
        "profile_arn": token.get("profile_arn", ""),
        "expires_at": expires_at,
        "auth_method": auth_method,
        "email": email or "",
        "disabled": False,
    }
    if token.get("client_id"):
        out["client_id"] = token["client_id"]
    if region:
        out["region"] = region
    if token.get("issuer_url"):
        out["issuer_url"] = token["issuer_url"]
    if token.get("token_endpoint"):
        out["token_endpoint"] = token["token_endpoint"]
    if token.get("scopes"):
        out["scopes"] = token["scopes"]

    # provider tag drives CPA's filename + refresh routing
    am = auth_method.lower().replace("-", "_")
    if am in ("external_idp", "idc"):
        out["provider"] = "Enterprise"
    elif am in ("builder_id", "builderid"):
        out["provider"] = "AWS"
    else:
        out["provider"] = "Google"
    return out


def _cpa_filename(cpa_entry: dict) -> str:
    """Filename for the CPA (CLIProxyAPI native) single-account credential.

    ``CLIProxyAPI_<id>.json`` — this is what CPA reads out of
    ``~/.cli-proxy-api/`` at startup. The id_part is the email if we have
    one, else profile ARN tail, else client_id."""
    email = cpa_entry.get("email", "")
    profile_arn = cpa_entry.get("profile_arn", "")
    client_id = cpa_entry.get("client_id", "")
    if email:
        id_part = _sanitize_file_component(email)
    elif profile_arn:
        id_part = _sanitize_file_component(profile_arn.rsplit("/", 1)[-1])
    elif client_id:
        id_part = _sanitize_file_component(client_id)
    else:
        id_part = "credential"
    return f"CLIProxyAPI_{id_part}.json"


# --- Public entrypoint -------------------------------------------------------


def run(req: LoginRequest, progress: ProgressCallback = noop_progress) -> LoginResult:
    """Drive a Kiro external_idp (M365) SSO round-trip — protocol-first.

    Design:
      1. **Protocol**: POST GetLoginMetadata to app.kiro.dev — returns the kiro
         M365 App's client_id + issuer_url + scopes. No browser needed here.
      2. **Protocol**: OIDC-discover the tenant's authorize/token endpoints.
      3. **Protocol**: mint PKCE + state + M365 authorize URL locally.
      4. **Browser (Camoufox)**: goto the M365 authorize URL, auto-fill
         email/password + KMSI, intercept the :3128 callback code.
      5. **Protocol**: exchange code → tokens, list CodeWhisperer profiles,
         write CLIProxyAPI JSON.

    Kiro portal's SPA hoops (Your organization / idp-email-input / Continue)
    are completely skipped because step 1 gives us everything the portal
    would've told us via its 302.
    """

    # Method 2 (AWS IAM Identity Center SSO) — dispatched when caller supplies
    # a Start URL. Keeps Method 1 (M365 external_idp via GetLoginMetadata) below
    # completely untouched.
    if (req.extras.get("sso_start_url") or "").strip():
        from . import kiro_idc
        return kiro_idc.run(req, progress)

    email = (req.extras.get("email") or req.label or "").strip()
    password = (req.extras.get("password") or "").strip()
    if not email or not password:
        raise LoginError("kiro requires extras.email + extras.password")

    proxy_url = resolve_proxy(req.proxy)
    region = (req.extras.get("region") or DEFAULT_REGION).strip() or DEFAULT_REGION
    username_override = (req.extras.get("username") or "").strip()

    progress("info", f"proxy → {proxy_url or 'direct'}")
    progress("step", f"fetching kiro login metadata for {email} …")
    client_id, issuer_url, scopes = _get_login_metadata(email, proxy_url)
    progress("info", f"kiro portal → clientId={client_id}, issuer={issuer_url[:80]}, scopes={len(scopes)}")

    progress("step", "OIDC-discovering M365 authorize/token endpoints …")
    auth_endpoint, token_endpoint = _oidc_discover(issuer_url, proxy_url)

    verifier = _random_url_safe(96)
    state = _random_url_safe(32)
    challenge = _pkce_challenge(verifier)
    redirect_uri = SOCIAL_REDIRECT_URI + OAUTH_CALLBACK_PATH
    # OIDC / M365 wants scope as a *space-separated string*, not a list.
    scope_str = " ".join(scopes) if isinstance(scopes, list) else str(scopes)
    authorize_url = _external_idp_authorize_url(
        auth_endpoint, client_id, redirect_uri, scope_str, challenge, state, email,
    )
    progress("url", authorize_url)

    # Bind the real loopback listener BEFORE launching the browser — the
    # browser will actually GET http://localhost:3128/oauth/callback?code=…
    # and our server here answers with a friendly HTML page. NB: page.route
    # interception has been tried and it *breaks* M365 anti-bot fingerprinting
    # (the sign-in page renders empty), so we must not use route here.
    progress("step", f"binding loopback listener on :{SOCIAL_REDIRECT_PORT} …")
    servers, _holder, getter = _start_callback_listener()

    callback_host_port = f"localhost:{SOCIAL_REDIRECT_PORT}"
    headless = bool(req.extras.get("headless", True))
    try:
        callback_url = _camoufox.capture_m365_signin(
            auth_url=authorize_url,
            callback_host_port=callback_host_port,
            callback_path=OAUTH_CALLBACK_PATH,
            proxy=proxy_url,
            email=email,
            password=password,
            progress=progress,
            timeout=req.timeout,
            headless=headless,
            callback_getter=getter,
        )
    finally:
        for srv in servers:
            try:
                srv.shutdown()
            except Exception:  # noqa: BLE001
                pass

    q = urllib.parse.parse_qs(urllib.parse.urlparse(callback_url).query)
    code = (q.get("code", [""])[0] or "").strip()
    if not code:
        err = (q.get("error", [""])[0] or "").strip()
        desc = (q.get("error_description", [""])[0] or "").strip()
        raise LoginError(f"kiro callback missing ?code=: error={err} desc={desc[:200]}")
    got_state = (q.get("state", [""])[0] or "").strip()
    if got_state and got_state != state:
        raise LoginError(f"state mismatch: sent {state[:10]}…, got {got_state[:10]}…")

    progress("step", "exchanging authorization code for tokens …")
    access, refresh, expires_in, _ = _exchange_external_idp_code(
        token_endpoint, client_id, code, verifier, redirect_uri, scope_str, proxy_url,
    )
    token: dict = {
        "auth_method": "external_idp",
        "access_token": access,
        "refresh_token": refresh,
        "expires_in": expires_in,
        "profile_arn": "",
        "client_id": client_id,
        "token_endpoint": token_endpoint,
        "issuer_url": issuer_url,
        "scopes": scope_str,
    }
    external_idp = True

    if not token.get("profile_arn"):
        progress("step", "resolving CodeWhisperer profile ARN …")
        token["profile_arn"] = _list_available_profiles(
            token["access_token"], region, external_idp, proxy_url
        )

    arn_region = _region_from_profile_arn(token["profile_arn"])
    if arn_region:
        region = arn_region

    username = username_override or _derive_username(token["access_token"])
    if not username:
        username = f"kiro-{int(time.time() * 1000)}"
    safe = _sanitize_file_component(username) or f"kiro-{int(time.time() * 1000)}"

    out_dir = os.path.abspath(req.out_dir or os.getcwd())
    os.makedirs(out_dir, exist_ok=True)

    # 1) CPA native format — snake_case, single-account JSON object.
    #    Filename: CLIProxyAPI_<email>.json (goes into ~/.cli-proxy-api/).
    cpa_obj = _build_cpa_json(token, region, email)
    cpa_path = os.path.join(out_dir, _cpa_filename(cpa_obj))
    fd = os.open(cpa_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(cpa_obj, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    progress("done", f"saved {cpa_path}")

    # 2) kiro.rs format — camelCase, single-account JSON object.
    #    Filename: kiro-rs-<email>.json.
    rs_obj = _build_kiro_rs_json(token, region, email)
    rs_path = os.path.join(out_dir, f"kiro-rs-{safe}.json")
    fd = os.open(rs_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(rs_obj, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    progress("done", f"saved {rs_path}")

    # 3) kiro.rs merged array — multi-account bundle for batch import.
    #    Filename: credentials.kiro-rs.json (same email → in-place update).
    creds_path = os.path.join(out_dir, "credentials.kiro-rs.json")
    total, replaced = _append_to_credentials(creds_path, rs_obj)
    verb = "updated" if replaced else "appended"
    progress("done", f"{verb} credentials.kiro-rs.json (total {total} entries)")

    extra_out = {
        "auth_method": token["auth_method"],
        "profile_arn": token["profile_arn"],
        "region": region,
        "kiro_rs_path": rs_path,
        "credentials_path": creds_path,
    }
    # Surface a new password if M365 forced a rotation mid-flow (temporary /
    # expired credential). Caller must record this or the account is lost.
    new_pw = getattr(callback_url, "new_password", None)
    if new_pw:
        extra_out["new_password"] = new_pw
        extra_out["old_password"] = getattr(callback_url, "old_password", None)
        progress("done", f"⚠ password rotated: new_password={new_pw}")

    return LoginResult(
        provider="kiro",
        identity=username,
        out_path=cpa_path,
        extra=extra_out,
    )
