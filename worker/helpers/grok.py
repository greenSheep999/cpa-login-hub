"""Grok (x.ai) login — pure HTTP RPC, no browser.

The HAR for an actual grok-cli OAuth login shows the flow is:

  1. POST https://accounts.x.ai/api/rpc
       body: {"rpc":"createSession","req":{
         "createSessionRequest":{"credentials":{"case":"emailAndPassword",
           "value":{"email":..., "clearTextPassword":...}}},
         "turnstileToken":"<solved by yescaptcha>"
       }}
     → 200 OK + sets cookies

  2. POST https://accounts.x.ai/oauth2/consent?<authorize_params>
       body: [{"action":"allow","clientId":...,"redirectUri":...,
              "scope":...,"state":...,"codeChallenge":...,
              "codeChallengeMethod":"S256","nonce":...,
              "principalType":"User","principalId":"",
              "referrer":"cli-proxy-api"}]
     → 200 OK with RSC body containing the redirect to
       http://127.0.0.1:56121/callback?state=...&code=...

  3. POST https://auth.x.ai/oauth2/token (PKCE token exchange)

We use:
- ``yescaptcha`` to solve the Cloudflare Turnstile challenge → real token
- ``curl_cffi`` with ``impersonate="chrome"`` so Cloudflare doesn't ding us
  on TLS fingerprint
- The proxy bridge (SOCKS5+auth → local SOCKS5/HTTP) for routing

No browser, no JS, no DOM clicking. The Turnstile checkbox is bypassed by
solving it server-side via yescaptcha and putting the token directly into
the createSession RPC body — that's exactly what the genuine grok-cli does.
"""

from __future__ import annotations

import base64
import hashlib
import http.server
import json
import os
import re
import secrets
import socket
import socketserver
import threading
import time
import urllib.parse
from typing import Optional

from . import _camoufox, _proxy_bridge, _turnstile
from .common import LoginError, LoginRequest, LoginResult, ProgressCallback, noop_progress, resolve_proxy


# --- Constants (from HAR) ---------------------------------------------------

CLIENT_ID = "b1a00492-073a-47ea-816f-4c329264a828"
CALLBACK_PORT = 56121
CALLBACK_PATH = "/callback"
CALLBACK_HOSTPORT = f"127.0.0.1:{CALLBACK_PORT}"
CALLBACK_URI = f"http://{CALLBACK_HOSTPORT}{CALLBACK_PATH}"

AUTHORIZE_BASE = "https://auth.x.ai/oauth2/authorize"
RPC_URL = "https://accounts.x.ai/api/rpc"
CONSENT_URL = "https://accounts.x.ai/oauth2/consent"
TOKEN_URL = "https://auth.x.ai/oauth2/token"

SCOPES = "openid profile email offline_access grok-cli:access api:access"
TURNSTILE_SITEKEY = "0x4AAAAAAAhr9JGVDZbrZOo0"  # x.ai sitewide

# Chrome 149 (matching HAR) UA
UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36")


# --- PKCE -------------------------------------------------------------------


def _pkce_pair() -> tuple[str, str]:
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(64)).rstrip(b"=").decode()
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return verifier, challenge


def _build_authorize_params(state: str, nonce: str, code_challenge: str) -> dict:
    return {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": CALLBACK_URI,
        "scope": SCOPES,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "nonce": nonce,
        "referrer": "cli-proxy-api",
        "plan": "generic",
    }


# --- Session via curl_cffi --------------------------------------------------


def _make_session(proxy_url: Optional[str]):
    """curl_cffi Session impersonating Chrome 124+. SOCKS5+auth doesn't work
    reliably with curl_cffi's libcurl build (SOCKS5 auth phase fails), so we
    route through the local pproxy HTTP bridge — which talks SOCKS5+auth to
    upstream itself and gives us a plain HTTP proxy on 127.0.0.1."""
    try:
        from curl_cffi import requests as curl_requests  # type: ignore
    except ImportError as exc:
        raise LoginError("curl_cffi not installed: pip install curl_cffi") from exc

    s = curl_requests.Session(impersonate="chrome")
    if proxy_url:
        local = _proxy_bridge.to_urllib_proxy(proxy_url)
        if local:
            s.proxies = {"http": local, "https": local}
    s.headers.update({
        "User-Agent": UA,
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.9",
    })
    return s


# --- Output -----------------------------------------------------------------


def _credential_filename(email: str) -> str:
    safe = "".join(ch if (ch.isalnum() and ch.isascii()) or ch in "._-@" else "-" for ch in email).strip("-")
    return f"grok-{safe or 'unknown'}.json"


def _build_record(email: str, token_resp: dict) -> dict:
    now = time.time()
    expires_in = int(token_resp.get("expires_in") or 0)
    expired_at = time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime(now + expires_in)) if expires_in else ""
    rec = {
        "access_token": token_resp.get("access_token", ""),
        "disabled": False,
        "email": email,
        "expires_in": expires_in,
        "refresh_token": token_resp.get("refresh_token", ""),
        "scope": token_resp.get("scope", SCOPES),
        "timestamp": int(now * 1000),
        "token_type": token_resp.get("token_type", "Bearer"),
        "type": "grok",
    }
    if "id_token" in token_resp:
        rec["id_token"] = token_resp["id_token"]
    if expired_at:
        rec["expired"] = expired_at
    return rec


def _write_record(out_dir: str, record: dict, email: str) -> str:
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, _credential_filename(email))
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


# --- Loopback callback listener ---------------------------------------------


class _CallbackHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):  # noqa: A003
        pass

    def do_GET(self):  # noqa: N802
        holder = self.server.holder  # type: ignore[attr-defined]
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path != CALLBACK_PATH:
            self.send_response(404); self.end_headers(); return
        full_url = f"http://{self.headers.get('Host','localhost')}{self.path}"
        with holder["lock"]:
            if holder.get("url") is None:
                holder["url"] = full_url
        body = (
            b"<!doctype html><meta charset=utf-8><title>Grok Sign-In</title>"
            b"<body style='font-family:sans-serif;padding:2rem'>"
            b"<p>Grok sign-in complete. You can close this tab.</p></body>"
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
    """Start loopback :CALLBACK_PORT listener (IPv4 always, IPv6 if free).
    Returns ``(servers, holder, getter)``. Getter → captured URL or None."""
    holder = {"url": None, "lock": threading.Lock()}
    servers = []
    try:
        v4 = _V4Server(("127.0.0.1", CALLBACK_PORT), _CallbackHandler)
    except OSError as exc:
        raise LoginError(
            f"cannot bind 127.0.0.1:{CALLBACK_PORT} for OAuth callback: {exc}"
        )
    v4.holder = holder  # type: ignore[attr-defined]
    servers.append(v4)
    try:
        v6 = _V6Server(("::1", CALLBACK_PORT), _CallbackHandler)
        v6.holder = holder  # type: ignore[attr-defined]
        servers.append(v6)
    except OSError:
        pass
    for srv in servers:
        threading.Thread(target=srv.serve_forever, daemon=True).start()

    def getter():
        with holder["lock"]:
            return holder.get("url")

    return servers, holder, getter


def _consent_in_camoufox(*, proxy, authorize_url, cookies, progress, callback_getter, timeout=300):
    """Launch Camoufox with the curl_cffi cookies pre-injected. Navigate to
    /oauth2/authorize — because we're already logged in via the injected
    session, x.ai 303s straight to /oauth2/consent. Click 'Allow' and wait
    for the real HTTP loopback listener to capture the code.

    Returns ``(code, state)``.
    """
    Camoufox = _camoufox._import_camoufox()
    pw_proxy = _camoufox._proxy_for_camoufox(proxy)

    # Convert curl_cffi Cookie objects to Playwright's expected shape.
    pw_cookies = []
    for c in cookies:
        domain = c.domain or ""
        if not domain:
            continue
        pw_cookies.append({
            "name": c.name,
            "value": c.value,
            "domain": domain,
            "path": c.path or "/",
            "secure": bool(c.secure),
        })

    progress("info", f"camoufox launching for consent click (cookies={len(pw_cookies)})")
    with Camoufox(
        headless=False,
        proxy=pw_proxy,
        humanize=False,
        i_know_what_im_doing=True,
        geoip=True if pw_proxy else False,
    ) as browser:
        context = browser.new_context(viewport={"width": 1280, "height": 860})
        try:
            context.add_cookies(pw_cookies)
        except Exception as exc:  # noqa: BLE001
            progress("warn", f"add_cookies partial: {exc}")

        page = context.new_page()
        try:
            page.bring_to_front()
        except Exception:  # noqa: BLE001
            pass

        # Loopback callback interceptor — only for :56121, so we don't touch
        # x.ai's own requests. When Firefox 302s to the loopback after Allow,
        # this route captures the URL and fulfils with 200 (the real HTTP
        # listener also captures it; both paths are safe).
        loopback_captured = {"url": None}

        def _route_loopback(route):
            try:
                u = route.request.url
                if CALLBACK_HOSTPORT in u and CALLBACK_PATH in u and "code=" in u:
                    loopback_captured["url"] = u
                    try:
                        route.fulfill(status=200, content_type="text/html; charset=utf-8",
                                      body=b"<meta charset=utf-8><p>OK - return to terminal.</p>")
                    except Exception:  # noqa: BLE001
                        pass
                    return
            except Exception:  # noqa: BLE001
                pass
            try:
                route.continue_()
            except Exception:  # noqa: BLE001
                pass

        page.route(f"http://{CALLBACK_HOSTPORT}/**", _route_loopback)

        progress("step", "opening x.ai authorize URL …")
        try:
            page.goto(authorize_url, wait_until="domcontentloaded", timeout=45_000)
        except Exception as exc:  # noqa: BLE001
            progress("warn", f"page.goto: {str(exc)[:120]}")

        # Dismiss any cookie banner first — the visible "Allow" button on
        # x.ai's cookie prompt overlaps with our target and takes priority in
        # naive selectors like ``button:has-text('Allow')``. Cookie banners on
        # x.ai are inside data-testid=cookieBanner (observed).
        for sel in [
            "button:has-text('Accept all')",
            "button[data-testid='reject-cookie']",
            "button:has-text('Reject all')",
        ]:
            try:
                loc = page.locator(sel).first
                if loc.count() > 0 and loc.is_visible(timeout=500):
                    progress("step", f"dismissing cookie banner ({sel})")
                    loc.click(timeout=3000, force=True)
                    page.wait_for_timeout(500)
                    break
            except Exception:  # noqa: BLE001
                continue

        # Find and click the Allow button that submits the OAuth consent
        # form. We target it via the surrounding form's role so we don't
        # accidentally hit "Allow all" on a cookie prompt.
        deadline_click = time.time() + 45
        clicked = False
        while time.time() < deadline_click and not clicked:
            if callback_getter() is not None:
                break
            try:
                cur = page.url
            except Exception:  # noqa: BLE001
                break
            if "/oauth2/consent" not in cur and CALLBACK_PATH not in cur:
                progress("info", f"waiting for consent page; cur={cur[:80]}")
                time.sleep(1); continue
            # Dump visible buttons once for diagnosis (only on first pass)
            if not hasattr(_consent_in_camoufox, "_dumped"):
                _consent_in_camoufox._dumped = True
                try:
                    btns = page.query_selector_all("button, [role='button']")
                    seen = []
                    for b in btns[:15]:
                        try:
                            txt = (b.inner_text() or "").strip()[:40]
                            visible = b.is_visible()
                            attrs = f"type={b.get_attribute('type')} data-testid={b.get_attribute('data-testid')}"
                            seen.append(f"[{visible}]{txt!r} {attrs}")
                        except Exception:
                            pass
                    progress("info", f"buttons on consent page: {seen[:10]}")
                except Exception as exc:  # noqa: BLE001
                    progress("info", f"dump err: {exc}")

            # Preferred locators — the actual consent button is inside a form
            # or has clear OAuth-consent attributes.
            for sel in [
                "button[type='submit'][name='action'][value='allow']",
                "button[data-testid='consent-allow']",
                "form button:has-text('Allow')",
                "button:has-text('Authorize')",
                "button:has-text('授权')",
                "button:has-text('允许')",
                "main button:has-text('Allow')",
                "button:has-text('Allow')",
            ]:
                try:
                    loc = page.locator(sel).first
                    if loc.count() > 0 and loc.is_visible(timeout=1000):
                        progress("step", f"clicking consent Allow ({sel})")
                        loc.click(timeout=5000, force=True)
                        clicked = True
                        break
                except Exception:  # noqa: BLE001
                    continue
            time.sleep(1)

        if not clicked:
            progress("warn", "Allow button not found — you may need to click it manually in the Camoufox window")

        # Wait for callback to arrive — either via the real HTTP loopback
        # server, or via page.route intercepting Firefox's own request.
        deadline = time.time() + timeout
        last_diag = 0.0
        last_reported_url = ""
        while time.time() < deadline:
            got = callback_getter() or loopback_captured["url"]
            now = time.time()
            if now - last_diag > 5:
                last_diag = now
                try:
                    cur = page.url
                    if cur != last_reported_url:
                        progress("info", f"page url={cur[:120]}")
                        last_reported_url = cur
                except Exception:  # noqa: BLE001
                    pass
            if got:
                progress("step", "captured OAuth callback (loopback listener)")
                try:
                    context.close()
                except Exception:  # noqa: BLE001
                    pass
                q = urllib.parse.parse_qs(urllib.parse.urlparse(got).query)
                code = (q.get("code", [""])[0] or "").strip()
                got_state = (q.get("state", [""])[0] or "").strip()
                if not code:
                    raise LoginError(f"callback missing ?code=: {got}")
                return code, got_state
            time.sleep(1)

        try:
            context.close()
        except Exception:  # noqa: BLE001
            pass
        raise LoginError("Camoufox consent flow timed out — no callback received")


# --- Entry ------------------------------------------------------------------


def run(req: LoginRequest, progress: ProgressCallback = noop_progress) -> LoginResult:
    email = (req.extras.get("email") or req.label or "").strip()
    password = (req.extras.get("password") or "").strip()
    if not email or not password:
        raise LoginError("grok requires extras.email + extras.password")

    proxy = resolve_proxy(req.proxy)
    progress("info", f"proxy → {proxy or 'direct'}")

    # --- Step 0: PKCE + state ---
    state = secrets.token_hex(16)
    nonce = secrets.token_hex(16)
    verifier, challenge = _pkce_pair()
    auth_params = _build_authorize_params(state, nonce, challenge)
    progress("url", AUTHORIZE_BASE + "?" + urllib.parse.urlencode(auth_params))

    sess = _make_session(proxy)

    # --- Step 1: prime cookies by hitting /sign-in (sets _cflb / __cf_bm etc.)
    progress("step", "priming session with GET /sign-in")
    try:
        r = sess.get(
            "https://accounts.x.ai/sign-in?email=true",
            timeout=30,
            allow_redirects=True,
        )
        progress("info", f"sign-in primer status={r.status_code} cookies={len(sess.cookies)}")
    except Exception as exc:  # noqa: BLE001
        raise LoginError(f"sign-in primer failed: {exc}") from exc

    # --- Step 2: solve Turnstile via YesCaptcha ---
    progress("step", "solving Cloudflare Turnstile via YesCaptcha …")
    try:
        ts_token = _turnstile.solve_turnstile(
            website_url="https://accounts.x.ai/sign-in",
            website_key=TURNSTILE_SITEKEY,
            timeout=180,
        )
        progress("step", f"turnstile token solved (len={len(ts_token)})")
    except Exception as exc:  # noqa: BLE001
        raise LoginError(f"turnstile solve failed: {exc}") from exc

    # --- Step 3: POST /api/rpc createSession ---
    progress("step", "POST /api/rpc createSession")
    rpc_body = {
        "rpc": "createSession",
        "req": {
            "createSessionRequest": {
                "credentials": {
                    "case": "emailAndPassword",
                    "value": {
                        "email": email,
                        "clearTextPassword": password,
                    },
                },
            },
            "turnstileToken": ts_token,
        },
    }
    try:
        r = sess.post(
            RPC_URL,
            json=rpc_body,
            headers={
                "Content-Type": "application/json",
                "Origin": "https://accounts.x.ai",
                "Referer": "https://accounts.x.ai/sign-in?email=true",
            },
            timeout=30,
        )
        progress("info", f"createSession status={r.status_code} body[:200]={r.text[:200]}")
        if r.status_code != 200:
            raise LoginError(f"createSession HTTP {r.status_code}: {r.text[:300]}")
    except Exception as exc:
        if isinstance(exc, LoginError):
            raise
        raise LoginError(f"createSession request failed: {exc}") from exc

    progress("step", f"session created; cookies={len(sess.cookies)}")

    # --- Step 3b: follow cookieSetterUrl chain ---
    # createSession returns {cookieSetterUrl: "https://auth.grokipedia.com/
    # set-cookie?q=..."} — that page 303-redirects through each grok domain
    # (grokipedia, grokusercontent, grok, x.ai) setting auth cookies. Without
    # following this chain, accounts.x.ai/oauth2/consent doesn't see us as
    # logged in and bounces back to /sign-in.
    try:
        cookie_setter = (r.json() or {}).get("cookieSetterUrl")
    except Exception:  # noqa: BLE001
        cookie_setter = None
    if cookie_setter:
        progress("step", f"following cookieSetterUrl chain")
        try:
            r2 = sess.get(cookie_setter, timeout=30, allow_redirects=True)
            progress("info", f"cookie chain done, final={r2.url[:80]} cookies={len(sess.cookies)}")
        except Exception as exc:  # noqa: BLE001
            progress("warn", f"cookieSetter chain err: {exc}")
    else:
        progress("warn", "no cookieSetterUrl in createSession response")

    # --- Step 4: POST /oauth2/authorize with the consent form body ---
    # The consent page is a form with all params as hidden inputs; the Allow
    # button submits to https://auth.x.ai/oauth2/authorize (POST). That POST
    # 303s straight to the loopback callback with ?code=. No Next.js server
    # action / no createServerReference hash / no browser needed — the whole
    # OAuth flow is pure HTTP once cookies are set.
    progress("step", "POST auth.x.ai/oauth2/authorize (form submit)")
    form_data = {
        "client_id": CLIENT_ID,
        "redirect_uri": CALLBACK_URI,
        "scope": SCOPES,
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "nonce": nonce,
        "principal_type": "User",
        "principal_id": "",
        "referrer": "cli-proxy-api",
    }
    try:
        r = sess.post(
            "https://auth.x.ai/oauth2/authorize",
            data=form_data,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Origin": "https://accounts.x.ai",
                "Referer": f"https://accounts.x.ai/oauth2/consent?{urllib.parse.urlencode(auth_params, quote_via=urllib.parse.quote)}",
            },
            timeout=30,
            allow_redirects=False,
        )
        progress("info", f"authorize POST status={r.status_code} loc={(r.headers.get('Location') or '')[:120]}")
    except Exception as exc:
        raise LoginError(f"authorize POST failed: {exc}") from exc

    location = r.headers.get("Location", "")
    if r.status_code not in (302, 303) or not location:
        raise LoginError(f"authorize POST unexpected: status={r.status_code} body[:300]={r.text[:300]}")
    if "code=" not in location:
        raise LoginError(f"authorize POST returned Location without code=: {location[:300]}")

    # Parse code + state from the Location header (loopback URL — never
    # actually hits the network since sess doesn't follow the redirect).
    q = urllib.parse.parse_qs(urllib.parse.urlparse(location).query)
    code = (q.get("code", [""])[0] or "").strip()
    got_state = (q.get("state", [""])[0] or "").strip()
    if not code:
        raise LoginError(f"authorize POST callback missing ?code=: {location[:200]}")
    if got_state != state:
        raise LoginError(f"state mismatch: sent {state[:10]}…, got {got_state[:10]}…")
    progress("step", f"got authorization code (len={len(code)})")

    # --- Step 6: exchange code → tokens at /oauth2/token ---
    progress("step", "exchanging code → access_token")
    form = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": CALLBACK_URI,
        "client_id": CLIENT_ID,
        "code_verifier": verifier,
    }
    try:
        r = sess.post(
            TOKEN_URL,
            data=form,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=30,
        )
        if r.status_code != 200:
            raise LoginError(f"token endpoint HTTP {r.status_code}: {r.text[:300]}")
        token_resp = r.json()
    except Exception as exc:
        if isinstance(exc, LoginError):
            raise
        raise LoginError(f"token exchange failed: {exc}") from exc

    if not token_resp.get("access_token"):
        raise LoginError(f"no access_token in token response: {token_resp}")

    out_dir = req.out_dir or os.getcwd()
    record = _build_record(email, token_resp)
    out_path = _write_record(out_dir, record, email)
    progress("done", f"saved {out_path}")

    return LoginResult(
        provider="grok",
        identity=email,
        out_path=out_path,
        extra={"scope": token_resp.get("scope", SCOPES)},
    )
