"""OpenAI / Codex CLI OAuth login — pure protocol.

Vendored from the codex-cli desktop-app HAR (``chatgpt_Oauth_phone.har``).
Full flow, no browser required:

  1. GET  /oauth/authorize?client_id=<app_id>&code_challenge=<S256>&…
     → 302 → /api/oauth/oauth2/auth → 302 → /api/accounts/login → 302 → /log-in
  2. GET  /log-in                       (primes session cookies)
  3. POST /api/accounts/authorize/continue  {"username":{"kind":"email","value":"…"}}
  4. POST /api/accounts/password/verify  {"password":"…"}
  5. POST /api/accounts/mfa/issue_challenge  {"id":"<from step 4>","type":"totp"}
  6. POST /api/accounts/mfa/verify  {"id":"…","type":"totp","code":"<TOTP>"}
  7. POST /api/accounts/phone-otp/send  {"channel":"sms"}
  8. Wait for SMS code (chongpt.xyz), then
     POST /api/accounts/phone-otp/validate  {"code":"<sms>"}
  9. POST /api/accounts/workspace/select  {"workspace_id":"<from step 8>"}
 10. GET  /api/oauth/oauth2/auth?…          → 302 → …/consent → 302 → callback code
 11. POST /oauth/token   grant_type=authorization_code + code_verifier

Output JSON is CPA-compatible so it can overwrite existing CPA credentials
without producing duplicate files: ``codex-<email>-<plan>.json`` where plan
comes from the JWT ``chatgpt_plan_type`` claim (free / plus / pro / team / …).
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import time
import urllib.parse
from datetime import datetime, timedelta, timezone
from typing import Optional

from curl_cffi import requests

from . import _chongpt, _proxy_bridge
from .common import LoginError, LoginRequest, LoginResult, ProgressCallback, noop_progress, resolve_proxy


# --- Constants (mirror codex-cli desktop app) --------------------------------

CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"
AUTH_BASE = "https://auth.openai.com"
CALLBACK_PORT = 1455
CALLBACK_PATH = "/auth/callback"
CALLBACK_URI = f"http://localhost:{CALLBACK_PORT}{CALLBACK_PATH}"

SCOPES = "openid email profile offline_access"

# Sentinel service — a local Node.js server (helpers/../../Downloads/sentinel/)
# that exposes POST /token accepting cookie/bearer and returning the
# openai-sentinel-token header value. See sentinel-service.js.
SENTINEL_SERVICE_URL = os.environ.get("SENTINEL_SERVICE_URL", "http://127.0.0.1:3847/token")

# Per-run OAuth context (state/challenge/nonce) — populated by run(),
# consumed by the resume/consent hop when Remix HTML page is encountered.
_CTX: dict = {}


# --- helpers -----------------------------------------------------------------


def _cookie_header(sess) -> str:
    """Serialize the session's OpenAI cookies as a single Cookie: header."""
    parts = []
    for c in sess.cookies.jar:
        dom = (c.domain or "").lower()
        if "openai.com" not in dom:
            continue
        parts.append(f"{c.name}={c.value}")
    return "; ".join(parts)


def _sentinel_token(sess, flow: str, device_id: str, proxy_url: Optional[str] = None) -> str:
    """Ask the local sentinel service to mint an openai-sentinel-token for the
    current session (cookie-authed). Returns the raw token string (JSON with
    p/t/c/id/flow that the OpenAI API expects in ``openai-sentinel-token`` header).

    Note: ``proxy_url`` is intentionally NOT passed to sentinel — the sentinel
    challenge endpoint (chatgpt.com/backend-api/sentinel/req) has no geo
    restriction and residential proxies to it are slow/blocked; the local
    machine's default network reaches it fine.
    """
    import urllib.request
    body = {
        "cookie": _cookie_header(sess),
        "device_id": device_id,
        "flow": flow,
    }
    # Retry sentinel on transient failures — chatgpt.com/sentinel/req occasionally
    # 500s under load; a quick backoff usually clears it.
    import time as _time
    last_exc = None
    for attempt in range(3):
        req = urllib.request.Request(
            SENTINEL_SERVICE_URL,
            data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=45) as r:
                j = json.loads(r.read().decode())
                break
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            _time.sleep(2.0 + attempt * 2)
    else:
        raise LoginError(
            f"sentinel service unreachable at {SENTINEL_SERVICE_URL} after 3 tries — "
            f"start it with: node ~/Downloads/sentinel/sentinel-service.js. Error: {last_exc}"
        ) from last_exc
    tok = j.get("token", "")
    if not tok:
        raise LoginError(f"sentinel returned no token: {j}")
    return tok


def _pkce_pair() -> tuple[str, str]:
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(64)).rstrip(b"=").decode()
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).rstrip(b"=").decode()
    return verifier, challenge


def _authorize_url(state: str, challenge: str, nonce: str) -> str:
    params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": CALLBACK_URI,
        "scope": SCOPES,
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "nonce": nonce,
        "codex_cli_simplified_flow": "true",
        "originator": "codex_cli_rs",
    }
    return AUTH_BASE + "/oauth/authorize?" + urllib.parse.urlencode(params)


def _make_session(proxy_url: Optional[str]):
    s = requests.Session(impersonate="chrome")
    if proxy_url:
        local = _proxy_bridge.to_urllib_proxy(proxy_url)
        if local:
            s.proxies = {"http": local, "https": local}
    # NOTE: do NOT set default Content-Type OR Origin here. On a GET request,
    # both are bot signals that Cloudflare blocks with a 403 challenge on
    # auth.openai.com (real browsers don't send Origin on top-level GETs).
    # POST requests that need them set them per-call (json= adds Content-Type;
    # add Origin explicitly in _post_with_sentinel).
    s.headers.update({
        "Accept": "application/json, text/plain, */*",
    })
    return s


def _decode_jwt_claims(token: str) -> dict:
    try:
        payload_b64 = token.split(".")[1]
        payload_b64 += "=" * (-len(payload_b64) % 4)
        return json.loads(base64.urlsafe_b64decode(payload_b64))
    except Exception:  # noqa: BLE001
        return {}


def _sanitize_file_component(s: str) -> str:
    # ``+`` must be preserved — Gmail aliases (``user+tag@gmail.com``) are
    # distinct accounts server-side; replacing ``+`` with ``-`` would collide
    # ``user+tag`` and ``user-tag`` into the same filename and silently
    # overwrite one JSON with the other.
    s = (s or "").strip()
    out = "".join(ch if (ch.isalnum() and ch.isascii()) or ch in "._-@+" else "-" for ch in s)
    return out.strip("-") or "unknown"


def _cpa_filename(email: str, plan: str) -> str:
    """CPA-Plus native naming: ``codex-<email>-<plan>.json``. plan comes from
    the JWT's ``chatgpt_plan_type`` claim; falls back to ``free``."""
    safe_email = _sanitize_file_component(email)
    safe_plan = _sanitize_file_component(plan or "free").lower()
    if not safe_plan:
        safe_plan = "free"
    return f"codex-{safe_email}-{safe_plan}.json"


def _build_cpa_record(email: str, token_resp: dict, id_token_claims: dict) -> dict:
    """CPA-compatible schema, matching the on-disk format the ChongPT web
    recharge system produces (so re-imports overwrite instead of duplicating)."""
    now = int(time.time())
    expires_in = int(token_resp.get("expires_in") or 0)
    # +08:00 timezone (Asia/Shanghai) — matches CPA's ISO format
    tz = timezone(timedelta(hours=8))
    expired = datetime.fromtimestamp(now + expires_in, tz=tz).strftime("%Y-%m-%dT%H:%M:%S+08:00")
    last_refresh = datetime.fromtimestamp(now, tz=tz).strftime("%Y-%m-%dT%H:%M:%S+08:00")

    # account_id — chatgpt_account_id inside id_token claim
    auth_claim = id_token_claims.get("https://api.openai.com/auth", {}) or {}
    account_id = auth_claim.get("chatgpt_account_id", "") or ""

    return {
        "access_token": token_resp.get("access_token", ""),
        "account_id": account_id,
        "disabled": False,
        "email": email,
        "expired": expired,
        "id_token": token_resp.get("id_token", ""),
        "last_refresh": last_refresh,
        "refresh_token": token_resp.get("refresh_token", ""),
        "type": "codex",
    }


def _extract_plan(access_token: str) -> str:
    claims = _decode_jwt_claims(access_token)
    auth_claim = claims.get("https://api.openai.com/auth", {}) or {}
    plan = auth_claim.get("chatgpt_plan_type", "") or ""
    return plan


# --- OAuth flow steps --------------------------------------------------------


def _bootstrap_login(sess, authorize_url: str) -> str:
    """Step 1+2: walk the OpenAI auth chain manually.

    The ``codex_cli_simplified_flow=true`` mode returns JSON envelopes with
    a ``continue_url`` field (in place of HTTP 302) telling the client where
    to hop next — this is how codex-cli navigates without a browser. We
    handle three response types:

      * 200 + JSON body containing ``continue_url``  → GET that URL next
      * 3xx redirect with ``Location`` header        → follow the header
      * 200 + HTML body (has ``entry.client`` bundle) → terminal /log-in page

    Along the way, all necessary ``__Host-openai-*`` login cookies get set.
    """
    cur_url = authorize_url
    for hop in range(8):
        r = sess.get(cur_url, timeout=30, allow_redirects=False)
        if r.status_code in (301, 302, 303, 307, 308):
            loc = r.headers.get("Location", "")
            if not loc:
                raise LoginError(f"redirect missing Location hop={hop} url={cur_url[:200]}")
            cur_url = loc if loc.startswith("http") else urllib.parse.urljoin(cur_url, loc)
            continue
        if r.status_code == 200:
            body = r.text
            ct = (r.headers.get("Content-Type") or "").lower()
            # JSON continue_url envelope — codex simplified flow
            if "json" in ct or body.lstrip().startswith("{"):
                try:
                    j = r.json()
                except Exception:  # noqa: BLE001
                    j = {}
                cont = (j.get("continue_url") or "").strip()
                if cont:
                    cur_url = cont
                    continue
            # HTML login page — terminal
            if "entry.client" in body or "auth-cdn.oaistatic.com" in body or "login-web" in body:
                return cur_url
            raise LoginError(
                f"bootstrap terminal on unknown page hop={hop} url={cur_url[:200]} body[:200]={body[:200]}"
            )
        raise LoginError(f"bootstrap unexpected status={r.status_code} hop={hop} url={cur_url[:200]} body[:200]={r.text[:200]}")
    raise LoginError(f"bootstrap redirect loop (>8 hops) — last url={cur_url[:200]}")


def _post_with_sentinel(sess, path: str, body: dict, flow: str, device_id: str, proxy_url: Optional[str]) -> "requests.Response":
    """Fresh sentinel-token per request (each has unique id/flow)."""
    token = _sentinel_token(sess, flow, device_id, proxy_url)
    return sess.post(
        AUTH_BASE + path, json=body, timeout=30,
        headers={
            "openai-sentinel-token": token,
            "oai-device-id": device_id,
            # POST endpoints are XHR from the login SPA — Origin/Referer are
            # expected here (unlike top-level GETs). Send them per-call.
            "Origin": AUTH_BASE,
            "Referer": AUTH_BASE + "/log-in",
        },
    )


def _submit_email(sess, email: str, device_id: str, proxy_url: Optional[str]) -> dict:
    r = _post_with_sentinel(
        sess, "/api/accounts/authorize/continue",
        {"username": {"kind": "email", "value": email}},
        "authorize_continue", device_id, proxy_url,
    )
    if r.status_code != 200:
        raise LoginError(f"authorize/continue HTTP {r.status_code}: {r.text[:300]}")
    return r.json()


def _submit_password(sess, password: str, device_id: str, proxy_url: Optional[str]) -> dict:
    r = _post_with_sentinel(
        sess, "/api/accounts/password/verify",
        {"password": password},
        "password_verify", device_id, proxy_url,
    )
    if r.status_code != 200:
        # Surface OpenAI-specific hard failures (deactivated / locked / etc.)
        # with a clean one-line reason instead of the raw JSON blob.
        body = r.text or ""
        try:
            j = r.json()
            code = (j.get("error") or {}).get("code") or ""
            msg = (j.get("error") or {}).get("message") or ""
            if code in ("account_deactivated", "account_disabled", "account_locked"):
                raise LoginError(
                    f"OpenAI refused sign-in ({code}) — account is {code.split('_')[-1]}. "
                    f"msg={msg[:200]}"
                )
            if code == "invalid_username_or_password":
                raise LoginError(f"OpenAI: password rejected ({code}). msg={msg[:200]}")
        except LoginError:
            raise
        except Exception:  # noqa: BLE001
            pass
        raise LoginError(f"password/verify HTTP {r.status_code}: {body[:300]}")
    return r.json()


def _mfa_totp(sess, totp_secret: str, pw_resp: dict, device_id: str, proxy_url: Optional[str], progress: ProgressCallback) -> dict:
    """Issue TOTP challenge + verify with pyotp-generated code.

    ``pw_resp`` is the response from _submit_password — it contains the MFA
    factor list under ``page.payload.factors``. We pick the one with
    ``factor_type == "totp"`` and use its ``id`` for issue_challenge.
    """
    try:
        import pyotp  # type: ignore
    except ImportError as exc:
        raise LoginError("pyotp required for TOTP") from exc

    # Extract TOTP factor id from password response
    payload = (pw_resp.get("page") or {}).get("payload") or {}
    factors = payload.get("factors") or []
    totp_id = ""
    for f in factors:
        if f.get("factor_type") == "totp":
            totp_id = f.get("id", "")
            break
    if not totp_id:
        raise LoginError(f"no TOTP factor in password response: {pw_resp}")

    issue = _post_with_sentinel(
        sess, "/api/accounts/mfa/issue_challenge",
        {"id": totp_id, "type": "totp", "force_fresh_challenge": False},
        "mfa_issue_challenge", device_id, proxy_url,
    )
    if issue.status_code != 200:
        raise LoginError(f"mfa/issue HTTP {issue.status_code}: {issue.text[:300]}")

    code = pyotp.TOTP(totp_secret).now()
    progress("step", f"TOTP verify code={code}")
    r = _post_with_sentinel(
        sess, "/api/accounts/mfa/verify",
        {"id": totp_id, "type": "totp", "code": code},
        "mfa_verify", device_id, proxy_url,
    )
    if r.status_code != 200:
        raise LoginError(f"mfa/verify HTTP {r.status_code}: {r.text[:300]}")
    return r.json()


def _phone_otp(sess, sms_cdk: str, device_id: str, proxy_url: Optional[str], progress: ProgressCallback) -> dict:
    """Trigger SMS send from OpenAI, then poll chongpt.xyz for the code.

    chongpt.xyz is accessed direct (no proxy) — the residential proxy adds
    latency and can time out, while chongpt has no geo restriction."""
    try:
        pre = _chongpt.session(sms_cdk, force_new=False, proxy_url=None)
        prev_at = pre.get("receivedAt") or ""
        progress("info", f"chongpt pre-send snapshot receivedAt={prev_at} code={'*' if pre.get('verificationCode') else 'none'}")
    except Exception as exc:  # noqa: BLE001
        prev_at = ""
        progress("warn", f"chongpt pre-snapshot failed: {exc}")

    progress("step", "POST /phone-otp/send channel=sms")
    r = _post_with_sentinel(
        sess, "/api/accounts/phone-otp/send",
        {"channel": "sms"},
        "phone_otp_send", device_id, proxy_url,
    )
    if r.status_code != 200:
        raise LoginError(f"phone-otp/send HTTP {r.status_code}: {r.text[:300]}")

    progress("step", "waiting for SMS via chongpt.xyz (up to 120s) …")
    sms_code, snap = _chongpt.wait_for_new_code(
        sms_cdk, since_received_at=prev_at, timeout=120,
        proxy_url=None,
        progress=progress,
    )
    progress("step", f"chongpt got SMS code={sms_code} phone={snap.get('phoneNumber')}")

    r = _post_with_sentinel(
        sess, "/api/accounts/phone-otp/validate",
        {"code": sms_code},
        "phone_otp_validate", device_id, proxy_url,
    )
    if r.status_code != 200:
        raise LoginError(f"phone-otp/validate HTTP {r.status_code}: {r.text[:300]}")
    return r.json()


def _select_workspace(sess, workspace_id: str, device_id: str, proxy_url: Optional[str]) -> dict:
    r = _post_with_sentinel(
        sess, "/api/accounts/workspace/select",
        {"workspace_id": workspace_id},
        "workspace_select", device_id, proxy_url,
    )
    if r.status_code != 200:
        raise LoginError(f"workspace/select HTTP {r.status_code}: {r.text[:300]}")
    return r.json()


def _resume_oauth_and_get_code(sess, continue_url: str, device_id: str, proxy_url: Optional[str], progress: ProgressCallback) -> tuple[str, str]:
    """Step 10+: follow ``continue_url`` returned by the last auth step. It may
    point at:
      * /sign-in-with-chatgpt/codex/consent   — codex consent screen (HTML)
      * /log-in/workspace                     — workspace selection (HTML)
      * /api/oauth/oauth2/auth                — direct 302 to /callback (already approved)

    We handle three response types:
      * 3xx: follow Location, if it's a loopback URL → parse code
      * 200 JSON: follow continue_url in body (codex simplified flow)
      * 200 HTML with codex consent SPA: POST /api/accounts/consent explicitly
    """
    cur = continue_url
    for hop in range(10):
        r = sess.get(cur, timeout=30, allow_redirects=False)
        loc = r.headers.get("Location", "")
        if r.status_code in (301, 302, 303):
            if not loc:
                raise LoginError(f"redirect missing Location hop={hop} url={cur[:200]}")
            if not loc.startswith("http"):
                loc = urllib.parse.urljoin(cur, loc)
            if loc.startswith("http://localhost") or loc.startswith("http://127.0.0.1"):
                q = urllib.parse.parse_qs(urllib.parse.urlparse(loc).query)
                code = (q.get("code", [""])[0] or "").strip()
                got_state = (q.get("state", [""])[0] or "").strip()
                if not code:
                    raise LoginError(f"callback missing ?code=: {loc[:200]}")
                return code, got_state
            cur = loc
            continue
        if r.status_code == 200:
            body = r.text
            ct = (r.headers.get("Content-Type") or "").lower()
            if "json" in ct or body.lstrip().startswith("{"):
                try:
                    j = r.json()
                except Exception:  # noqa: BLE001
                    j = {}
                nxt = (j.get("continue_url") or "").strip()
                if nxt:
                    cur = nxt
                    continue
            # HTML consent page — the codex "consent" is granted by
            # workspace/select (done before resume). After that, we just
            # need to hit /api/oauth/oauth2/auth (same URL as bootstrap)
            # which now 303s to the loopback callback.
            if "/sign-in-with-chatgpt/codex/consent" in cur or "codex_consent" in body.lower():
                # Force jump to /api/oauth/oauth2/auth with codex params.
                cur = AUTH_BASE + "/api/oauth/oauth2/auth?" + urllib.parse.urlencode({
                    "response_type": "code", "client_id": CLIENT_ID,
                    "redirect_uri": CALLBACK_URI, "scope": SCOPES,
                    "state": _CTX["state"], "code_challenge": _CTX["challenge"],
                    "code_challenge_method": "S256", "nonce": _CTX["nonce"],
                    "codex_cli_simplified_flow": "true",
                    "id_token_add_organizations": "true",
                    "prompt": "login",
                })
                continue
            raise LoginError(
                f"resume terminal 200 without callback hop={hop} url={cur[:200]} body[:200]={body[:200]}"
            )
        raise LoginError(
            f"resume: unexpected status={r.status_code} hop={hop} url={cur[:200]} body[:200]={r.text[:200]}"
        )
    raise LoginError(f"resume too many hops (>10), last url={cur[:200]}")


def _exchange_token(sess, code: str, verifier: str) -> dict:
    r = sess.post(AUTH_BASE + "/oauth/token",
                  data={
                      "grant_type": "authorization_code",
                      "client_id": CLIENT_ID,
                      "code": code,
                      "redirect_uri": CALLBACK_URI,
                      "code_verifier": verifier,
                  },
                  headers={"Content-Type": "application/x-www-form-urlencoded"},
                  timeout=30)
    if r.status_code != 200:
        raise LoginError(f"token endpoint HTTP {r.status_code}: {r.text[:300]}")
    return r.json()


# --- Entry -------------------------------------------------------------------


def run(req: LoginRequest, progress: ProgressCallback = noop_progress) -> LoginResult:
    email = (req.extras.get("email") or req.label or "").strip()
    password = (req.extras.get("password") or "").strip()
    totp_secret = (req.extras.get("totp_secret") or "").strip()
    sms_cdk = (req.extras.get("sms_cdk") or "").strip()
    if not email or not password:
        raise LoginError("openai requires extras.email + extras.password")

    proxy = resolve_proxy(req.proxy)
    progress("info", f"proxy → {proxy or 'direct'}")

    verifier, challenge = _pkce_pair()
    state = secrets.token_hex(16)
    nonce = secrets.token_hex(16)
    _CTX.update({"state": state, "challenge": challenge, "nonce": nonce})
    auth_url = _authorize_url(state, challenge, nonce)
    progress("url", auth_url)

    # device_id is stable per login — sentinel includes it in the payload,
    # OpenAI includes it in oai-did cookie / oai-device-id header. It must
    # be a UUID (36 chars) that stays constant across all requests in this
    # login attempt.
    import uuid
    device_id = str(uuid.uuid4())

    sess = _make_session(proxy)

    progress("step", "bootstrapping login session …")
    _bootstrap_login(sess, auth_url)

    progress("step", f"submitting email: {email}")
    _submit_email(sess, email, device_id, proxy)

    progress("step", "submitting password")
    pw_resp = _submit_password(sess, password, device_id, proxy)

    # Track the "current" server-side state so we know which auth step is
    # expected next. The response's page.type + continue_url tell us this.
    last_resp = pw_resp

    if totp_secret and last_resp.get("page", {}).get("type") == "mfa_challenge":
        progress("step", "MFA / TOTP challenge")
        last_resp = _mfa_totp(sess, totp_secret, pw_resp, device_id, proxy, progress)

    # Only run phone-otp if OpenAI's flow *asks* for it. After MFA, some
    # accounts skip straight to consent (phone already verified before);
    # others land on ``phone_otp_select_channel`` (first-time or new-device
    # login). Both signal "we need SMS now".
    next_type = last_resp.get("page", {}).get("type", "")
    phone_types = (
        "phone_verification", "phone_challenge", "phone_otp",
        "phone_otp_select_channel", "phone_otp_challenge",
    )
    if next_type in phone_types:
        if not sms_cdk:
            raise LoginError(
                f"OpenAI requires SMS 2FA (page.type={next_type}) but no sms_cdk provided"
            )
        progress("step", f"phone OTP required (page.type={next_type}) — using chongpt CDK")
        last_resp = _phone_otp(sess, sms_cdk, device_id, proxy, progress)
    else:
        progress("info", f"skip phone OTP (page.type={next_type!r})")

    # Workspace select — required for codex_consent page. The workspace list
    # is already in the last_resp under oai-client-auth-session.workspaces.
    # Codex CLI picks the first one; that's what the desktop app does.
    workspace_id = ""
    sess_info = last_resp.get("oai-client-auth-session") or {}
    workspaces = sess_info.get("workspaces") or []
    if workspaces:
        workspace_id = workspaces[0].get("id", "")

    if workspace_id:
        progress("step", f"selecting workspace {workspace_id}")
        last_resp = _select_workspace(sess, workspace_id, device_id, proxy)

    # Continue URL from the last step is what tells us where to go for the
    # code redemption. Fall back to explicit resume URL if missing.
    continue_url = last_resp.get("continue_url") or ""
    if not continue_url:
        continue_url = AUTH_BASE + "/api/oauth/oauth2/auth?" + urllib.parse.urlencode({
            "response_type": "code", "client_id": CLIENT_ID,
            "redirect_uri": CALLBACK_URI, "scope": SCOPES,
            "state": state, "code_challenge": challenge,
            "code_challenge_method": "S256", "nonce": nonce,
            "codex_cli_simplified_flow": "true", "id_token_add_organizations": "true",
            "prompt": "login",
        })

    progress("step", f"resuming OAuth via continue_url={continue_url[:100]}")
    code, got_state = _resume_oauth_and_get_code(sess, continue_url, device_id, proxy, progress)
    if got_state and got_state != state:
        progress("warn", f"state mismatch: sent {state[:10]}… got {got_state[:10]}…")

    progress("step", "exchanging code for tokens")
    token = _exchange_token(sess, code, verifier)
    access = token.get("access_token", "")
    if not access:
        raise LoginError(f"token exchange returned no access_token: {token}")

    id_claims = _decode_jwt_claims(token.get("id_token") or "")
    plan = _extract_plan(access) or "free"
    progress("info", f"plan={plan}, chatgpt_account_id={(id_claims.get('https://api.openai.com/auth') or {}).get('chatgpt_account_id','')}")

    out_dir = os.path.abspath(req.out_dir or os.getcwd())
    os.makedirs(out_dir, exist_ok=True)
    record = _build_cpa_record(email, token, id_claims)
    out_path = os.path.join(out_dir, _cpa_filename(email, plan))
    fd = os.open(out_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(record, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    progress("done", f"saved {out_path}")

    return LoginResult(
        provider="openai",
        identity=email,
        out_path=out_path,
        extra={"plan": plan, "account_id": record["account_id"]},
    )
