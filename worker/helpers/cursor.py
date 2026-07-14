"""Cursor Pro login helper — Camoufox + YesCaptcha Turnstile.

Cursor's authenticator (authenticator.cursor.sh) sits behind Cloudflare
Turnstile with a signed bot_detection_token and a browser-fingerprint
signals payload. Pure HTTP scripting is refused. This helper drives the
sign-in flow inside an isolated Camoufox context (Firefox + anti-
fingerprint), solves the Turnstile challenge via YesCaptcha, and pulls
the 6-digit magic code from the account's inbox.

Flow, per row:

  1. Camoufox launches a fresh Firefox context (per-email profile,
     optional proxy).
  2. Navigate to https://cursor.com/dashboard → bounces to
     ``authenticator.cursor.sh/?authorization_session_id=…``
  3. Type ``req.extras.email`` → click Continue → redirect to
     ``/password?authorization_session_id=…``.
  4. Detect the Turnstile widget; solve via YesCaptcha; inject the
     token via ``_turnstile.inject_turnstile_token``.
  5. Click "Email sign-in code" → redirect to
     ``/magic-code?authentication_challenge_id=…``.
  6. Poll the account's inbox (IMAP; provider-specific) for the code.
  7. Insert code into the 6-digit input → wait for redirect back to
     ``cursor.com``.
  8. Read ``/api/auth/me`` from inside the same browser context to
     harvest ``accessToken`` + ``refreshToken`` (Cursor's session
     cookie is Http-Only, so we can't lift it from the DOM directly —
     the auth/me endpoint decodes it server-side and hands us the
     tokens the CLI uses).
  9. Persist as ``cursor-<sanitized-email>.json`` in the cursor-proto
     Account shape — directly consumable by ``cursor-to-cpa`` for
     CLIProxyAPI's ``auths/`` directory.

Request extras (all strings unless noted):

  - ``email``          the Cursor account email (required)
  - ``mail_host``      IMAP hostname (default outlook.office365.com)
  - ``mail_port``      IMAP TLS port (default 993)
  - ``mail_user``      IMAP username (default = email)
  - ``mail_pass``      IMAP password / app-specific password (required
                       unless ``otp`` is supplied)
  - ``otp``            literal 6-digit code (skips inbox lookup;
                       useful for manual testing)
  - ``headless``       "true" / "false" (default "true"; set false to
                       watch the flow in a visible Firefox window)

Environment:

  YESCAPTCHA_API_KEY — required for Turnstile solving; the helper
  fails fast with a readable error if it's unset.

Not yet implemented (deliberately left as follow-ups when this helper
migrates to muxhub's central login-provider registry):

  - refresh_token exchange loop (Cursor JWTs expire ~60 days; refresh
    would let the number-pool live longer)
  - non-IMAP inbox providers (some brokers hand you a web-based inbox
    without IMAP; those need per-broker scrapers)
  - captcha budget throttling (a busy YesCaptcha account can burn
    credits fast; the hub currently doesn't debounce)
"""

from __future__ import annotations

import base64
import json
import os
import re
import time
from typing import Optional
from urllib.parse import urlparse

from . import _camoufox, _proxy_bridge, _turnstile
from .common import (
    LoginError,
    LoginRequest,
    LoginResult,
    ProgressCallback,
    noop_progress,
    resolve_proxy,
)


# --- Constants ---------------------------------------------------------------

# The Cursor sign-in entry is `/dashboard` — hitting it while
# unauthenticated bounces to WorkOS (`authenticator.cursor.sh`) with a
# fresh `authorization_session_id`. Both URLs are stable; the
# authenticator side never changes host, only path segments as the flow
# progresses (/  → /password → /magic-code).
DASHBOARD_URL = "https://cursor.com/dashboard"
AUTH_HOST = "authenticator.cursor.sh"
CURSOR_HOST = "cursor.com"

# /api/auth/me is what the dashboard's client calls internally to hydrate
# its own state. It reads the session cookie server-side and echoes the
# access + refresh tokens along with the account identity. Cheaper (and
# more reliable) than parsing the WorkOS session cookie ourselves.
AUTH_ME_URL = "https://cursor.com/api/auth/me"

# Timeouts (seconds). These are conservative — Cursor's authenticator
# adds noticeable latency between navigations, especially on cold
# fingerprints, and YesCaptcha can take 20-40s to solve a Turnstile
# challenge on top.
NAV_TIMEOUT = 45
OTP_POLL_TIMEOUT = 120
POST_OTP_REDIRECT_TIMEOUT = 30


# --- Public entry point ------------------------------------------------------


def run(req: LoginRequest, progress: ProgressCallback = noop_progress) -> LoginResult:
    """Drive one full email-magic-code login and persist the result.

    Raises ``LoginError`` on any expected failure path (missing extras,
    Turnstile solve failure, inbox timeout, unexpected redirect). Other
    exceptions bubble as-is and the worker records them as ``error``.
    """
    email = (req.extras.get("email") or req.label or "").strip()
    if not email:
        raise LoginError("cursor requires extras.email")

    otp_literal = (req.extras.get("otp") or "").strip()
    mail_host = (req.extras.get("mail_host") or "outlook.office365.com").strip()
    mail_port = int(req.extras.get("mail_port") or 993)
    mail_user = (req.extras.get("mail_user") or email).strip()
    mail_pass = (req.extras.get("mail_pass") or "").strip()
    headless = _extras_bool(req.extras.get("headless"), default=True)

    if not otp_literal and not mail_pass:
        raise LoginError(
            "cursor requires either extras.otp (literal 6-digit code) "
            "or extras.mail_pass (for IMAP inbox polling)"
        )

    proxy = resolve_proxy(req.proxy)
    progress("info", f"proxy → {proxy or 'direct'}")

    yescaptcha_key = os.environ.get("YESCAPTCHA_API_KEY", "").strip()
    if not yescaptcha_key:
        raise LoginError(
            "YESCAPTCHA_API_KEY env var not set — Cursor's authenticator "
            "requires a Turnstile solve on every /password intent."
        )

    # We use Camoufox's raw sync_api because Cursor's sign-in isn't a
    # simple OAuth code-capture — it's a stateful multi-page flow where
    # we need to inject a Turnstile token mid-way, then observe a final
    # redirect back to cursor.com. The `_camoufox` helpers in this
    # repo target Google/M365 OAuth capture, which is a different
    # shape (single navigation → callback). Reusing the same Camoufox
    # binary, launcher, and proxy bridge, just orchestrated inline.
    Camoufox = _camoufox._import_camoufox()  # noqa: SLF001 — intentional reuse
    pw_proxy = _proxy_bridge.to_camoufox_proxy(proxy)

    safe_email = re.sub(r"[^A-Za-z0-9._-]+", "-", email).strip("-") or "unknown"
    profile_dir = os.path.expanduser(f"~/.cache/login-hub/cursor/{safe_email}")
    os.makedirs(profile_dir, exist_ok=True)

    tokens: dict = {}
    with Camoufox(
        headless=headless,
        proxy=pw_proxy,
        persistent_context=True,
        user_data_dir=profile_dir,
    ) as browser:
        # Camoufox in persistent_context mode yields a Playwright
        # BrowserContext, not a Browser. Grab (or create) the first
        # page.
        ctx = browser
        page = ctx.pages[0] if getattr(ctx, "pages", None) else ctx.new_page()
        page.set_default_timeout(NAV_TIMEOUT * 1000)

        _drive_flow(
            page=page,
            email=email,
            otp_literal=otp_literal,
            imap_conf=dict(host=mail_host, port=mail_port, user=mail_user, password=mail_pass),
            yescaptcha_key=yescaptcha_key,
            proxy=proxy,
            progress=progress,
            tokens=tokens,
        )

    if not tokens.get("access_token"):
        raise LoginError("login flow completed but access_token was not captured")

    record = _build_record(email=email, tokens=tokens)
    out_path = _write_credential(req.out_dir, record)
    progress("done", f"wrote {out_path}")
    return LoginResult(
        provider="cursor",
        identity=record["email"],
        out_path=out_path,
        extra={
            "expires_at": record.get("expires_at"),
            "refreshable": record.get("refreshable", False),
        },
    )


# --- Flow driver -------------------------------------------------------------


def _drive_flow(
    *,
    page,
    email: str,
    otp_literal: str,
    imap_conf: dict,
    yescaptcha_key: str,
    proxy: Optional[str],
    progress: ProgressCallback,
    tokens: dict,
) -> None:
    """Execute the eight-step flow against ``page``. Populates ``tokens``
    with ``access_token`` / ``refresh_token`` / ``user_id`` on success."""

    otp_lookup_since = time.time() - 120  # generous slop for clock skew

    progress("step", f"navigating to {DASHBOARD_URL}")
    page.goto(DASHBOARD_URL, wait_until="load")
    if AUTH_HOST not in page.url:
        raise LoginError(f"expected redirect to {AUTH_HOST}, got {page.url}")

    progress("step", "filling email")
    page.fill("input[type=email], input[name*='email']", email)
    with page.expect_navigation(wait_until="load", timeout=NAV_TIMEOUT * 1000):
        page.click("button[type=submit]")

    if "/password" not in page.url:
        raise LoginError(f"expected /password, got {page.url}")

    progress("step", "solving Turnstile challenge")
    sitekey = _turnstile.detect_sitekey(page)
    if not sitekey:
        # It's rare, but the widget occasionally hasn't finished
        # mounting by the time the page fires 'load'. Give it a beat.
        for _ in range(5):
            page.wait_for_timeout(500)
            sitekey = _turnstile.detect_sitekey(page)
            if sitekey:
                break
    if not sitekey:
        raise LoginError("no Turnstile widget found on /password page")

    token = _turnstile.solve_turnstile(
        website_url=page.url,
        website_key=sitekey,
        api_key=yescaptcha_key,
    )
    injected = _turnstile.inject_turnstile_token(page, token)
    progress("info", f"turnstile token injected ({injected})")

    progress("step", "requesting email sign-in code")
    with page.expect_navigation(wait_until="load", timeout=NAV_TIMEOUT * 1000):
        page.click("button:has-text('Email sign-in code')")

    if "/magic-code" not in page.url:
        raise LoginError(f"expected /magic-code, got {page.url}")

    progress("step", "waiting for OTP")
    code = _fetch_otp(
        literal=otp_literal,
        imap_conf=imap_conf,
        email=email,
        since_epoch=otp_lookup_since,
        progress=progress,
    )
    progress("info", f"otp received ({len(code)} digits)")

    # The magic-code page's six <input> boxes advance focus per keypress
    # in React. Focusing the first box and typing all six digits ends up
    # populating them correctly — the form auto-submits when the last
    # box fills.
    inputs = page.query_selector_all("input")
    if not inputs:
        raise LoginError("no <input> boxes on /magic-code page")
    inputs[0].click()
    page.keyboard.type(code, delay=40)

    # Wait for the redirect that indicates OTP was accepted.
    deadline = time.time() + POST_OTP_REDIRECT_TIMEOUT
    while time.time() < deadline:
        if CURSOR_HOST in urlparse(page.url).netloc:
            break
        page.wait_for_timeout(500)
    else:
        raise LoginError(
            f"OTP submitted but no redirect back to {CURSOR_HOST} (got {page.url}) — "
            "code may have been rejected or expired"
        )

    progress("step", "reading /api/auth/me")
    raw = page.evaluate(
        "async () => { const r = await fetch('/api/auth/me', {credentials:'include'}); return r.status + '\\n' + await r.text(); }"
    )
    status_line, _, body = str(raw).partition("\n")
    if not status_line.startswith("2"):
        raise LoginError(f"/api/auth/me returned HTTP {status_line}: {body[:200]}")
    try:
        me = json.loads(body)
    except json.JSONDecodeError as exc:
        raise LoginError(f"/api/auth/me not JSON: {exc} (body[:200]={body[:200]})") from exc

    access = (
        me.get("accessToken")
        or me.get("access_token")
        or _dig(me, "session", "accessToken")
        or ""
    )
    refresh = (
        me.get("refreshToken")
        or me.get("refresh_token")
        or _dig(me, "session", "refreshToken")
        or ""
    )
    if not access:
        raise LoginError(
            "/api/auth/me returned no access token. Cursor may have changed "
            f"the response shape; raw keys: {list(me.keys())}"
        )
    tokens["access_token"] = access
    tokens["refresh_token"] = refresh
    tokens["user_id"] = me.get("sub") or me.get("id") or _dig(me, "user", "id") or ""
    tokens["auth_type"] = me.get("authType") or "email-otp"


# --- OTP retrieval -----------------------------------------------------------


def _fetch_otp(
    *,
    literal: str,
    imap_conf: dict,
    email: str,
    since_epoch: float,
    progress: ProgressCallback,
) -> str:
    """Return a validated 6-digit code. ``literal`` short-circuits;
    otherwise we poll the inbox described by ``imap_conf``."""
    if literal:
        return _validate_code(literal)

    deadline = time.time() + OTP_POLL_TIMEOUT
    last_err: Optional[Exception] = None
    while time.time() < deadline:
        try:
            code = _imap_fetch_once(imap_conf, email, since_epoch)
            if code:
                return code
        except Exception as exc:  # noqa: BLE001
            last_err = exc
            progress("warn", f"imap: {exc}")
        time.sleep(4)
    if last_err:
        raise LoginError(f"OTP inbox poll timed out: {last_err}")
    raise LoginError(f"OTP inbox poll timed out (no cursor mail arrived at {email})")


def _imap_fetch_once(cfg: dict, email: str, since_epoch: float) -> Optional[str]:
    """Poll the inbox once; return the code or None if not yet arrived."""
    import email as _email_mod  # stdlib
    import imaplib

    with imaplib.IMAP4_SSL(cfg["host"], cfg["port"]) as m:
        m.login(cfg["user"], cfg["password"])
        m.select("INBOX")

        # SINCE takes a date, not a datetime. Widen by one day to
        # accommodate clock skew (Hotmail's server clock has been
        # observed drifting a few minutes from UTC).
        since_str = time.strftime("%d-%b-%Y", time.gmtime(since_epoch - 86400))
        typ, data = m.search(None, "FROM", "cursor.sh", "SINCE", since_str)
        if typ != "OK" or not data or not data[0]:
            return None
        ids = data[0].split()
        if not ids:
            return None

        # Newest first; Cursor's later resend can arrive as a separate
        # message and we want the freshest.
        for msg_id in reversed(ids):
            typ, msg_data = m.fetch(msg_id, "(RFC822)")
            if typ != "OK" or not msg_data:
                continue
            raw = msg_data[0][1]
            if isinstance(raw, (bytes, bytearray)):
                msg = _email_mod.message_from_bytes(raw)
            else:
                msg = _email_mod.message_from_string(raw)
            body = _extract_body(msg)
            code = _extract_code(body)
            if code:
                return code
        return None


def _extract_body(msg) -> str:
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                payload = part.get_payload(decode=True) or b""
                return payload.decode(part.get_content_charset() or "utf-8", errors="replace")
        # Fall back to HTML if there's no plain part
        for part in msg.walk():
            if part.get_content_type() == "text/html":
                payload = part.get_payload(decode=True) or b""
                return payload.decode(part.get_content_charset() or "utf-8", errors="replace")
        return ""
    payload = msg.get_payload(decode=True) or b""
    return payload.decode(msg.get_content_charset() or "utf-8", errors="replace")


_CODE_RE = re.compile(r"\b(\d{6})\b")


def _extract_code(body: str) -> Optional[str]:
    m = _CODE_RE.search(body)
    return m.group(1) if m else None


def _validate_code(code: str) -> str:
    c = code.strip()
    if not re.fullmatch(r"\d{6}", c):
        raise LoginError(f"expected 6-digit code, got {code!r}")
    return c


# --- Output ------------------------------------------------------------------


def _build_record(*, email: str, tokens: dict) -> dict:
    """Return the CPA-shaped auth file for CLIProxyAPI's auths/ dir.

    Field names mirror ``sdk/cpaformat.CursorTokenStorage`` from
    cursor-proto exactly — this is the same shape ``cursor-to-cpa``
    produces, so operators can drop the file straight into
    ``~/.cli-proxy-api/`` (or the CPA container's auth mount) without
    a second conversion step. The other four helpers in this hub also
    write CPA-shaped output directly; keeping cursor consistent means
    the number-pool ingestion path is the same for every provider.
    """
    access = tokens["access_token"]
    iat_iso, exp_iso = _jwt_lifespan(access)
    return {
        # Discriminator CPA's synthesizer keys off; must be exactly "cursor".
        "type": "cursor",
        "access_token": access,
        "refresh_token": tokens.get("refresh_token", ""),
        "email": email,
        "user_id": tokens.get("user_id", ""),
        "auth_id": tokens.get("auth_id", ""),
        # "auth_kind" — CPA convention. cursor-proto's Account uses
        # AuthType internally, but the on-disk field is auth_kind.
        "auth_kind": tokens.get("auth_type", "email-otp"),
        # Device identifiers: leave blank so CPA's cursor plugin
        # regenerates fresh ones at load. Baking this login host's
        # machine_id in would leak our environment into every login
        # and break Cursor's "one machine per identity" heuristics.
        "machine_id": "",
        "mac_machine_id": "",
        "issued_at": iat_iso,
        "last_refresh": iat_iso,
        # CPA reads token expiry via AuthFile.ExpirationTime() from the
        # "expired" key — not "expires_at".
        "expired": exp_iso,
        "refreshable": bool(tokens.get("refresh_token")),
    }


def _credential_filename(email: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9._+-]", "_", email.lower())
    return f"cursor-{safe}.json"


def _write_credential(out_dir: str, record: dict) -> str:
    out_dir = out_dir or "output"
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


# --- Utilities ---------------------------------------------------------------


def _dig(d: dict, *path: str):
    cur = d
    for p in path:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(p)
    return cur


def _extras_bool(v, default: bool = False) -> bool:
    if v is None:
        return default
    if isinstance(v, bool):
        return v
    return str(v).strip().lower() in ("1", "true", "yes", "on")


def _jwt_lifespan(token: str) -> tuple[str, str]:
    """Return (issued_at_ISO, expires_at_ISO) parsed from the token's
    unsigned payload. Returns empty strings on any parse failure — the
    caller doesn't need them to succeed, they're metadata for the pool
    inspector."""
    parts = token.split(".")
    if len(parts) < 2:
        return "", ""
    payload = parts[1] + "=" * ((4 - len(parts[1]) % 4) % 4)
    try:
        raw = base64.urlsafe_b64decode(payload)
        claims = json.loads(raw)
    except Exception:  # noqa: BLE001
        return "", ""
    iat = claims.get("iat")
    exp = claims.get("exp")
    return (_iso(iat), _iso(exp))


def _iso(epoch) -> str:
    if not epoch:
        return ""
    try:
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(int(epoch)))
    except Exception:  # noqa: BLE001
        return ""
