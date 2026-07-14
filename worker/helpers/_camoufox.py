"""Camoufox-based Google OAuth driver.

Per-row isolation: a fresh Camoufox process is launched per login. Stealth
fingerprint, proxy, cookies — all per-context, GC'd on exit.

This module is **vendored from** ``Antigravity-Manager/scripts/auto_oauth_only.py``
(the ``google_auto_signin`` function and its URL/state machine), simplified
and adapted so:

  - the callback URL is the local listener under our own control
    (``http://localhost:<port>/<path>``), not g2a/AM's
  - we use ``page.route`` to intercept the loopback hit so no real listener
    is needed (avoids port conflicts with cli-proxy-api-plus)
  - SOCKS5+auth upstream proxies are routed via the ``_proxy_bridge`` shim
    because Playwright/Camoufox doesn't speak SOCKS5 auth natively

The state machine handles: email → password → 2FA-method-picker → TOTP →
consent / firstparty/nativeapp → captured callback. Challenges that need a
human (qrcode, recaptcha, device prompt) just pause the auto loop and wait —
the human deals with the browser, the script keeps polling for the next
state.
"""

from __future__ import annotations

import json
import os
import re
import time
from typing import Optional
from urllib.parse import urlparse

from . import _proxy_bridge
from .common import LoginError, ProgressCallback


class CamoufoxUnavailable(LoginError):
    pass


def _import_camoufox():
    try:
        from camoufox.sync_api import Camoufox  # type: ignore
        return Camoufox
    except ImportError as exc:
        raise CamoufoxUnavailable(
            "Camoufox 未安装。在 scripts/login-hub/ 跑：\n"
            "  pip install 'camoufox[geoip]' pproxy pyotp && python -m camoufox fetch"
        ) from exc


def _import_pyotp():
    try:
        import pyotp  # type: ignore
        return pyotp
    except ImportError as exc:
        raise LoginError("pyotp 未安装：pip install pyotp") from exc


def _proxy_for_camoufox(proxy_url: Optional[str]) -> Optional[dict]:
    return _proxy_bridge.to_camoufox_proxy(proxy_url)


def _resolve_exit_ip(pw_proxy: Optional[dict]) -> Optional[str]:
    """Probe the real exit IP through the proxy bridge. Camoufox's geoip
    feature needs a real IP — it sees only 127.0.0.1 otherwise."""
    if not pw_proxy:
        return None
    import urllib.request as _ur
    try:
        opener = _ur.build_opener(_ur.ProxyHandler({
            "http": pw_proxy["server"], "https": pw_proxy["server"]
        }))
        with opener.open("https://api.ipify.org", timeout=10) as r:
            return r.read().decode().strip()
    except Exception:  # noqa: BLE001
        return None


def capture_m365_signin(
    *,
    auth_url: str,
    callback_host_port: str,          # e.g. "localhost:3128"
    callback_path: str,                # e.g. "/oauth/callback"
    proxy: Optional[str],
    email: str,
    password: str,
    progress: ProgressCallback,
    timeout: int,
    headless: bool = False,
    callback_getter=None,               # callable() -> Optional[str], polled each loop tick
) -> str:
    """Drive a Microsoft 365 (Entra ID) OIDC sign-in in Camoufox.

    Given a fully-constructed authorize URL (client_id + PKCE + state +
    redirect_uri already baked in by the caller), navigate there, auto-fill
    email → password → answer KMSI. **Does NOT intercept the callback via
    page.route** — Playwright's route mechanism breaks M365 anti-bot
    fingerprinting and the sign-in page renders empty. The caller must run a
    real loopback HTTP server on ``callback_host_port`` and pass a
    ``callback_getter`` that returns the captured URL once it arrives.

    Returns the intercepted callback URL string (contains ?code=&state=).
    """
    Camoufox = _import_camoufox()
    pw_proxy = _proxy_for_camoufox(proxy)
    exit_ip = _resolve_exit_ip(pw_proxy)
    if exit_ip:
        progress("info", f"upstream exit IP: {exit_ip}")

    progress("info", f"camoufox launching (proxy={pw_proxy['server'] if pw_proxy else 'direct'})")

    captured: dict[str, str] = {}
    with Camoufox(
        headless=headless,
        proxy=pw_proxy,
        humanize=False,   # M365 form doesn't like humanize keystroke gaps
        i_know_what_im_doing=True,
        geoip=True if pw_proxy else False,
    ) as browser:
        # Camoufox's Firefox driver (Playwright 1.61+) rejects the
        # ``isMobile`` field auto-injected by ``new_context(viewport=…)``.
        # Skip Playwright-side viewport and set it via page.set_viewport_size
        # after the page is created — Firefox honors that path directly.
        context = browser.new_context(no_viewport=True)
        page = context.new_page()
        try:
            page.set_viewport_size({"width": 1280, "height": 860})
        except Exception:  # noqa: BLE001
            pass

        progress("step", "opening M365 authorize URL …")
        try:
            # M365 sign-in bundles JS-drives form field rendering — need "load"
            # (all resources loaded) not "domcontentloaded" (only HTML parsed).
            page.goto(auth_url, wait_until="load", timeout=60_000)
        except Exception as exc:  # noqa: BLE001
            progress("info", f"page.goto ended: {str(exc)[:120]}")

        # Small settle for the JS to mount the input fields
        try:
            page.wait_for_load_state("networkidle", timeout=15_000)
        except Exception:  # noqa: BLE001
            pass

        _run_m365_state_machine(
            page, email, password, progress, captured, callback_path,
            timeout, callback_getter,
        )

        try:
            context.close()
        except Exception:  # noqa: BLE001
            pass

    if "url" in captured:
        # For backward compat return the URL string directly, but also stash
        # side channels (new_password) on the return string via a subclass.
        result = _M365CaptureResult(captured["url"])
        result.new_password = captured.get("new_password")
        result.old_password = captured.get("old_password")
        return result
    # last-chance poll of the external listener
    if callback_getter is not None:
        got = callback_getter()
        if got:
            return _M365CaptureResult(got)
    raise LoginError("M365 callback never captured (timeout or unexpected page)")


class _M365CaptureResult(str):
    """str-subclass so existing callers using ``callback_url`` as a str still
    work, but new callers can read ``.new_password`` when M365 forced a
    password rotation mid-flow."""
    new_password: Optional[str] = None
    old_password: Optional[str] = None


def _generate_m365_password(email: str = "") -> str:
    """Generate a password that satisfies M365 default complexity: 8-256 chars,
    3 of 4 character classes (upper/lower/digit/special), no full username.

    The output has 16 chars: 3 upper + 3 lower + 3 digits + 3 specials from a
    safe set, plus 4 random alnum, then shuffled. Always compliant and
    printable / typable.
    """
    import random, string
    upper = random.choices(string.ascii_uppercase, k=3)
    lower = random.choices(string.ascii_lowercase, k=3)
    digit = random.choices(string.digits, k=3)
    # avoid ambiguous / shell-quoting-hostile chars ($ ` " ' \ !)
    safe_special = "@#%^&*_+=-"
    special = random.choices(safe_special, k=3)
    rest = random.choices(string.ascii_letters + string.digits, k=4)
    pool = upper + lower + digit + special + rest
    random.shuffle(pool)
    pw = "".join(pool)
    # Sanity: never contain the username (M365 rejects passwords that include
    # the user's login name). Given randomness this is astronomically rare,
    # but re-roll defensively.
    localpart = (email.split("@")[0] if "@" in email else email).lower()
    if localpart and len(localpart) >= 3 and localpart in pw.lower():
        return _generate_m365_password(email)
    return pw


def _run_m365_state_machine(page, email, password, progress, captured, callback_path, timeout, callback_getter=None):
    """M365 sign-in autopilot:
      1. input[name='loginfmt'] → fill email → click #idSIButton9 (Next)
      2. input[name='passwd']   → fill password → click #idSIButton9 (Sign in)
      3. "Stay signed in?" (KMSI) → click #idBtn_Back ("No") if present
      4. Callback intercept fires (route or framenavigated).
    """
    AUTO_DEADLINE = 120
    MANUAL_DEADLINE = 600
    deadline = time.time() + AUTO_DEADLINE
    email_filled = False
    password_filled = False
    password_changed = False
    stay_signed_in_answered = False
    last_url = ""
    manual_announced = False
    last_dump = 0.0

    while time.time() < deadline:
        if "url" in captured:
            break

        # Poll external loopback listener first — most flows end there.
        if callback_getter is not None:
            got = callback_getter()
            if got:
                captured["url"] = got
                progress("step", "captured M365 OAuth callback (loopback listener)")
                break

        try:
            url = page.url
        except Exception:  # noqa: BLE001
            break

        if url != last_url:
            progress("info", f"url={url[:120]}")
            last_url = url

        # Diagnostic dump every 10 s
        now = time.time()
        if now - last_dump > 10:
            last_dump = now
            try:
                title = page.title()
                inputs = page.query_selector_all("input")
                names = []
                for i in inputs[:8]:
                    n = i.get_attribute("name"); t = i.get_attribute("type")
                    names.append(f"{n}:{t}")
                progress("info", f"page: title={title!r} inputs={len(inputs)} [{', '.join(names)}]")
            except Exception as exc:  # noqa: BLE001
                progress("info", f"diag err: {exc}")

        if _is_ms_callback(url, callback_path):
            captured["url"] = url
            break

        # M365 always pre-loads BOTH loginfmt and passwd inputs into the DOM
        # (passwd is hidden until email is submitted). Using count() alone
        # misidentifies the current step — always dispatch on URL/visibility.
        #
        # URL patterns:
        #   /<tenant>/oauth2/v2.0/authorize?...  → initial email step
        #   /<tenant>/login                       → password step (after email submit)
        #   /common/SAS/BeginAuth                 → MFA/KMSI
        is_password_page = (
            password_filled  # already advanced
            or "/login" in url and "oauth2/v2.0/authorize" not in url
        )

        # Password step — only when URL says we're past email, OR when the
        # visible passwd input actually exists (login_hint fast-path).
        if not password_filled:
            try:
                pw = page.locator("input[name='passwd'][type='password']:visible, input#i0118:visible").first
                pw_visible = pw.count() > 0 and pw.is_visible(timeout=500)
            except Exception:  # noqa: BLE001
                pw_visible = False

            if is_password_page or pw_visible:
                try:
                    pw = page.locator("input[name='passwd'][type='password'], input#i0118").first
                    pw.wait_for(state="visible", timeout=8000)
                    progress("step", "M365: password input visible → filling")
                    pw.fill(password, timeout=5000)
                    page.wait_for_timeout(300)
                    signin_btn = page.locator(
                        "input[type='submit']#idSIButton9, "
                        "button:has-text('Sign in'), input[value='Sign in']"
                    ).first
                    signin_btn.click(timeout=5000, force=True)
                    password_filled = True
                    email_filled = True
                    page.wait_for_timeout(3500)
                    continue
                except Exception as exc:  # noqa: BLE001
                    progress("warn", f"M365 password step: {str(exc)[:150]}")

        # Email step — URL still on /authorize, passwd not yet visible.
        if not email_filled:
            try:
                ei = page.locator("input[name='loginfmt']:visible, input#i0116:visible").first
                if ei.count() > 0 and ei.is_visible(timeout=1500):
                    progress("step", f"M365: filling email → {email}")
                    ei.fill(email, timeout=5000)
                    page.wait_for_timeout(300)
                    nxt = page.locator(
                        "input[type='submit']#idSIButton9, "
                        "button:has-text('Next'), input[value='Next']"
                    ).first
                    nxt.click(timeout=5000, force=True)
                    email_filled = True
                    page.wait_for_timeout(2500)
                    continue
            except Exception as exc:  # noqa: BLE001
                progress("warn", f"M365 email step: {str(exc)[:150]}")

        # "Update your password" page — M365 forces password change (temporary
        # password expired). Auto-generate a compliant new password, fill it,
        # submit, and surface it via progress so the caller can record it.
        # Detected by the trio of inputs: currentpasswd/newpasswd/confirmnewpasswd.
        if password_filled and "login.microsoftonline.com" in url and not password_changed:
            try:
                has_change_pw = (
                    page.locator("input[name='currentpasswd']").count() > 0
                    and page.locator("input[name='newpasswd']").count() > 0
                )
            except Exception:  # noqa: BLE001
                has_change_pw = False
            if has_change_pw:
                new_pw = _generate_m365_password(email)
                # stash new_pw so the caller can surface it in the final result
                captured["new_password"] = new_pw
                captured["old_password"] = password
                progress("manual", f"⚠ M365 requires password change — NEW PASSWORD: {new_pw}")
                try:
                    page.locator("input[name='currentpasswd']").first.fill(password, timeout=5000)
                    page.locator("input[name='newpasswd']").first.fill(new_pw, timeout=5000)
                    page.locator("input[name='confirmnewpasswd']").first.fill(new_pw, timeout=5000)
                    page.wait_for_timeout(400)
                    submit = page.locator(
                        "input[type='submit']#idSIButton9, input[type='submit'][value='Sign in'], "
                        "input[type='submit'][value='Submit']"
                    ).first
                    submit.click(timeout=5000, force=True)
                    password_changed = True
                    # Update the "current" password in memory — subsequent
                    # form fields (KMSI) don't need it, but log it for reference.
                    progress("step", f"M365: submitted password change → new_pw={new_pw}")
                    page.wait_for_timeout(4500)
                    continue
                except Exception as exc:  # noqa: BLE001
                    raise LoginError(
                        f"M365 password change form fill failed: {exc}. new_pw would have been: {new_pw}"
                    ) from exc

        # KMSI ("Stay signed in?") — click No to keep session isolated
        if password_filled and not stay_signed_in_answered:
            try:
                no_btn = page.locator(
                    "input#idBtn_Back, button:has-text(\"No\"), input[value='No']"
                ).first
                if no_btn.is_visible(timeout=1500):
                    progress("step", "M365: answering KMSI (No)")
                    no_btn.click(timeout=4000)
                    stay_signed_in_answered = True
                    page.wait_for_timeout(2500)
                    continue
            except Exception:  # noqa: BLE001
                pass

        # Detect MFA / verification / error pages → extend deadline, let the
        # human do it manually.
        if password_filled and "login.microsoftonline.com" in url:
            try:
                page_text = (page.inner_text("body", timeout=1500) or "")[:400].lower()
            except Exception:  # noqa: BLE001
                page_text = ""
            manual_signals = (
                "verify your identity", "approve sign in", "text a code",
                "call me", "we sent a text", "use your authenticator",
                "additional information required", "confirm your identity",
                "your account or password is incorrect",
                "we couldn't find an account",
            )
            if any(s in page_text for s in manual_signals):
                if not manual_announced:
                    deadline = time.time() + MANUAL_DEADLINE
                    progress(
                        "manual",
                        f"⚠ M365 challenge/verification detected — 请手动完成 "
                        f"(page: {page_text[:120]})",
                    )
                    manual_announced = True
                time.sleep(2)
                continue

        time.sleep(1)


def _is_ms_callback(url: str, callback_path: str) -> bool:
    try:
        p = urlparse(url)
        return (
            p.hostname in ("localhost", "127.0.0.1")
            and p.path == callback_path
            and ("code=" in (p.query or "") or "error=" in (p.query or ""))
        )
    except Exception:  # noqa: BLE001
        return False


def capture_oauth_redirect(
    *,
    auth_url: str,
    callback_host_port: str,
    callback_path: str,        # e.g. "/oauth-callback"
    proxy: Optional[str],
    email: str,
    password: str,
    totp_secret: Optional[str],
    progress: ProgressCallback,
    post_capture: Optional[callable] = None,  # (page, captured_url) → bool: run inline before browser closes
    timeout: int,
    headless: bool = False,
    site: str = "google",      # "google" | "grok" | "kiro" — picks the right form selectors
    user_data_dir: Optional[str] = None,  # persistent Firefox profile — cures Google SMS-on-every-login by keeping device fingerprint
    callback_getter: Optional[callable] = None,  # returns Optional[str] — polled each state-machine tick; when caller runs a real loopback HTTP server this is where the code lands
) -> dict:
    """Drive an OAuth login (Google / x.ai / kiro M365), intercept loopback redirect,
    return ``{"url": <callback_url>, "kiro_leg2": {...}}``.

    ``kiro_leg2`` only present when ``site='kiro'`` AND the portal actually
    dispatched external_idp (M365) — carries the leg-2 PKCE / token endpoint
    context needed by ``kiro.run()`` for the token exchange.

    For ``site='google'``: Google sign-in state machine
    (account chooser / email / password / TOTP / consent / firstparty nativeapp).

    For ``site='grok'``: x.ai sign-in
    (email + password + Cloudflare Turnstile + consent).

    For ``site='kiro'``: portal redirect capture — leg-1 external_idp
    descriptor is transparently converted to an M365 authorize URL by the
    route handler, then the M365 state machine drives sign-in.
    """
    Camoufox = _import_camoufox()
    pyotp = _import_pyotp() if totp_secret else None
    pw_proxy = _proxy_for_camoufox(proxy)
    exit_ip = _resolve_exit_ip(pw_proxy)
    if exit_ip:
        progress("info", f"upstream exit IP: {exit_ip}")

    captured: dict[str, str] = {}

    def _is_real_callback(u: str) -> bool:
        try:
            p = urlparse(u)
            return (
                p.hostname in ("localhost", "127.0.0.1")
                and p.path == callback_path
                and "code=" in (p.query or "")
            )
        except Exception:  # noqa: BLE001
            return False

    if user_data_dir:
        import os as _os
        _os.makedirs(user_data_dir, exist_ok=True)
        progress("info", f"camoufox launching persistent (proxy={pw_proxy['server'] if pw_proxy else 'direct'}, profile={user_data_dir})")
    else:
        progress("info", f"camoufox launching (proxy={pw_proxy['server'] if pw_proxy else 'direct'})")

    camoufox_kwargs = dict(
        headless=headless,
        proxy=pw_proxy,
        humanize=False,  # slows form fills without adding realism vs residential proxy TLS
        i_know_what_im_doing=True,
        geoip=True if pw_proxy else False,
    )
    if user_data_dir:
        camoufox_kwargs["persistent_context"] = True
        camoufox_kwargs["user_data_dir"] = user_data_dir

    with Camoufox(**camoufox_kwargs) as browser_or_ctx:
        # Persistent-context mode returns a BrowserContext directly; non-
        # persistent returns a Browser and we create a fresh context.
        if user_data_dir:
            context = browser_or_ctx
            page = context.pages[0] if context.pages else context.new_page()
        else:
            # See M365 helper: skip Playwright viewport auto-set (isMobile
            # field breaks Camoufox's Firefox driver) — apply after page.
            context = browser_or_ctx.new_context(no_viewport=True)
            page = context.new_page()
            try:
                page.set_viewport_size({"width": 1280, "height": 860})
            except Exception:  # noqa: BLE001
                pass

        # Intercept the loopback callback BEFORE any navigation so the browser
        # can't actually try to hit localhost:port (cli-proxy-api-plus may
        # have it bound).
        def _on_route(route):
            try:
                u = route.request.url

                # kiro leg-1: portal 302s to loopback with descriptor
                # (login_option=external_idp / issuer_url / client_id, no
                # code). We OIDC-discover the IdP, build M365 authorize URL,
                # and 302 the browser onward.
                if site == "kiro" and callback_host_port in u:
                    import urllib.parse as _up
                    q = _up.parse_qs(_up.urlparse(u).query)
                    is_desc = (
                        q.get("login_option", [""])[0].strip().lower() == "external_idp"
                        or bool(q.get("issuer_url", [""])[0].strip())
                    )
                    has_code = "code=" in u
                    if is_desc and not has_code and "kiro_leg2" not in captured:
                        from . import kiro as _kh
                        issuer_url = q.get("issuer_url", [""])[0].strip()
                        client_id = q.get("client_id", [""])[0].strip()
                        scopes = q.get("scopes", [""])[0].strip()
                        login_hint = q.get("login_hint", [email])[0].strip() or email
                        try:
                            auth_endpoint, token_endpoint = _kh._oidc_discover(issuer_url, None)
                        except Exception as exc:  # noqa: BLE001
                            captured["url"] = f"error://oidc_discover:{exc}"
                            try:
                                route.fulfill(status=500, body=f"OIDC err: {exc}")
                            except Exception:  # noqa: BLE001
                                pass
                            return
                        verifier = _kh._random_url_safe(96)
                        state2 = _kh._random_url_safe(32)
                        redirect_uri = f"http://{callback_host_port}{callback_path}"
                        challenge = _kh._pkce_challenge(verifier)
                        captured["kiro_leg2"] = {
                            "state": state2, "verifier": verifier,
                            "token_endpoint": token_endpoint,
                            "issuer_url": issuer_url, "client_id": client_id,
                            "scopes": scopes, "redirect_uri": redirect_uri,
                        }
                        m365_url = _kh._external_idp_authorize_url(
                            auth_endpoint, client_id, redirect_uri, scopes,
                            challenge, state2, login_hint,
                        )
                        try:
                            route.fulfill(
                                status=302,
                                headers={"Location": m365_url},
                                body="",
                            )
                            return
                        except Exception:  # noqa: BLE001
                            pass

                if _is_real_callback(u):
                    if "url" not in captured:
                        captured["url"] = u
                        progress("step", "captured OAuth callback")
                    route.fulfill(
                        status=200,
                        content_type="text/html; charset=utf-8",
                        body="<!doctype html><meta charset=utf-8><h2>OK — return to the terminal.</h2>",
                    )
                    return
            except Exception:  # noqa: BLE001
                pass
            try:
                route.continue_()
            except Exception:  # noqa: BLE001
                pass

        # Only intercept requests that hit the loopback callback host — Firefox
        # (Camoufox) aborts top-level navigations that were touched by
        # page.route even with continue_() (NS_ERROR_ABORT), and Google's
        # anti-bot flags the request pattern. Restricting to the loopback URL
        # keeps every other request completely unmodified.
        page.route(f"http://{callback_host_port}/**", _on_route)
        page.route(f"http://{callback_host_port}", _on_route)

        # Also watch navigation — sometimes Camoufox's request route fires
        # after the page has already navigated.
        def _on_framenav(frame):
            try:
                if frame == page.main_frame and _is_real_callback(frame.url):
                    if "url" not in captured:
                        captured["url"] = frame.url
                        progress("step", "captured OAuth callback (framenav)")
            except Exception:  # noqa: BLE001
                pass

        page.on("framenavigated", _on_framenav)

        progress("step", "opening OAuth start URL …")
        # Bring the Camoufox window to front so macOS doesn't hide it behind
        # the (usually many) other open apps — user needs to see the QR later.
        try:
            page.bring_to_front()
        except Exception:  # noqa: BLE001
            pass
        try:
            # domcontentloaded is fine — the form inputs are in the initial
            # HTML. Extra JS load happens in the background; state machine
            # polls every second and fills as fields appear. Longer timeout
            # (60s) is for slow socks5 residential proxies.
            page.goto(auth_url, wait_until="domcontentloaded", timeout=60_000)
        except Exception as exc:  # noqa: BLE001
            progress("warn", f"page.goto: {exc}")

        # --- site dispatch -----------------------------------------------
        if site == "grok":
            _run_grok_state_machine(page, email, password, progress, captured, callback_path, timeout, auth_url=auth_url)
        elif site == "kiro":
            _run_kiro_state_machine(page, email, password, progress, captured, callback_path, timeout)
        else:
            _run_google_state_machine(page, email, password, totp_secret, progress, captured, callback_path, timeout, pyotp, callback_getter)

        # Past the state-machine deadline — extend polling for the route
        # handler to fire even if the loop exited. Also poll the external
        # loopback listener if the caller supplied one.
        extra_deadline = time.time() + 60
        while "url" not in captured and time.time() < extra_deadline:
            if callback_getter is not None:
                got = callback_getter()
                if got:
                    captured["url"] = got
                    progress("step", "captured OAuth callback (loopback listener)")
                    break
            try:
                u = page.url
                if _is_real_callback(u):
                    captured["url"] = u
                    break
            except Exception:  # noqa: BLE001
                break
            time.sleep(1)

        # Post-capture inline hook — runs while the browser + session are
        # still alive, so the caller can drive follow-up flows (e.g. QR-scan
        # activation) in the SAME Google-authenticated session without a
        # second sign-in. Return True = success; False → captured["_post_ok"]
        # is set so caller can decide to abort.
        if "url" in captured and post_capture is not None:
            try:
                ok = post_capture(page, captured["url"])
                captured["_post_ok"] = bool(ok)
            except Exception as exc:  # noqa: BLE001
                progress("warn", f"post-capture hook errored: {exc}")
                captured["_post_ok"] = False

        try:
            context.close()
        except Exception:  # noqa: BLE001
            pass

    if "url" not in captured:
        raise LoginError("OAuth callback never captured (timeout or user closed browser)")
    out: dict = {"url": captured["url"]}
    if "kiro_leg2" in captured:
        out["kiro_leg2"] = captured["kiro_leg2"]
    if "_post_ok" in captured:
        out["post_ok"] = captured["_post_ok"]
    return out


# ---- Google state machine ---------------------------------------------------

def _run_google_state_machine(page, email, password, totp_secret, progress, captured, callback_path, timeout, pyotp, callback_getter=None):
    """Google sign-in: account chooser / email / password / TOTP / consent /
    firstparty/nativeapp. Vendored from auto_oauth_only.py."""
    AUTO_DEADLINE = 120  # a bit more slack for socks5 residential
    MANUAL_DEADLINE = 600
    deadline = time.time() + AUTO_DEADLINE
    email_submitted = False
    password_submitted = False
    totp_submitted = False
    last_url = ""
    last_challenge = ""
    last_totp_code = ""
    last_totp_at = 0.0

    def _has_visible_captcha() -> bool:
        try:
            n = page.locator(
                "input[name='ca']:visible, input[name='Captcha']:visible, "
                "input[name='captcha']:visible, "
                "img[src*='Captcha']:visible, img[id*='captchaimg']:visible, "
                "iframe[src*='recaptcha/api2/bframe']:visible, "
                "iframe[title*='recaptcha challenge']:visible, "
                "iframe[title*='验证']:visible, div.g-recaptcha:visible"
            ).count()
            return n > 0
        except Exception:  # noqa: BLE001
            return False

    def _detect_challenge(u: str) -> Optional[str]:
        if "/v3/signin/challenge/iap/qrcode" in u: return "iap_qrcode"
        if "/uplevelingstep/" in u: return "uplevelingstep"
        if "/v3/signin/challenge/recaptcha" in u: return "recaptcha"
        if "/v3/signin/challenge/dp" in u: return "device_prompt"
        return None

    def _detect_terminal_reject(u: str) -> Optional[str]:
        """Terminal states we must NOT retry-poll — the account is dead or
        Google refused the sign-in outright. Return a short reason string,
        None if we should keep polling."""
        # /signin/rejected — account disabled / suspended / policy block
        if "/v3/signin/rejected" in u or "/signin/rejected" in u:
            return "account_rejected"
        # /disabled — account taken down
        if "/signin/disabled/explanation" in u or "/signin/v2/disabled" in u:
            return "account_disabled"
        # /identifier/rejected — email doesn't exist / removed
        if "/v3/signin/identifier/rejected" in u:
            return "identifier_rejected"
        # /_/lookup/accountlookup with denial — hijacked / policy locked
        if "signin/v2/challenge/az" in u:  # unusual sign-in blocked
            return "unusual_signin_blocked"
        return None

    while time.time() < deadline:
        if "url" in captured:
            break
        # Poll external loopback listener — Google 302 to :51121 lands there
        # even when Camoufox page.route misses (Firefox aborts top nav
        # touched by route; a real HTTP server is the reliable capture path).
        if callback_getter is not None:
            got = callback_getter()
            if got:
                captured["url"] = got
                progress("step", "captured OAuth callback (loopback listener)")
                break
        try:
            url = page.url
        except Exception:  # noqa: BLE001
            break

        if url != last_url:
            progress("info", f"url={url[:100]}")
            last_url = url

        # Terminal reject — bail immediately, don't burn 90s of state machine.
        reject = _detect_terminal_reject(url)
        if reject:
            raise LoginError(
                f"Google refused sign-in ({reject}) — account likely disabled/suspended. "
                f"url={url[:200]}"
            )

        ch = _detect_challenge(url)
        if ch:
            if ch != last_challenge:
                deadline = time.time() + MANUAL_DEADLINE
                progress("manual", f"⚠ 挑战触发: {ch} — 浏览器里手动完成 (最多 {MANUAL_DEADLINE//60}min)")
                last_challenge = ch
            time.sleep(2)
            continue
        else:
            if last_challenge in ("iap_qrcode", "uplevelingstep", "recaptcha", "device_prompt"):
                last_challenge = ""

        if any(s in url for s in ("auth/callback", "auth-success", "auth_success_gemini", "chrome-error", "chromewebdata")):
            if "url" not in captured and callback_path in url and "code=" in url:
                captured["url"] = url
            break

        # email page
        if "/v3/signin/identifier" in url or "/signin/v2/identifier" in url:
            if _has_visible_captcha():
                if last_challenge != "captcha_on_email":
                    deadline = time.time() + MANUAL_DEADLINE
                    progress("manual", "⚠ email 页验证码 — 请手动完成")
                    last_challenge = "captcha_on_email"
                time.sleep(2); continue
            if last_challenge == "captcha_on_email":
                last_challenge = ""
            if not email_submitted:
                progress("step", f"filling email: {email}")
                try:
                    ei = page.locator("input[type='email'], input[name='identifier'], #identifierId").first
                    ei.wait_for(state="visible", timeout=4000)
                    if not ei.input_value():
                        ei.fill(email)
                        page.wait_for_timeout(400)
                    ei.press("Enter")
                    email_submitted = True
                    page.wait_for_timeout(2500)
                except Exception:  # noqa: BLE001
                    pass
            else:
                time.sleep(2)
            continue

        # account chooser
        if "/v3/signin/accountchooser" in url:
            # Google sometimes stays on the accountchooser URL but shows an
            # "Account disabled / locked" message instead of a clickable
            # account tile. Detect the disabled state by body text or page
            # title BEFORE trying to click, so we fail fast.
            try:
                title_text = (page.title() or "").lower()
                body_text = (page.inner_text("body", timeout=2000) or "").lower()
            except Exception:  # noqa: BLE001
                title_text = ""
                body_text = ""
            disabled_signals = (
                "account disabled", "account has been disabled",
                "locked it to protect", "account has been locked",
                "your account was found to be violating",
                "we noticed unusual activity",
            )
            if any(sig in title_text or sig in body_text for sig in disabled_signals):
                # find the most informative phrase to surface
                snippet = ""
                for sig in disabled_signals:
                    if sig in body_text:
                        idx = body_text.find(sig)
                        snippet = body_text[max(0, idx-20):idx+220].strip().replace("\n", " ")
                        break
                raise LoginError(
                    f"Google account disabled/locked (accountchooser). "
                    f"title={title_text[:80]!r} msg={snippet[:200]!r}"
                )

            progress("step", "account chooser — clicking saved account")
            try:
                link = page.locator(f"a:has-text('{email}'), li:has-text('{email}')").first
                link.wait_for(state="visible", timeout=5000)
                link.click()
                page.wait_for_timeout(2500)
            except Exception:  # noqa: BLE001
                progress("warn", "account chooser: account link not found")
            continue

        # password page
        if "challenge/pwd" in url or "/signin/pwd" in url:
            if _has_visible_captcha():
                if last_challenge != "captcha_on_pwd":
                    deadline = time.time() + MANUAL_DEADLINE
                    progress("manual", "⚠ 密码页验证码 — 请手动完成")
                    last_challenge = "captcha_on_pwd"
                time.sleep(2); continue
            if last_challenge == "captcha_on_pwd":
                last_challenge = ""
            if not password_submitted:
                progress("step", "filling password")
                try:
                    pi = page.locator("input[type='password'], input[name='Passwd']").first
                    pi.wait_for(state="visible", timeout=4000)
                    if not pi.input_value():
                        pi.fill(password)
                        page.wait_for_timeout(400)
                    pi.press("Enter")
                    password_submitted = True
                    page.wait_for_timeout(2500)
                except Exception:  # noqa: BLE001
                    pass
            else:
                time.sleep(2)
            continue

        # 2FA selection
        if "/v3/signin/challenge/selection" in url:
            progress("step", "2FA method picker — choosing Authenticator")
            try:
                btn = page.locator(
                    "li:has-text('Authenticator'), li:has-text('身份验证器'), "
                    "li:has-text('身份驗證器'), li:has-text('인증'), li:has-text('認証'), "
                    "[data-challengetype='6'], [data-challengetype='3']"
                ).first
                btn.wait_for(state="visible", timeout=5000)
                btn.click()
                page.wait_for_timeout(2500)
            except Exception:  # noqa: BLE001
                progress("warn", "Authenticator option not found")
            continue

        # TOTP — submit at most once per fresh code. Google throttles / locks
        # accounts if the same TOTP page keeps re-filling; only re-submit if
        # (a) the URL is still the TOTP challenge, AND (b) the pyotp code has
        # rotated to a new 30s window, AND (c) at least 20s since last try.
        if "challenge/totp" in url or "challenge/skotp" in url:
            if not totp_secret:
                raise LoginError("TOTP required but no totp_secret provided")
            code = pyotp.TOTP(totp_secret).now()
            now = time.time()
            should_submit = (
                not totp_submitted
                or (code != last_totp_code and (now - last_totp_at) > 20)
            )
            if not should_submit:
                time.sleep(2)
                continue
            progress("step", f"filling TOTP {code}")
            try:
                inp = page.locator(
                    "input[type='tel'], input[name='totpPin'], "
                    "input[autocomplete='one-time-code']"
                ).first
                inp.wait_for(state="visible", timeout=6000)
                inp.fill("")            # clear whatever's there first
                inp.fill(code)
                page.wait_for_timeout(500)
                inp.press("Enter")
                totp_submitted = True
                last_totp_code = code
                last_totp_at = now
                progress("step", f"TOTP submitted: {code}")
                page.wait_for_timeout(4000)
            except Exception as exc:  # noqa: BLE001
                progress("warn", f"TOTP fill failed: {str(exc)[:120]}")
            continue

        # consent
        if "/signin/oauth/consent" in url or "/oauth/firstparty/nativeapp" in url:
            progress("step", "consent page — clicking approve")
            try:
                btn = page.locator(
                    "#submit_approve_access button, div#submit_approve_access button, "
                    "button:has-text('Allow'), button:has-text('允许'), "
                    "button:has-text('Continue'), button:has-text('继续'), "
                    "button:has-text('登录'), button:has-text('登錄'), "
                    "button:has-text('로그인'), button:has-text('동의'), button:has-text('同意')"
                ).first
                btn.wait_for(state="visible", timeout=8000)
                btn.click()
                page.wait_for_timeout(3000)
            except Exception:  # noqa: BLE001
                progress("warn", "consent button not found")
            continue

        time.sleep(2)


# ---- Grok (x.ai) state machine ----------------------------------------------

def _run_grok_state_machine(page, email, password, progress, captured, callback_path, timeout, auth_url=None):
    """x.ai sign-in:
      1. /sign-in landing page → click 'Login with email' (testid='continue-with-email')
      2. /sign-in?email=true → fill email (testid='email') → click sign-in-submit
      3. Same URL, password field appears → fill (testid='password')
         → BEFORE submit: detect Turnstile sitekey + solve via YesCaptcha
           + inject token (if a sitekey is rendered)
         → click sign-in-submit
      4. → /oauth2/consent → click 'Allow' button
      5. → 302 to http://127.0.0.1:56121/callback?code=...&state=... (intercepted)

    Cloudflare Turnstile: when the widget is rendered (with a visible iframe
    or a div.cf-turnstile that has data-sitekey), we send the sitekey + page
    URL to YesCaptcha and inject the returned token before clicking Login.
    If sitekey can't be found we proceed without — Cloudflare's invisible
    mode often passes without explicit interaction.
    """
    from . import _turnstile

    AUTO_DEADLINE = 180  # turnstile solve can take 30-60s
    MANUAL_DEADLINE = 600
    deadline = time.time() + AUTO_DEADLINE

    email_filled = False
    password_filled = False
    landing_clicked = False
    last_url = ""
    turnstile_announced = False

    # State accumulated across loop iterations (CF handling needs persistence)
    _grok_state = {
        "cf_passed": False,
        "login_clicked": False,
        "cf_wait_start": None,
    }

    def _has_visible_turnstile() -> bool:
        try:
            n = page.locator(
                "iframe[src*='challenges.cloudflare.com/turnstile']:visible, "
                "iframe[title*='challenge']:visible, "
                "div.cf-turnstile:visible"
            ).count()
            return n > 0
        except Exception:  # noqa: BLE001
            return False

    # Dismiss the cookies dialog once if visible (it can intercept clicks).
    try:
        cookie_close = page.get_by_role("button", name=re.compile(r"^(Reject All|Close|关闭)$", re.I))
        if cookie_close.count() > 0:
            cookie_close.first.click(timeout=2000)
            progress("step", "dismissed cookie dialog")
    except Exception:  # noqa: BLE001
        pass

    while time.time() < deadline:
        if "url" in captured:
            break
        try:
            url = page.url
        except Exception:  # noqa: BLE001
            break

        if url != last_url:
            progress("info", f"url={url[:100]}")
            last_url = url

        # Already at the callback?
        if callback_path in url and "code=" in url:
            captured["url"] = url
            break

        # --- Landing /sign-in (4 buttons: 𝕏 / email / Google / Apple) ----
        if "/sign-in" in url and "email=true" not in url:
            if not landing_clicked:
                progress("step", "landing — clicking 'Login with email'")
                try:
                    btn = page.get_by_test_id("continue-with-email")
                    btn.wait_for(state="visible", timeout=8000)
                    btn.click()
                    landing_clicked = True
                    page.wait_for_timeout(1500)
                except Exception as exc:  # noqa: BLE001
                    progress("warn", f"continue-with-email click failed: {exc}")
            else:
                time.sleep(1)
            continue

        # --- Email + password form (?email=true) -------------------------
        if "/sign-in" in url and "email=true" in url:
            if _has_visible_turnstile() and not turnstile_announced:
                deadline = time.time() + MANUAL_DEADLINE
                progress("manual",
                         "⚠ Cloudflare Turnstile 可见挑战 — 浏览器里点 checkbox / 图片")
                turnstile_announced = True
                time.sleep(2); continue

            if not email_filled:
                progress("step", f"filling email: {email}")
                try:
                    ei = page.get_by_test_id("email")
                    ei.wait_for(state="visible", timeout=8000)
                    ei.fill(email)
                    page.wait_for_timeout(300)
                    # Click Next
                    submit = page.get_by_test_id("sign-in-submit")
                    submit.wait_for(state="visible", timeout=5000)
                    submit.click()
                    email_filled = True
                    page.wait_for_timeout(1500)
                except Exception as exc:  # noqa: BLE001
                    progress("warn", f"email step failed: {exc}")
                continue

            if not password_filled:
                progress("step", "filling password (real keystrokes)")
                try:
                    pi = page.get_by_test_id("password")
                    pi.wait_for(state="visible", timeout=8000)
                    pi.click()
                    pi.press_sequentially(password, delay=80)
                    page.wait_for_timeout(800)
                    password_filled = True
                    deadline = time.time() + MANUAL_DEADLINE
                    continue
                except Exception as exc:  # noqa: BLE001
                    progress("warn", f"password fill failed: {exc}")
                    continue

            # Both fields filled. The CF widget shows up between password
            # and Login button. The page renders 2 iframes but neither has
            # 'challenges.cloudflare.com' in src — turnstile likely embeds
            # via a wrapper. We fall back to: find the visible widget
            # element (a wrapper with class containing 'turnstile' or text
            # 'Verify you are human'), and mouse-click its left edge.
            if not _grok_state["cf_passed"]:
                # Find ALL iframes (CF nests its iframe behind a wrapper div).
                # Also look in the cf-turnstile container and the cf-chl-widget.
                try:
                    n_iframes = page.locator("iframe").count()
                    cf_count = page.locator(
                        'iframe[src*="challenges.cloudflare.com"]'
                    ).count()
                    if not _grok_state.get("cf_logged"):
                        progress("info", f"iframes on page: total={n_iframes} cf={cf_count}")
                        _grok_state["cf_logged"] = True
                except Exception:  # noqa: BLE001
                    cf_count = 0

                if not _grok_state.get("cf_clicked"):
                    # Strategy: find any iframe whose bbox is below the
                    # password input + above the Login button. That's the
                    # CF widget regardless of its src. Click left ~30px.
                    cf_box = None
                    try:
                        # 1) Try: any iframe (cf may use neutral src)
                        iframes = page.locator("iframe").all()
                        for ifr in iframes:
                            try:
                                b = ifr.bounding_box()
                                if not b or b["width"] < 100 or b["height"] < 30:
                                    continue
                                # Reasonable size for cf widget (~300x65)
                                if 200 < b["width"] < 500 and 40 < b["height"] < 100:
                                    cf_box = b
                                    progress("info", f"candidate iframe box={b}")
                                    break
                            except Exception:  # noqa: BLE001
                                continue
                        # 2) Fallback: find element by visible text
                        if not cf_box:
                            try:
                                widget = page.get_by_text(
                                    "Verify you are human"
                                ).first
                                cf_box = widget.bounding_box()
                                progress("info", f"found by text box={cf_box}")
                            except Exception:  # noqa: BLE001
                                pass
                        # 3) Fallback: cf-turnstile class wrapper
                        if not cf_box:
                            try:
                                w = page.locator(
                                    ".cf-turnstile, div[class*='turnstile']"
                                ).first
                                cf_box = w.bounding_box()
                                progress("info", f"found by class box={cf_box}")
                            except Exception:  # noqa: BLE001
                                pass
                    except Exception as exc:  # noqa: BLE001
                        progress("warn", f"cf widget search err: {exc}")

                    if cf_box and cf_box["width"] > 0:
                        try:
                            # Checkbox sits at the left edge, vertically
                            # centered in the widget.
                            cx = cf_box["x"] + 30
                            cy = cf_box["y"] + cf_box["height"] / 2
                            page.mouse.move(cx - 80, cy + 30)
                            page.wait_for_timeout(250)
                            page.mouse.move(cx - 20, cy + 5)
                            page.wait_for_timeout(150)
                            page.mouse.move(cx, cy)
                            page.wait_for_timeout(200)
                            page.mouse.click(cx, cy)
                            progress("step", f"clicked cf checkbox @ ({cx:.0f},{cy:.0f})")
                            _grok_state["cf_clicked"] = True
                            page.wait_for_timeout(3000)
                        except Exception as exc:  # noqa: BLE001
                            progress("warn", f"cf click err: {exc}")
                    else:
                        # Not found yet; wait for it to render.
                        if not _grok_state.get("cf_search_logged"):
                            progress("info", "cf widget not located yet — waiting for render")
                            _grok_state["cf_search_logged"] = True

                # Poll: did cf token populate? (cf-turnstile-response input
                # gets a value when cf is happy)
                try:
                    tok = page.evaluate(
                        """() => {
                            const i = document.querySelector(
                                'input[name="cf-turnstile-response"]'
                            );
                            return i ? i.value : '';
                        }"""
                    )
                    if tok and len(tok) > 20:
                        _grok_state["cf_passed"] = True
                        progress("step", f"cf token populated len={len(tok)}")
                except Exception:  # noqa: BLE001
                    pass

                time.sleep(2)
                continue

            # CF passed — now click Login
            if not _grok_state["login_clicked"]:
                try:
                    submit = page.get_by_test_id("sign-in-submit")
                    submit.wait_for(state="visible", timeout=5000)
                    submit.click()
                    progress("step", "Login clicked (after cf passed)")
                    _grok_state["login_clicked"] = True
                    page.wait_for_timeout(3000)
                    continue
                except Exception as exc:  # noqa: BLE001
                    progress("warn", f"Login click failed: {exc}")
                    continue

            # All done with sign-in flow — wait for consent / callback
            time.sleep(2)
            continue

        # --- Consent ----------------------------------------------------
        if "/oauth2/consent" in url:
            progress("step", "consent page — clicking Allow")
            try:
                btn = page.get_by_role("button", name=re.compile(r"^(Allow|Authorize|Approve|允许)$"))
                btn.wait_for(state="visible", timeout=8000)
                btn.click()
                page.wait_for_timeout(3000)
            except Exception as exc:  # noqa: BLE001
                progress("warn", f"consent Allow click failed: {exc}")
            continue

        # --- Account page: signed in but OAuth flow lost ----
        # Re-navigate to the authorize URL so consent kicks in.
        if "/account" in url:
            if auth_url:
                try:
                    progress("step", "logged in — re-navigating to authorize URL for OAuth")
                    page.goto(auth_url, wait_until="domcontentloaded", timeout=20000)
                    page.wait_for_timeout(2000)
                except Exception as exc:  # noqa: BLE001
                    progress("warn", f"re-nav to authorize failed: {exc}")
            else:
                progress("warn", "logged in but auth_url unknown — cannot resume OAuth")
            time.sleep(2)
            continue

        time.sleep(2)


def _run_kiro_state_machine(page, email, password, progress, captured, callback_path, timeout):
    """Kiro M365 SSO — full autopilot:
      1. https://app.kiro.dev/signin — portal shows 4 choices (Google / GitHub
         / Builder ID / Your organization). Click "Your organization Sign in".
      2. /organization page — fill email into input#idp-email-input, wait for
         Continue button to become enabled (portal AJAX-resolves domain), click.
      3. Portal 302s to loopback :3128/signin/callback?login_option=external_idp
         &issuer_url=…&client_id=…. Our route handler intercepts, OIDC-discovers
         the IdP, mints leg-2 PKCE, and 302s to login.microsoftonline.com.
      4. M365 email step (input[name='loginfmt']) → auto-filled → Next.
         (Some tenants auto-skip because portal passed login_hint.)
      5. M365 password step (input[name='passwd']) → Sign in.
      6. "Stay signed in?" (KMSI) prompt → click "No" (input#idBtn_Back).
      7. M365 302 → http://localhost:3128/oauth/callback?code=&state=
         (intercepted by page.route → captured).
    """
    AUTO_DEADLINE = 180
    MANUAL_DEADLINE = 600
    deadline = time.time() + AUTO_DEADLINE
    portal_org_clicked = False
    portal_email_filled = False
    portal_continue_clicked = False
    email_filled = False
    password_filled = False
    stay_signed_in_answered = False
    last_url = ""
    manual_announced = False

    while time.time() < deadline:
        if "url" in captured:
            break
        try:
            url = page.url
        except Exception:  # noqa: BLE001
            break

        if url != last_url:
            progress("info", f"url={url[:100]}")
            last_url = url

        # Callback captured?
        if callback_path in url and "code=" in url:
            captured["url"] = url
            break

        # Only relevant while we are still on the kiro portal SPA. Note the
        # portal is a client-router — URL stays at /signin even after step-1
        # click. So we branch on DOM state, not URL segments.
        on_portal = "app.kiro.dev" in url

        # ---- kiro portal cookie banner (only shows when un-consented) ----
        if on_portal and not portal_continue_clicked:
            try:
                dec = page.locator("button[data-id='awsccc-cb-btn-decline']").first
                if dec.count() > 0 and dec.is_visible(timeout=1000):
                    progress("step", "dismissing kiro cookie banner (Decline)")
                    dec.click()
                    page.wait_for_timeout(800)
            except Exception:  # noqa: BLE001
                pass

        # ---- kiro portal step 1: "Your organization Sign in" chooser ----
        # Portal at app.kiro.dev/signin shows 4 buttons (Google / GitHub /
        # Builder ID / Your organization). Click the org one to reach the
        # M365-style email prompt. The button's accessible name isn't always
        # tagged visible=true, but Playwright can still click it.
        if on_portal and not portal_org_clicked:
            try:
                # Check if we're already past step 1 (email input already shown)
                if page.locator("input#idp-email-input").count() > 0:
                    portal_org_clicked = True
                else:
                    org_btn = page.get_by_role(
                        "button", name="Your organization Sign in", exact=True
                    )
                    if org_btn.count() > 0:
                        progress("step", "clicking kiro portal 'Your organization Sign in'")
                        org_btn.first.click(force=True, timeout=8000)
                        portal_org_clicked = True
                        page.wait_for_timeout(1500)
                        continue
            except Exception as exc:  # noqa: BLE001
                progress("warn", f"kiro portal org-chooser click failed: {exc}")
                time.sleep(1)

        # ---- kiro portal step 2: fill email + Continue ----
        if on_portal and portal_org_clicked and not portal_continue_clicked:
            try:
                if not portal_email_filled:
                    ei = page.locator("input#idp-email-input").first
                    ei.wait_for(state="visible", timeout=10000)
                    progress("step", f"filling kiro portal org email: {email}")
                    ei.click()
                    ei.press_sequentially(email, delay=60)
                    portal_email_filled = True
                    page.wait_for_timeout(1500)  # let portal resolve domain → enable Continue
                # Continue: use exact=True to avoid matching cookie banner's
                # "Decline - Continue without…" button.
                cont = page.get_by_role("button", name="Continue", exact=True)
                cont.first.wait_for(state="visible", timeout=8000)
                enabled_deadline = time.time() + 15
                while time.time() < enabled_deadline:
                    try:
                        if cont.first.is_enabled(timeout=1000):
                            break
                    except Exception:  # noqa: BLE001
                        pass
                    time.sleep(0.5)
                progress("step", "clicking kiro portal Continue")
                cont.first.click(force=True, timeout=8000)
                portal_continue_clicked = True
                page.wait_for_timeout(2500)  # let 302 → route handler → M365 fly
                continue
            except Exception as exc:  # noqa: BLE001
                progress("warn", f"kiro portal email/Continue step failed: {exc}")
                time.sleep(2)

        # M365 email step
        if "login.microsoftonline.com" in url and ("loginfmt" in url.lower()
                                                    or not email_filled):
            if not email_filled:
                try:
                    ei = page.locator(
                        "input[type='email'], input[name='loginfmt'], "
                        "input#i0116"
                    ).first
                    ei.wait_for(state="visible", timeout=15000)
                    progress("step", f"filling M365 email: {email}")
                    ei.click()
                    ei.press_sequentially(email, delay=60)
                    page.wait_for_timeout(400)
                    # Click Next
                    nxt = page.locator(
                        "input[type='submit']#idSIButton9, "
                        "button:has-text('Next'), input[value='Next']"
                    ).first
                    nxt.wait_for(state="visible", timeout=5000)
                    nxt.click()
                    email_filled = True
                    page.wait_for_timeout(2500)
                    continue
                except Exception as exc:  # noqa: BLE001
                    progress("warn", f"M365 email step failed: {exc}")

        # M365 password step
        if "login.microsoftonline.com" in url and email_filled and not password_filled:
            try:
                pi = page.locator(
                    "input[type='password'], input[name='passwd'], "
                    "input#i0118"
                ).first
                pi.wait_for(state="visible", timeout=15000)
                progress("step", "filling M365 password")
                pi.click()
                pi.press_sequentially(password, delay=60)
                page.wait_for_timeout(400)
                signin_btn = page.locator(
                    "input[type='submit']#idSIButton9, "
                    "button:has-text('Sign in'), input[value='Sign in']"
                ).first
                signin_btn.wait_for(state="visible", timeout=5000)
                signin_btn.click()
                password_filled = True
                page.wait_for_timeout(3500)
                continue
            except Exception as exc:  # noqa: BLE001
                progress("warn", f"M365 password step failed: {exc}")

        # "Stay signed in?" prompt (KMSI)
        if "login.microsoftonline.com" in url and password_filled and not stay_signed_in_answered:
            try:
                # Click "No" — safer for isolated login sessions
                no_btn = page.locator(
                    "input#idBtn_Back, button:has-text('No'), "
                    "input[value='No']"
                ).first
                if no_btn.count() > 0 and no_btn.is_visible(timeout=2000):
                    progress("step", "answering 'Stay signed in?': No")
                    no_btn.click()
                    stay_signed_in_answered = True
                    page.wait_for_timeout(3000)
                    continue
            except Exception:  # noqa: BLE001
                pass

        # Any "Verify your identity" / MFA / device page — announce once and wait
        if "login.microsoftonline.com" in url and password_filled:
            try:
                page_text = (page.inner_text("body", timeout=1500) or "")[:400].lower()
            except Exception:  # noqa: BLE001
                page_text = ""
            manual_signals = (
                "verify your identity", "approve sign in", "text a code",
                "call me", "we sent a text", "use your authenticator",
                "additional information required", "confirm your identity",
            )
            if any(s in page_text for s in manual_signals):
                if not manual_announced:
                    deadline = time.time() + MANUAL_DEADLINE
                    progress("manual",
                             f"⚠ M365 MFA/verification page — 请在浏览器手动完成 "
                             f"(page: {page_text[:120]})")
                    manual_announced = True
                time.sleep(2)
                continue

        # App consent / permission page (kiro asks for scopes)
        if "login.microsoftonline.com" in url and ("consent" in url.lower()
                                                    or "kmsi" in url.lower()):
            try:
                accept = page.locator(
                    "input#idBtn_Accept, input[value='Accept'], "
                    "button:has-text('Accept'), input#idSIButton9"
                ).first
                if accept.count() > 0 and accept.is_visible(timeout=2000):
                    progress("step", "clicking Accept on M365 consent")
                    accept.click()
                    page.wait_for_timeout(3000)
                    continue
            except Exception:  # noqa: BLE001
                pass

        time.sleep(2)


def activate_in_page(page, access_token: str, project_id: str, progress: ProgressCallback, timeout: int = 600) -> bool:
    """In-page activation: probe cloudcode-pa via the *current* page's request
    context, and if VALIDATION_REQUIRED is returned, navigate the same page to
    the validation_url and wait for the success redirect. Runs inside an
    already-open, already-logged-in browser session (see
    ``capture_oauth_redirect(post_capture=...)``), so Google skips re-auth.

    Returns True if activated / not required; False on timeout or block.
    Best-effort; never raises.
    """
    try:
        progress("info", "probing cloudcode-pa for VALIDATION_REQUIRED …")
        resp = page.context.request.post(
            "https://cloudcode-pa.googleapis.com/v1internal:generateContent",
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json",
            },
            data={
                "model": "models/gemini-2.5-flash",
                "project": project_id,
                "request": {"contents": [{"role": "user", "parts": [{"text": "ping"}]}]},
            },
            timeout=30_000,
        )
        body = resp.text()[:2000]
        progress("info", f"probe status={resp.status} body[:120]={body[:120]}")

        if resp.status == 200 and "VALIDATION_REQUIRED" not in body:
            progress("done", "no activation needed")
            return True

        m = re.search(r'"validation_url":\s*"([^"]+)"', body)
        if not m:
            progress("warn", "403 but no validation_url — manual activation required")
            return False
        validation_url = m.group(1).replace("\\u0026", "&")
        progress("manual", f"⚠ 需要扫码激活 — 在浏览器窗口用手机 Google App 扫码 ({validation_url[:80]}…)")

        # Same tab navigates onward. Because we already logged in as this
        # user in this session, the QR page shows immediately (no re-login).
        try:
            page.goto(validation_url, wait_until="domcontentloaded", timeout=30_000)
        except Exception as exc:  # noqa: BLE001
            progress("warn", f"goto validation_url: {exc}")

        # Bring window forward so user actually sees the QR (macOS may hide it
        # behind other apps). page.bring_to_front is the Playwright way.
        try:
            page.bring_to_front()
        except Exception:  # noqa: BLE001
            pass

        deadline = time.time() + timeout
        last_url = ""
        while time.time() < deadline:
            try:
                cur = page.url
            except Exception:  # noqa: BLE001
                break
            if cur != last_url:
                progress("info", f"scan url={cur[:100]}")
                last_url = cur
            try:
                p = urlparse(cur)
                if "developers.google.com" in (p.hostname or "") and "auth_success_gemini" in (p.path or ""):
                    progress("step", "扫码成功 — 验证账号中")
                    time.sleep(2)
                    break
                if "auth-success" in (p.path or ""):
                    progress("step", "扫码成功 — 验证账号中")
                    time.sleep(2)
                    break
            except Exception:  # noqa: BLE001
                pass
            time.sleep(2)
        else:
            progress("warn", "扫码超时未完成激活")
            return False

        # Re-probe to confirm
        try:
            verify = page.context.request.post(
                "https://cloudcode-pa.googleapis.com/v1internal:generateContent",
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Content-Type": "application/json",
                },
                data={
                    "model": "models/gemini-2.5-flash",
                    "project": project_id,
                    "request": {"contents": [{"role": "user", "parts": [{"text": "ping"}]}]},
                },
                timeout=20_000,
            )
            vbody = verify.text()[:200]
            if verify.status == 200 and "VALIDATION_REQUIRED" not in vbody:
                progress("done", "activation verified (200 OK)")
                return True
            progress("warn", f"post-scan verify: status={verify.status} body[:80]={vbody[:80]}")
            return False
        except Exception as exc:  # noqa: BLE001
            progress("warn", f"post-scan verify errored: {exc}")
            return False
    except Exception as exc:  # noqa: BLE001
        progress("warn", f"activate_in_page failed: {exc}")
        return False


def scan_qrcode_to_activate(
    *,
    access_token: str,
    project_id: str,
    proxy: Optional[str],
    progress: ProgressCallback,
    headless: bool = False,
    timeout: int = 600,
) -> bool:
    """After token exchange, probe cloudcode-pa to see if the account needs
    antigravity activation (HTTP 403 with ``validation_url`` in body). If so,
    open a fresh Camoufox tab on that URL, wait for the user to scan, and
    detect the success redirect (``auth_success_gemini``).

    Returns True if activation succeeded (or wasn't needed), False on
    timeout / persistent block. Never raises — activation is best-effort
    after the json is already on disk.
    """
    Camoufox = _import_camoufox()
    pw_proxy = _proxy_for_camoufox(proxy)
    exit_ip = _resolve_exit_ip(pw_proxy)

    progress("info", "probing cloudcode-pa for VALIDATION_REQUIRED …")

    with Camoufox(
        headless=headless,
        proxy=pw_proxy,
        humanize=True,
        i_know_what_im_doing=True,
        geoip=True if pw_proxy else False,
    ) as browser:
        context = browser.new_context()
        page = context.new_page()

        # Probe generateContent inside the browser request context (no SSL
        # issues through the proxy bridge).
        try:
            resp = context.request.post(
                "https://cloudcode-pa.googleapis.com/v1internal:generateContent",
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Content-Type": "application/json",
                },
                data={
                    "model": "models/gemini-2.5-flash",
                    "project": project_id,
                    "request": {"contents": [{"role": "user", "parts": [{"text": "ping"}]}]},
                },
                timeout=30000,
            )
        except Exception as exc:  # noqa: BLE001
            progress("warn", f"probe request failed: {exc}")
            try:
                context.close()
            except Exception:  # noqa: BLE001
                pass
            return False

        body = resp.text()[:2000]
        progress("info", f"probe status={resp.status} body[:120]={body[:120]}")

        if resp.status == 200 and "VALIDATION_REQUIRED" not in body:
            progress("done", "no activation needed (account already validated)")
            try:
                context.close()
            except Exception:  # noqa: BLE001
                pass
            return True

        # Extract validation_url
        m = re.search(r'"validation_url":\s*"([^"]+)"', body)
        if not m:
            progress("warn", f"403 but no validation_url in body — manual activation required")
            try:
                context.close()
            except Exception:  # noqa: BLE001
                pass
            return False
        validation_url = m.group(1).replace("\\u0026", "&")
        progress("manual", f"⚠ 需要扫码激活 — 在 Camoufox 里用手机 Google App 扫码 (validation_url={validation_url[:80]}…)")

        # Open validation_url in same browser; wait for redirect to success
        try:
            page.goto(validation_url, wait_until="domcontentloaded", timeout=30_000)
        except Exception as exc:  # noqa: BLE001
            progress("warn", f"goto validation_url: {exc}")

        def _is_real_success(u: str) -> bool:
            try:
                p = urlparse(u)
                host = (p.hostname or "").lower()
                path = p.path or ""
                if "developers.google.com" in host and "auth_success_gemini" in path:
                    return True
                if "auth-success" in path:
                    return True
                return False
            except Exception:  # noqa: BLE001
                return False

        deadline = time.time() + timeout
        last_url = ""
        ok = False
        while time.time() < deadline:
            try:
                cur = page.url
            except Exception:  # noqa: BLE001
                break
            if cur != last_url:
                progress("info", f"scan url={cur[:100]}")
                last_url = cur
            if _is_real_success(cur):
                ok = True
                progress("step", "扫码成功 — 等 2s 后再验证")
                time.sleep(2)
                break
            time.sleep(2)

        if not ok:
            progress("warn", "扫码超时未完成激活")
            try:
                context.close()
            except Exception:  # noqa: BLE001
                pass
            return False

        # Verify: probe again, expect 200
        try:
            verify = context.request.post(
                "https://cloudcode-pa.googleapis.com/v1internal:generateContent",
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Content-Type": "application/json",
                },
                data={
                    "model": "models/gemini-2.5-flash",
                    "project": project_id,
                    "request": {"contents": [{"role": "user", "parts": [{"text": "ping"}]}]},
                },
                timeout=30000,
            )
            vb = verify.text()[:300]
            if verify.status == 200 and "VALIDATION_REQUIRED" not in vb:
                progress("done", "✅ 二次验证 200 — 激活完成")
                try:
                    context.close()
                except Exception:  # noqa: BLE001
                    pass
                return True
            progress("warn", f"二次验证 HTTP {verify.status} body[:120]={vb[:120]}")
        except Exception as exc:  # noqa: BLE001
            progress("warn", f"verify request failed: {exc}")

        try:
            context.close()
        except Exception:  # noqa: BLE001
            pass
        return False


# --- IdC (AWS IAM Identity Center) sign-in — Method 2 ------------------------
#
# Companion to kiro_idc.py's protocol layer. Drives a verificationUriComplete
# URL through the seven-state IdC login journey observed empirically:
#
#   S1 signin    → username → Next
#   S2 password  → password → Sign in
#   S3 mfa-reg   → pick Authenticator app → Show secret → scrape → 6-digit → Assign MFA → Done
#   S4 setpw     → generate + fill new password twice → Set new password
#   S5 mfa-chal  → 6-digit from totp_secret → submit
#   S6 confirm   → "Confirm and continue" (device code page)
#   S7 consent   → "Allow access" (kiro-rs scopes)
#   S8 approved  → "Request approved" (terminal)
#
# Signals for the state detector are chosen to be resilient to AWS's frequent
# copy tweaks — we prefer role+name over exact selectors.


class _IdcCaptureResult:
    """Side-channel outputs of the IdC state machine. All optional."""
    def __init__(self):
        self.new_password: Optional[str] = None
        self.new_password_source: str = ""   # "reused_original" | "generated"
        self.registered_totp_secret: Optional[str] = None
        self.email: Optional[str] = None


def _persist_idc_secret(record: dict, out_dir: Optional[str] = None) -> str:
    """Append a secret record to ``<out_dir>/idc_secrets.jsonl`` BEFORE we act
    on it. Every mutation of an IdC account (new password, MFA secret) MUST
    go through here first — this file is our only guarantee that a crash mid-
    submit doesn't lose the credential.

    Falls back to ``scripts/login-hub/output/`` if the caller doesn't supply
    an ``out_dir`` (e.g. running from a different cwd)."""
    import datetime as _dt
    if not out_dir:
        # Best-effort default — same place login-hub already writes its JSON
        here = os.path.dirname(os.path.abspath(__file__))
        out_dir = os.path.normpath(os.path.join(here, "..", "output"))
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, "idc_secrets.jsonl")
    entry = {"ts": _dt.datetime.now().isoformat(timespec="seconds"), **record}
    line = json.dumps(entry, ensure_ascii=False) + "\n"
    # O_APPEND + fsync — no chance of a partial write eating the entry.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.write(fd, line.encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)
    return path


# HARD-CODED fallback new password used ONLY when AWS refuses to accept the
# caller's original password on the "set new password" prompt.
#
# Design rules (do NOT randomize this file — the whole point is that every
# account we set up shares one known-good value that appears in git history):
#   • ≥ 8 chars, mix of upper/lower/digit/special (AWS IdC default policy)
#   • no substring that could plausibly overlap an IdC username
#   • memorable enough to type by hand into the AWS console during recovery
IDC_FIXED_NEW_PASSWORD = "LoginHub!Kiro2026#Fixed"


def _idc_detect_state(page) -> str:
    """Return a coarse state label for the current page.

    Strategy:
      1. URL hash routes (most reliable — /mfa/register, /#/device, ...)
      2. Live DOM probes (role=textbox by name + testid buttons) — resilient
         to AWS copy tweaks and to render timing (innerText may still lag
         while the DOM is already in place).
      3. innerText keyword fallback for terminal / no-input pages.
    """
    url = (page.url or "")
    # (1) URL routes ----------------------------------------------------------
    if "/mfa/register" in url:
        return "mfa_register"
    if "/mfa/challenge" in url or "/mfa/verify" in url:
        return "mfa_challenge"
    if "force-device-enrollment" in url or "force-password" in url:
        return "set_new_password"
    if "/#/device" in url:
        return "device_confirm"

    # (2) DOM probes — cheap `.count()` doesn't wait; returns 0 if absent ----
    def _probe(fn):
        try:
            return fn() > 0
        except Exception:  # noqa: BLE001
            return False

    if _probe(lambda: page.locator('[data-testid="allow-access-button"]').count()):
        return "consent"
    if _probe(lambda: page.get_by_role("button", name="Confirm and continue").count()):
        return "device_confirm"
    if _probe(lambda: page.get_by_role("button", name="Allow access").count()):
        return "consent"
    if _probe(lambda: page.get_by_role("button", name="Assign MFA").count()) or \
       _probe(lambda: page.locator('a[data-testid="show-secret-key-button"]').count()) or \
       _probe(lambda: page.get_by_role("radio", name="Authenticator app").count()):
        return "mfa_register"
    if _probe(lambda: page.get_by_role("button", name="Set new password").count()) or \
       _probe(lambda: page.get_by_role("textbox", name="Confirm new password").count()):
        return "set_new_password"
    # Login pages — check Password first: the password page also displays
    # "Username: xxx" as text, so an unconditional Username probe would
    # incorrectly land on 'signin' after the user has already typed one.
    if _probe(lambda: page.get_by_role("textbox", name="Password").count()):
        return "password"
    if _probe(lambda: page.get_by_role("textbox", name="Username").count()):
        return "signin"
    # "Authenticator code" appears on the MFA register page (during setup).
    # "MFA code" appears on the MFA challenge page (subsequent logins after
    # MFA is already registered — different DOM, different label).
    if _probe(lambda: page.get_by_role("textbox", name="MFA code").count()):
        return "mfa_challenge"
    if _probe(lambda: page.get_by_role("textbox", name="Authenticator code").count()):
        return "mfa_challenge"

    # (3) innerText fallback for terminal pages -----------------------------
    try:
        html_lc = (page.content() or "").lower()
    except Exception:  # noqa: BLE001
        html_lc = ""
    if "request approved" in html_lc:
        return "approved"
    if "authorization requested" in html_lc:
        return "device_confirm"
    if "allow kiro" in html_lc:
        return "consent"
    # AWS MFA challenge heading — catches the case where the textbox name
    # varies (localized copy tweaks)
    if "additional verification required" in html_lc:
        return "mfa_challenge"
    return "unknown"


def _idc_click_first_available(page, refs, timeout=3000) -> bool:
    """Click the first locator that succeeds. Each ref may be a role dict
    ``{'role': 'button', 'name': 'Next'}`` or a CSS selector string."""
    for ref in refs:
        try:
            if isinstance(ref, dict):
                loc = page.get_by_role(ref["role"], name=ref["name"])
            else:
                loc = page.locator(ref)
            loc.first.click(timeout=timeout)
            return True
        except Exception:  # noqa: BLE001
            continue
    return False


def _idc_fill_first_available(page, refs, value: str, timeout=3000) -> bool:
    for ref in refs:
        try:
            if isinstance(ref, dict):
                loc = page.get_by_role(ref["role"], name=ref["name"])
            else:
                loc = page.locator(ref)
            loc.first.fill(value, timeout=timeout)
            return True
        except Exception:  # noqa: BLE001
            continue
    return False


def _idc_wait_totp_window(min_remaining: int = 10) -> None:
    """Sleep to the next TOTP window if we're too close to the boundary — a
    filled code that expires mid-submit will bounce us back to the MFA page."""
    remaining = 30 - int(time.time()) % 30
    if remaining < min_remaining:
        time.sleep(remaining + 1)


def _idc_scrape_totp_secret(page) -> Optional[str]:
    """After clicking "Show secret key.", read the base32 secret out of the
    ``.secret-key`` span. Returns None if not present yet."""
    try:
        return page.evaluate(
            """() => {
                const el = document.querySelector('.secret-key');
                if (!el) return null;
                const t = (el.textContent || '').trim();
                return /^[A-Z2-7\\s]{16,64}$/.test(t) ? t.replace(/\\s/g,'') : null;
            }"""
        )
    except Exception:  # noqa: BLE001
        return None


def _run_idc_state_machine(
    page,
    username: str,
    password: str,
    totp_secret: str,
    user_code: str,
    progress: ProgressCallback,
    result: "_IdcCaptureResult",
    timeout: int,
    out_dir: Optional[str] = None,
) -> None:
    """Loop-until-approved state machine. Idempotent per state — re-entry
    (e.g. from a stale detection) just re-runs the same action, which the
    AWS SPA silently absorbs."""
    pyotp = _import_pyotp()
    deadline = time.time() + max(120, int(timeout or 300))
    last_state = ""
    stable_ticks = 0
    current_totp = totp_secret

    while time.time() < deadline:
        # Small settle so JS transitions finish before we sniff state
        try:
            page.wait_for_load_state("domcontentloaded", timeout=8_000)
        except Exception:  # noqa: BLE001
            pass
        time.sleep(0.8)

        state = _idc_detect_state(page)
        if state == last_state:
            stable_ticks += 1
        else:
            stable_ticks = 0
            last_state = state
            progress("info", f"IdC state → {state}")

        if state == "approved":
            return

        if state == "signin":
            _idc_fill_first_available(page, [
                {"role": "textbox", "name": "Username"},
            ], username)
            _idc_click_first_available(page, [
                {"role": "button", "name": "Next"},
            ])
            continue

        if state == "password":
            _idc_fill_first_available(page, [
                {"role": "textbox", "name": "Password"},
            ], password)
            _idc_click_first_available(page, [
                {"role": "button", "name": "Sign in"},
            ])
            continue

        if state == "mfa_register":
            # Two sub-pages: device picker (Authenticator/Security key/Built-in)
            # then the actual set-up-authenticator-app screen with QR + secret.
            # Detect by looking for the secret key link.
            has_show_secret = False
            try:
                has_show_secret = page.locator('a[data-testid="show-secret-key-button"]').count() > 0
            except Exception:  # noqa: BLE001
                pass

            if not has_show_secret:
                # Sub-page 1: pick Authenticator app → Next
                try:
                    page.get_by_role("radio", name="Authenticator app").first.click(timeout=3000)
                except Exception:  # noqa: BLE001
                    pass
                _idc_click_first_available(page, [
                    '[data-testid="test-next-button"]',
                    {"role": "button", "name": "Next"},
                ])
                continue

            # Sub-page 2: reveal secret + fill 6-digit code
            try:
                page.locator('a[data-testid="show-secret-key-button"]').first.click(timeout=3000)
            except Exception:  # noqa: BLE001
                pass
            time.sleep(0.4)
            secret = _idc_scrape_totp_secret(page)
            if not secret:
                # secret not visible yet — loop and retry
                continue

            result.registered_totp_secret = secret
            current_totp = secret
            # HARD RULE — persist the raw secret to disk BEFORE we submit
            # anything. If Python or the browser dies mid-Assign, this file
            # is the only artifact tying the AWS-side MFA binding back to a
            # usable secret. If persist itself fails we bail (crashing is
            # safer than silently proceeding with an unrecorded secret).
            path = _persist_idc_secret(
                {"username": username, "kind": "mfa_secret", "value": secret},
                out_dir=out_dir,
            )
            progress("info", f"IdC MFA secret persisted → {path}  (value={secret})")

            _idc_wait_totp_window(min_remaining=12)
            code = pyotp.TOTP(secret).now()
            _idc_fill_first_available(page, [
                {"role": "textbox", "name": "Authenticator code"},
            ], code)
            _idc_click_first_available(page, [
                {"role": "button", "name": "Assign MFA"},
            ])
            # Landing page = "Authenticator app registered" with a Done button
            try:
                page.get_by_role("button", name="Done").first.click(timeout=8000)
            except Exception:  # noqa: BLE001
                pass
            continue

        if state == "set_new_password":
            # HARD RULE — decide + persist BEFORE we ever fill the form.
            #
            # Two-tier deterministic choice, NO randomness:
            #   pass 1 → reuse the CALLER'S original password
            #   pass 2 → fall back to the fixed known constant above
            # Same account can therefore have at most two distinct
            # passwords, both of which appear in git history and in
            # idc_secrets.jsonl.
            if not result.new_password:
                candidate = password
                result.new_password_source = "reused_original"
            elif result.new_password_source == "reused_original":
                candidate = IDC_FIXED_NEW_PASSWORD
                result.new_password_source = "fixed_constant"
            else:
                candidate = result.new_password   # idempotent re-entry
            if result.new_password != candidate:
                result.new_password = candidate
                path = _persist_idc_secret(
                    {"username": username, "kind": "new_password",
                     "value": candidate, "source": result.new_password_source},
                    out_dir=out_dir,
                )
                progress("info",
                         f"IdC new_password ({result.new_password_source}) persisted → {path}  "
                         f"(value={candidate})")
            new_pw = result.new_password
            # Order matters: fill Confirm first, then New (avoids Confirm being
            # populated before New and firing an inequality validator).
            _idc_fill_first_available(page, [
                {"role": "textbox", "name": "Confirm new password"},
            ], new_pw)
            _idc_fill_first_available(page, [
                '[data-testid="test-new-password-input"] input',
                {"role": "textbox", "name": "New password"},
            ], new_pw)
            _idc_click_first_available(page, [
                {"role": "button", "name": "Set new password"},
            ])
            continue

        if state == "mfa_challenge":
            if not current_totp:
                raise LoginError("IdC asked for MFA code but no totp_secret provided")
            _idc_wait_totp_window(min_remaining=10)
            code = pyotp.TOTP(current_totp).now()
            _idc_fill_first_available(page, [
                {"role": "textbox", "name": "Authenticator code"},
                {"role": "textbox", "name": "MFA code"},
                'input[type="text"][autocomplete="one-time-code"]',
            ], code)
            _idc_click_first_available(page, [
                {"role": "button", "name": "Sign in"},
                {"role": "button", "name": "Verify"},
                {"role": "button", "name": "Submit"},
            ])
            continue

        if state == "device_confirm":
            # Optional sanity: verify displayed user_code matches ours
            if user_code:
                try:
                    shown = page.locator(f'text="{user_code}"').count()
                    if shown == 0:
                        progress("info", f"IdC device page did not show expected code {user_code}")
                except Exception:  # noqa: BLE001
                    pass
            _idc_click_first_available(page, [
                {"role": "button", "name": "Confirm and continue"},
            ])
            continue

        if state == "consent":
            _idc_click_first_available(page, [
                '[data-testid="allow-access-button"]',
                {"role": "button", "name": "Allow access"},
            ])
            continue

        # Unknown state — give the page a much longer runway before giving up.
        # AWS SPA transitions can leave the DOM briefly empty between routes;
        # ~30 ticks × ~1s = 30s of grace is generous but bounded.
        if state == "unknown" and stable_ticks > 30:
            try:
                dom_head = page.evaluate("() => (document.body?.innerText || '').slice(0, 400)")
            except Exception:  # noqa: BLE001
                dom_head = "(evaluate failed)"
            raise LoginError(
                f"IdC state machine stuck at unknown (url={page.url[:120]}) "
                f"body-head={dom_head!r}"
            )

    raise LoginError(f"IdC state machine timed out (last_state={last_state}, url={page.url[:120]})")


def capture_idc_signin(
    *,
    verify_uri: str,
    user_code: str,
    proxy: Optional[str],
    username: str,
    password: str,
    totp_secret: str,
    progress: ProgressCallback,
    timeout: int,
    headless: bool = False,
    out_dir: Optional[str] = None,
) -> _IdcCaptureResult:
    """Launch Camoufox, walk the verification URI through IdC login until we
    see the "Request approved" terminal state. The token itself is fetched by
    the caller (via CreateToken polling) — this function only makes sure the
    device authorization gets user consent.
    """
    Camoufox = _import_camoufox()
    pw_proxy = _proxy_for_camoufox(proxy)
    exit_ip = _resolve_exit_ip(pw_proxy)
    if exit_ip:
        progress("info", f"upstream exit IP: {exit_ip}")

    progress("info", f"camoufox launching (proxy={pw_proxy['server'] if pw_proxy else 'direct'})")

    result = _IdcCaptureResult()
    with Camoufox(
        headless=headless,
        proxy=pw_proxy,
        humanize=False,
        i_know_what_im_doing=True,
        geoip=True if pw_proxy else False,
        # Force English UI regardless of proxy egress locale — AWS SSO honors
        # both Accept-Language and navigator.languages when picking a locale,
        # and our state-machine selectors are English-only ("Username" /
        # "Password" / "Sign in" / "Allow access" / ...).
        locale=["en-US", "en"],
    ) as browser:
        # Camoufox's Firefox driver (Playwright 1.61+) rejects the
        # ``isMobile`` field Playwright auto-injects for viewport dicts.
        # Skip Playwright-side viewport, apply via page.set_viewport_size.
        context = browser.new_context(
            no_viewport=True,
            locale="en-US",
            extra_http_headers={"Accept-Language": "en-US,en;q=0.9"},
        )
        page = context.new_page()
        try:
            page.set_viewport_size({"width": 1280, "height": 860})
        except Exception:  # noqa: BLE001
            pass

        progress("step", "opening IdC verification URI …")
        try:
            page.goto(verify_uri, wait_until="load", timeout=60_000)
        except Exception as exc:  # noqa: BLE001
            progress("info", f"page.goto ended: {str(exc)[:120]}")

        try:
            page.wait_for_load_state("networkidle", timeout=15_000)
        except Exception:  # noqa: BLE001
            pass

        _run_idc_state_machine(
            page, username, password, totp_secret, user_code,
            progress, result, timeout, out_dir=out_dir,
        )

        try:
            context.close()
        except Exception:  # noqa: BLE001
            pass

    return result
