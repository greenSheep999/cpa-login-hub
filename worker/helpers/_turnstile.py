"""YesCaptcha / anti-captcha Turnstile solver.

YesCaptcha 兼容 anti-captcha API 协议。Cloudflare Turnstile 用
``TurnstileTaskProxyless`` 任务类型（无代理，YesCaptcha 自己跑）。

Flow:
  1. POST /createTask   {clientKey, task: {type, websiteURL, websiteKey}}
     → {errorId:0, taskId:...}
  2. POST /getTaskResult {clientKey, taskId}  → polling until status='ready'
     → {status:'ready', solution: {token: '...'}}
  3. The token is injected into the page via JS — Cloudflare Turnstile reads
     it from ``input[name="cf-turnstile-response"]`` AND fires the
     ``onSuccess`` callback the site registered.

Env vars:
  YESCAPTCHA_API_KEY — required
  YESCAPTCHA_BASE    — optional, default https://api.yescaptcha.com
"""

from __future__ import annotations

import json
import os
import time
import urllib.parse
import urllib.request
from typing import Optional


class TurnstileSolveError(RuntimeError):
    pass


def _post_json(url: str, payload: dict, proxy_url: Optional[str] = None, timeout: int = 30) -> dict:
    """POST JSON. Solver API itself is called direct, no proxy — YesCaptcha
    accepts requests from anywhere."""
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    handlers = []
    if proxy_url:
        handlers.append(urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url}))
    opener = urllib.request.build_opener(*handlers) if handlers else urllib.request.build_opener()
    with opener.open(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def solve_turnstile(
    *,
    website_url: str,
    website_key: str,
    api_key: Optional[str] = None,
    api_base: Optional[str] = None,
    timeout: int = 120,
) -> str:
    """Solve a Cloudflare Turnstile challenge. Returns the token string.

    ``website_url`` is the page hosting the widget. ``website_key`` is the
    ``data-sitekey`` value on ``<div class="cf-turnstile">``.

    Raises ``TurnstileSolveError`` on any failure (no key, API error, polling
    timeout).
    """
    api_key = api_key or os.environ.get("YESCAPTCHA_API_KEY", "").strip()
    if not api_key:
        raise TurnstileSolveError("YESCAPTCHA_API_KEY env var not set")
    api_base = (api_base or os.environ.get("YESCAPTCHA_BASE") or "https://api.yescaptcha.com").rstrip("/")

    # 1. createTask
    try:
        r = _post_json(api_base + "/createTask", {
            "clientKey": api_key,
            "task": {
                "type": "TurnstileTaskProxyless",
                "websiteURL": website_url,
                "websiteKey": website_key,
            },
        })
    except Exception as exc:
        raise TurnstileSolveError(f"createTask request failed: {exc}") from exc

    if r.get("errorId") not in (0, None):
        raise TurnstileSolveError(f"createTask error: {r.get('errorCode')} {r.get('errorDescription')}")
    task_id = r.get("taskId")
    if not task_id:
        raise TurnstileSolveError(f"createTask returned no taskId: {r}")

    # 2. poll getTaskResult
    deadline = time.time() + timeout
    last_status = "processing"
    while time.time() < deadline:
        time.sleep(3)
        try:
            r = _post_json(api_base + "/getTaskResult", {
                "clientKey": api_key,
                "taskId": task_id,
            })
        except Exception as exc:
            raise TurnstileSolveError(f"getTaskResult request failed: {exc}") from exc

        if r.get("errorId") not in (0, None):
            raise TurnstileSolveError(f"getTaskResult error: {r.get('errorCode')} {r.get('errorDescription')}")
        status = r.get("status", "processing")
        last_status = status
        if status == "ready":
            token = (r.get("solution") or {}).get("token") or (r.get("solution") or {}).get("gRecaptchaResponse")
            if not token:
                raise TurnstileSolveError(f"getTaskResult ready but no token: {r}")
            return token

    raise TurnstileSolveError(f"solve timeout after {timeout}s (last status: {last_status})")


# --- Camoufox / Playwright helper -------------------------------------------


JS_INJECT_TURNSTILE = """
(token) => {
  // Set the hidden input that Cloudflare populates with the token.
  const inputs = document.querySelectorAll(
    'input[name="cf-turnstile-response"], input[name="g-recaptcha-response"]'
  );
  inputs.forEach(inp => {
    inp.value = token;
    inp.dispatchEvent(new Event('input', {bubbles: true}));
    inp.dispatchEvent(new Event('change', {bubbles: true}));
  });

  // Fire any onSuccess callback the site registered with the widget.
  // The widget exposes its callback id via window.turnstile.execute or via
  // the data-callback attribute on the cf-turnstile div.
  const widgets = document.querySelectorAll('[data-callback], .cf-turnstile');
  let fired = 0;
  widgets.forEach(w => {
    const name = w.getAttribute('data-callback');
    if (name && typeof window[name] === 'function') {
      try { window[name](token); fired++; } catch (e) {}
    }
  });

  return { injected: inputs.length, callbacks_fired: fired };
}
"""


def inject_turnstile_token(page, token: str) -> dict:
    """Inject a solved Turnstile token into the page. Returns a dict with
    counts ``{injected, callbacks_fired}``."""
    return page.evaluate(JS_INJECT_TURNSTILE, token)


def detect_sitekey(page) -> Optional[str]:
    """Find the Turnstile widget sitekey on the page. Returns None if no
    widget is rendered."""
    try:
        sk = page.evaluate("""() => {
            const el = document.querySelector('[data-sitekey], .cf-turnstile[data-sitekey]');
            if (el) return el.getAttribute('data-sitekey');
            // Sometimes the sitekey is in an iframe src
            const ifr = document.querySelector('iframe[src*="challenges.cloudflare.com/turnstile"]');
            if (ifr) {
                const m = ifr.src.match(/[?&]k=([a-zA-Z0-9_-]+)/);
                if (m) return m[1];
            }
            return null;
        }""")
        return sk if isinstance(sk, str) and sk else None
    except Exception:  # noqa: BLE001
        return None
