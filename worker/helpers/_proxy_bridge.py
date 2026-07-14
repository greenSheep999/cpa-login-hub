"""SOCKS5(+auth) → local listener forwarder.

We start pproxy with **two** local listeners pointing at the upstream:

  - SOCKS5 (no auth) on 127.0.0.1:<sport>  — for the browser (Camoufox /
    Playwright). Browsers preserve TLS ALPN/SNI/JA3 over SOCKS5 raw TCP,
    so Cloudflare-protected sites (like x.ai) don't see "weird proxy"
    fingerprints.

  - HTTP on 127.0.0.1:<hport>  — for ``urllib.request`` token exchange.
    urllib doesn't speak SOCKS5; HTTP CONNECT works for it.

Both listeners forward to the same upstream SOCKS5+auth URL.

The browser path was added because plain HTTP CONNECT tunneling through
pproxy → Cloudflare reads the TCP fingerprint as non-browser and either
returns 403 or RSTs the connection mid-TLS-handshake. SOCKS5 is raw enough
that the browser's TLS goes straight through.

Each unique upstream URL gets its own pair of listeners; subsequent calls
reuse them. Bridges live as background subprocesses.
"""

from __future__ import annotations

import atexit
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.parse
from typing import Optional

_BRIDGES: dict[str, dict] = {}  # upstream_url -> {"socks_port", "http_port", "proc"}
_LOCK = threading.Lock()


def _needs_bridge(parsed: urllib.parse.ParseResult) -> bool:
    """Only SOCKS5/SOCKS5h need the bridge — even without auth, browsers
    benefit from the local SOCKS5 listener for cleaner TLS forwarding."""
    scheme = (parsed.scheme or "").lower()
    return scheme in ("socks5", "socks5h")


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _to_pproxy_url(upstream: str) -> str:
    """``socks5://user:pass@host:port`` (urllib syntax) →
    ``socks5://host:port#user:pass`` (pproxy syntax — colons in userinfo are
    parsed as cipher specs, so credentials go after a ``#``)."""
    parsed = urllib.parse.urlparse(upstream)
    scheme = parsed.scheme or "socks5"
    if scheme == "socks5h":
        scheme = "socks5"  # pproxy doesn't distinguish; both resolve remotely
    host = parsed.hostname or ""
    port = parsed.port
    netloc = host if not port else f"{host}:{port}"
    base = f"{scheme}://{netloc}"
    if parsed.username:
        user = urllib.parse.unquote(parsed.username)
        pwd = urllib.parse.unquote(parsed.password or "")
        base = f"{base}#{user}:{pwd}" if pwd else f"{base}#{user}"
    return base


def _spawn_pproxy_bridge(upstream: str) -> tuple[int, int]:
    """Spawn a local SOCKS5+HTTP → upstream SOCKS5+auth forwarder.

    Historically this used ``pproxy`` (subprocess). pproxy stalls under load
    talking TLS to Google/x.ai (seen in the wild as 15–60 s hangs on the
    first CONNECT), so we replaced it with an in-process asyncio forwarder in
    ``_asyncio_bridge``. Function name is kept for callers.
    """
    from . import _asyncio_bridge
    sport, hport, thread = _asyncio_bridge.spawn_bridge(upstream)
    _BRIDGES[upstream] = {
        "socks_port": sport, "http_port": hport,
        "proc": _ThreadShim(thread),
    }
    return sport, hport


class _ThreadShim:
    """Minimal adapter so ``_shutdown_all`` / probes that expect a subprocess
    ``.poll()`` / ``.terminate()`` interface work with our daemon thread. The
    thread is a daemon so it dies with the process; nothing to actually stop.
    """
    def __init__(self, thread):
        self._thread = thread
    def poll(self):
        return None if self._thread.is_alive() else 0
    def terminate(self):
        pass
    def kill(self):
        pass
    def wait(self, timeout=None):
        return 0


def _shutdown_all():
    for info in _BRIDGES.values():
        proc = info.get("proc")
        if proc and proc.poll() is None:
            try:
                proc.terminate()
            except Exception:  # noqa: BLE001
                pass


atexit.register(_shutdown_all)


def to_camoufox_proxy(upstream: Optional[str]) -> Optional[dict]:
    """Translate upstream proxy URL into the ``Camoufox(proxy=…)`` dict.

    - ``None`` → ``None`` (direct).
    - HTTP/HTTPS pass-through (Camoufox handles these natively).
    - SOCKS5 (any auth) → return ``{"server": "socks5://127.0.0.1:<sport>"}``
      pointing at the local SOCKS5 listener of the bridge. The bridge is
      started/reused as needed.
    """
    if not upstream:
        return None
    parsed = urllib.parse.urlparse(upstream)
    if not _needs_bridge(parsed):
        # plain HTTP/HTTPS proxy — pass through
        scheme = parsed.scheme or "http"
        host = parsed.hostname or ""
        port = parsed.port
        server = f"{scheme}://{host}"
        if port:
            server += f":{port}"
        d = {"server": server}
        if parsed.username:
            d["username"] = urllib.parse.unquote(parsed.username)
        if parsed.password:
            d["password"] = urllib.parse.unquote(parsed.password)
        return d

    # SOCKS5 → local SOCKS5 listener
    with _LOCK:
        info = _BRIDGES.get(upstream)
        if info and info["proc"].poll() is None:
            sport = info["socks_port"]
        else:
            try:
                __import__("pproxy")
            except ImportError as exc:
                raise RuntimeError(
                    "pproxy not installed. In login-hub venv:\n  pip install pproxy"
                ) from exc
            sport, _ = _spawn_pproxy_bridge(upstream)
    return {"server": f"socks5://127.0.0.1:{sport}"}


def to_urllib_proxy(upstream: Optional[str]) -> Optional[str]:
    """Translate upstream proxy URL into a URL urllib can use.

    - ``None`` → ``None``.
    - HTTP/HTTPS proxy → return as-is.
    - SOCKS5 → return ``http://127.0.0.1:<hport>`` (local HTTP listener of
      the bridge). urllib doesn't speak SOCKS5, so we hop through pproxy's
      HTTP CONNECT listener which forwards to the upstream SOCKS5.
    """
    if not upstream:
        return None
    parsed = urllib.parse.urlparse(upstream)
    if not _needs_bridge(parsed):
        return upstream

    with _LOCK:
        info = _BRIDGES.get(upstream)
        if info and info["proc"].poll() is None:
            hport = info["http_port"]
        else:
            try:
                __import__("pproxy")
            except ImportError as exc:
                raise RuntimeError("pproxy not installed") from exc
            _, hport = _spawn_pproxy_bridge(upstream)
    return f"http://127.0.0.1:{hport}"
