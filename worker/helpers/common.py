"""Shared types for login helpers.

Designed so that when this hub is migrated into muxhub's
``backend/service/account_pool/login_providers/`` registry, each helper can be
wrapped as a concrete ``AccountPoolLoginStrategy`` with minimal changes:

- ``LoginRequest`` maps 1:1 to a strategy's input DTO
- ``progress`` callback maps to the event-bus emitter
- ``LoginResult`` carries the persisted credential metadata
- ``LoginError`` is the canonical failure type
- ``resolve_proxy()`` centralizes the row.proxy → env → system-proxy fallback
"""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass, field
from typing import Any, Callable, Optional


@dataclass
class LoginRequest:
    """Inputs every provider accepts.

    ``label`` is a free-form tag the UI shows in the batch table. It does NOT
    have to match the actual signed-in identity — the helper derives the final
    filename from whatever account the user actually authenticates with.
    """

    label: str = ""
    proxy: Optional[str] = None  # explicit per-row proxy; None means "use fallback"
    out_dir: str = ""
    timeout: int = 600
    extras: dict[str, Any] = field(default_factory=dict)


@dataclass
class LoginResult:
    provider: str
    identity: str
    out_path: str
    extra: dict[str, Any] = field(default_factory=dict)


class LoginError(RuntimeError):
    pass


# Progress callback signature. Kinds the UI knows about:
# ``info`` | ``step`` | ``url`` | ``warn`` | ``manual`` | ``done`` | ``error``
ProgressCallback = Callable[[str, str], None]


def noop_progress(_kind: str, _msg: str) -> None:
    pass


# --- proxy resolution --------------------------------------------------------


def _macos_system_proxy() -> Optional[str]:
    """Read the macOS Wi-Fi secure web proxy, if any. Best-effort, returns None on
    any failure so callers can keep falling back to direct."""
    try:
        out = subprocess.run(
            ["networksetup", "-getsecurewebproxy", "Wi-Fi"],
            capture_output=True,
            text=True,
            timeout=2,
        )
    except Exception:  # noqa: BLE001
        return None
    if out.returncode != 0:
        return None
    fields = {}
    for line in out.stdout.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            fields[k.strip().lower()] = v.strip()
    if fields.get("enabled", "").lower() != "yes":
        return None
    host = fields.get("server")
    port = fields.get("port")
    if not host or not port:
        return None
    return f"http://{host}:{port}"


def resolve_proxy(explicit: Optional[str]) -> Optional[str]:
    """row.proxy > HTTPS_PROXY/HTTP_PROXY env > macOS system proxy > None.

    Empty string / whitespace counts as "not set", not as "direct" — to force
    direct you'd have to pick the UI's direct option (future). For now, an
    explicit ``"direct"`` literal also forces direct.
    """
    if explicit:
        e = explicit.strip()
        if e.lower() in ("direct", "no", "none"):
            return None
        if e:
            return e
    for env_key in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"):
        v = os.environ.get(env_key)
        if v and v.strip():
            return v.strip()
    sys_proxy = _macos_system_proxy()
    if sys_proxy:
        return sys_proxy
    return None


# --- TOTP --------------------------------------------------------------------


def totp_now(secret_b32: str, t: Optional[float] = None) -> str:
    """RFC 6238 TOTP for a base32 secret. Returns 6-digit string."""
    import base64
    import hashlib
    import hmac
    import struct
    import time as _time

    if not secret_b32:
        raise LoginError("totp_secret is empty")
    key = base64.b32decode(secret_b32.strip().upper() + "=" * ((8 - len(secret_b32.strip()) % 8) % 8))
    counter = int((t if t is not None else _time.time()) // 30)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % 1_000_000
    return f"{code:06d}"
