"""Minimal asyncio SOCKS5/HTTP → SOCKS5+auth forwarder.

Replaces ``pproxy`` (slow, sometimes deadlocks on TLS to Google/x.ai). Two
listeners bind locally:

  * ``socks5://127.0.0.1:<sport>``  — no auth; for Camoufox / Firefox.
  * ``http://127.0.0.1:<hport>``    — no auth; for ``urllib.request``.

Every accepted client is handed off to a coroutine that (a) parses the
minimal greeting for its listener type, (b) opens a SOCKS5 CONNECT tunnel
through the upstream (doing username/password auth if credentials are set),
and (c) pipes bytes both directions until either side closes.

Runs in its own thread with its own event loop so importing this module
doesn't affect a caller that already uses asyncio.
"""

from __future__ import annotations

import asyncio
import socket
import struct
import threading
import urllib.parse
from typing import Optional


def _pick_free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


async def _socks5_connect(host: str, port: int, user: str, pw: str, target_host: str, target_port: int):
    """Open an authenticated SOCKS5 CONNECT tunnel to (target_host, target_port)
    via upstream (host, port). Returns (reader, writer) on success, or raises."""
    reader, writer = await asyncio.open_connection(host, port)
    try:
        # Greeting: methods = [NOAUTH, USERPASS] if creds, else [NOAUTH]
        if user or pw:
            writer.write(b"\x05\x02\x00\x02")
        else:
            writer.write(b"\x05\x01\x00")
        await writer.drain()
        greet = await reader.readexactly(2)
        if greet[0] != 0x05:
            raise OSError(f"upstream not SOCKS5 (got {greet.hex()})")
        method = greet[1]
        if method == 0x02:
            u = user.encode(); p = pw.encode()
            writer.write(b"\x01" + bytes([len(u)]) + u + bytes([len(p)]) + p)
            await writer.drain()
            auth_reply = await reader.readexactly(2)
            if auth_reply[1] != 0x00:
                raise OSError(f"SOCKS5 auth rejected (code={auth_reply[1]})")
        elif method != 0x00:
            raise OSError(f"SOCKS5 method rejected ({method})")

        # CONNECT
        th = target_host.encode()
        writer.write(b"\x05\x01\x00\x03" + bytes([len(th)]) + th + struct.pack(">H", target_port))
        await writer.drain()
        reply = await reader.readexactly(4)
        if reply[1] != 0x00:
            raise OSError(f"SOCKS5 CONNECT rejected (code={reply[1]})")
        atyp = reply[3]
        if atyp == 0x01:
            await reader.readexactly(4 + 2)
        elif atyp == 0x03:
            ln = (await reader.readexactly(1))[0]
            await reader.readexactly(ln + 2)
        elif atyp == 0x04:
            await reader.readexactly(16 + 2)
        else:
            raise OSError(f"SOCKS5 unknown ATYP={atyp}")
        return reader, writer
    except Exception:
        try:
            writer.close(); await writer.wait_closed()
        except Exception:  # noqa: BLE001
            pass
        raise


async def _pipe(src_reader: asyncio.StreamReader, dst_writer: asyncio.StreamWriter):
    try:
        while True:
            chunk = await src_reader.read(65536)
            if not chunk:
                break
            dst_writer.write(chunk)
            await dst_writer.drain()
    except Exception:  # noqa: BLE001
        pass
    finally:
        try:
            dst_writer.close()
        except Exception:  # noqa: BLE001
            pass


async def _handle_socks5_client(client_reader, client_writer, upstream: dict):
    """Serve one downstream SOCKS5 request; tunnel through upstream."""
    try:
        # Greeting
        head = await client_reader.readexactly(2)
        if head[0] != 0x05:
            client_writer.close(); return
        nm = head[1]
        await client_reader.readexactly(nm)  # drain methods
        client_writer.write(b"\x05\x00")     # accept no-auth
        await client_writer.drain()

        # Request
        req = await client_reader.readexactly(4)
        if req[1] != 0x01:  # only CONNECT
            client_writer.write(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
            await client_writer.drain(); client_writer.close(); return
        atyp = req[3]
        if atyp == 0x01:
            host_b = await client_reader.readexactly(4)
            target_host = ".".join(str(b) for b in host_b)
        elif atyp == 0x03:
            ln = (await client_reader.readexactly(1))[0]
            target_host = (await client_reader.readexactly(ln)).decode()
        elif atyp == 0x04:
            host_b = await client_reader.readexactly(16)
            target_host = ":".join(f"{host_b[i]<<8|host_b[i+1]:x}" for i in range(0, 16, 2))
        else:
            client_writer.close(); return
        target_port = struct.unpack(">H", await client_reader.readexactly(2))[0]

        # Upstream tunnel
        try:
            up_r, up_w = await _socks5_connect(
                upstream["host"], upstream["port"],
                upstream["user"], upstream["pw"],
                target_host, target_port,
            )
        except Exception:
            client_writer.write(b"\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00")
            await client_writer.drain(); client_writer.close(); return

        # Success reply to downstream
        client_writer.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        await client_writer.drain()

        # Bidirectional pipe
        await asyncio.gather(
            _pipe(client_reader, up_w),
            _pipe(up_r, client_writer),
        )
    except Exception:  # noqa: BLE001
        try: client_writer.close()
        except Exception: pass


async def _handle_http_client(client_reader, client_writer, upstream: dict):
    """Serve one downstream HTTP proxy request (CONNECT or absolute-URI GET)."""
    try:
        line = await client_reader.readline()
        if not line:
            client_writer.close(); return
        parts = line.decode(errors="replace").strip().split()
        if len(parts) < 3:
            client_writer.close(); return
        method, target, _http = parts[0], parts[1], parts[2]

        # Drain headers
        headers_raw = b""
        while True:
            hl = await client_reader.readline()
            if not hl or hl in (b"\r\n", b"\n"):
                break
            headers_raw += hl

        if method.upper() == "CONNECT":
            host, _, port_s = target.partition(":")
            target_port = int(port_s or "443")
            target_host = host
            initial_data = b""
        else:
            # absolute-URI (e.g. GET http://host/path HTTP/1.1) — turn into CONNECT
            u = urllib.parse.urlparse(target)
            target_host = u.hostname
            target_port = u.port or (443 if u.scheme == "https" else 80)
            # Re-emit the request line + headers to the upstream target
            path = target[len(f"{u.scheme}://{u.netloc}"):] or "/"
            initial_data = (
                f"{method} {path} {_http}\r\n".encode() + headers_raw + b"\r\n"
            )

        try:
            up_r, up_w = await _socks5_connect(
                upstream["host"], upstream["port"],
                upstream["user"], upstream["pw"],
                target_host, target_port,
            )
        except Exception:
            client_writer.write(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
            await client_writer.drain(); client_writer.close(); return

        if method.upper() == "CONNECT":
            client_writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await client_writer.drain()
        else:
            up_w.write(initial_data)
            await up_w.drain()

        await asyncio.gather(
            _pipe(client_reader, up_w),
            _pipe(up_r, client_writer),
        )
    except Exception:  # noqa: BLE001
        try: client_writer.close()
        except Exception: pass


async def _run_forever(upstream: dict, sport: int, hport: int, ready: threading.Event):
    socks_server = await asyncio.start_server(
        lambda r, w: _handle_socks5_client(r, w, upstream),
        "127.0.0.1", sport,
    )
    http_server = await asyncio.start_server(
        lambda r, w: _handle_http_client(r, w, upstream),
        "127.0.0.1", hport,
    )
    ready.set()
    async with socks_server, http_server:
        await asyncio.Event().wait()  # forever


def spawn_bridge(upstream_url: str) -> tuple[int, int, threading.Thread]:
    """Start local SOCKS5 (no-auth) + HTTP proxy listeners forwarding to
    ``upstream_url`` (must be ``socks5://user:pass@host:port``).

    Returns ``(socks_port, http_port, thread)``. The thread runs the asyncio
    event loop as a daemon — the process just needs to stay alive.
    """
    parsed = urllib.parse.urlparse(upstream_url)
    if parsed.scheme.lower() not in ("socks5", "socks5h"):
        raise ValueError(f"upstream must be socks5://, got {parsed.scheme!r}")
    upstream = {
        "host": parsed.hostname or "",
        "port": parsed.port or 1080,
        "user": urllib.parse.unquote(parsed.username or ""),
        "pw": urllib.parse.unquote(parsed.password or ""),
    }
    sport = _pick_free_port()
    hport = _pick_free_port()
    ready = threading.Event()

    def _thread_main():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(_run_forever(upstream, sport, hport, ready))
        except Exception:
            ready.set()  # unblock spawner if boot failed

    t = threading.Thread(target=_thread_main, name=f"proxy-bridge-{sport}", daemon=True)
    t.start()
    if not ready.wait(timeout=5.0):
        raise RuntimeError(f"asyncio bridge for {upstream_url} did not start within 5s")
    return sport, hport, t
