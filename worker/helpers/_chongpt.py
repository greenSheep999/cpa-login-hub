"""chongpt.xyz SMS pool client.

Given an SMS-type CDK (e.g. ``SMSTKNSQZNEBZC4M2RE``), this client can:
  * verify the CDK is alive and get the leased phone number
  * poll for a fresh incoming SMS code

The chongpt API is public (no auth), fastify/nestjs backend on
``https://chongpt.xyz``. Endpoints used (discovered from the SPA):

  POST /api/public/cdk/verify   {"code": "<cdk>"}
    → {"valid": true, "sms": {"phoneNumber": "...", "slotIndex": 1, ...}}

  POST /api/public/sms/session  {"code": "<cdk>", "forceNew": <bool>}
    → {"status": "waiting"|"received", "verificationCode": "720555"|null,
       "receivedAt": "2026-07-01 16:22:04", ...}

The typical flow is:
  1. verify() to confirm and get phone number
  2. session(force_new=True) to start listening for the NEXT SMS
     (drops any cached older code)
  3. poll session() repeatedly until status == "received"
"""

from __future__ import annotations

import time
from typing import Optional

from curl_cffi import requests

BASE = "https://chongpt.xyz"


class ChongptError(RuntimeError):
    pass


def _session(proxy_url: Optional[str] = None):
    s = requests.Session(impersonate="chrome")
    if proxy_url:
        s.proxies = {"http": proxy_url, "https": proxy_url}
    s.headers.update({
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Origin": BASE,
        "Referer": BASE + "/recharge",
    })
    return s


def verify(cdk: str, proxy_url: Optional[str] = None) -> dict:
    """Verify a CDK. Returns the API's parsed JSON body.
    ``valid=False`` means the CDK doesn't exist / has been consumed.
    ``valid=True`` for SMS CDKs includes an ``sms`` object with the phone
    number and slot info."""
    r = _session(proxy_url).post(BASE + "/api/public/cdk/verify",
                                 json={"code": cdk}, timeout=20)
    if r.status_code != 200:
        raise ChongptError(f"verify HTTP {r.status_code}: {r.text[:300]}")
    return r.json()


def session(cdk: str, force_new: bool = False, proxy_url: Optional[str] = None) -> dict:
    """Ask chongpt for the current SMS session for this CDK.

    ``force_new=True`` starts a fresh listener (drops any cached older code
    and waits for the NEXT SMS to arrive). Use this at the moment you triggered
    the SMS send (e.g. right after clicking "send code" in OpenAI's UI).

    ``force_new=False`` returns whatever the server already has cached — good
    for polling once you've asked with ``force_new=True`` earlier.
    """
    r = _session(proxy_url).post(BASE + "/api/public/sms/session",
                                 json={"code": cdk, "forceNew": force_new},
                                 timeout=20)
    if r.status_code != 200:
        raise ChongptError(f"session HTTP {r.status_code}: {r.text[:300]}")
    return r.json()


def wait_for_new_code(cdk: str, *, since_received_at: Optional[str] = None,
                      timeout: int = 120, proxy_url: Optional[str] = None,
                      progress=None) -> tuple[str, dict]:
    """Poll ``session()`` until a new SMS arrives.

    ``since_received_at`` is a filter: if the server returns a code whose
    ``receivedAt`` timestamp is ``<=`` this value, we treat it as stale
    (same as the code that was there before we triggered the send). Pass
    the ``receivedAt`` from a ``force_new=True`` snapshot BEFORE triggering
    the SMS send, or omit to accept the first ``received`` snapshot.

    Returns ``(code_str, full_snapshot_dict)`` when a fresh code arrives.
    Raises ``ChongptError`` on timeout.
    """
    deadline = time.time() + timeout
    poll_seq = 0
    while time.time() < deadline:
        force = poll_seq == 0  # first call: force new so server rearms listener
        snap = session(cdk, force_new=force, proxy_url=proxy_url)
        poll_seq += 1
        status = snap.get("status")
        code = (snap.get("verificationCode") or "").strip()
        received_at = snap.get("receivedAt") or ""
        if progress:
            progress("info", f"chongpt sms poll #{poll_seq}: status={status} code={'*'*len(code)} received_at={received_at}")
        if status == "received" and code:
            if since_received_at and received_at and received_at <= since_received_at:
                # cached older code; keep polling
                time.sleep(3); continue
            return code, snap
        time.sleep(3)
    raise ChongptError(f"timed out waiting for chongpt SMS after {timeout}s")
