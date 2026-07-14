"""Kiro AWS IAM Identity Center (IdC) SSO login helper — Method 2.

Companion to ``kiro.py`` (Method 1 = M365 external_idp via GetLoginMetadata).
Method 2 is a *device-authorization* OAuth flow against AWS SSO OIDC:

    1.  RegisterClient      → ephemeral clientId/clientSecret + issuer=startUrl
    2.  StartDeviceAuthorization → verificationUriComplete + deviceCode
    3.  Camoufox drives verificationUriComplete through:
          username → password → [MFA register + secret scrape] →
          [set new password] → [MFA challenge] → device-confirm → consent
    4.  poll CreateToken (grant_type=device_code) → access/refresh tokens
    5.  reuse existing kiro.py post-processing (_list_available_profiles,
        _build_cpa_json, _build_kiro_rs_json, _append_to_credentials)

Router:  ``kiro.py::run()`` dispatches here iff ``req.extras['sso_start_url']``
is present. The M365 path is left untouched.

Field additions written into the CPA JSON output (all optional, unknown fields
ignored by CPA):

- ``sso_start_url`` / ``sso_region``     — replayable IdC entry point
- ``generated_password``                 — if state machine had to rotate it
- ``generated_totp_secret``              — if state machine registered MFA
- ``sso_username``                       — original login username

Ported protocol layer mirrors ``kiro.rs::src/kiro/auth/idc.rs`` byte-for-byte
so credentials produced here are drop-in compatible with kiro-rs's own
Enterprise IdC bucket.
"""

from __future__ import annotations

import json
import os
import time
import urllib.parse
import urllib.request
from typing import Optional

from . import _camoufox
from .common import LoginError, LoginRequest, LoginResult, ProgressCallback, noop_progress, resolve_proxy


# --- Constants mirrored from kiro.rs::auth::idc + AWS SSO OIDC docs ----------

# Client identity we send during RegisterClient. AWS SSO OIDC is entirely
# public — no pre-registration — so this is just a friendly display name.
IDC_CLIENT_NAME = "kiro-rs"
IDC_CLIENT_TYPE = "public"

# Scopes must exactly match what Kiro IDE requests, otherwise the CodeWhisperer
# token verifier rejects our access_token even though it's "valid". These are
# the same five scopes the real Kiro desktop client uses.
IDC_SCOPES = (
    "codewhisperer:completions",
    "codewhisperer:analysis",
    "codewhisperer:conversations",
    "codewhisperer:transformations",
    "codewhisperer:taskassist",
)

IDC_GRANT_TYPES = (
    "urn:ietf:params:oauth:grant-type:device_code",
    "refresh_token",
)

# AWS Builder ID (Amazon personal AWS accounts) uses this fixed Start URL —
# reserved for the Method 2 default if the caller doesn't supply one.
BUILDER_ID_START_URL = "https://view.awsapps.com/start"


def _oidc_endpoint(region: str) -> str:
    return f"https://oidc.{region}.amazonaws.com"


# --- HTTP helpers (share style with kiro.py) ---------------------------------


def _http_post_json(url: str, payload: dict, headers: dict, proxy_url, timeout: int = 30):
    """POST JSON. Returns (http_status, parsed_body_or_None, raw_text)."""
    body = json.dumps(payload).encode("utf-8")
    base_headers = {"Content-Type": "application/json", "Accept": "application/json"}
    base_headers.update(headers or {})
    req = urllib.request.Request(url, data=body, method="POST", headers=base_headers)

    handlers = []
    if proxy_url:
        handlers.append(urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url}))
    opener = urllib.request.build_opener(*handlers) if handlers else urllib.request.build_opener()

    try:
        with opener.open(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", "replace")
            try:
                return resp.status, json.loads(raw), raw
            except json.JSONDecodeError:
                return resp.status, None, raw
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", "replace")
        try:
            return exc.code, json.loads(raw), raw
        except json.JSONDecodeError:
            return exc.code, None, raw


# --- OIDC 3-step protocol ----------------------------------------------------


def register_client(region: str, start_url: str, proxy_url) -> dict:
    """AWS SSO OIDC RegisterClient. Returns dict with clientId/clientSecret
    (both strings, opaque). The pair is ephemeral (~days) — we re-register on
    every login, matching kiro.rs behavior for simplicity."""
    url = f"{_oidc_endpoint(region)}/client/register"
    payload = {
        "clientName": IDC_CLIENT_NAME,
        "clientType": IDC_CLIENT_TYPE,
        "scopes": list(IDC_SCOPES),
        "grantTypes": list(IDC_GRANT_TYPES),
        "issuerUrl": start_url,
    }
    headers = {"Host": f"oidc.{region}.amazonaws.com"}
    status, parsed, raw = _http_post_json(url, payload, headers, proxy_url)
    if not (200 <= status < 300) or not parsed:
        raise LoginError(f"IdC RegisterClient HTTP {status}: {raw[:300]}")
    if "clientId" not in parsed or "clientSecret" not in parsed:
        raise LoginError(f"IdC RegisterClient missing clientId/clientSecret in {raw[:300]}")
    return parsed


def start_device_authorization(region: str, start_url: str, client_id: str, client_secret: str, proxy_url) -> dict:
    """AWS SSO OIDC StartDeviceAuthorization. Returns dict with
    verificationUri, verificationUriComplete, deviceCode, userCode, interval,
    expiresIn."""
    url = f"{_oidc_endpoint(region)}/device_authorization"
    payload = {
        "clientId": client_id,
        "clientSecret": client_secret,
        "startUrl": start_url,
    }
    headers = {"Host": f"oidc.{region}.amazonaws.com"}
    status, parsed, raw = _http_post_json(url, payload, headers, proxy_url)
    if not (200 <= status < 300) or not parsed:
        raise LoginError(f"IdC StartDeviceAuthorization HTTP {status}: {raw[:300]}")
    for key in ("deviceCode", "userCode", "verificationUri", "verificationUriComplete", "expiresIn", "interval"):
        if key not in parsed:
            raise LoginError(f"IdC device-auth missing {key!r}: {raw[:300]}")
    return parsed


def poll_create_token(
    region: str,
    client_id: str,
    client_secret: str,
    device_code: str,
    interval: int,
    expires_in: int,
    proxy_url,
    progress: ProgressCallback,
) -> dict:
    """Poll CreateToken until user completes authorization. Returns dict with
    accessToken/refreshToken/expiresIn/tokenType.

    OIDC error codes handled per RFC 8628 §3.5:
      - authorization_pending  → keep polling
      - slow_down              → interval += 5
      - expired_token          → raise (device code lifetime up)
      - access_denied          → raise (user hit Deny)
    """
    url = f"{_oidc_endpoint(region)}/token"
    payload = {
        "clientId": client_id,
        "clientSecret": client_secret,
        "grantType": IDC_GRANT_TYPES[0],
        "deviceCode": device_code,
    }
    headers = {"Host": f"oidc.{region}.amazonaws.com"}

    deadline = time.time() + max(60, int(expires_in))
    tick = max(1, int(interval))
    while time.time() < deadline:
        time.sleep(tick)
        status, parsed, raw = _http_post_json(url, payload, headers, proxy_url)
        if 200 <= status < 300 and parsed and parsed.get("accessToken"):
            return parsed
        err = (parsed or {}).get("error", "") if parsed else ""
        if err == "authorization_pending":
            continue
        if err == "slow_down":
            tick += 5
            continue
        if err in ("expired_token", "access_denied"):
            raise LoginError(f"IdC token poll rejected: {err} — {raw[:200]}")
        # Unknown → log and keep polling (transient AWS-side blip)
        progress("info", f"IdC token poll transient status={status} err={err!r}")
    raise LoginError("IdC device authorization timed out")


# --- Post-processing (reuse kiro.py's builders) -------------------------------


def _reuse_kiro_helpers():
    """Delayed import to avoid circular dependency with kiro.py."""
    from . import kiro
    return kiro


def _build_idc_token_dict(
    token_resp: dict,
    region: str,
    start_url: str,
    client_id: str,
    client_secret: str,
) -> dict:
    """Adapt AWS SSO OIDC CreateToken response into the ``token`` dict shape
    that gets threaded through kiro.py's shared post-processing helpers.

    Not identical to the M365 external_idp shape:
      - carries ``client_secret`` (IdC refresh needs it — external_idp doesn't)
      - carries ``start_url`` (IdC-specific)
      - deliberately omits ``token_endpoint`` (kiro-rs treats presence of
        that field as a signal that this is external_idp → refresh uses the
        wrong request shape → AWS returns 400 invalid_request)
    """
    return {
        "auth_method": "idc",
        "access_token": token_resp.get("accessToken", ""),
        "refresh_token": token_resp.get("refreshToken", ""),
        "expires_in": int(token_resp.get("expiresIn") or 0),
        "profile_arn": "",
        "client_id": client_id,
        "client_secret": client_secret,     # NEW — required for IdC refresh
        "start_url": start_url,             # NEW — Enterprise/IdC field
        "scopes": " ".join(IDC_SCOPES),
    }


def _postprocess_kiro_rs_for_idc(rs_obj: dict, token: dict) -> None:
    """Patch a ``_build_kiro_rs_json`` result to match what kiro-rs itself
    writes for an IdC-source credential (see admin/service.rs::start_idc_login
    → KiroCredentials template). In-place.

    Adds camelCase fields kiro-rs expects; removes fields whose presence would
    make ``Credentials::is_external_idp()`` misclassify this as M365."""
    rs_obj["provider"] = "Enterprise"
    if token.get("client_secret"):
        rs_obj["clientSecret"] = token["client_secret"]
    if token.get("start_url"):
        rs_obj["startUrl"] = token["start_url"]
    # Drop fields that would trip is_external_idp() heuristics
    rs_obj.pop("tokenEndpoint", None)
    rs_obj.pop("issuerUrl", None)


def _postprocess_cpa_for_idc(cpa_obj: dict, token: dict) -> None:
    """Same idea as `_postprocess_kiro_rs_for_idc` but for CPA's snake_case
    single-account file. In-place."""
    if token.get("client_secret"):
        cpa_obj["client_secret"] = token["client_secret"]
    if token.get("start_url"):
        cpa_obj["start_url"] = token["start_url"]
    # Drop M365-only fields — CPA-Plus honors is_external_idp too
    cpa_obj.pop("token_endpoint", None)
    cpa_obj.pop("issuer_url", None)


# --- Public entrypoint -------------------------------------------------------


def run(req: LoginRequest, progress: ProgressCallback = noop_progress) -> LoginResult:
    """Drive AWS IAM Identity Center SSO login end-to-end.

    Required ``req.extras``:
      - ``sso_start_url``   — e.g. ``https://d-906677dcf9.awsapps.com/start``
      - ``username``        — IdC username (NOT necessarily an email)
      - ``password``        — initial or current password

    Optional:
      - ``region``          — defaults to ``us-east-1``
      - ``totp_secret``     — if empty AND account is first-login, the state
                              machine will register a fresh Authenticator and
                              scrape the secret; otherwise used for MFA
      - ``email``           — display email for filename/JSON (falls back to
                              username if unset)
      - ``headless``        — bool, default True
    """
    start_url = (req.extras.get("sso_start_url") or "").strip()
    if not start_url:
        raise LoginError("kiro_idc requires extras.sso_start_url")

    username = (req.extras.get("username") or req.extras.get("email") or req.label or "").strip()
    password = (req.extras.get("password") or "").strip()
    if not username or not password:
        raise LoginError("kiro_idc requires extras.username + extras.password")

    region = (req.extras.get("region") or "us-east-1").strip() or "us-east-1"
    totp_secret = (req.extras.get("totp_secret") or "").strip()
    email = (req.extras.get("email") or "").strip()
    headless = bool(req.extras.get("headless", True))

    proxy_url = resolve_proxy(req.proxy)
    progress("info", f"proxy → {proxy_url or 'direct'}")

    # Step 1 — RegisterClient
    progress("step", "IdC RegisterClient …")
    reg = register_client(region, start_url, proxy_url)
    client_id = reg["clientId"]
    client_secret = reg["clientSecret"]
    progress("info", f"IdC clientId={client_id[:16]}… expires_in={reg.get('clientSecretExpiresAt', '?')}")

    # Step 2 — StartDeviceAuthorization
    progress("step", "IdC StartDeviceAuthorization …")
    device = start_device_authorization(region, start_url, client_id, client_secret, proxy_url)
    verify_uri = device["verificationUriComplete"]
    device_code = device["deviceCode"]
    user_code = device.get("userCode", "")
    poll_interval = int(device.get("interval") or 5)
    poll_expires = int(device.get("expiresIn") or 600)
    progress("url", verify_uri)
    progress("info", f"userCode={user_code}  interval={poll_interval}s  expires_in={poll_expires}s")

    # Step 3 — Camoufox drives the verification URI
    progress("step", "opening verification URI in Camoufox …")
    resolved_out_dir = os.path.abspath(req.out_dir or os.getcwd())
    idc_result = _camoufox.capture_idc_signin(
        verify_uri=verify_uri,
        user_code=user_code,
        proxy=proxy_url,
        username=username,
        password=password,
        totp_secret=totp_secret,
        progress=progress,
        timeout=req.timeout,
        headless=headless,
        out_dir=resolved_out_dir,
    )

    # Step 4 — poll CreateToken (user has clicked Allow by now)
    progress("step", "polling IdC CreateToken …")
    tok = poll_create_token(
        region, client_id, client_secret, device_code,
        poll_interval, poll_expires, proxy_url, progress,
    )
    progress("info", f"IdC token acquired  expires_in={tok.get('expiresIn')}s")

    # Step 5 — hand off to kiro.py's shared post-processing
    kiro = _reuse_kiro_helpers()
    token = _build_idc_token_dict(tok, region, start_url, client_id, client_secret)

    progress("step", "resolving CodeWhisperer profile ARN …")
    # IdC tokens are AWS-native SSO tokens (Bearer only) — do NOT send the
    # ``TokenType: EXTERNAL_IDP`` header the M365 leg uses; codewhisperer
    # returns 403 AccessDeniedException if you do.
    token["profile_arn"] = kiro._list_available_profiles(
        token["access_token"], region, external_idp=False, proxy_url=proxy_url,
    )
    arn_region = kiro._region_from_profile_arn(token["profile_arn"])
    if arn_region:
        region = arn_region

    display_email = email or idc_result.email or username
    display_username = idc_result.email or kiro._derive_username(token["access_token"]) or username
    safe = kiro._sanitize_file_component(display_username) or f"kiro-{int(time.time() * 1000)}"

    out_dir = os.path.abspath(req.out_dir or os.getcwd())
    os.makedirs(out_dir, exist_ok=True)

    cpa_obj = kiro._build_cpa_json(token, region, display_email)
    _postprocess_cpa_for_idc(cpa_obj, token)
    # Custom replay fields — CPA ignores unknown keys, useful for humans and
    # for any Enterprise fork that wants to auto-recover the IdC login.
    cpa_obj["sso_username"] = username
    if idc_result.new_password:
        cpa_obj["generated_password"] = idc_result.new_password
    if idc_result.registered_totp_secret:
        cpa_obj["generated_totp_secret"] = idc_result.registered_totp_secret

    cpa_path = os.path.join(out_dir, kiro._cpa_filename(cpa_obj))
    fd = os.open(cpa_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(cpa_obj, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    progress("done", f"saved {cpa_path}")

    rs_obj = kiro._build_kiro_rs_json(token, region, display_email)
    _postprocess_kiro_rs_for_idc(rs_obj, token)
    rs_path = os.path.join(out_dir, f"kiro-rs-{safe}.json")
    fd = os.open(rs_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(rs_obj, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    progress("done", f"saved {rs_path}")

    creds_path = os.path.join(out_dir, "credentials.kiro-rs.json")
    total, replaced = kiro._append_to_credentials(creds_path, rs_obj)
    verb = "updated" if replaced else "appended"
    progress("done", f"{verb} credentials.kiro-rs.json (total {total} entries)")

    extra_out = {
        "auth_method": "idc",
        "profile_arn": token["profile_arn"],
        "region": region,
        "sso_start_url": start_url,
        "kiro_rs_path": rs_path,
        "credentials_path": creds_path,
    }
    if idc_result.new_password:
        extra_out["new_password"] = idc_result.new_password
        extra_out["old_password"] = password
        progress("done", f"⚠ password rotated → new_password={idc_result.new_password}")
    if idc_result.registered_totp_secret:
        extra_out["totp_secret"] = idc_result.registered_totp_secret
        progress("done", f"⚠ MFA registered → totp_secret={idc_result.registered_totp_secret}")

    return LoginResult(
        provider="kiro",
        identity=display_username,
        out_path=cpa_path,
        extra=extra_out,
    )
