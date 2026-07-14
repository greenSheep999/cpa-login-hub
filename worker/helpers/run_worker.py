"""Subprocess entry-point for a single login job.

Invoked by ``server.py`` as ``python -m helpers.run_worker``. Reads a JSON
job spec from stdin, runs the right helper, and streams progress events to
stdout as JSON lines (one per line). Exits 0 on success, non-zero on failure.

Why a subprocess: ``camoufox.sync_api`` uses Playwright's sync wrapper, which
spins up an internal asyncio loop per thread. Reusing a worker thread for a
second login surfaces "Sync API inside the asyncio loop" errors because the
prior loop state lingers. A fresh process per job sidesteps the whole class
of teardown bugs and guarantees the browser plus its child processes are
collected when the job ends.

Protocol:
  stdin:  {"provider": "antigravity", "label": "...", "proxy": "...",
           "out_dir": "...", "timeout": 600, "extras": {...}}
  stdout: stream of JSON lines, each {"kind": str, "msg": str}.
          The final line is always {"kind": "_result", "data": {...}} on
          success or {"kind": "_error", "msg": "..."} on failure.
"""

from __future__ import annotations

import json
import os
import sys

# Make ``helpers`` importable when run as ``python -m helpers.run_worker``
# from any cwd: parent dir of this file is the project root.
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from dataclasses import asdict  # noqa: E402

from helpers import antigravity, grok, kiro, openai  # noqa: E402
from helpers.common import LoginError, LoginRequest  # noqa: E402

PROVIDERS = {
    "antigravity": antigravity.run,
    "kiro": kiro.run,
    "grok": grok.run,
    "openai": openai.run,
}


def _emit(kind: str, msg: str = "", **extra) -> None:
    payload = {"kind": kind, "msg": msg, **extra}
    sys.stdout.write(json.dumps(payload, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def main() -> int:
    raw = sys.stdin.read()
    try:
        spec = json.loads(raw)
    except Exception as exc:  # noqa: BLE001
        _emit("_error", f"invalid worker spec: {exc}")
        return 2

    provider = spec.get("provider", "")
    runner = PROVIDERS.get(provider)
    if not runner:
        _emit("_error", f"unknown provider {provider!r}")
        return 2

    req = LoginRequest(
        label=spec.get("label", "") or "",
        proxy=spec.get("proxy") or None,
        out_dir=spec.get("out_dir", "") or "",
        timeout=int(spec.get("timeout", 600) or 600),
        extras=spec.get("extras", {}) or {},
    )

    def progress(kind: str, msg: str) -> None:
        _emit(kind, msg)

    try:
        result = runner(req, progress)
        _emit("_result", "", data=asdict(result))
        return 0
    except LoginError as exc:
        _emit("_error", str(exc))
        return 1
    except Exception as exc:  # noqa: BLE001
        import traceback
        _emit("_error", f"{type(exc).__name__}: {exc}\n{traceback.format_exc()}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
