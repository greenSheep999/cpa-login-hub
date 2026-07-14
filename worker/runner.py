"""cpa-login-hub Python worker entry point.

Invoked by the Go plugin as ``python -m worker.runner``. Delegates to
``worker.helpers.run_worker`` (vendored from muxhub scripts/login-hub —
same stdin/stdout protocol) so the browser state machines stay identical.

Protocol:
  stdin:  {"provider": "<name>", "label": "...", "proxy": "...",
           "out_dir": "...", "timeout": 600, "extras": {...}}
  stdout: stream of JSON lines, each ``{"kind": str, "msg": str, ...}``.
          Terminal line is ``{"kind": "_result", "data": {...}}`` on
          success or ``{"kind": "_error", "msg": "..."}`` on failure.
"""

from __future__ import annotations

import os
import sys

# When run as ``python -m worker.runner`` from the plugin bundle root,
# ``worker/`` is on sys.path (that's what -m does). helpers/ is a sub-
# package so ``worker.helpers.run_worker`` imports cleanly. run_worker
# was originally written to be invoked as ``python -m helpers.run_worker``
# from the login-hub root; we thin-wrap it here to keep that import
# style working when helpers/ lives under worker/.
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from helpers.run_worker import main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(main())
