#!/usr/bin/env bash
# Manual Python venv provisioner. Normally the Go plugin runs this
# automatically on first login (see venv_setup.go). Use this script when:
#   - the auto-provision fails (no network, weird pip resolver state, ...)
#   - you're developing the worker and want a venv for repl testing

set -euo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
WORKER="$HERE/worker"

if [ ! -f "$WORKER/requirements.txt" ]; then
  echo "worker/requirements.txt missing at $WORKER" >&2
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 not on PATH — install Python 3.11+ and retry" >&2
  exit 1
fi

# Nuke any half-built venv from a failed prior attempt
if [ -d "$WORKER/.venv" ]; then
  echo "removing existing $WORKER/.venv"
  rm -rf "$WORKER/.venv"
fi

python3 -m venv "$WORKER/.venv"
"$WORKER/.venv/bin/pip" install --upgrade pip
"$WORKER/.venv/bin/pip" install -r "$WORKER/requirements.txt"
"$WORKER/.venv/bin/python" -m camoufox fetch

# Record sentinel with the requirements hash so ensureVenv() short-circuits
python3 -c "
import hashlib, pathlib
h = hashlib.sha256(pathlib.Path('$WORKER/requirements.txt').read_bytes()).hexdigest()
pathlib.Path('$WORKER/.setup_done').write_text(h)
"

echo "venv ready at $WORKER/.venv"
