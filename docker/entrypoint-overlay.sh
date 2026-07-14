#!/usr/bin/env bash
# entrypoint-overlay.sh — link the pre-warmed venv into the plugin bundle,
# then hand off to CPA's own entrypoint.
#
# The pre-warmed venv lives at /opt/cpa-login-hub-venv (built during
# Dockerfile.overlay). The plugin locates its venv at:
#   $CPA_PLUGIN_DIR/cpa-login-hub/worker/.venv
# We symlink the pre-warmed one there so venv_setup.go's sentinel check
# short-circuits on first login.
#
# If the plugin bundle isn't mounted / installed yet, all we do is skip
# the symlink — no harm done.

set -e

PLUGIN_DIRS=(
  # CPA scans platform-specific subdirs first (see platform.go:candidateDirs).
  "/CLIProxyAPI/plugins/linux/arm64/cpa-login-hub/worker"
  "/CLIProxyAPI/plugins/linux/amd64/cpa-login-hub/worker"
  "/CLIProxyAPI/plugins/cpa-login-hub/worker"
)

link_venv() {
  local worker_dir="$1"
  if [ ! -d "$worker_dir" ]; then
    return 0
  fi
  local venv_link="$worker_dir/.venv"
  local sentinel="$worker_dir/.setup_done"
  local req_hash
  req_hash=$(sha256sum "$worker_dir/requirements.txt" 2>/dev/null | awk '{print $1}') || return 0
  # Only relink if the venv link is missing or stale.
  if [ -L "$venv_link" ] && [ -e "$venv_link" ]; then
    return 0
  fi
  rm -rf "$venv_link"
  ln -s /opt/cpa-login-hub-venv "$venv_link"
  # Write the sentinel so venv_setup.go's fingerprint check skips its
  # own install path.
  echo -n "$req_hash" > "$sentinel"
  echo "[entrypoint-overlay] linked pre-warmed venv into $worker_dir"
}

for d in "${PLUGIN_DIRS[@]}"; do
  link_venv "$d"
done

# Hand off to CPA's original process. The base image has no ENTRYPOINT
# and CMD = ["./CLIProxyAPI"] with WorkingDir = /CLIProxyAPI. If the
# caller passes args (e.g. docker run image -flag), use those; otherwise
# fall back to the base image's default CMD.
cd /CLIProxyAPI
if [ $# -gt 0 ]; then
  exec "$@"
else
  exec ./CLIProxyAPI
fi
