#!/usr/bin/env bash
# Deploy cpa-login-hub to vps196 (Debian 13 arm64, CPA runs in Docker).
#
# What it does:
#   1. rsync source to vps196:/root/build/cpa-login-hub/  (excludes .git, venv, dylibs)
#   2. Build the linux/arm64 .so natively on vps196 (needs go 1.26 at /usr/local/go/bin/go)
#   3. Back up the old .so, copy new .so to /data/cli-proxy-api/plugins/linux/arm64/
#   4. rsync worker/ + panel/ to the sibling bundle dir
#   5. docker restart cli-proxy-api
#   6. Tail startup logs
#
# Preconditions:
#   - ~/.ssh/config alias "vps196" resolves to the correct host
#   - Go 1.26 installed at /usr/local/go on the remote host
#   - rsync installed on the remote host
#
# Usage:  bash scripts/deploy_vps196.sh
set -euo pipefail

SSH_HOST="vps196"
REMOTE_BUILD_DIR="/root/build/cpa-login-hub"
REMOTE_PLUGIN_DIR="/data/cli-proxy-api/plugins/linux/arm64"

echo "→ rsync source to ${SSH_HOST}:${REMOTE_BUILD_DIR}/"
rsync -az --delete \
  --exclude '.git/' --exclude '*.dylib' --exclude '*.so' --exclude '*.h' \
  --exclude '*.tar.gz' --exclude '.venv/' --exclude '__pycache__/' --exclude '*.pyc' \
  --exclude '.setup_done' --exclude '.setup.lock' \
  --exclude 'worker/runs/' --exclude 'stage/' --exclude 'examples/' \
  ./ "${SSH_HOST}:${REMOTE_BUILD_DIR}/"

echo "→ building linux/arm64 .so on ${SSH_HOST}"
ssh "${SSH_HOST}" "
  set -e
  cd ${REMOTE_BUILD_DIR}
  export PATH=/usr/local/go/bin:\$PATH
  export CGO_ENABLED=1
  go build -buildmode=c-shared -o cpa-login-hub.so .
  ls -la cpa-login-hub.so
"

echo "→ installing to CPA plugins dir + restarting container"
ssh "${SSH_HOST}" "
  set -e
  STAMP=\$(date -u +%Y%m%d-%H%M%S)
  if [ -f ${REMOTE_PLUGIN_DIR}/cpa-login-hub.so ]; then
    cp -a ${REMOTE_PLUGIN_DIR}/cpa-login-hub.so ${REMOTE_PLUGIN_DIR}/cpa-login-hub.so.bak-\$STAMP
  fi
  cp ${REMOTE_BUILD_DIR}/cpa-login-hub.so ${REMOTE_PLUGIN_DIR}/cpa-login-hub.so

  mkdir -p ${REMOTE_PLUGIN_DIR}/cpa-login-hub
  rsync -a --delete \
    --exclude .venv/ --exclude __pycache__/ --exclude '*.pyc' \
    --exclude .setup_done --exclude .setup.lock --exclude runs/ \
    ${REMOTE_BUILD_DIR}/worker/ ${REMOTE_PLUGIN_DIR}/cpa-login-hub/worker/

  echo '--- files in place ---'
  ls -la ${REMOTE_PLUGIN_DIR}/cpa-login-hub.so ${REMOTE_PLUGIN_DIR}/cpa-login-hub/

  echo '--- docker restart ---'
  docker restart cli-proxy-api

  echo '--- waiting 6s for startup ---'
  sleep 6
  docker logs --tail 40 cli-proxy-api 2>&1 | tail -30
"

echo ""
echo "✅ deploy done. Test at https://cpa.muxpay.xyz/management.html"
echo "   → click OAuth Login → CPA Login Hub → fill form → submit"
