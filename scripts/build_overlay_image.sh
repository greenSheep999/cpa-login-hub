#!/usr/bin/env bash
# Build the CPA + cpa-login-hub overlay image ON vps196 (arm64 native so
# no QEMU emulation), tag it locally, update compose to use it, restart.
#
# Idempotent — safe to rerun. Doesn't touch the plugin bundle deployment
# (that's what scripts/deploy_vps196.sh does).
set -euo pipefail

SSH_HOST="vps196"
IMAGE_TAG="cpa-login-hub-overlay:latest"
BUILD_CTX="/root/build/cpa-login-hub"

echo "→ rsync source (needed for worker/requirements.txt + docker/*)"
rsync -az --delete \
  --exclude '.git/' --exclude '*.dylib' --exclude '*.so' --exclude '*.h' \
  --exclude '*.tar.gz' --exclude '.venv/' --exclude '__pycache__/' --exclude '*.pyc' \
  --exclude '.setup_done' --exclude '.setup.lock' \
  --exclude 'worker/runs/' --exclude 'stage/' --exclude 'examples/' \
  ./ "${SSH_HOST}:${BUILD_CTX}/"

echo "→ docker build overlay image (native arm64 on vps196)"
ssh "${SSH_HOST}" "
  set -e
  cd ${BUILD_CTX}
  # Skip 'docker pull' — the base image is private on GHCR and the host
  # already has it cached (that's what cli-proxy-api is running from).
  # If you need to update, run 'docker pull' interactively after login.
  docker build \
    -f docker/Dockerfile.overlay \
    -t ${IMAGE_TAG} \
    --build-arg BASE=ghcr.io/daniellee2015/cli-proxy-api:latest \
    .
  echo '--- image built ---'
  docker images ${IMAGE_TAG} --format 'table {{.Repository}}\t{{.Tag}}\t{{.Size}}\t{{.CreatedAt}}'
"

echo ""
echo "→ restart cli-proxy-api using new image"
ssh "${SSH_HOST}" "
  set -e
  # Preserve the same mounts / networks / env; only swap the image.
  # The simplest way: recreate the container with docker commit is
  # brittle; we use docker run --rm with the *inspected* config.
  # However most people manage this via compose — if you use compose,
  # edit the service's image: field and \\\`docker compose up -d\\\`.
  echo 'Manual next step:'
  echo '  1. Update your compose/service to use image: ${IMAGE_TAG}'
  echo '  2. docker compose up -d cli-proxy-api  (or the equivalent)'
  echo ''
  echo 'Quick one-shot verification without compose:'
  echo '  docker rm -f cli-proxy-api'
  echo '  docker run -d --name cli-proxy-api \\\\'
  echo '    -p 8317:8317 \\\\'
  echo '    -v /data/cli-proxy-api/static:/CLIProxyAPI/static \\\\'
  echo '    -v /data/cli-proxy-api/config.yaml:/CLIProxyAPI/config.yaml \\\\'
  echo '    -v /data/cli-proxy-api/auths:/root/.cli-proxy-api \\\\'
  echo '    -v /data/cli-proxy-api/logs:/CLIProxyAPI/logs \\\\'
  echo '    -v /data/cli-proxy-api/plugins:/CLIProxyAPI/plugins \\\\'
  echo '    --restart unless-stopped \\\\'
  echo '    ${IMAGE_TAG}'
"
