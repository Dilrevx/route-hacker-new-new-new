#!/usr/bin/env bash
set -euo pipefail

CONTAINER_NAME="${PHEDITOR_CONTAINER_NAME:-runtime-v2-u143-103-pheditor-warm}"
IMAGE_NAME="${PHEDITOR_IMAGE_NAME:-pheditor-vuln:latest}"
HOST_PORT="${PHEDITOR_HOST_PORT:-18185}"

if docker ps --format '{{.Names}}' | grep -Fxq "$CONTAINER_NAME"; then
  exit 0
fi

if docker ps -a --format '{{.Names}}' | grep -Fxq "$CONTAINER_NAME"; then
  docker start "$CONTAINER_NAME" >/dev/null
else
  docker run -d \
    --name "$CONTAINER_NAME" \
    --label route-hacker.runtime-v2=true \
    -p "127.0.0.1:${HOST_PORT}:80" \
    "$IMAGE_NAME" >/dev/null
fi
