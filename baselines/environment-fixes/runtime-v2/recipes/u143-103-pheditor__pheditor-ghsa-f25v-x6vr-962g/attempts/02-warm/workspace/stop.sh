#!/usr/bin/env bash
set -euo pipefail

CONTAINER_NAME="${PHEDITOR_CONTAINER_NAME:-runtime-v2-u143-103-pheditor-warm}"

if docker ps --format '{{.Names}}' | grep -Fxq "$CONTAINER_NAME"; then
  docker stop "$CONTAINER_NAME" >/dev/null
fi
