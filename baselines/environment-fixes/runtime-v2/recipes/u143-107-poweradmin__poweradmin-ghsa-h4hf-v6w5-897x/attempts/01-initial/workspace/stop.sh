#!/usr/bin/env sh
set -eu

container_name="runtime-v2-poweradmin-ghsa-h4hf-v6w5-897x"
docker rm -f "$container_name" >/dev/null 2>&1 || true
