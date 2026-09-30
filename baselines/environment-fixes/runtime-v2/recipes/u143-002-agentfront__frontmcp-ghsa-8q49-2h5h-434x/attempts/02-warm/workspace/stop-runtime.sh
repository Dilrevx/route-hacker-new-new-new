#!/usr/bin/env bash
set -euo pipefail

WORKSPACE="${GCA_RUNTIME_ROOT}/runtime-v2-review-full143-20260815T120149Z/tasks/u143-002-agentfront__frontmcp-ghsa-8q49-2h5h-434x/attempts/02-warm/workspace"
PID_FILE="$WORKSPACE/.runtime-v2-frontmcp.pid"

if [ -s "$PID_FILE" ]; then
  pid="$(cat "$PID_FILE" 2>/dev/null || true)"
  if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
    process_cwd="$(readlink -f "/proc/$pid/cwd" 2>/dev/null || true)"
    if [ "$process_cwd" = "$WORKSPACE" ]; then
      kill "$pid" 2>/dev/null || true
      for _ in {1..40}; do
        kill -0 "$pid" 2>/dev/null || break
        sleep 0.25
      done
    fi
  fi
  rm -f "$PID_FILE"
fi
