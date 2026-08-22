#!/usr/bin/env bash
set -euo pipefail

# Run the first N latest-default-branch Apache audits with native Codex
# Security, then hand only the remaining queue entries to the TraeX wrapper.
# The two phases share state, so phase two never repeats terminal native rows.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNNER="$SCRIPT_DIR/run_blind_batch.sh"

RUN_ROOT="${CODEX_SECURITY_RUN_ROOT:?CODEX_SECURITY_RUN_ROOT is required}"
QUEUE="${CODEX_SECURITY_QUEUE:-$RUN_ROOT/control/queue.jsonl}"
NATIVE_CASES="${CODEX_SECURITY_NATIVE_CASES:-10}"
MODEL="${CODEX_SECURITY_MODEL:-gpt-5.5}"
EFFORT="${CODEX_SECURITY_EFFORT:-high}"
WRAPPER="${CODEX_SECURITY_WRAPPER:?CODEX_SECURITY_WRAPPER is required}"
TRAE_BIN="${CODEX_SECURITY_TRAEX_BIN:-traex}"
PLUGIN_DIR="${CODEX_SECURITY_PLUGIN_DIR:-}"
NATIVE_QUEUE="$RUN_ROOT/control/native-first-${NATIVE_CASES}-queue.jsonl"

[[ "$NATIVE_CASES" =~ ^[1-9][0-9]*$ ]] || {
  echo "CODEX_SECURITY_NATIVE_CASES must be a positive integer" >&2
  exit 64
}
[[ -x "$WRAPPER" ]] || {
  echo "TraeX wrapper is not executable: $WRAPPER" >&2
  exit 64
}
command -v "$TRAE_BIN" >/dev/null || {
  echo "TraeX binary not found: $TRAE_BIN" >&2
  exit 64
}

# The native phase must always be restricted to the first N rank-ordered rows,
# including after a restart.  The TraeX phase then reads the complete queue and
# skips those rows through their terminal state markers.
head -n "$NATIVE_CASES" "$QUEUE" >"$NATIVE_QUEUE"
[[ "$(wc -l <"$NATIVE_QUEUE" | tr -d ' ')" == "$NATIVE_CASES" ]] || {
  echo "queue has fewer than $NATIVE_CASES rows: $QUEUE" >&2
  exit 64
}

echo "phase=native cases=1-$NATIVE_CASES model=$MODEL effort=$EFFORT"
env \
  CODEX_SECURITY_RUN_ROOT="$RUN_ROOT" \
  CODEX_SECURITY_QUEUE="$NATIVE_QUEUE" \
  CODEX_SECURITY_MODEL="$MODEL" \
  CODEX_SECURITY_EFFORT="$EFFORT" \
  CODEX_SECURITY_OUTER_PARALLELISM="${CODEX_SECURITY_OUTER_PARALLELISM:-2}" \
  CODEX_SECURITY_MAX_NEW_CASES="$NATIVE_CASES" \
  CODEX_SECURITY_USE_TRAEX_WRAPPER=0 \
  "$RUNNER"

# The native runner returns only after all slots it started are terminal.
# Its state markers make the TraeX phase skip exactly those first N rows.
echo "phase=traex cases=$((NATIVE_CASES + 1))-end model=$MODEL effort=$EFFORT"
env \
  CODEX_SECURITY_RUN_ROOT="$RUN_ROOT" \
  CODEX_SECURITY_QUEUE="$QUEUE" \
  CODEX_SECURITY_MODEL="$MODEL" \
  CODEX_SECURITY_EFFORT="$EFFORT" \
  CODEX_SECURITY_OUTER_PARALLELISM="${CODEX_SECURITY_OUTER_PARALLELISM:-2}" \
  CODEX_SECURITY_USE_TRAEX_WRAPPER=1 \
  CODEX_SECURITY_WRAPPER="$WRAPPER" \
  CODEX_SECURITY_TRAEX_BIN="$TRAE_BIN" \
  CODEX_SECURITY_PLUGIN_DIR="$PLUGIN_DIR" \
  "$RUNNER"
