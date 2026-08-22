#!/usr/bin/env bash
set -euo pipefail
run_with_timeout() {
  local seconds="${TRAE_JUDGE_TIMEOUT_SECONDS:-1800}"
  if command -v timeout >/dev/null 2>&1; then
    timeout "${seconds}s" "$@"
  elif command -v perl >/dev/null 2>&1; then
    perl -e 'alarm shift; exec @ARGV' "$seconds" "$@"
  else
    "$@"
  fi
}
OUT_DIR="${1:-judge_outputs}"
mkdir -p "$OUT_DIR"
for prompt in prompts/*.md; do
  name="$(basename "$prompt" .md)"
  run_with_timeout traecli exec --sandbox read-only -o "$OUT_DIR/$name.json" < "$prompt"
done
