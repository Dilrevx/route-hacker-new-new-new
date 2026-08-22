#!/usr/bin/env bash
set -euo pipefail
CONCURRENCY="${TRAE_JUDGE_CONCURRENCY:-1}"
case "$CONCURRENCY" in
  ""|*[!0-9]*) echo "TRAE_JUDGE_CONCURRENCY must be a positive integer" >&2; exit 2 ;;
esac
if [ "$CONCURRENCY" -lt 1 ]; then
  echo "TRAE_JUDGE_CONCURRENCY must be >= 1" >&2
  exit 2
fi
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
run_one() {
  local prompt="$1"
  local name
  name="$(basename "$prompt" .md)"
  run_with_timeout traecli exec --sandbox read-only -o "$OUT_DIR/$name.json" < "$prompt"
}
export OUT_DIR TRAE_JUDGE_TIMEOUT_SECONDS
export -f run_with_timeout run_one
find prompts -name "*.md" -type f | sort | xargs -n 1 -P "$CONCURRENCY" bash -c 'run_one "$1"' _
