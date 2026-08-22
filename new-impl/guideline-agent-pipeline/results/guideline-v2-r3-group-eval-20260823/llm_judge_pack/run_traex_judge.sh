#!/usr/bin/env bash
set -euo pipefail
OUT_DIR="${1:-judge_outputs}"
mkdir -p "$OUT_DIR"
for prompt in prompts/*.md; do
  name="$(basename "$prompt" .md)"
  timeout "${TRAE_JUDGE_TIMEOUT:-30m}" traecli exec -o "$OUT_DIR/$name.json" < "$prompt"
done
