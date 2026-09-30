#!/usr/bin/env bash
set -euo pipefail

response_file="$(mktemp)"
headers_file="$(mktemp)"
trap 'rm -f "$response_file" "$headers_file"' EXIT

status="$(
  curl --silent --show-error \
    --max-time 15 \
    --dump-header "$headers_file" \
    --output "$response_file" \
    --write-out '%{http_code}' \
    --request POST \
    'http://127.0.0.1:13114/' \
    --header 'Content-Type: application/json' \
    --header 'Accept: application/json, text/event-stream' \
    --data-binary '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"runtime-v2-probe","version":"1.0"}}}'
)"

test "$status" = 200
grep -Eqi '^mcp-session-id:' "$headers_file"
grep -q '"jsonrpc":"2.0"' "$response_file"
grep -q '"serverInfo"' "$response_file"
