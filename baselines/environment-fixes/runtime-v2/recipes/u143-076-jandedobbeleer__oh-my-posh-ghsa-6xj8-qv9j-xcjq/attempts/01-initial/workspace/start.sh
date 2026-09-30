#!/usr/bin/env bash
set -euo pipefail
DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
PORT=${RUNTIME_PORT:-19076}
PIDFILE="$DIR/runtime.pid"
LOGFILE="$DIR/runtime.log"
if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
  exit 0
fi
if command -v lsof >/dev/null 2>&1; then
  OLD=$(lsof -tiTCP:"$PORT" -sTCP:LISTEN 2>/dev/null || true)
  if [ -n "$OLD" ]; then
    kill $OLD 2>/dev/null || true
    sleep 1
  fi
fi
chmod +x "$DIR/oh-my-posh/oh-my-posh" "$DIR/runtime_server.py"
RUNTIME_PORT="$PORT" nohup python3 "$DIR/runtime_server.py" >"$LOGFILE" 2>&1 &
echo $! > "$PIDFILE"
for _ in $(seq 1 50); do
  if python3 - "$PORT" <<'PY' >/dev/null 2>&1
import http.client, sys
port = int(sys.argv[1])
conn = http.client.HTTPConnection('127.0.0.1', port, timeout=1)
conn.request('GET', '/health')
resp = conn.getresponse()
sys.exit(0 if resp.status == 200 else 1)
PY
  then
    exit 0
  fi
  if ! kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
    cat "$LOGFILE" >&2 || true
    exit 1
  fi
  sleep 0.2
done
cat "$LOGFILE" >&2 || true
exit 1
