#!/usr/bin/env python3
import json
import os
import subprocess
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

ROOT = os.path.abspath(os.path.dirname(__file__))
BIN = os.path.join(ROOT, "oh-my-posh", "oh-my-posh")
THEME = os.path.join(ROOT, "oh-my-posh", "themes", "1_shell.omp.json")
REVISION = "7ec9fb8eb0f091354795eca7b024332a59e6614f"


def run_omp(args, timeout=8):
    env = os.environ.copy()
    env.setdefault("HOME", os.path.join(ROOT, ".home"))
    env.setdefault("TERM", "xterm-256color")
    os.makedirs(env["HOME"], exist_ok=True)
    return subprocess.run([BIN] + args, cwd=ROOT, env=env, capture_output=True, text=True, timeout=timeout)


class Handler(BaseHTTPRequestHandler):
    server_version = "oh-my-posh-runtime/1.0"

    def write(self, status, body, content_type="application/json"):
        if isinstance(body, (dict, list)):
            payload = json.dumps(body, sort_keys=True).encode("utf-8")
        elif isinstance(body, str):
            payload = body.encode("utf-8")
        else:
            payload = body
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/health":
            try:
                result = run_omp(["version"], timeout=5)
                status = 200 if result.returncode == 0 else 503
                self.write(status, {
                    "status": "ok" if status == 200 else "unhealthy",
                    "revision": REVISION,
                    "version": result.stdout.strip() or result.stderr.strip(),
                    "returncode": result.returncode,
                })
            except Exception as exc:
                self.write(503, {"status": "error", "error": str(exc)})
        elif path == "/render":
            try:
                result = run_omp([
                    "print", "primary",
                    "--config", THEME,
                    "--plain",
                    "--shell", "bash",
                    "--pwd", "/tmp",
                ], timeout=8)
                if result.returncode == 0:
                    self.write(200, result.stdout or "rendered\n", "text/plain; charset=utf-8")
                else:
                    self.write(503, {"status": "render_failed", "stderr": result.stderr, "returncode": result.returncode})
            except Exception as exc:
                self.write(503, {"status": "error", "error": str(exc)})
        elif path == "/version":
            try:
                result = run_omp(["version"], timeout=5)
                self.write(200 if result.returncode == 0 else 503, result.stdout or result.stderr, "text/plain; charset=utf-8")
            except Exception as exc:
                self.write(503, str(exc), "text/plain; charset=utf-8")
        else:
            self.write(404, {"error": "not found"})

    def log_message(self, fmt, *args):
        return


if __name__ == "__main__":
    port = int(os.environ.get("RUNTIME_PORT", "19076"))
    httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    httpd.serve_forever()
