#!/usr/bin/env python3
"""Expose local ``traex exec`` as the minimal OpenAI Chat Completions API IRIS uses.

This bridge changes only the LLM transport.  IRIS continues to construct its
own prompts, label source/sink candidates, generate its project-specific
CodeQL query, run CodeQL, perform posthoc filtering, and evaluate the result.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import tempfile
import threading
import time
import uuid
import re
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


def render_prompt(messages: list[dict[str, Any]], require_json_object: bool) -> str:
    """Preserve IRIS's system and user roles in one TraeX prompt."""

    parts = [
        "You are serving as the LLM backend for a fixed security-analysis pipeline.",
        "Follow the system instruction and user request below. Do not inspect files, run tools,",
        "or change the task. Return only the requested answer.",
        "",
    ]
    for message in messages:
        role = str(message.get("role", "user")).upper()
        content = message.get("content", "")
        if not isinstance(content, str):
            raise ValueError("chat message content must be a string")
        parts.extend((f"[{role}]", content, ""))
    if require_json_object:
        parts.extend(
            (
                "The caller requires one valid JSON object and nothing else.",
                "Do not wrap it in Markdown fences.",
            )
        )
    return "\n".join(parts)


def response_payload(model: str, content: str) -> dict[str, Any]:
    return {
        "id": f"chatcmpl-traex-{uuid.uuid4().hex}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": content},
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
    }


class TraexBackend:
    def __init__(
        self,
        *,
        traex_bin: str,
        model: str,
        workdir: Path,
        timeout_seconds: int,
        max_concurrency: int,
        metrics_log: Path | None,
    ) -> None:
        self.traex_bin = traex_bin
        self.model = model
        self.workdir = workdir
        self.timeout_seconds = timeout_seconds
        self._semaphore = threading.BoundedSemaphore(max_concurrency)
        self.metrics_log = metrics_log
        self._metrics_lock = threading.Lock()

    def _record_metric(self, metric: dict[str, Any]) -> None:
        if self.metrics_log is None:
            return
        self.metrics_log.parent.mkdir(parents=True, exist_ok=True)
        with self._metrics_lock:
            with self.metrics_log.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(metric, sort_keys=True) + "\n")
                handle.flush()

    def complete(self, request: dict[str, Any], headers: Any) -> dict[str, Any]:
        messages = request.get("messages")
        if not isinstance(messages, list) or not messages:
            raise ValueError("messages must be a non-empty list")
        request_model = request.get("model")
        if request_model and str(request_model).lower() not in {
            self.model.lower(),
            "deepseek-v4-flash",
            "deepseek-v4-pro",
        }:
            raise ValueError(f"bridge only serves {self.model}, got {request_model}")
        response_format = request.get("response_format")
        require_json_object = isinstance(response_format, dict) and response_format.get("type") == "json_object"
        prompt = render_prompt(messages, require_json_object=require_json_object)
        prompt_digest = hashlib.sha256(prompt.encode("utf-8")).hexdigest()[:16]
        request_id = f"traex-{uuid.uuid4().hex}"
        run_id = str(headers.get("X-Iris-Run-Id", ""))
        case_id = str(headers.get("X-Iris-Case-Id", ""))

        with self._semaphore:
            with tempfile.TemporaryDirectory(prefix="iris-traex-") as temp_dir:
                output_path = Path(temp_dir) / "final.txt"
                command = [
                    self.traex_bin,
                    "exec",
                    "--ephemeral",
                    "--skip-git-repo-check",
                    "-C",
                    str(self.workdir),
                    "-m",
                    self.model,
                    "-s",
                    "danger-full-access",
                    "--output-last-message",
                    str(output_path),
                    "-",
                ]
                started = time.monotonic()
                try:
                    completed = subprocess.run(
                        command,
                        input=prompt,
                        text=True,
                        capture_output=True,
                        timeout=self.timeout_seconds,
                        check=False,
                    )
                except subprocess.TimeoutExpired:
                    self._record_metric(
                        {
                            "schema_version": "iris_native_traex_bridge_call.v1",
                            "request_id": request_id,
                            "recorded_at": int(time.time()),
                            "run_id": run_id,
                            "case_id": case_id,
                            "model": self.model,
                            "prompt_sha256_prefix": prompt_digest,
                            "elapsed_seconds": round(time.monotonic() - started, 3),
                            "status": "timeout",
                            "traex_reported_total_tokens": None,
                        }
                    )
                    raise
                elapsed_seconds = round(time.monotonic() - started, 3)
                token_match = re.search(r"tokens used\s*\n\s*([0-9,]+)", completed.stdout)
                reported_tokens = int(token_match.group(1).replace(",", "")) if token_match else None
                if completed.returncode != 0:
                    self._record_metric(
                        {
                            "schema_version": "iris_native_traex_bridge_call.v1",
                            "request_id": request_id,
                            "recorded_at": int(time.time()),
                            "run_id": run_id,
                            "case_id": case_id,
                            "model": self.model,
                            "prompt_sha256_prefix": prompt_digest,
                            "elapsed_seconds": elapsed_seconds,
                            "status": "nonzero_exit",
                            "returncode": completed.returncode,
                            "traex_reported_total_tokens": reported_tokens,
                        }
                    )
                    raise RuntimeError(
                        "traex exec failed "
                        f"(rc={completed.returncode}, prompt_sha256={prompt_digest}): "
                        f"{completed.stderr[-1200:]}"
                    )
                if not output_path.is_file():
                    raise RuntimeError(f"traex did not produce final output (prompt_sha256={prompt_digest})")
                content = output_path.read_text(encoding="utf-8").strip()
                if not content:
                    raise RuntimeError(f"traex produced empty final output (prompt_sha256={prompt_digest})")
                self._record_metric(
                    {
                        "schema_version": "iris_native_traex_bridge_call.v1",
                        "request_id": request_id,
                        "recorded_at": int(time.time()),
                        "run_id": run_id,
                        "case_id": case_id,
                        "model": self.model,
                        "prompt_sha256_prefix": prompt_digest,
                        "response_sha256": hashlib.sha256(content.encode("utf-8")).hexdigest(),
                        "elapsed_seconds": elapsed_seconds,
                        "status": "completed",
                        "traex_reported_total_tokens": reported_tokens,
                        "response_characters": len(content),
                    }
                )
                return response_payload(self.model, content)


class Handler(BaseHTTPRequestHandler):
    backend: TraexBackend

    def log_message(self, format: str, *args: Any) -> None:
        # Avoid logging prompts or source snippets. Access metadata is sufficient.
        print(f"{self.address_string()} {format % args}", flush=True)

    def _send_json(self, status: HTTPStatus, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, ensure_ascii=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path == "/healthz":
            self._send_json(HTTPStatus.OK, {"status": "ok", "transport": "traex"})
            return
        self._send_json(HTTPStatus.NOT_FOUND, {"error": {"message": "not found"}})

    def do_POST(self) -> None:
        if self.path.rstrip("/") != "/v1/chat/completions":
            self._send_json(HTTPStatus.NOT_FOUND, {"error": {"message": "not found"}})
            return
        try:
            content_length = int(self.headers.get("Content-Length", "0"))
            if content_length <= 0 or content_length > 8 * 1024 * 1024:
                raise ValueError("invalid Content-Length")
            payload = json.loads(self.rfile.read(content_length).decode("utf-8"))
            if not isinstance(payload, dict):
                raise ValueError("request body must be a JSON object")
            self._send_json(HTTPStatus.OK, self.backend.complete(payload, self.headers))
        except subprocess.TimeoutExpired:
            self._send_json(HTTPStatus.GATEWAY_TIMEOUT, {"error": {"message": "traex request timed out"}})
        except (ValueError, RuntimeError) as error:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": {"message": str(error)}})
        except Exception as error:  # pragma: no cover - protects a long native run.
            self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": {"message": str(error)}})


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--traex-bin", default="traex")
    parser.add_argument("--model", choices=("DeepSeek-V4-Flash", "DeepSeek-V4-Pro"), default="DeepSeek-V4-Flash")
    parser.add_argument("--workdir", type=Path, default=Path.cwd())
    parser.add_argument("--timeout-seconds", type=int, default=900)
    parser.add_argument("--max-concurrency", type=int, default=1)
    parser.add_argument("--metrics-log", type=Path)
    args = parser.parse_args()
    if args.max_concurrency < 1:
        raise SystemExit("--max-concurrency must be positive")
    if args.timeout_seconds < 1:
        raise SystemExit("--timeout-seconds must be positive")

    Handler.backend = TraexBackend(
        traex_bin=args.traex_bin,
        model=args.model,
        workdir=args.workdir.resolve(),
        timeout_seconds=args.timeout_seconds,
        max_concurrency=args.max_concurrency,
        metrics_log=args.metrics_log.resolve() if args.metrics_log else None,
    )
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(
        json.dumps(
            {
                "status": "ready",
                "host": args.host,
                "port": args.port,
                "model": args.model,
                "max_concurrency": args.max_concurrency,
            },
            sort_keys=True,
        ),
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        return 130
    finally:
        server.server_close()


if __name__ == "__main__":
    raise SystemExit(main())
