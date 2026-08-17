#!/usr/bin/env python3
"""Run function packets through the official VulRAG core with TraeX as the LLM."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("_") or "case"


class TraexClient:
    def __init__(
        self,
        *,
        executable: Path,
        model: str,
        reasoning_effort: str,
        workspace: Path,
        timeout_seconds: int,
    ):
        self.executable = executable
        self.model_name = model
        self.reasoning_effort = reasoning_effort
        self.workspace = workspace
        self.timeout_seconds = timeout_seconds
        self.call_count = 0
        self.latency_seconds = 0.0
        self.input_tokens = 0
        self.output_tokens = 0
        self.usage_missing_count = 0
        self.traex_reported_tokens = 0

    def generate_text(self, prompt: list[dict[str, str]], model_settings=None) -> str:
        del model_settings
        content = "\n\n".join(
            message.get("content", "")
            for message in prompt
            if message.get("content")
        )
        instruction = (
            "Answer the following request directly. Do not use tools, inspect files, "
            "or add commentary outside the requested response format.\n\n"
            + content
        )
        started = time.monotonic()
        self.workspace.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            dir=self.workspace,
            prefix="traex-output-",
            suffix=".txt",
            delete=False,
        ) as handle:
            output_path = Path(handle.name)
        command = [
            str(self.executable),
            "exec",
            "-C",
            str(self.workspace),
            "--skip-git-repo-check",
            "--ephemeral",
            "--ignore-user-config",
            "--ignore-rules",
            "--disable",
            "hooks",
            "--sandbox",
            "read-only",
            "-m",
            self.model_name,
            "-c",
            f'model_reasoning_effort="{self.reasoning_effort}"',
            "-o",
            str(output_path),
            "-",
        ]
        try:
            completed = subprocess.run(
                command,
                input=instruction,
                text=True,
                capture_output=True,
                timeout=self.timeout_seconds,
                check=True,
            )
            transcript = completed.stdout + "\n" + completed.stderr
            token_match = re.search(r"tokens used\s*\n\s*([\d,]+)", transcript)
            if token_match:
                self.traex_reported_tokens += int(token_match.group(1).replace(",", ""))
            else:
                self.usage_missing_count += 1
            return output_path.read_text(encoding="utf-8").strip()
        finally:
            self.call_count += 1
            self.latency_seconds += time.monotonic() - started
            output_path.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packets", required=True, type=Path)
    parser.add_argument("--w6-root", required=True, type=Path)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--out-dir", required=True, type=Path)
    parser.add_argument("--traex", type=Path, default=Path.home() / ".local/bin/traex")
    parser.add_argument("--model", default="GPT-5.6-Sol")
    parser.add_argument("--reasoning-effort", default="low")
    parser.add_argument("--call-timeout-seconds", type=int, default=900)
    parser.add_argument(
        "--runtime-key",
        default=None,
        help="Unique W6 runtime-copy key; required to isolate concurrent shards.",
    )
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--start-index", type=int, default=0)
    parser.add_argument(
        "--stride",
        type=int,
        default=1,
        help="Process every Nth packet after --start-index for simple disjoint sharding.",
    )
    args = parser.parse_args()
    if args.stride < 1:
        parser.error("--stride must be at least 1")

    os.environ["VULRAG_CONFIG_PATH"] = str(args.config.resolve())
    os.environ.setdefault("OPENAI_API_KEY", "traex-local-transport")
    os.environ.setdefault("OPENAI_BASE_URL", "http://127.0.0.1:1/v1")
    sys.path.insert(0, str((args.w6_root / "src").resolve()))

    from vulrag_adapter.java_provider_substituted_pilot import prepare_runtime
    from vulrag_adapter.official_core import DetectionError, OfficialEngine

    config = json.loads(args.config.read_text(encoding="utf-8"))
    runtime_app, runtime_receipt = prepare_runtime(
        config,
        runtime_key=(
            args.runtime_key
            or f"vulrag-func-level-0817-traex-{args.start_index}-{args.stride}"
        ),
    )
    engine = OfficialEngine(config, runtime_app=runtime_app)
    client = TraexClient(
        executable=args.traex,
        model=args.model,
        reasoning_effort=args.reasoning_effort,
        workspace=args.out_dir / "traex-workspace",
        timeout_seconds=args.call_timeout_seconds,
    )
    engine.module.LLM_CLIENT = client
    engine.module.SUMMARY_LLM_CLIENT = client

    all_packets = read_jsonl(args.packets)
    packet_entries = list(
        enumerate(all_packets[args.start_index :: args.stride])
    )
    if args.limit is not None:
        packet_entries = packet_entries[: args.limit]
    args.out_dir.mkdir(parents=True, exist_ok=True)
    summary = {
        "completed": 0,
        "failed": 0,
        "skipped": 0,
        "total": len(packet_entries),
    }

    for shard_offset, envelope in packet_entries:
        offset = args.start_index + shard_offset * args.stride
        packet = envelope["runtime_packet"]
        function = packet["function"]
        identity = envelope["identity_key"]
        receipt_path = args.out_dir / "receipts" / f"{offset + 1:03d}-{safe_name(identity)}.json"
        if receipt_path.is_file():
            existing = json.loads(receipt_path.read_text(encoding="utf-8"))
            if existing.get("execution_status") == "completed":
                summary["skipped"] += 1
                continue

        before = {
            "call_count": client.call_count,
            "latency_seconds": client.latency_seconds,
            "traex_reported_tokens": client.traex_reported_tokens,
            "usage_missing_count": client.usage_missing_count,
        }
        receipt: dict[str, Any] = {
            "schema_version": "vulrag_func_level_0817.traex_receipt.v1",
            "identity_key": identity,
            "case_id": packet["case_id"],
            "source_revision": packet["source_revision"],
            "input_scope": packet["input_scope"],
            "function": {
                key: function[key]
                for key in (
                    "relative_path",
                    "name",
                    "kind",
                    "start_line",
                    "end_line",
                    "source_sha256",
                )
            },
            "transport": {
                "type": "traex_exec",
                "model": args.model,
                "reasoning_effort": args.reasoning_effort,
                "executable": str(args.traex),
            },
            "knowledge_base_sha256": engine.receipt["knowledge_base_sha256"],
            "runtime_receipt": runtime_receipt,
            "started_at": now_utc(),
        }
        started = time.monotonic()
        try:
            detection = engine.detect(function["code"])
            detection.pop("_adapter_metrics", None)
            receipt["detection"] = detection
            receipt["execution_status"] = "completed"
            receipt["verdict"] = (
                "vulnerable"
                if detection.get("final_result") == 1
                else "no_vulnerability_found"
            )
            summary["completed"] += 1
        except DetectionError as error:
            receipt["execution_status"] = "failed"
            receipt["error_type"] = error.original_error_type
            receipt["error_message"] = str(error)[:2_000]
            summary["failed"] += 1
        except Exception as error:
            receipt["execution_status"] = "failed"
            receipt["error_type"] = type(error).__name__
            receipt["error_message"] = str(error)[:2_000]
            summary["failed"] += 1
        receipt["ended_at"] = now_utc()
        receipt["latency_seconds"] = round(time.monotonic() - started, 6)
        receipt["metrics"] = {
            "llm_call_count": client.call_count - before["call_count"],
            "llm_latency_seconds": round(
                client.latency_seconds - before["latency_seconds"],
                6,
            ),
            "traex_reported_tokens": (
                client.traex_reported_tokens - before["traex_reported_tokens"]
            ),
            "usage_missing_count": (
                client.usage_missing_count - before["usage_missing_count"]
            ),
            "token_accounting": "aggregate tokens reported by TRAE CLI exec",
        }
        write_json(receipt_path, receipt)
        write_json(args.out_dir / "summary.json", summary)
        print(
            json.dumps(
                {
                    "index": offset + 1,
                    "identity_key": identity,
                    "status": receipt["execution_status"],
                    "verdict": receipt.get("verdict"),
                    "metrics": receipt["metrics"],
                    "receipt": str(receipt_path),
                },
                sort_keys=True,
            ),
            flush=True,
        )

    summary["packets_sha256"] = hashlib.sha256(args.packets.read_bytes()).hexdigest()
    summary["ended_at"] = now_utc()
    write_json(args.out_dir / "summary.json", summary)
    print(json.dumps(summary, sort_keys=True))
    return 0 if summary["failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
