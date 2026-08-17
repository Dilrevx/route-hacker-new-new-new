#!/usr/bin/env python3
"""Create resumable receipts for bounded native-IRIS case dispatch."""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def append_jsonl(path: Path, row: dict[str, Any]) -> None:
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, sort_keys=True) + "\n")
        handle.flush()


def safe_name(value: str) -> str:
    return "".join(char if char.isalnum() or char in "._-" else "_" for char in value)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--receipts", type=Path, required=True)
    parser.add_argument("--workspace-root", type=Path, required=True)
    parser.add_argument("--clean-iris-root", type=Path, required=True)
    parser.add_argument("--codeql-dir", type=Path, required=True)
    parser.add_argument("--bridge-url", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--materializer", type=Path, required=True)
    parser.add_argument("--single-case-runner", type=Path, required=True)
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--max-workers", type=int, default=2)
    parser.add_argument("--limit", type=int)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--attempt-id", default="attempt-1")
    parser.add_argument("--llm", choices=("gpt-traex-flash", "gpt-traex-pro"), default="gpt-traex-flash")
    parser.add_argument("--num-threads", type=int, default=1)
    parser.add_argument("--timeout-seconds", type=int, default=3600)
    args = parser.parse_args()
    if args.max_workers < 1 or args.max_workers > 8:
        raise SystemExit("--max-workers must be in [1, 8]")
    if not safe_name(args.attempt_id) or safe_name(args.attempt_id) != args.attempt_id:
        raise SystemExit("--attempt-id may contain only letters, numbers, '.', '_' and '-'")

    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    ledger = output_dir / "receipts.jsonl"
    completed: set[str] = set()
    if args.resume and ledger.is_file():
        completed = {
            str(row["case_id"])
            for row in read_jsonl(ledger)
            if row.get("status") == "completed_verified" and row.get("case_id")
        }
    ready = [row for row in read_jsonl(args.receipts) if row.get("status") == "iris_shadow_root_ready"]
    selected = [row for row in ready if str(row.get("case_id")) not in completed]
    if args.limit is not None:
        selected = selected[: args.limit]

    def run_case(row: dict[str, Any]) -> dict[str, Any]:
        slug = str(row["project_slug"])
        case_id = str(row["case_id"])
        case_dir = output_dir / "cases" / safe_name(case_id)
        workspace = args.workspace_root.resolve() / args.attempt_id / safe_name(case_id)
        run_id = f"native-traex-{args.attempt_id}-{safe_name(slug)}"
        materialize = [
            args.python, str(args.materializer), "--receipts", str(args.receipts),
            "--case-id", case_id, "--clean-iris-root", str(args.clean_iris_root),
            "--codeql-dir", str(args.codeql_dir), "--workspace", str(workspace),
        ]
        materialized = subprocess.run(materialize, text=True, capture_output=True, check=False)
        if materialized.returncode != 0:
            return {"case_id": case_id, "project_slug": slug, "status": "materialization_failed", "stderr": materialized.stderr[-2000:]}
        run = [
            args.python, str(args.single_case_runner), "--workspace", str(workspace),
            "--run-id", run_id, "--bridge-url", args.bridge_url, "--llm", args.llm,
            "--num-threads", str(args.num_threads), "--timeout-seconds", str(args.timeout_seconds),
            "--output-dir", str(case_dir),
        ]
        executed = subprocess.run(run, text=True, capture_output=True, check=False)
        summary_path = case_dir / "summary.json"
        summary = json.loads(summary_path.read_text()) if summary_path.is_file() else {}
        return {
            "recorded_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
            "case_id": case_id,
            "project_slug": slug,
            "attempt_id": args.attempt_id,
            "status": summary.get("status", "runner_summary_missing"),
            "runner_returncode": executed.returncode,
            "summary_path": str(summary_path) if summary_path.is_file() else None,
            "verified_completion": summary.get("verified_completion"),
        }

    with ThreadPoolExecutor(max_workers=args.max_workers) as pool:
        futures = [pool.submit(run_case, row) for row in selected]
        for future in as_completed(futures):
            receipt = future.result()
            append_jsonl(ledger, receipt)
            print(json.dumps(receipt, sort_keys=True), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
