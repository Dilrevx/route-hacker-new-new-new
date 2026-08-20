#!/usr/bin/env python3
"""Run resumable LLM semantic adjudication over prepared case prompts.

The runner is intentionally separate from the blind-audit runner: it consumes
ground truth only after Codex Security artifacts already exist. It records raw
model answers, validates the requested JSON shape, and bounds each invocation
with a process-group timeout.
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any


VALID_VERDICTS = {
    "same_vulnerability",
    "related_but_different",
    "different_vulnerability",
    "insufficient_evidence",
}
VALID_CONFIDENCE = {"high", "medium", "low"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", required=True, type=Path)
    parser.add_argument("--traex-bin", default="/Users/bytedance/.local/bin/traex")
    parser.add_argument("--model", default="GPT-5.6-Luna")
    parser.add_argument("--reasoning-effort", default="medium", choices=sorted(VALID_CONFIDENCE))
    parser.add_argument("--parallelism", type=int, default=2)
    parser.add_argument("--timeout-seconds", type=int, default=1800)
    parser.add_argument("--case-id", action="append", help="Run only one or more specified cases.")
    parser.add_argument("--rerun-invalid", action="store_true")
    return parser.parse_args()


def validate_answer(path: Path, expected_case_id: str) -> tuple[bool, str]:
    if not path.exists() or not path.read_text(encoding="utf-8").strip():
        return False, "missing_or_empty_output"
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return False, f"invalid_json:{exc.msg}"
    if not isinstance(value, dict):
        return False, "json_not_object"
    if value.get("case_id") != expected_case_id:
        return False, "case_id_mismatch"
    if value.get("case_verdict") not in VALID_VERDICTS:
        return False, "invalid_case_verdict"
    if value.get("confidence") not in VALID_CONFIDENCE:
        return False, "invalid_confidence"
    if not isinstance(value.get("matching_finding_ids"), list):
        return False, "missing_matching_finding_ids"
    if not isinstance(value.get("finding_judgments"), list):
        return False, "missing_finding_judgments"
    for item in value["finding_judgments"]:
        if not isinstance(item, dict) or item.get("verdict") not in VALID_VERDICTS:
            return False, "invalid_finding_judgment"
    return True, "valid"


def run_one(args: argparse.Namespace, row: dict[str, Any]) -> dict[str, Any]:
    run_dir: Path = args.run_dir
    case_id = row["case_id"]
    prompt = run_dir / "prompts" / f"{case_id}.txt"
    output = run_dir / "outputs" / f"{case_id}.json"
    stdout = run_dir / "logs" / f"{case_id}.stdout"
    stderr = run_dir / "logs" / f"{case_id}.stderr"
    existing_ok, existing_state = validate_answer(output, case_id)
    if existing_ok and not args.rerun_invalid:
        return {"case_id": case_id, "status": "already_valid", "validation": existing_state, "elapsed_seconds": 0}
    if not prompt.exists():
        return {"case_id": case_id, "status": "missing_prompt", "validation": "missing_prompt", "elapsed_seconds": 0}

    command = [
        args.traex_bin, "exec", "--ephemeral", "--skip-git-repo-check",
        "-C", str(run_dir), "-m", args.model,
        "-c", f'model_reasoning_effort=\"{args.reasoning_effort}\"',
        "--output-last-message", str(output), "-",
    ]
    started = time.monotonic()
    with prompt.open("rb") as input_handle, stdout.open("wb") as out_handle, stderr.open("wb") as err_handle:
        process = subprocess.Popen(
            command, stdin=input_handle, stdout=out_handle, stderr=err_handle,
            start_new_session=True,
        )
        timed_out = False
        try:
            exit_code = process.wait(timeout=args.timeout_seconds)
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(process.pid, signal.SIGTERM)
            try:
                exit_code = process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                exit_code = process.wait()
    elapsed = round(time.monotonic() - started, 3)
    valid, validation = validate_answer(output, case_id)
    return {
        "case_id": case_id, "status": "valid" if valid else ("timed_out" if timed_out else "invalid_output"),
        "validation": validation, "elapsed_seconds": elapsed,
        "exit_code": exit_code, "timed_out": timed_out,
        "model": args.model, "reasoning_effort": args.reasoning_effort,
    }


def main() -> None:
    args = parse_args()
    if args.parallelism < 1 or args.timeout_seconds < 1:
        raise SystemExit("parallelism and timeout must be positive")
    manifest_path = args.run_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if args.case_id:
        wanted = set(args.case_id)
        manifest = [row for row in manifest if row["case_id"] in wanted]
    (args.run_dir / "outputs").mkdir(exist_ok=True)
    (args.run_dir / "logs").mkdir(exist_ok=True)
    records: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=args.parallelism) as pool:
        futures = {pool.submit(run_one, args, row): row["case_id"] for row in manifest}
        for future in as_completed(futures):
            record = future.result()
            records.append(record)
            print(json.dumps(record, sort_keys=True), flush=True)
    records.sort(key=lambda item: int(item["case_id"].split("_")[-1]))
    (args.run_dir / "run_records.json").write_text(json.dumps(records, indent=2) + "\n", encoding="utf-8")
    failures = [item for item in records if item["status"] not in {"valid", "already_valid"}]
    print(json.dumps({"total": len(records), "valid_or_existing": len(records) - len(failures), "not_valid": len(failures)}, sort_keys=True))
    raise SystemExit(1 if failures else 0)


if __name__ == "__main__":
    main()
