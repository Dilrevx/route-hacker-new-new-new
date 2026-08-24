#!/usr/bin/env python3
"""Run official CodeQL baselines for native-IRIS workspaces in parallel."""
from __future__ import annotations

import argparse
import csv
import json
import subprocess
import sys
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError(f"expected JSON object at {path}:{line_number}")
        rows.append(value)
    return rows


def safe_name(value: str) -> str:
    return "".join(char if char.isalnum() or char in "._-" else "_" for char in value)


def row_slug(row: dict[str, Any]) -> str | None:
    slug = row.get("project_slug")
    return str(slug) if slug else None


def row_workspace(row: dict[str, Any]) -> Path | None:
    workspace = row.get("native_workspace") or row.get("workspace")
    return Path(str(workspace)) if workspace else None


def already_completed(output_dir: Path, slug: str) -> bool:
    summary_path = output_dir / safe_name(slug) / "summary.json"
    if not summary_path.is_file():
        return False
    try:
        summary = read_json(summary_path)
    except (OSError, json.JSONDecodeError, ValueError):
        return False
    return summary.get("verified_completion") is True


def run_one(
    *,
    python: str,
    runner: Path,
    run_id: str,
    output_dir: Path,
    overwrite: bool,
    row: dict[str, Any],
) -> dict[str, Any]:
    slug = row_slug(row)
    workspace = row_workspace(row)
    if not slug:
        return {"status": "skipped", "reason": "missing project_slug", "row": row}
    if workspace is None:
        return {"project_slug": slug, "status": "skipped", "reason": "missing native_workspace"}
    case_output = output_dir / safe_name(slug)
    if already_completed(output_dir, slug) and not overwrite:
        return {
            "project_slug": slug,
            "workspace": str(workspace),
            "output_dir": str(case_output),
            "status": "already_completed",
            "returncode": 0,
        }
    command = [
        python,
        str(runner),
        "--workspace",
        str(workspace),
        "--run-id",
        run_id,
        "--output-dir",
        str(case_output),
    ]
    if overwrite:
        command.append("--overwrite")
    completed = subprocess.run(command, text=True, capture_output=True, check=False)
    stdout_path = case_output / "batch.stdout.txt"
    stderr_path = case_output / "batch.stderr.txt"
    case_output.mkdir(parents=True, exist_ok=True)
    stdout_path.write_text(completed.stdout, encoding="utf-8")
    stderr_path.write_text(completed.stderr, encoding="utf-8")
    status = "completed_verified" if completed.returncode == 0 and already_completed(output_dir, slug) else "failed"
    return {
        "project_slug": slug,
        "workspace": str(workspace),
        "output_dir": str(case_output),
        "status": status,
        "returncode": completed.returncode,
        "command": command,
        "stdout_path": str(stdout_path),
        "stderr_path": str(stderr_path),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-jsonl", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--runner", type=Path, default=Path(__file__).with_name("run_official_codeql_baseline.py"))
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--max-workers", type=int, default=2)
    parser.add_argument("--overwrite", action="store_true")
    args = parser.parse_args()

    if args.max_workers < 1:
        raise SystemExit("--max-workers must be >= 1")
    rows = read_jsonl(args.input_jsonl.resolve())
    args.output_dir.mkdir(parents=True, exist_ok=True)
    status_path = args.output_dir / "batch.status.jsonl"
    tsv_path = args.output_dir / "batch.status.tsv"
    results: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=args.max_workers) as executor:
        futures = [
            executor.submit(
                run_one,
                python=args.python,
                runner=args.runner.resolve(),
                run_id=args.run_id,
                output_dir=args.output_dir.resolve(),
                overwrite=args.overwrite,
                row=row,
            )
            for row in rows
        ]
        for future in as_completed(futures):
            result = future.result()
            result["recorded_at"] = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
            results.append(result)
            with status_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(result, sort_keys=True) + "\n")
                handle.flush()
            print(json.dumps(result, sort_keys=True))

    with tsv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["project_slug", "status", "returncode", "workspace", "output_dir", "reason"],
            delimiter="\t",
        )
        writer.writeheader()
        for result in sorted(results, key=lambda item: str(item.get("project_slug"))):
            writer.writerow({key: result.get(key) for key in writer.fieldnames})
    summary = {
        "schema_version": "iris_native_traex_official_codeql_batch.v1",
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "input_jsonl": str(args.input_jsonl.resolve()),
        "run_id": args.run_id,
        "case_count": len(rows),
        "status_counts": dict(sorted(Counter(str(row.get("status")) for row in results).items())),
        "outputs": {
            "status_jsonl": str(status_path),
            "status_tsv": str(tsv_path),
        },
    }
    (args.output_dir / "batch.summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return 0 if not any(row.get("status") == "failed" for row in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
