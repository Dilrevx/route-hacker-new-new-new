#!/usr/bin/env python3
"""Summarize current unified-v2 CodeQL and native-IRIS baseline rows."""
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def format_float(value: float | None) -> str:
    return "--" if value is None else f"{value:.4f}"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--current-review", required=True, type=Path)
    parser.add_argument("--codeql-manifest", required=True, type=Path)
    parser.add_argument("--codeql-eval-summary", required=True, type=Path)
    parser.add_argument("--iris-current-queue-summary", type=Path)
    parser.add_argument("--iris-current-case-status", type=Path)
    parser.add_argument("--out-dir", required=True, type=Path)
    args = parser.parse_args()

    args.out_dir.mkdir(parents=True, exist_ok=True)
    current_rows = read_jsonl(args.current_review)
    codeql_manifest = read_jsonl(args.codeql_manifest)
    codeql_summary = read_json(args.codeql_eval_summary)

    current_keys = {row["identity_key"] for row in current_rows}
    codeql_keys = {row["identity_key"] for row in codeql_manifest}
    codeql_exact = codeql_summary["exact_anchor_overlap"]
    denominator = len(codeql_manifest)
    iris_summary: dict[str, Any] = {}
    iris_case_rows: list[dict[str, Any]] = []
    if args.iris_current_queue_summary and args.iris_current_queue_summary.is_file():
        iris_summary = read_json(args.iris_current_queue_summary)
    if args.iris_current_case_status and args.iris_current_case_status.is_file():
        iris_case_rows = read_jsonl(args.iris_current_case_status)

    reusable = iris_summary.get("reusable_completed") or {}
    iris_vanilla_recall = reusable.get("lower_bound_vanilla_recall_on_codeql_denominator")
    iris_posthoc_recall = reusable.get("lower_bound_posthoc_recall_on_codeql_denominator")

    table_rows = [
        {
            "method": "CodeQL official CWE queries",
            "denominator": denominator,
            "completed_or_executed": codeql_summary.get("effective_executed_case_count"),
            "recall": codeql_exact["recall"],
            "precision": codeql_exact["precision"],
            "f1": codeql_exact["f1"],
            "alarms": codeql_summary["alarm_count"],
            "note": "Exact anchor-overlap on current unified-v2 cases with usable historical CodeQL DBs.",
        },
        {
            "method": "Native IRIS vanilla",
            "denominator": denominator,
            "completed_or_executed": reusable.get("case_count"),
            "recall": iris_vanilla_recall,
            "precision": None,
            "f1": None,
            "alarms": None,
            "note": "Strict-revision-safe reuse of old 213 native IRIS rows; lower-bound until queued current-v2 native runs finish.",
        },
        {
            "method": "Native IRIS posthoc",
            "denominator": denominator,
            "completed_or_executed": reusable.get("case_count"),
            "recall": iris_posthoc_recall,
            "precision": None,
            "f1": None,
            "alarms": None,
            "note": "Strict-revision-safe reuse of old 213 native IRIS rows; lower-bound until queued current-v2 native runs finish.",
        },
    ]

    summary = {
        "schema_version": "current_unified_v2_baseline_summary.v1",
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "inputs": {
            "current_review": str(args.current_review),
            "codeql_manifest": str(args.codeql_manifest),
            "codeql_eval_summary": str(args.codeql_eval_summary),
            "iris_current_queue_summary": str(args.iris_current_queue_summary) if args.iris_current_queue_summary else None,
            "iris_current_case_status": str(args.iris_current_case_status) if args.iris_current_case_status else None,
        },
        "dataset": {
            "current_unified_v2_selected_cases": len(current_keys),
            "current_cases_with_usable_historical_codeql_db": len(codeql_keys),
            "current_cases_without_usable_historical_codeql_db": len(current_keys - codeql_keys),
        },
        "codeql": codeql_summary,
        "iris_current_v2": iris_summary,
        "paper_table_rows": table_rows,
    }
    (args.out_dir / "baseline_comparison_current_v2.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    md = [
        "# Current Unified-v2 Baseline Snapshot",
        "",
        f"- Current unified-v2 selected cases: {len(current_keys)}",
        f"- Current cases with usable historical CodeQL DB: {len(codeql_keys)}",
        f"- Current cases without usable historical CodeQL DB: {len(current_keys - codeql_keys)}",
        f"- IRIS strict-revision-safe completed rows: {reusable.get('case_count', '--')}",
        f"- IRIS queued rows needing native run: {(iris_summary.get('counts') or {}).get('queue_ready_cases', '--')}",
        "",
        "| Method | Denominator | Completed/executed | Recall | Precision | F1 | Alarms | Note |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |",
    ]
    for row in table_rows:
        md.append(
            "| {method} | {denominator} | {completed_or_executed} | {recall} | {precision} | {f1} | {alarms} | {note} |".format(
                method=row["method"],
                denominator=row["denominator"],
                completed_or_executed=row["completed_or_executed"],
                recall=format_float(row["recall"]),
                precision=format_float(row["precision"]),
                f1=format_float(row["f1"]),
                alarms="--" if row["alarms"] is None else row["alarms"],
                note=row["note"],
            )
        )
    md.extend(
        [
            "",
            "## CodeQL Status",
            "",
            f"- Run status: `{codeql_summary['run_status_counts']}`",
            f"- Case relation: `{codeql_summary['case_relation_counts']}`",
            "",
            "## IRIS Boundary",
            "",
            "The IRIS rows above use CVE/GHSA plus checkout-revision alignment to reuse the prior 213-case native IRIS snapshot. They are lower-bound recall rows until the current-v2 native queue is executed. Precision is unavailable from the reused positive-only fix-method labels.",
        ]
    )
    (args.out_dir / "baseline_comparison_current_v2.md").write_text("\n".join(md) + "\n", encoding="utf-8")

    if iris_case_rows:
        (args.out_dir / "iris_current_v2_case_status.jsonl").write_text(
            "\n".join(json.dumps(row, ensure_ascii=False, sort_keys=True) for row in iris_case_rows) + "\n",
            encoding="utf-8",
        )
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
