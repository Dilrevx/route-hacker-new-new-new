#!/usr/bin/env python3
"""Merge native-IRIS receipts and Agent CLI bridge-call metrics for reporting."""
from __future__ import annotations

import argparse
import collections
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def numeric_total(rows: list[dict[str, Any]], key: str) -> int | float:
    return sum(value for row in rows if isinstance((value := row.get(key)), (int, float)))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--receipt-ledger", type=Path, required=True)
    parser.add_argument("--bridge-metrics", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    receipts = read_jsonl(args.receipt_ledger)
    calls = read_jsonl(args.bridge_metrics)
    verified = [row for row in receipts if row.get("status") == "completed_verified"]
    completed_calls = [row for row in calls if row.get("status") == "completed"]
    token_values = [
        row["agent_reported_total_tokens"]
        for row in completed_calls
        if isinstance(row.get("agent_reported_total_tokens"), int)
    ]
    per_case_calls = collections.Counter(
        str(row.get("case_id")) for row in calls if row.get("case_id")
    )
    per_case_tokens = collections.Counter()
    for row in completed_calls:
        if row.get("case_id") and isinstance(row.get("agent_reported_total_tokens"), int):
            per_case_tokens[str(row["case_id"])] += row["agent_reported_total_tokens"]

    verified_case_metrics = []
    for receipt in verified:
        case_id = str(receipt.get("case_id"))
        statistics = receipt.get("iris_statistics") or {}
        verified_case_metrics.append(
            {
                "case_id": case_id,
                "project_slug": receipt.get("project_slug"),
                "summary_path": receipt.get("summary_path"),
                "elapsed_seconds": receipt.get("elapsed_seconds"),
                "llm_call_count": per_case_calls[case_id],
                "agent_reported_total_tokens": per_case_tokens.get(case_id),
                "candidate_apis": statistics.get("candidate_apis"),
                "labelled_sources": statistics.get("labelled_sources"),
                "labelled_taint_propagators": statistics.get("labelled_taint_propagators"),
                "labelled_sinks": statistics.get("labelled_sinks"),
                "vanilla_paths": statistics.get("vanilla_paths"),
                "posthoc_paths": statistics.get("posthoc_paths"),
                "vanilla_tp_paths_method": statistics.get("vanilla_tp_paths_method"),
                "posthoc_tp_paths_method": statistics.get("posthoc_tp_paths_method"),
            }
        )
    report = {
        "schema_version": "iris_native_agent_paper_metrics.v1",
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "inputs": {
            "receipt_ledger": str(args.receipt_ledger.resolve()),
            "bridge_metrics": str(args.bridge_metrics.resolve()),
        },
        "execution": {
            "receipt_count": len(receipts),
            "verified_completion_count": len(verified),
            "receipt_status_counts": dict(sorted(collections.Counter(str(row.get("status")) for row in receipts).items())),
            "total_case_elapsed_seconds": numeric_total(verified, "elapsed_seconds"),
        },
        "llm": {
            "bridge_call_count": len(calls),
            "bridge_status_counts": dict(sorted(collections.Counter(str(row.get("status")) for row in calls).items())),
            "completed_call_count": len(completed_calls),
            "calls_with_reported_total_tokens": len(token_values),
            "agent_reported_total_tokens": sum(token_values) if token_values else None,
            "token_accounting": "Agent CLI CLI reported total tokens only; input/output split is not inferred.",
        },
        "paths": {
            "vanilla_paths": sum(
                value for row in verified_case_metrics if isinstance((value := row["vanilla_paths"]), (int, float))
            ),
            "posthoc_paths": sum(
                value for row in verified_case_metrics if isinstance((value := row["posthoc_paths"]), (int, float))
            ),
            "vanilla_method_overlap_paths": sum(
                value for row in verified_case_metrics
                if isinstance((value := row["vanilla_tp_paths_method"]), (int, float))
            ),
            "posthoc_method_overlap_paths": sum(
                value for row in verified_case_metrics
                if isinstance((value := row["posthoc_tp_paths_method"]), (int, float))
            ),
        },
        "cases": verified_case_metrics,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
