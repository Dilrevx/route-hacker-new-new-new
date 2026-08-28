#!/usr/bin/env python3
"""Summarize sharded VulRAG receipts against the full evaluation denominator."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--allowlist", required=True, type=Path)
    parser.add_argument("--packets", required=True, type=Path)
    parser.add_argument("--unresolved", required=True, type=Path)
    parser.add_argument("--receipts-root", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()

    allowlist = read_jsonl(args.allowlist)
    packet_rows = read_jsonl(args.packets)
    unresolved_rows = read_jsonl(args.unresolved)
    expected = [row["identity_key"] for row in allowlist]
    packet_identities = {
        row["identity_key"]: row["runtime_packet"]["case_id"] for row in packet_rows
    }
    unresolved = {row["identity_key"]: row for row in unresolved_rows}

    receipts: dict[str, dict[str, Any]] = {}
    duplicate_receipts: list[str] = []
    for path in sorted(args.receipts_root.glob("**/receipts/*.json")):
        receipt = json.loads(path.read_text(encoding="utf-8"))
        identity = receipt["identity_key"]
        if identity in receipts:
            duplicate_receipts.append(identity)
            continue
        receipt["_receipt_path"] = str(path.relative_to(args.receipts_root))
        receipts[identity] = receipt

    models = sorted(
        {
            receipt.get("transport", {}).get("model")
            for receipt in receipts.values()
            if receipt.get("transport", {}).get("model")
        }
    )
    reasoning_efforts = sorted(
        {
            receipt.get("transport", {}).get("reasoning_effort")
            for receipt in receipts.values()
            if receipt.get("transport", {}).get("reasoning_effort")
        }
    )
    knowledge_base_hashes = sorted(
        {
            receipt.get("knowledge_base_sha256")
            for receipt in receipts.values()
            if receipt.get("knowledge_base_sha256")
        }
    )

    rows = []
    for identity in expected:
        receipt = receipts.get(identity)
        unresolved_row = unresolved.get(identity)
        if receipt is not None:
            status = receipt["execution_status"]
            verdict = receipt.get("verdict")
            reason = receipt.get("error_type")
        elif unresolved_row is not None:
            status = "unresolved"
            verdict = None
            reason = unresolved_row["reason"]
        elif identity in packet_identities:
            status = "pending"
            verdict = None
            reason = None
        else:
            status = "missing_input_accounting"
            verdict = None
            reason = None
        rows.append(
            {
                "identity_key": identity,
                "status": status,
                "verdict": verdict,
                "reason": reason,
                "case_id": packet_identities.get(identity)
                or (unresolved_row or {}).get("case_id"),
                "receipt_path": (receipt or {}).get("_receipt_path"),
                "model": (receipt or {}).get("transport", {}).get("model"),
                "reasoning_effort": (receipt or {}).get("transport", {}).get(
                    "reasoning_effort"
                ),
                "llm_call_count": (receipt or {}).get("metrics", {}).get(
                    "llm_call_count"
                ),
                "agent_reported_tokens": (receipt or {}).get("metrics", {}).get(
                    "agent_reported_tokens"
                ),
            }
        )

    status_counts = Counter(row["status"] for row in rows)
    verdict_counts = Counter(
        row["verdict"] for row in rows if row["verdict"] is not None
    )
    completed = status_counts["completed"]
    vulnerable = verdict_counts["vulnerable"]
    summary = {
        "schema_version": "vulrag_func_level_0817.evaluation_summary.v1",
        "denominator": len(expected),
        "packet_count": len(packet_rows),
        "unresolved_count": len(unresolved_rows),
        "receipt_count": len(receipts),
        "models": models,
        "reasoning_efforts": reasoning_efforts,
        "knowledge_base_sha256": knowledge_base_hashes,
        "status_counts": dict(sorted(status_counts.items())),
        "verdict_counts": dict(sorted(verdict_counts.items())),
        "completed_case_detection_rate": (
            vulnerable / completed if completed else None
        ),
        "full_denominator_detection_rate": vulnerable / len(expected),
        "llm_call_count": sum(row["llm_call_count"] or 0 for row in rows),
        "agent_reported_tokens": sum(
            row["agent_reported_tokens"] or 0 for row in rows
        ),
        "duplicate_receipt_identities": sorted(set(duplicate_receipts)),
        "cases": rows,
    }
    write_json(args.out, summary)
    print(
        json.dumps(
            {key: value for key, value in summary.items() if key != "cases"},
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
