#!/usr/bin/env python3
"""Merge per-case HCVR recall outputs into one ranked-result artifact."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


DEFAULT_BUDGETS = (1, 3, 5, 10, 20, 30, 50, 100, 200, 300, 500)


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.is_file():
        return rows
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                rows.append(json.loads(line))
    return rows


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def parse_budgets(text: str) -> list[int]:
    budgets = sorted({int(item.strip()) for item in text.split(",") if item.strip()})
    if not budgets or any(value < 1 for value in budgets):
        raise ValueError("budgets must be positive integers")
    return budgets


def best_rank(row: dict[str, Any]) -> int | None:
    value = row.get("best_known_anchor_rank")
    if isinstance(value, int) and value > 0:
        return value
    ranks = [
        anchor.get("rank")
        for anchor in row.get("top_anchors", [])
        if isinstance(anchor, dict) and anchor.get("known_anchor_overlap")
    ]
    ranks = [rank for rank in ranks if isinstance(rank, int) and rank > 0]
    return min(ranks) if ranks else None


def identity_order(identity_file: Path | None) -> list[str]:
    if identity_file is None:
        return []
    return [
        row["identity_key"]
        for row in read_jsonl(identity_file)
        if isinstance(row.get("identity_key"), str) and row["identity_key"]
    ]


def summarize(results: list[dict[str, Any]], budgets: list[int]) -> dict[str, Any]:
    completed = [row for row in results if row.get("state") == "completed"]
    failed = [row for row in results if row.get("state") != "completed"]
    ranks = [best_rank(row) for row in completed]
    hit_ranks = [rank for rank in ranks if rank is not None]
    metrics: dict[str, Any] = {
        "case_count": len(results),
        "completed_count": len(completed),
        "failed_count": len(failed),
        "candidate_count": sum(int(row.get("candidate_count") or 0) for row in completed),
        "mean_candidates_per_completed_case": (
            sum(int(row.get("candidate_count") or 0) for row in completed) / len(completed)
            if completed
            else 0.0
        ),
        "hit_cases": len(hit_ranks),
        "mrr": sum(1.0 / rank for rank in hit_ranks) / len(results) if results else 0.0,
    }
    for budget in budgets:
        count = sum(1 for rank in hit_ranks if rank <= budget)
        metrics[f"hit_count_at_{budget}"] = count
        metrics[f"known_anchor_hit_at_{budget}"] = count / len(results) if results else 0.0
    return metrics


def merge_shards(
    *,
    shard_root: Path,
    output_dir: Path,
    identity_file: Path | None,
    budgets: list[int],
) -> dict[str, Any]:
    order = identity_order(identity_file)
    order_map = {identity: index for index, identity in enumerate(order)}
    results: list[dict[str, Any]] = []
    selected: list[dict[str, Any]] = []
    seen: set[str] = set()
    failures: list[dict[str, Any]] = []

    for shard_dir in sorted(path for path in shard_root.iterdir() if path.is_dir()):
        recall_rows = read_jsonl(shard_dir / "recall_results.jsonl")
        selected_rows = read_jsonl(shard_dir / "selected_cases.jsonl")
        if not recall_rows:
            failures.append({"shard": shard_dir.name, "state": "missing_recall_results"})
            continue
        for row in recall_rows:
            identity = row.get("identity_key")
            if not isinstance(identity, str) or not identity:
                failures.append({"shard": shard_dir.name, "state": "missing_identity_key"})
                continue
            if identity in seen:
                failures.append({"shard": shard_dir.name, "identity_key": identity, "state": "duplicate_identity"})
                continue
            seen.add(identity)
            row["_merge_source"] = shard_dir.name
            results.append(row)
        for row in selected_rows:
            row["_merge_source"] = shard_dir.name
            selected.append(row)

    missing_identities = [identity for identity in order if identity not in seen]
    for identity in missing_identities:
        results.append(
            {
                "_merge_source": None,
                "identity_key": identity,
                "state": "missing",
                "candidate_count": 0,
                "known_anchor_count": 0,
                "best_known_anchor_rank": None,
                "top_anchors": [],
            }
        )

    def sort_key(row: dict[str, Any]) -> tuple[int, str]:
        identity = str(row.get("identity_key") or "")
        return (order_map.get(identity, 10**9), identity)

    results.sort(key=sort_key)
    selected.sort(key=sort_key)
    output_dir.mkdir(parents=True, exist_ok=True)
    recall_path = output_dir / "recall_results.jsonl"
    selected_path = output_dir / "selected_cases.jsonl"
    summary_path = output_dir / "summary.json"
    write_jsonl(recall_path, results)
    write_jsonl(selected_path, selected)
    summary = {
        "schema_version": "hcvr_recall_shard_merge.v1",
        "shard_root": str(shard_root.resolve()),
        "identity_file": str(identity_file.resolve()) if identity_file else None,
        "identity_count": len(order) if order else None,
        "missing_identities": missing_identities,
        "merge_failures": failures,
        "artifacts": {
            "recall_results": str(recall_path),
            "selected_cases": str(selected_path),
        },
        "metrics": summarize(results, budgets),
    }
    write_json(summary_path, summary)
    return summary


def markdown_report(summary: dict[str, Any], budgets: list[int]) -> str:
    metrics = summary["metrics"]
    lines = [
        "# Merged HCVR Recall Shards",
        "",
        f"- Shard root: `{summary['shard_root']}`",
        f"- Identity file: `{summary['identity_file']}`",
        f"- Cases: {metrics['case_count']}",
        f"- Completed: {metrics['completed_count']}",
        f"- Failed/missing: {metrics['failed_count']}",
        f"- Candidate anchors: {metrics['candidate_count']}",
        f"- MRR: {metrics['mrr']:.6f}",
        "",
        "## Hit@K",
        "",
        "| K | Hit Count | Rate |",
        "| ---: | ---: | ---: |",
    ]
    for budget in budgets:
        lines.append(
            f"| {budget} | {metrics[f'hit_count_at_{budget}']} | "
            f"{metrics[f'known_anchor_hit_at_{budget}']:.4f} |"
        )
    if summary["missing_identities"]:
        lines.extend(["", "## Missing Identities", ""])
        for identity in summary["missing_identities"]:
            lines.append(f"- `{identity}`")
    if summary["merge_failures"]:
        lines.extend(["", "## Merge Failures", ""])
        for failure in summary["merge_failures"]:
            lines.append(f"- `{json.dumps(failure, ensure_ascii=False, sort_keys=True)}`")
    return "\n".join(lines).rstrip() + "\n"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--shard-root", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--identity-file", type=Path)
    parser.add_argument("--budgets", default=",".join(str(value) for value in DEFAULT_BUDGETS))
    args = parser.parse_args()

    budgets = parse_budgets(args.budgets)
    summary = merge_shards(
        shard_root=args.shard_root,
        output_dir=args.output_dir,
        identity_file=args.identity_file,
        budgets=budgets,
    )
    report = markdown_report(summary, budgets)
    (args.output_dir / "README.md").write_text(report, encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    if summary["missing_identities"] or summary["merge_failures"]:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
