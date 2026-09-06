#!/usr/bin/env python3
"""Compare two HCVR recall rank tables with identity-set guardrails."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


DEFAULT_BUDGETS = (30, 50, 100, 200)


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                rows.append(json.loads(line))
    return rows


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def parse_budgets(text: str) -> list[int]:
    values: list[int] = []
    for item in text.split(","):
        item = item.strip()
        if not item:
            continue
        value = int(item)
        if value < 1:
            raise ValueError("budgets must be positive")
        values.append(value)
    if not values:
        raise ValueError("at least one budget is required")
    return sorted(set(values))


def normalize_rank(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int) and value > 0:
        return value
    if isinstance(value, str) and value.isdigit():
        parsed = int(value)
        return parsed if parsed > 0 else None
    return None


def best_rank(row: dict[str, Any]) -> int | None:
    """Extract best known-anchor rank from supported recall result formats."""

    for key in ("best_known_anchor_rank", "rank"):
        rank = normalize_rank(row.get(key))
        if rank is not None:
            return rank
    anchor_ranks = [
        normalize_rank(anchor.get("rank"))
        for anchor in row.get("top_anchors", [])
        if isinstance(anchor, dict) and anchor.get("known_anchor_overlap")
    ]
    anchor_ranks = [rank for rank in anchor_ranks if rank is not None]
    return min(anchor_ranks) if anchor_ranks else None


def index_by_identity(rows: list[dict[str, Any]], label: str) -> tuple[list[str], dict[str, dict[str, Any]]]:
    order: list[str] = []
    indexed: dict[str, dict[str, Any]] = {}
    duplicates: list[str] = []
    for row in rows:
        identity = row.get("identity_key")
        if not isinstance(identity, str) or not identity:
            raise ValueError(f"{label} row missing identity_key: {row}")
        if identity in indexed:
            duplicates.append(identity)
            continue
        order.append(identity)
        indexed[identity] = row
    if duplicates:
        raise ValueError(f"{label} has duplicate identities: {sorted(duplicates)[:10]}")
    return order, indexed


def hit(rank: int | None, budget: int) -> bool:
    return rank is not None and rank <= budget


def compare_tables(
    *,
    left_rows: list[dict[str, Any]],
    right_rows: list[dict[str, Any]],
    left_label: str,
    right_label: str,
    budgets: list[int],
    primary_budget: int,
) -> dict[str, Any]:
    left_order, left = index_by_identity(left_rows, left_label)
    right_order, right = index_by_identity(right_rows, right_label)
    left_set = set(left)
    right_set = set(right)
    common_ids = [identity for identity in left_order if identity in right_set]
    same_identity_set = left_set == right_set
    same_identity_order = same_identity_set and left_order == right_order

    rows: list[dict[str, Any]] = []
    for identity in common_ids:
        left_row = left[identity]
        right_row = right[identity]
        rows.append(
            {
                "identity_key": identity,
                "left_rank": best_rank(left_row),
                "right_rank": best_rank(right_row),
                "left_candidate_count": left_row.get("candidate_count"),
                "right_candidate_count": right_row.get("candidate_count"),
                "hcvr_type": left_row.get("hcvr_type") or right_row.get("hcvr_type") or "",
                "cwe_ids": left_row.get("cwe_ids") or right_row.get("cwe_ids") or [],
            }
        )

    metrics: dict[str, Any] = {}
    denominator = len(rows) or 1
    for budget in budgets:
        left_hits = sum(1 for row in rows if hit(row["left_rank"], budget))
        right_hits = sum(1 for row in rows if hit(row["right_rank"], budget))
        metrics[f"hit_at_{budget}"] = {
            "left_count": left_hits,
            "right_count": right_hits,
            "delta_count": left_hits - right_hits,
            "left_rate": left_hits / denominator,
            "right_rate": right_hits / denominator,
            "delta_rate": (left_hits - right_hits) / denominator,
        }

    left_mrr = sum(1.0 / row["left_rank"] for row in rows if row["left_rank"]) / denominator
    right_mrr = sum(1.0 / row["right_rank"] for row in rows if row["right_rank"]) / denominator
    metrics["mrr"] = {
        "left": left_mrr,
        "right": right_mrr,
        "delta": left_mrr - right_mrr,
    }

    left_only_primary = [
        row
        for row in rows
        if hit(row["left_rank"], primary_budget) and not hit(row["right_rank"], primary_budget)
    ]
    right_only_primary = [
        row
        for row in rows
        if hit(row["right_rank"], primary_budget) and not hit(row["left_rank"], primary_budget)
    ]
    both_hit_primary = [
        row
        for row in rows
        if hit(row["left_rank"], primary_budget) and hit(row["right_rank"], primary_budget)
    ]
    both_miss_primary = [
        row
        for row in rows
        if not hit(row["left_rank"], primary_budget) and not hit(row["right_rank"], primary_budget)
    ]

    return {
        "schema_version": "hcvr_recall_rank_comparison.v1",
        "left_label": left_label,
        "right_label": right_label,
        "left_count": len(left_rows),
        "right_count": len(right_rows),
        "common_count": len(common_ids),
        "same_identity_set": same_identity_set,
        "same_identity_order": same_identity_order,
        "left_only_count": len(left_set - right_set),
        "right_only_count": len(right_set - left_set),
        "left_only_sample": sorted(left_set - right_set)[:20],
        "right_only_sample": sorted(right_set - left_set)[:20],
        "budgets": budgets,
        "primary_budget": primary_budget,
        "metrics_on_common_identities": metrics,
        "primary_budget_crossing": {
            "both_hit_count": len(both_hit_primary),
            "left_only_hit_count": len(left_only_primary),
            "right_only_hit_count": len(right_only_primary),
            "both_miss_count": len(both_miss_primary),
            "left_only_hits": sorted(left_only_primary, key=lambda row: row["left_rank"] or 10**18)[:50],
            "right_only_hits": sorted(right_only_primary, key=lambda row: row["right_rank"] or 10**18)[:50],
        },
        "candidate_count_on_common": {
            "left_total": sum(int(row["left_candidate_count"] or 0) for row in rows),
            "right_total": sum(int(row["right_candidate_count"] or 0) for row in rows),
            "different_count": sum(
                1 for row in rows if row["left_candidate_count"] != row["right_candidate_count"]
            ),
        },
    }


def markdown_report(summary: dict[str, Any], *, mismatch_allowed: bool) -> str:
    lines: list[str] = []
    lines.append("# HCVR Recall Rank Comparison")
    lines.append("")
    lines.append(f"- Left: `{summary['left_label']}` ({summary['left_count']} rows)")
    lines.append(f"- Right: `{summary['right_label']}` ({summary['right_count']} rows)")
    lines.append(f"- Common identities: {summary['common_count']}")
    lines.append(f"- Same identity set: {summary['same_identity_set']}")
    lines.append(f"- Same identity order: {summary['same_identity_order']}")
    lines.append(f"- Mismatch allowed: {mismatch_allowed}")
    if not summary["same_identity_set"]:
        lines.append(f"- Left-only identities: {summary['left_only_count']}")
        lines.append(f"- Right-only identities: {summary['right_only_count']}")
    lines.append("")
    lines.append("## Metrics On Common Identities")
    lines.append("")
    lines.append("| Metric | Left | Right | Delta |")
    lines.append("| --- | ---: | ---: | ---: |")
    for budget in summary["budgets"]:
        metric = summary["metrics_on_common_identities"][f"hit_at_{budget}"]
        lines.append(
            f"| Hit@{budget} | {metric['left_count']}/{summary['common_count']} | "
            f"{metric['right_count']}/{summary['common_count']} | {metric['delta_count']} |"
        )
    mrr = summary["metrics_on_common_identities"]["mrr"]
    lines.append(f"| MRR | {mrr['left']:.6f} | {mrr['right']:.6f} | {mrr['delta']:.6f} |")
    lines.append("")
    lines.append(f"## Primary Budget Crossing: Top-{summary['primary_budget']}")
    lines.append("")
    crossing = summary["primary_budget_crossing"]
    lines.append(f"- Both hit: {crossing['both_hit_count']}")
    lines.append(f"- Left-only hit: {crossing['left_only_hit_count']}")
    lines.append(f"- Right-only hit: {crossing['right_only_hit_count']}")
    lines.append(f"- Both miss: {crossing['both_miss_count']}")
    lines.append("")
    if crossing["left_only_hits"]:
        lines.append("### Left-Only Hits")
        lines.append("")
        for row in crossing["left_only_hits"]:
            lines.append(
                f"- `{row['identity_key']}` left={row['left_rank']} right={row['right_rank']} "
                f"type=`{row['hcvr_type']}`"
            )
        lines.append("")
    if crossing["right_only_hits"]:
        lines.append("### Right-Only Hits")
        lines.append("")
        for row in crossing["right_only_hits"]:
            lines.append(
                f"- `{row['identity_key']}` right={row['right_rank']} left={row['left_rank']} "
                f"type=`{row['hcvr_type']}`"
            )
        lines.append("")
    if not summary["same_identity_set"]:
        lines.append("## Identity Mismatch Samples")
        lines.append("")
        lines.append("Left-only sample:")
        for identity in summary["left_only_sample"]:
            lines.append(f"- `{identity}`")
        lines.append("")
        lines.append("Right-only sample:")
        for identity in summary["right_only_sample"]:
            lines.append(f"- `{identity}`")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--left", type=Path, required=True)
    parser.add_argument("--right", type=Path, required=True)
    parser.add_argument("--left-label")
    parser.add_argument("--right-label")
    parser.add_argument("--budgets", default=",".join(str(value) for value in DEFAULT_BUDGETS))
    parser.add_argument("--primary-budget", type=int, default=200)
    parser.add_argument("--allow-mismatch", action="store_true")
    parser.add_argument("--output-json", type=Path)
    parser.add_argument("--output-md", type=Path)
    args = parser.parse_args()

    budgets = parse_budgets(args.budgets)
    if args.primary_budget < 1:
        raise SystemExit("--primary-budget must be positive")
    if args.primary_budget not in budgets:
        budgets = sorted(set([*budgets, args.primary_budget]))

    summary = compare_tables(
        left_rows=read_jsonl(args.left),
        right_rows=read_jsonl(args.right),
        left_label=args.left_label or args.left.name,
        right_label=args.right_label or args.right.name,
        budgets=budgets,
        primary_budget=args.primary_budget,
    )
    report = markdown_report(summary, mismatch_allowed=args.allow_mismatch)
    if args.output_json:
        write_json(args.output_json, summary)
    if args.output_md:
        args.output_md.parent.mkdir(parents=True, exist_ok=True)
        args.output_md.write_text(report, encoding="utf-8")
    sys.stdout.write(report)
    if not summary["same_identity_set"] and not args.allow_mismatch:
        raise SystemExit(
            "identity sets differ; rerun with the same identity file, or pass --allow-mismatch "
            "to inspect the intersection explicitly"
        )


if __name__ == "__main__":
    main()
