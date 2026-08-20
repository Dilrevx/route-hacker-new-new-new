#!/usr/bin/env python3
"""Fuse two HCVR recall outputs with anchor-level reciprocal rank fusion."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


DEFAULT_BUDGETS = (30, 50, 100, 200, 300, 500)


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


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def parse_budgets(text: str) -> list[int]:
    budgets = sorted({int(item.strip()) for item in text.split(",") if item.strip()})
    if not budgets or any(value < 1 for value in budgets):
        raise ValueError("budgets must be positive integers")
    return budgets


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
    rank = normalize_rank(row.get("best_known_anchor_rank"))
    if rank is not None:
        return rank
    ranks = [
        normalize_rank(anchor.get("rank"))
        for anchor in row.get("top_anchors", [])
        if isinstance(anchor, dict) and anchor.get("known_anchor_overlap")
    ]
    ranks = [rank for rank in ranks if rank is not None]
    return min(ranks) if ranks else None


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


def anchor_key(anchor: dict[str, Any]) -> tuple[str, int, int, str, str]:
    return (
        str(anchor.get("file") or ""),
        int(anchor.get("start_line") or 0),
        int(anchor.get("end_line") or 0),
        str(anchor.get("span_kind") or ""),
        str(anchor.get("symbol") or ""),
    )


def fuse_case(
    *,
    left_row: dict[str, Any],
    right_row: dict[str, Any],
    left_label: str,
    right_label: str,
    left_weight: float,
    right_weight: float,
    rrf_k: float,
    per_source_cap: int | None,
) -> dict[str, Any]:
    anchors: dict[tuple[str, int, int, str, str], dict[str, Any]] = {}

    def add_anchor(anchor: dict[str, Any], source: str, source_label: str) -> None:
        rank = normalize_rank(anchor.get("rank"))
        if rank is None:
            return
        key = anchor_key(anchor)
        fused = anchors.setdefault(
            key,
            {
                "file": key[0],
                "start_line": key[1],
                "end_line": key[2],
                "span_kind": key[3],
                "symbol": key[4],
                "known_anchor_overlap": False,
                "source_ranks": {},
                "source_scores": {},
                "source_anchor_ids": {},
            },
        )
        fused["known_anchor_overlap"] = fused["known_anchor_overlap"] or bool(anchor.get("known_anchor_overlap"))
        fused["source_ranks"][source_label] = rank
        if isinstance(anchor.get("score"), (int, float)):
            fused["source_scores"][source_label] = float(anchor["score"])
        if anchor.get("anchor_id"):
            fused["source_anchor_ids"][source_label] = anchor["anchor_id"]
        if source == "left":
            fused["_left_rank"] = rank
        else:
            fused["_right_rank"] = rank

    left_anchors = left_row.get("top_anchors") or []
    right_anchors = right_row.get("top_anchors") or []
    if per_source_cap is not None:
        left_anchors = left_anchors[:per_source_cap]
        right_anchors = right_anchors[:per_source_cap]
    for anchor in left_anchors:
        if isinstance(anchor, dict):
            add_anchor(anchor, "left", left_label)
    for anchor in right_anchors:
        if isinstance(anchor, dict):
            add_anchor(anchor, "right", right_label)

    def fused_score(anchor: dict[str, Any]) -> float:
        left_rank = anchor.get("_left_rank")
        right_rank = anchor.get("_right_rank")
        return (
            (left_weight / (rrf_k + left_rank) if isinstance(left_rank, int) else 0.0)
            + (right_weight / (rrf_k + right_rank) if isinstance(right_rank, int) else 0.0)
        )

    top_anchors: list[dict[str, Any]] = []
    for rank, anchor in enumerate(sorted(anchors.values(), key=fused_score, reverse=True), 1):
        row = {key: value for key, value in anchor.items() if not key.startswith("_")}
        row["anchor_id"] = f"fused_anchor::{rank:08d}"
        row["rank"] = rank
        row["score"] = fused_score(anchor)
        row["retrieval_source"] = "anchor_level_rrf"
        top_anchors.append(row)

    best_hit_rank = next((int(anchor["rank"]) for anchor in top_anchors if anchor.get("known_anchor_overlap")), None)
    return {
        "identity_key": left_row["identity_key"],
        "case_id": left_row.get("case_id") or right_row.get("case_id"),
        "repo_key": left_row.get("repo_key") or right_row.get("repo_key"),
        "repo_url": left_row.get("repo_url") or right_row.get("repo_url"),
        "checkout_revision": left_row.get("checkout_revision") or right_row.get("checkout_revision"),
        "hcvr_type": left_row.get("hcvr_type") or right_row.get("hcvr_type"),
        "cwe_ids": left_row.get("cwe_ids") or right_row.get("cwe_ids") or [],
        "state": "completed",
        "candidate_count": len(top_anchors),
        "known_anchor_count": left_row.get("known_anchor_count") or right_row.get("known_anchor_count"),
        "best_known_anchor_rank": best_hit_rank,
        "hit_at_top_k": best_hit_rank is not None,
        "fusion": {
            "method": "rrf",
            "left_label": left_label,
            "right_label": right_label,
            "left_weight": left_weight,
            "right_weight": right_weight,
            "rrf_k": rrf_k,
            "per_source_cap": per_source_cap,
            "left_best_known_anchor_rank": best_rank(left_row),
            "right_best_known_anchor_rank": best_rank(right_row),
            "left_candidate_count": left_row.get("candidate_count"),
            "right_candidate_count": right_row.get("candidate_count"),
        },
        "top_anchors": top_anchors,
    }


def summarize(rows: list[dict[str, Any]], budgets: list[int]) -> dict[str, Any]:
    ranks = [best_rank(row) for row in rows]
    hit_ranks = [rank for rank in ranks if rank is not None]
    summary: dict[str, Any] = {
        "case_count": len(rows),
        "completed_count": sum(1 for row in rows if row.get("state") == "completed"),
        "failed_count": sum(1 for row in rows if row.get("state") != "completed"),
        "candidate_count": sum(int(row.get("candidate_count") or 0) for row in rows),
        "mean_candidates_per_case": (
            sum(int(row.get("candidate_count") or 0) for row in rows) / len(rows) if rows else 0.0
        ),
        "hit_cases": len(hit_ranks),
        "mrr": sum(1.0 / rank for rank in hit_ranks) / len(rows) if rows else 0.0,
    }
    for budget in budgets:
        count = sum(1 for rank in hit_ranks if rank <= budget)
        summary[f"hit_count_at_{budget}"] = count
        summary[f"known_anchor_hit_at_{budget}"] = count / len(rows) if rows else 0.0
    return summary


def selected_anchor_row(case_result: dict[str, Any], rank: int) -> dict[str, Any] | None:
    for anchor in case_result.get("top_anchors") or []:
        if int(anchor.get("rank") or 0) == rank:
            return {
                "identity_key": case_result["identity_key"],
                "case_id": case_result.get("case_id"),
                "repo_url": case_result.get("repo_url"),
                "repo_key": case_result.get("repo_key"),
                "checkout_revision": case_result.get("checkout_revision"),
                "hcvr_type": case_result.get("hcvr_type"),
                **anchor,
            }
    return None


def fuse_tables(
    *,
    left_rows: list[dict[str, Any]],
    right_rows: list[dict[str, Any]],
    left_label: str,
    right_label: str,
    left_weight: float,
    right_weight: float,
    rrf_k: float,
    per_source_cap: int | None,
    budgets: list[int],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    left_order, left = index_by_identity(left_rows, left_label)
    right_order, right = index_by_identity(right_rows, right_label)
    left_set = set(left)
    right_set = set(right)
    if left_set != right_set:
        raise ValueError(
            "identity sets differ; fuse only same-identity recall outputs "
            f"(left_only={len(left_set - right_set)}, right_only={len(right_set - left_set)})"
        )
    if left_order != right_order:
        raise ValueError("identity order differs; rerun or reorder inputs before fusion")
    fused_rows = [
        fuse_case(
            left_row=left[identity],
            right_row=right[identity],
            left_label=left_label,
            right_label=right_label,
            left_weight=left_weight,
            right_weight=right_weight,
            rrf_k=rrf_k,
            per_source_cap=per_source_cap,
        )
        for identity in left_order
    ]
    summary = {
        "schema_version": "hcvr_anchor_rrf_fusion.v1",
        "left_label": left_label,
        "right_label": right_label,
        "left_count": len(left_rows),
        "right_count": len(right_rows),
        "same_identity_set": True,
        "same_identity_order": True,
        "fusion": {
            "method": "rrf",
            "left_weight": left_weight,
            "right_weight": right_weight,
            "rrf_k": rrf_k,
            "per_source_cap": per_source_cap,
        },
        "budgets": budgets,
        "metrics": summarize(fused_rows, budgets),
    }
    return fused_rows, summary


def markdown_report(summary: dict[str, Any]) -> str:
    metrics = summary["metrics"]
    lines = [
        "# HCVR Anchor-Level RRF Fusion",
        "",
        f"- Left: `{summary['left_label']}` ({summary['left_count']} rows)",
        f"- Right: `{summary['right_label']}` ({summary['right_count']} rows)",
        f"- Same identity set: {summary['same_identity_set']}",
        f"- Same identity order: {summary['same_identity_order']}",
        f"- Method: `{summary['fusion']['method']}`",
        f"- Weights: left={summary['fusion']['left_weight']}, right={summary['fusion']['right_weight']}",
        f"- RRF k: {summary['fusion']['rrf_k']}",
        f"- Per-source cap: {summary['fusion']['per_source_cap']}",
        f"- Cases: {metrics['case_count']}",
        f"- MRR: {metrics['mrr']:.6f}",
        "",
        "## Hit@K",
        "",
        "| K | Hit Count | Rate |",
        "| ---: | ---: | ---: |",
    ]
    for budget in summary["budgets"]:
        lines.append(
            f"| {budget} | {metrics[f'hit_count_at_{budget}']} | "
            f"{metrics[f'known_anchor_hit_at_{budget}']:.4f} |"
        )
    return "\n".join(lines).rstrip() + "\n"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--left", type=Path, required=True)
    parser.add_argument("--right", type=Path, required=True)
    parser.add_argument("--left-label", default="left")
    parser.add_argument("--right-label", default="right")
    parser.add_argument("--left-weight", type=float, default=1.5)
    parser.add_argument("--right-weight", type=float, default=1.0)
    parser.add_argument("--rrf-k", type=float, default=60.0)
    parser.add_argument("--per-source-cap", type=int, default=1000)
    parser.add_argument("--audit-anchor-rank", type=int, default=1)
    parser.add_argument("--budgets", default=",".join(str(value) for value in DEFAULT_BUDGETS))
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    if args.left_weight <= 0 or args.right_weight <= 0:
        raise SystemExit("weights must be positive")
    if args.rrf_k <= 0:
        raise SystemExit("--rrf-k must be positive")
    if args.per_source_cap < 1:
        raise SystemExit("--per-source-cap must be positive")
    if args.audit_anchor_rank < 1:
        raise SystemExit("--audit-anchor-rank must be positive")
    budgets = parse_budgets(args.budgets)
    fused_rows, summary = fuse_tables(
        left_rows=read_jsonl(args.left),
        right_rows=read_jsonl(args.right),
        left_label=args.left_label,
        right_label=args.right_label,
        left_weight=args.left_weight,
        right_weight=args.right_weight,
        rrf_k=args.rrf_k,
        per_source_cap=args.per_source_cap,
        budgets=budgets,
    )
    args.output_dir.mkdir(parents=True, exist_ok=True)
    recall_path = args.output_dir / "recall_results.jsonl"
    selected_path = args.output_dir / "selected_cases.jsonl"
    summary_path = args.output_dir / "summary.json"
    readme_path = args.output_dir / "README.md"
    selected_rows = [
        row
        for row in (selected_anchor_row(case_result, args.audit_anchor_rank) for case_result in fused_rows)
        if row is not None
    ]
    write_jsonl(recall_path, fused_rows)
    write_jsonl(selected_path, selected_rows)
    summary["audit_anchor_rank"] = args.audit_anchor_rank
    summary["artifacts"] = {
        "recall_results": str(recall_path),
        "selected_cases": str(selected_path),
        "summary": str(summary_path),
    }
    write_json(summary_path, summary)
    readme_path.write_text(markdown_report(summary), encoding="utf-8")
    sys.stdout.write(markdown_report(summary))


if __name__ == "__main__":
    main()
