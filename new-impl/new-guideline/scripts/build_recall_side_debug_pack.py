#!/usr/bin/env python3
"""Build a review-only debug pack for semantically clean recall misses."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


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


def format_tsv(value: Any) -> str:
    if value is None:
        return "n/a"
    if isinstance(value, float):
        return f"{value:.4f}"
    if isinstance(value, (list, tuple)):
        return ",".join(str(item) for item in value) or "n/a"
    if isinstance(value, dict):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return str(value).replace("\t", " ").replace("\n", " ") or "n/a"


def write_tsv(path: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        handle.write("\t".join(fields) + "\n")
        for row in rows:
            handle.write("\t".join(format_tsv(row.get(field)) for field in fields) + "\n")


def group_by_guideline(rows: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        guideline_id = str(row.get("guideline_id") or "")
        if not guideline_id:
            continue
        grouped.setdefault(guideline_id, []).append(row)
    return grouped


def clean_attention(row: dict[str, Any]) -> bool:
    attention = set(row.get("attention") or [])
    return "embedding_or_candidate_recall_attention" in attention


def build_case_summary(case: dict[str, Any], primary_budget: int) -> dict[str, Any]:
    present = bool(case.get("present_in_recall_table"))
    rank = case.get("rank")
    if not present:
        state = "coverage_gap_not_in_rank_table"
    elif isinstance(rank, int) and rank > primary_budget:
        state = "ranked_below_primary_budget"
    elif rank is None:
        state = "ranked_without_known_anchor_overlap"
    else:
        state = "unexpected_non_miss"
    return {
        "identity_key": case.get("identity_key"),
        "primary_hcvr_type": case.get("primary_hcvr_type"),
        "present_in_recall_table": present,
        "rank": rank,
        "miss_state": state,
        "baseline_rank": case.get("baseline_rank"),
        "rank_delta_vs_baseline": case.get("rank_delta_vs_baseline"),
    }


def recommended_checks(miss_states: set[str], has_label_mixture: bool) -> list[str]:
    checks = []
    if "coverage_gap_not_in_rank_table" in miss_states:
        checks.append("verify_identity_filter_dataset_split_and_rank_table_coverage")
    if "ranked_below_primary_budget" in miss_states:
        checks.extend(
            [
                "inspect_guideline_query_wording_against_source_evidence",
                "inspect_candidate_slicing_for_known_anchor_context",
                "compare_embedding_backend_or_query_adapter_on_same_identity",
            ]
        )
    if "ranked_without_known_anchor_overlap" in miss_states:
        checks.append("inspect_known_anchor_span_matching_and_candidate_overlap")
    if has_label_mixture:
        checks.append("review_label_mixture_without_treating_it_as_hard_failure")
    if not checks:
        checks.append("manual_recall_debug")
    return checks


def build_pack(
    *,
    alignment_summary: dict[str, Any],
    group_rows: list[dict[str, Any]],
    case_rows: list[dict[str, Any]],
    max_cases_per_group: int,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    cases_by_guideline = group_by_guideline(case_rows)
    primary_budget = int(alignment_summary.get("primary_budget") or 100)
    debug_rows: list[dict[str, Any]] = []
    for group in group_rows:
        if not clean_attention(group):
            continue
        guideline_id = str(group.get("guideline_id") or "")
        cases = cases_by_guideline.get(guideline_id, [])
        misses = [
            build_case_summary(case, primary_budget)
            for case in cases
            if not case.get("hit_at_primary_budget")
        ]
        if not misses:
            continue
        miss_state_counts: dict[str, int] = {}
        for miss in misses:
            state = str(miss["miss_state"])
            miss_state_counts[state] = miss_state_counts.get(state, 0) + 1
        has_label_mixture = "label_mixed_structural_attention" in set(group.get("attention") or [])
        debug_rows.append(
            {
                "guideline_id": guideline_id,
                "mechanism_id": group.get("mechanism_id"),
                "mechanism_name": group.get("mechanism_name"),
                "guideline_group_key": group.get("guideline_group_key"),
                "primary_budget": primary_budget,
                "assigned_case_count": group.get("assigned_case_count"),
                "recall_joined_case_count": group.get("recall_joined_case_count"),
                "missing_recall_count": group.get("missing_recall_count"),
                "primary_hit_count": group.get("primary_hit_count"),
                "primary_hit_rate": group.get("primary_hit_rate"),
                "flags": group.get("flags") or [],
                "attention": group.get("attention") or [],
                "miss_state_counts": dict(sorted(miss_state_counts.items())),
                "example_misses": misses[:max_cases_per_group],
                "recommended_checks": recommended_checks(set(miss_state_counts), has_label_mixture),
                "policy": "debug_only_no_guideline_or_ranking_change",
            }
        )

    debug_rows.sort(
        key=lambda row: (
            -(row.get("recall_joined_case_count") or 0),
            -(row.get("assigned_case_count") or 0),
            str(row.get("guideline_id") or ""),
        )
    )
    miss_state_totals: dict[str, int] = {}
    check_counts: dict[str, int] = {}
    for row in debug_rows:
        for state, count in (row.get("miss_state_counts") or {}).items():
            miss_state_totals[state] = miss_state_totals.get(state, 0) + int(count)
        for check in row.get("recommended_checks") or []:
            check_counts[check] = check_counts.get(check, 0) + 1

    summary = {
        "schema_version": "hcvr_recall_side_debug_pack.v1",
        "recall_label": alignment_summary.get("recall_label"),
        "primary_budget": primary_budget,
        "source_alignment_joined_recall_case_count": alignment_summary.get("joined_recall_case_count"),
        "source_alignment_recall_case_count": alignment_summary.get("recall_case_count"),
        "source_attention_counts": alignment_summary.get("attention_counts") or {},
        "cleanliness_policy": alignment_summary.get("cleanliness_policy") or {},
        "debug_group_count": len(debug_rows),
        "miss_state_totals": dict(sorted(miss_state_totals.items())),
        "recommended_check_counts": dict(sorted(check_counts.items())),
        "policy": [
            "This pack is recall-side diagnosis only.",
            "It does not update guidelines, sidecars, ranking, embedding weights, or audit prompts.",
            "Coverage gaps are separated from real Top-K misses.",
            "Mixed HCVR/CWE labels are review signals, not automatic taxonomy failures.",
            "Any replacement embedder, reranker, or fusion method must be evaluated on the same identities, snapshots, candidates, and budgets.",
        ],
    }
    return summary, debug_rows


def write_readme(path: Path, summary: dict[str, Any], rows: list[dict[str, Any]]) -> None:
    lines = [
        "# Recall-Side Debug Pack",
        "",
        "This pack lists semantically clean guideline groups whose joined recall rows still miss the primary Top-K budget.",
        "It is a diagnosis artifact only: it does not change guidelines, sidecars, embedding weights, ranking, or audit prompts.",
        "",
        "## Summary",
        "",
        f"- Recall label: `{summary['recall_label']}`",
        f"- Primary budget: Top-{summary['primary_budget']}",
        f"- Alignment join coverage: {summary['source_alignment_joined_recall_case_count']} / {summary['source_alignment_recall_case_count']}",
        f"- Debug groups: {summary['debug_group_count']}",
        f"- Miss states: {summary['miss_state_totals']}",
        f"- Recommended checks: {summary['recommended_check_counts']}",
        "",
        "## Debug Groups",
        "",
        "| Guideline | Mechanism | Joined | Miss States | Checks | Example Misses |",
        "| --- | --- | ---: | --- | --- | --- |",
    ]
    for row in rows:
        examples = [
            f"{item.get('identity_key')}@{item.get('rank') or 'none'}:{item.get('miss_state')}"
            for item in row.get("example_misses", [])
        ]
        lines.append(
            f"| `{row.get('guideline_id')}` | `{row.get('mechanism_id')}` | {row.get('recall_joined_case_count')} | "
            f"{format_tsv(row.get('miss_state_counts'))} | {format_tsv(row.get('recommended_checks'))} | {format_tsv(examples)} |"
        )
    lines.extend(
        [
            "",
            "## Use Policy",
            "",
            "- Inspect coverage gaps before blaming the embedding model.",
            "- Inspect query wording, candidate slicing, embedding backend, and adapter behavior for joined Top-K misses.",
            "- Do not convert missed identities, labels, or judge notes into runtime regex fallback or per-case routing.",
            "- Keep paper claims separated: semantic guideline quality, same-identity recall delta, sidecar equivalence, and engineering fusion are different claims.",
            "",
        ]
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--alignment-summary", type=Path, required=True)
    parser.add_argument("--group-alignment", type=Path, required=True)
    parser.add_argument("--case-alignment", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--max-cases-per-group", type=int, default=5)
    args = parser.parse_args()
    if args.output_dir.exists() and any(args.output_dir.iterdir()):
        raise FileExistsError(f"refusing to overwrite non-empty output directory: {args.output_dir}")
    summary, rows = build_pack(
        alignment_summary=read_json(args.alignment_summary),
        group_rows=read_jsonl(args.group_alignment),
        case_rows=read_jsonl(args.case_alignment),
        max_cases_per_group=args.max_cases_per_group,
    )
    args.output_dir.mkdir(parents=True, exist_ok=True)
    write_json(args.output_dir / "summary.json", summary)
    write_jsonl(args.output_dir / "recall_side_debug_pack.jsonl", rows)
    write_tsv(
        args.output_dir / "recall_side_debug_pack.tsv",
        rows,
        [
            "guideline_id",
            "mechanism_id",
            "recall_joined_case_count",
            "missing_recall_count",
            "primary_hit_count",
            "miss_state_counts",
            "recommended_checks",
        ],
    )
    write_readme(args.output_dir / "README.md", summary, rows)
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
