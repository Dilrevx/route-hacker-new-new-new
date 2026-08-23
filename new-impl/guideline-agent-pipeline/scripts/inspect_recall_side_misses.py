#!/usr/bin/env python3
"""Inspect recall-side misses for semantically clean guideline groups."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from statistics import mean
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


def normalize_rank(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int) and value > 0:
        return value
    if isinstance(value, str) and value.isdigit():
        parsed = int(value)
        return parsed if parsed > 0 else None
    return None


def index_by_key(rows: list[dict[str, Any]], key: str, label: str) -> dict[str, dict[str, Any]]:
    indexed: dict[str, dict[str, Any]] = {}
    duplicates: list[str] = []
    for row in rows:
        value = row.get(key)
        if not isinstance(value, str) or not value:
            raise ValueError(f"{label} row missing {key}: {row}")
        if value in indexed:
            duplicates.append(value)
            continue
        indexed[value] = row
    if duplicates:
        raise ValueError(f"{label} has duplicate {key} values: {sorted(duplicates)[:10]}")
    return indexed


def group_by_guideline(rows: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        guideline_id = str(row.get("guideline_id") or "")
        if guideline_id:
            grouped.setdefault(guideline_id, []).append(row)
    return grouped


def group_by_identity(rows: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        identity = str(row.get("identity_key") or "")
        if identity:
            grouped.setdefault(identity, []).append(row)
    for identity_rows in grouped.values():
        identity_rows.sort(key=lambda row: normalize_rank(row.get("rank")) or 10**12)
    return grouped


def miss_state(case: dict[str, Any], primary_budget: int) -> str:
    rank = normalize_rank(case.get("rank"))
    if not case.get("present_in_recall_table"):
        return "coverage_gap_not_in_rank_table"
    if rank is not None and rank > primary_budget:
        return "ranked_below_primary_budget"
    if rank is None:
        return "ranked_without_known_anchor_overlap"
    return "unexpected_non_miss"


def candidate_count_bucket(value: Any) -> str:
    if not isinstance(value, int):
        return "unknown"
    if value < 1000:
        return "lt_1k"
    if value < 5000:
        return "1k_to_5k"
    if value < 20000:
        return "5k_to_20k"
    return "gte_20k"


def summarize_exported_candidates(candidates: list[dict[str, Any]], primary_budget: int) -> dict[str, Any]:
    if not candidates:
        return {
            "provided": False,
            "exported_count": 0,
            "known_anchor_overlap_count": 0,
            "best_exported_overlap_rank": None,
            "overlap_within_primary_budget": None,
            "top_files": [],
        }
    overlap_ranks = [
        normalize_rank(row.get("rank"))
        for row in candidates
        if row.get("known_anchor_overlap")
    ]
    overlap_ranks = [rank for rank in overlap_ranks if rank is not None]
    top_files = []
    seen_files: set[str] = set()
    for row in candidates[:10]:
        file = str(row.get("file") or "")
        if file and file not in seen_files:
            seen_files.add(file)
            top_files.append(file)
    best_overlap = min(overlap_ranks) if overlap_ranks else None
    return {
        "provided": True,
        "exported_count": len(candidates),
        "known_anchor_overlap_count": len(overlap_ranks),
        "best_exported_overlap_rank": best_overlap,
        "overlap_within_primary_budget": (
            best_overlap <= primary_budget if best_overlap is not None else False
        ),
        "top_files": top_files,
    }


def inspect_case(
    *,
    case: dict[str, Any],
    group: dict[str, Any],
    rank_row: dict[str, Any] | None,
    exported_candidates: list[dict[str, Any]],
    primary_budget: int,
) -> dict[str, Any]:
    rank = normalize_rank(case.get("rank"))
    state = miss_state(case, primary_budget)
    top1 = {}
    if exported_candidates:
        first_candidate = exported_candidates[0]
        top1 = {
            "file": first_candidate.get("file"),
            "start_line": first_candidate.get("start_line"),
            "end_line": first_candidate.get("end_line"),
            "known_anchor_overlap": first_candidate.get("known_anchor_overlap"),
        }
    elif rank_row:
        top1 = {
            "file": rank_row.get("top1_file"),
            "start_line": rank_row.get("top1_start_line"),
            "end_line": rank_row.get("top1_end_line"),
            "known_anchor_overlap": rank_row.get("top1_known_anchor_overlap"),
        }

    candidate_summary = summarize_exported_candidates(exported_candidates, primary_budget)
    evidence_available = {
        "case_alignment_row": True,
        "case_rank_summary_row": rank_row is not None,
        "full_ranked_candidate_list": candidate_summary["provided"],
        "known_anchor_span_details": candidate_summary["provided"],
    }

    diagnosis: list[str] = []
    next_checks: list[str] = []
    if state == "coverage_gap_not_in_rank_table":
        diagnosis.append("identity_absent_from_rank_table")
        next_checks.append("verify_identity_filter_dataset_split_and_rank_table_coverage")
    elif state == "ranked_below_primary_budget":
        diagnosis.append("known_anchor_ranked_below_primary_budget")
        next_checks.extend(
            [
                "inspect_guideline_query_wording_against_source_evidence",
                "inspect_candidate_slicing_for_known_anchor_context",
                "compare_embedding_backend_or_query_adapter_on_same_identity",
            ]
        )
        if rank_row and rank_row.get("top1_known_anchor_overlap") is False:
            diagnosis.append("top1_candidate_does_not_overlap_known_anchor")
        if rank_row and candidate_count_bucket(rank_row.get("candidate_count")) in {"5k_to_20k", "gte_20k"}:
            diagnosis.append("large_candidate_pool_budget_pressure")
            next_checks.append("inspect_budget_or_reranker_need_on_same_identity")
        if candidate_summary["provided"] and candidate_summary["known_anchor_overlap_count"] == 0:
            diagnosis.append("exported_candidates_do_not_include_known_anchor_overlap")
            next_checks.append("increase_export_top_candidates_or_check_candidate_generation")
        elif (
            candidate_summary["provided"]
            and isinstance(candidate_summary["best_exported_overlap_rank"], int)
            and candidate_summary["best_exported_overlap_rank"] > primary_budget
        ):
            diagnosis.append("known_anchor_present_in_export_but_below_primary_budget")
    elif state == "ranked_without_known_anchor_overlap":
        diagnosis.append("rank_row_present_but_no_known_anchor_overlap_reported")
        next_checks.append("inspect_known_anchor_span_matching_and_candidate_overlap")
    else:
        diagnosis.append("unexpected_state_check_alignment_inputs")
        next_checks.append("manual_alignment_debug")

    return {
        "identity_key": case.get("identity_key"),
        "case_id": (rank_row or {}).get("case_id"),
        "repo_key": (rank_row or {}).get("repo_key"),
        "checkout_revision": (rank_row or {}).get("checkout_revision"),
        "guideline_id": case.get("guideline_id"),
        "guideline_group_key": case.get("guideline_group_key"),
        "mechanism_id": case.get("mechanism_id"),
        "mechanism_name": case.get("mechanism_name") or group.get("mechanism_name"),
        "mechanism_family": case.get("mechanism_family") or group.get("mechanism_family"),
        "primary_hcvr_type": case.get("primary_hcvr_type"),
        "primary_budget": primary_budget,
        "miss_state": state,
        "rank": rank,
        "rank_distance_from_primary_budget": (rank - primary_budget if rank is not None else None),
        "candidate_count": (rank_row or {}).get("candidate_count"),
        "candidate_count_bucket": candidate_count_bucket((rank_row or {}).get("candidate_count")),
        "known_anchor_count": (rank_row or {}).get("known_anchor_count"),
        "guideline_mode": (rank_row or {}).get("guideline_mode"),
        "guideline_query_count": (rank_row or {}).get("guideline_query_count"),
        "rank_row_state": (rank_row or {}).get("state"),
        "top1": top1,
        "exported_candidate_summary": candidate_summary,
        "group_flags": group.get("flags") or [],
        "group_attention": group.get("attention") or [],
        "evidence_available": evidence_available,
        "diagnosis": diagnosis,
        "next_checks": list(dict.fromkeys(next_checks)),
        "policy": "rank_only_recall_diagnosis_no_guideline_or_ranking_change",
    }


def build_inspection(
    *,
    debug_summary: dict[str, Any],
    group_rows: list[dict[str, Any]],
    case_rows: list[dict[str, Any]],
    rank_rows: list[dict[str, Any]],
    exported_candidate_rows: list[dict[str, Any]] | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    primary_budget = int(debug_summary.get("primary_budget") or 100)
    groups = index_by_key(group_rows, "guideline_id", "group alignment")
    cases_by_guideline = group_by_guideline(case_rows)
    ranks = index_by_key(rank_rows, "identity_key", "recall rank table")
    exported_candidates = group_by_identity(exported_candidate_rows or [])
    debug_guidelines = {
        str(row.get("guideline_id"))
        for row in group_rows
        if "embedding_or_candidate_recall_attention" in set(row.get("attention") or [])
    }
    rows: list[dict[str, Any]] = []
    for guideline_id in sorted(debug_guidelines):
        group = groups[guideline_id]
        for case in cases_by_guideline.get(guideline_id, []):
            if case.get("hit_at_primary_budget"):
                continue
            identity = str(case.get("identity_key") or "")
            rows.append(
                inspect_case(
                    case=case,
                    group=group,
                    rank_row=ranks.get(identity),
                    exported_candidates=exported_candidates.get(identity, []),
                    primary_budget=primary_budget,
                )
            )

    rows.sort(
        key=lambda row: (
            row["miss_state"] != "ranked_below_primary_budget",
            row.get("rank") if isinstance(row.get("rank"), int) else 10**12,
            str(row.get("guideline_id") or ""),
            str(row.get("identity_key") or ""),
        )
    )

    state_counts: dict[str, int] = {}
    diagnosis_counts: dict[str, int] = {}
    next_check_counts: dict[str, int] = {}
    rank_values: list[int] = []
    for row in rows:
        state = str(row["miss_state"])
        state_counts[state] = state_counts.get(state, 0) + 1
        if isinstance(row.get("rank"), int):
            rank_values.append(int(row["rank"]))
        for item in row.get("diagnosis") or []:
            diagnosis_counts[str(item)] = diagnosis_counts.get(str(item), 0) + 1
        for item in row.get("next_checks") or []:
            next_check_counts[str(item)] = next_check_counts.get(str(item), 0) + 1

    summary = {
        "schema_version": "hcvr_recall_side_miss_inspection.v1",
        "recall_label": debug_summary.get("recall_label"),
        "primary_budget": primary_budget,
        "debug_group_count": len(debug_guidelines),
        "case_count": len(rows),
        "miss_state_counts": dict(sorted(state_counts.items())),
        "diagnosis_counts": dict(sorted(diagnosis_counts.items())),
        "next_check_counts": dict(sorted(next_check_counts.items())),
        "ranked_miss_rank_stats": {
            "count": len(rank_values),
            "min": min(rank_values) if rank_values else None,
            "max": max(rank_values) if rank_values else None,
            "mean": mean(rank_values) if rank_values else None,
        },
        "input_capability": {
            "case_alignment_rows": True,
            "case_rank_summary_rows": True,
            "full_ranked_candidate_lists": bool(exported_candidate_rows),
            "known_anchor_span_details": bool(exported_candidate_rows),
        },
        "policy": [
            (
                "This is a candidate-aware recall-side inspection artifact."
                if exported_candidate_rows
                else "This is a rank-only recall-side inspection artifact."
            ),
            "It does not update guidelines, sidecars, ranking, embedding weights, or audit prompts.",
            "It separates rank-table coverage gaps from joined cases whose known anchor ranks below the primary budget.",
            (
                "It can report whether exported Top-N candidates include known-anchor overlap, but it does not prove vulnerability precision."
                if exported_candidate_rows
                else "It cannot prove candidate-slicing failure without full ranked candidate lists and known-anchor span details."
            ),
        ],
    }
    return summary, rows


def write_readme(path: Path, summary: dict[str, Any], rows: list[dict[str, Any]]) -> None:
    lines = [
        "# Recall-Side Miss Inspection",
        "",
        "This artifact expands the clean guideline miss debug pack to case-level rows.",
        (
            "It includes exported candidate summaries."
            if summary["input_capability"].get("full_ranked_candidate_lists")
            else "It is rank-only because the current input rank table contains case summaries, not full ranked candidate lists."
        ),
        "",
        "## Summary",
        "",
        f"- Recall label: `{summary['recall_label']}`",
        f"- Primary budget: Top-{summary['primary_budget']}",
        f"- Debug groups: {summary['debug_group_count']}",
        f"- Cases inspected: {summary['case_count']}",
        f"- Miss states: {summary['miss_state_counts']}",
        f"- Diagnosis counts: {summary['diagnosis_counts']}",
        f"- Next checks: {summary['next_check_counts']}",
        f"- Ranked miss rank stats: {summary['ranked_miss_rank_stats']}",
        "",
        "## Case Rows",
        "",
        "| Identity | Guideline | State | Rank | Candidate Count | Top1 | Exported Candidates | Diagnosis | Next Checks |",
        "| --- | --- | --- | ---: | ---: | --- | --- | --- | --- |",
    ]
    for row in rows:
        top1 = row.get("top1") or {}
        top1_text = "n/a"
        if top1:
            top1_text = f"{top1.get('file')}:{top1.get('start_line')}-{top1.get('end_line')}"
        lines.append(
            f"| `{row.get('identity_key')}` | `{row.get('guideline_id')}` | `{row.get('miss_state')}` | "
            f"{format_tsv(row.get('rank'))} | {format_tsv(row.get('candidate_count'))} | "
            f"{format_tsv(top1_text)} | {format_tsv(row.get('exported_candidate_summary'))} | "
            f"{format_tsv(row.get('diagnosis'))} | {format_tsv(row.get('next_checks'))} |"
        )
    lines.extend(
        [
            "",
            "## Limits",
            "",
            (
                "- This inspection includes exported Top-N candidate rows and can identify whether known-anchor-overlapping slices are present within that exported budget."
                if summary["input_capability"].get("full_ranked_candidate_lists")
                else "- The current rank table has only one Top-1 candidate summary plus the best known-anchor rank."
            ),
            (
                "- It still does not prove vulnerability precision; it only separates absent/ranked-low anchor evidence from semantic guideline review."
                if summary["input_capability"].get("full_ranked_candidate_lists")
                else "- This inspection cannot decide whether a specific known-anchor slice was malformed, absent, or simply ranked too low."
            ),
            (
                "- To inspect deeper rank positions, rerun recall with a larger `--export-top-candidates` under the same identity list and embedding backend."
                if summary["input_capability"].get("full_ranked_candidate_lists")
                else "- To inspect candidate slicing directly, rerun recall with full Top-N candidate export and known-anchor span details, then join those files by `identity_key`."
            ),
            "",
        ]
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--recall-side-debug-summary", type=Path, required=True)
    parser.add_argument("--group-alignment", type=Path, required=True)
    parser.add_argument("--case-alignment", type=Path, required=True)
    parser.add_argument("--recall-rank-table", type=Path, required=True)
    parser.add_argument(
        "--top-candidates",
        type=Path,
        help=(
            "Optional flat top_candidates.jsonl exported by recall_guideline_anchors.py "
            "--export-top-candidates. Enables candidate-overlap summaries."
        ),
    )
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    if args.output_dir.exists() and any(args.output_dir.iterdir()):
        raise FileExistsError(f"refusing to overwrite non-empty output directory: {args.output_dir}")
    summary, rows = build_inspection(
        debug_summary=read_json(args.recall_side_debug_summary),
        group_rows=read_jsonl(args.group_alignment),
        case_rows=read_jsonl(args.case_alignment),
        rank_rows=read_jsonl(args.recall_rank_table),
        exported_candidate_rows=read_jsonl(args.top_candidates) if args.top_candidates else None,
    )
    args.output_dir.mkdir(parents=True, exist_ok=True)
    write_json(args.output_dir / "summary.json", summary)
    write_jsonl(args.output_dir / "case_miss_inspection.jsonl", rows)
    write_tsv(
        args.output_dir / "case_miss_inspection.tsv",
        rows,
        [
            "identity_key",
            "guideline_id",
            "mechanism_id",
            "primary_hcvr_type",
            "miss_state",
            "rank",
            "rank_distance_from_primary_budget",
            "candidate_count",
            "candidate_count_bucket",
            "known_anchor_count",
            "top1",
            "exported_candidate_summary",
            "diagnosis",
            "next_checks",
        ],
    )
    write_readme(args.output_dir / "README.md", summary, rows)
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
