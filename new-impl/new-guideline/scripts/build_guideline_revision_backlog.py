#!/usr/bin/env python3
"""Build a review backlog from guideline judge output and recall alignment."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


DECISION_PRIORITY = {
    "invalid": 0,
    "missing": 0,
    "split": 1,
    "revise": 2,
    "needs_evidence": 3,
    "merge": 4,
    "accept": 5,
}
ATTENTION_PRIORITY = {
    "recall_regression_attention": 0,
    "guideline_quality_attention": 1,
    "embedding_or_candidate_recall_attention": 2,
    "guideline_pending_review": 3,
    "missing_recall_rows": 4,
    "recall_gain_evidence": 5,
}


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


def index_by_guideline(rows: list[dict[str, Any]], label: str) -> dict[str, dict[str, Any]]:
    indexed: dict[str, dict[str, Any]] = {}
    duplicates: list[str] = []
    for row in rows:
        guideline_id = str(row.get("guideline_id") or "")
        if not guideline_id:
            raise ValueError(f"{label} row missing guideline_id: {row}")
        if guideline_id in indexed:
            duplicates.append(guideline_id)
            continue
        indexed[guideline_id] = row
    if duplicates:
        raise ValueError(f"{label} has duplicate guideline_ids: {sorted(duplicates)[:10]}")
    return indexed


def min_attention_rank(attention: list[str]) -> int:
    if not attention:
        return len(ATTENTION_PRIORITY)
    return min(ATTENTION_PRIORITY.get(item, len(ATTENTION_PRIORITY)) for item in attention)


def min_score(row: dict[str, Any]) -> float | None:
    value = row.get("min_score")
    return value if isinstance(value, (int, float)) else None


def action_from(decision: str, attention: list[str], clean_enough: bool) -> str:
    attention_set = set(attention)
    if decision == "split":
        return "split_mechanism_boundary"
    if decision == "revise":
        return "revise_mechanism_text_from_evidence"
    if decision == "needs_evidence":
        return "collect_source_sink_guard_evidence"
    if "guideline_quality_attention" in attention_set or "guideline_pending_review" in attention_set:
        return "review_guideline_group_evidence"
    if clean_enough and "embedding_or_candidate_recall_attention" in attention_set:
        return "inspect_embedding_candidate_or_query_mismatch"
    if "recall_regression_attention" in attention_set:
        return "inspect_same_identity_recall_regression"
    if "missing_recall_rows" in attention_set:
        return "fix_recall_identity_join_or_run_coverage"
    if decision == "accept":
        return "keep_as_control_group"
    return "manual_review"


def build_backlog(
    *,
    judge_summary: dict[str, Any] | None,
    judge_rows: list[dict[str, Any]],
    alignment_summary: dict[str, Any] | None,
    alignment_rows: list[dict[str, Any]],
    max_items: int | None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    alignment_by_guideline = index_by_guideline(alignment_rows, "alignment") if alignment_rows else {}
    judge_ids = {str(row.get("guideline_id") or "") for row in judge_rows if row.get("guideline_id")}
    alignment_ids = set(alignment_by_guideline)
    ordered_ids = sorted(judge_ids | alignment_ids)

    backlog: list[dict[str, Any]] = []
    for guideline_id in ordered_ids:
        judge_row = next((row for row in judge_rows if row.get("guideline_id") == guideline_id), {})
        alignment_row = alignment_by_guideline.get(guideline_id, {})
        attention = alignment_row.get("attention") if isinstance(alignment_row.get("attention"), list) else []
        decision = str(judge_row.get("decision") or "not_judged")
        clean_enough = bool(alignment_row.get("guideline_clean_enough"))
        action = action_from(decision, attention, clean_enough)
        candidate_guideline = str(judge_row.get("suggested_guideline") or "").strip()
        backlog.append(
            {
                "guideline_id": guideline_id,
                "mechanism_id": judge_row.get("mechanism_id") or alignment_row.get("mechanism_id"),
                "mechanism_name": judge_row.get("mechanism_name") or alignment_row.get("mechanism_name"),
                "decision": decision,
                "min_score": min_score(judge_row),
                "main_issue": str(judge_row.get("main_issue") or "").strip(),
                "split_suggestions": judge_row.get("split_suggestions") if isinstance(judge_row.get("split_suggestions"), list) else [],
                "evidence_notes": judge_row.get("evidence_notes") if isinstance(judge_row.get("evidence_notes"), list) else [],
                "candidate_guideline_text": candidate_guideline,
                "candidate_guideline_status": "review_candidate_not_release" if candidate_guideline else "none",
                "attention": attention,
                "assigned_case_count": alignment_row.get("assigned_case_count"),
                "primary_budget": alignment_row.get("primary_budget"),
                "primary_hit_count": alignment_row.get("primary_hit_count"),
                "primary_hit_rate": alignment_row.get("primary_hit_rate"),
                "delta_primary_hit_count": alignment_row.get("delta_primary_hit_count"),
                "example_misses": alignment_row.get("example_misses") if isinstance(alignment_row.get("example_misses"), list) else [],
                "guideline_clean_enough": clean_enough if alignment_row else None,
                "recommended_action": action,
            }
        )

    backlog.sort(key=backlog_sort_key)
    if max_items is not None:
        backlog = backlog[:max_items]

    action_counts: dict[str, int] = {}
    decision_counts: dict[str, int] = {}
    attention_counts: dict[str, int] = {}
    for row in backlog:
        action_counts[row["recommended_action"]] = action_counts.get(row["recommended_action"], 0) + 1
        decision_counts[row["decision"]] = decision_counts.get(row["decision"], 0) + 1
        for item in row["attention"]:
            attention_counts[item] = attention_counts.get(item, 0) + 1

    summary = {
        "schema_version": "hcvr_guideline_revision_backlog.v1",
        "judge_summary": {
            "judge_input_count": (judge_summary or {}).get("judge_input_count"),
            "parsed_count": (judge_summary or {}).get("parsed_count"),
            "accepted_count": (judge_summary or {}).get("accepted_count"),
            "decision_counts": (judge_summary or {}).get("decision_counts"),
            "low_score_count": (judge_summary or {}).get("low_score_count"),
        },
        "alignment_summary": {
            "recall_label": (alignment_summary or {}).get("recall_label"),
            "baseline_label": (alignment_summary or {}).get("baseline_label"),
            "same_identity_baseline": (alignment_summary or {}).get("same_identity_baseline"),
            "joined_recall_case_count": (alignment_summary or {}).get("joined_recall_case_count"),
            "recall_case_count": (alignment_summary or {}).get("recall_case_count"),
            "primary_budget": (alignment_summary or {}).get("primary_budget"),
        },
        "backlog_count": len(backlog),
        "action_counts": dict(sorted(action_counts.items())),
        "decision_counts": dict(sorted(decision_counts.items())),
        "attention_counts": dict(sorted(attention_counts.items())),
        "policy": [
            "This backlog ranks review work; it does not update released guidelines.",
            "Candidate guideline text from a judge remains review_candidate_not_release until source evidence is checked.",
            "Recall misses on clean guideline groups should first trigger candidate slicing, query wording, or embedding inspection.",
            "Recall deltas are paper-facing only when the compared rank tables use the same identity set.",
        ],
    }
    return summary, backlog


def backlog_sort_key(row: dict[str, Any]) -> tuple[int, int, float, int, int, str]:
    decision_rank = DECISION_PRIORITY.get(row.get("decision"), len(DECISION_PRIORITY))
    attention_rank = min_attention_rank(row.get("attention") or [])
    score = row.get("min_score")
    score_rank = float(score) if isinstance(score, (int, float)) else 1.0
    regression = row.get("delta_primary_hit_count")
    regression_rank = int(regression) if isinstance(regression, int) else 0
    assigned = row.get("assigned_case_count")
    assigned_rank = int(assigned) if isinstance(assigned, int) else 0
    return (decision_rank, attention_rank, score_rank, regression_rank, -assigned_rank, str(row.get("guideline_id") or ""))


def write_readme(path: Path, summary: dict[str, Any], rows: list[dict[str, Any]]) -> None:
    lines = [
        "# Guideline Revision Backlog",
        "",
        "This backlog joins TraeX/LLM-as-judge output with recall-alignment diagnostics.",
        "It is a review queue for the next guideline iteration, not a released guideline file and not a ranking rule.",
        "",
        "## Summary",
        "",
        f"- Backlog rows: {summary['backlog_count']}",
        f"- Judge summary: {summary['judge_summary']}",
        f"- Alignment summary: {summary['alignment_summary']}",
        f"- Recommended actions: {summary['action_counts']}",
        f"- Judge decisions: {summary['decision_counts']}",
        f"- Recall/guideline attention: {summary['attention_counts']}",
        "",
        "## Highest Priority Items",
        "",
        "| Guideline | Mechanism | Decision | Min Score | Action | Attention | Issue |",
        "| --- | --- | --- | ---: | --- | --- | --- |",
    ]
    for row in rows[:25]:
        issue = str(row.get("main_issue") or "").replace("|", "\\|")
        if len(issue) > 180:
            issue = issue[:177] + "..."
        lines.append(
            f"| `{row['guideline_id']}` | `{row.get('mechanism_id')}` | {row.get('decision')} | "
            f"{format_tsv(row.get('min_score'))} | `{row.get('recommended_action')}` | "
            f"{format_tsv(row.get('attention'))} | {issue} |"
        )
    lines.extend(
        [
            "",
            "## Use Policy",
            "",
            "- Use this file to choose which guideline groups to reread against source evidence.",
            "- Do not copy judge-suggested text directly into the release without checking source/sink/guard evidence.",
            "- Do not convert issue strings, split suggestions, or example misses into regex routing rules.",
            "- A later paper-facing recall claim still needs a fresh same-identity recall comparison for the revised guideline sidecar.",
            "",
        ]
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--judge-summary", type=Path)
    parser.add_argument("--judge-report", type=Path, required=True)
    parser.add_argument("--alignment-summary", type=Path)
    parser.add_argument("--alignment-report", type=Path)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--max-items", type=int)
    args = parser.parse_args()
    if args.output_dir.exists() and any(args.output_dir.iterdir()):
        raise FileExistsError(f"refusing to overwrite non-empty output directory: {args.output_dir}")

    summary, rows = build_backlog(
        judge_summary=read_json(args.judge_summary) if args.judge_summary else None,
        judge_rows=read_jsonl(args.judge_report),
        alignment_summary=read_json(args.alignment_summary) if args.alignment_summary else None,
        alignment_rows=read_jsonl(args.alignment_report) if args.alignment_report else [],
        max_items=args.max_items,
    )
    args.output_dir.mkdir(parents=True, exist_ok=True)
    write_json(args.output_dir / "summary.json", summary)
    write_jsonl(args.output_dir / "revision_backlog.jsonl", rows)
    write_tsv(
        args.output_dir / "revision_backlog.tsv",
        rows,
        [
            "guideline_id",
            "mechanism_id",
            "decision",
            "min_score",
            "recommended_action",
            "attention",
            "assigned_case_count",
            "primary_hit_count",
            "delta_primary_hit_count",
            "example_misses",
            "main_issue",
        ],
    )
    write_readme(args.output_dir / "README.md", summary, rows)
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
