#!/usr/bin/env python3
"""Build a source/sink/guard evidence worklist from guideline review backlog."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


ACTION_PRIORITY = {
    "split_mechanism_boundary": 0,
    "revise_mechanism_text_from_evidence": 1,
    "collect_source_sink_guard_evidence": 2,
    "review_guideline_group_evidence": 3,
    "inspect_embedding_candidate_or_query_mismatch": 4,
    "inspect_same_identity_recall_regression": 5,
    "keep_as_control_group": 6,
}


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


def truncate(text: str, limit: int = 240) -> str:
    cleaned = " ".join(text.split())
    if len(cleaned) <= limit:
        return cleaned
    return cleaned[: limit - 3] + "..."


def group_reports_by_guideline(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    indexed: dict[str, dict[str, Any]] = {}
    for row in rows:
        guideline_id = str(row.get("guideline_id") or "")
        if guideline_id:
            indexed[guideline_id] = row
    return indexed


def case_evidence_state(case: dict[str, Any]) -> str:
    evidence = case.get("trace_evidence")
    if not isinstance(evidence, list) or not evidence:
        return "missing_trace_evidence"
    joined = " ".join(str(item).lower() for item in evidence)
    if "not proof" in joined or "retrieval ground truth" in joined or "review-entry" in joined:
        return "review_entry_only"
    return "source_trace_present"


def compact_case(case: dict[str, Any]) -> dict[str, Any]:
    anchors = case.get("anchor_examples") if isinstance(case.get("anchor_examples"), list) else []
    trace_evidence = case.get("trace_evidence") if isinstance(case.get("trace_evidence"), list) else []
    return {
        "case_id": case.get("case_id"),
        "identity_key": case.get("identity_key"),
        "cve_ids": case.get("cve_ids") if isinstance(case.get("cve_ids"), list) else [],
        "primary_hcvr_type": case.get("primary_hcvr_type"),
        "evidence_state": case_evidence_state(case),
        "anchor_count": len(anchors),
        "trace_evidence_count": len(trace_evidence),
        "first_trace_evidence": truncate(str(trace_evidence[0])) if trace_evidence else "",
        "first_anchor": anchors[0] if anchors else None,
    }


def evidence_counts(cases: list[dict[str, Any]]) -> dict[str, int]:
    counts = {
        "case_examples": len(cases),
        "source_trace_present": 0,
        "review_entry_only": 0,
        "missing_trace_evidence": 0,
    }
    for case in cases:
        state = case_evidence_state(case)
        counts[state] = counts.get(state, 0) + 1
    return counts


def derive_gaps(backlog_row: dict[str, Any], group_row: dict[str, Any], cases: list[dict[str, Any]]) -> list[str]:
    gaps: list[str] = []
    action = str(backlog_row.get("recommended_action") or "")
    if action == "split_mechanism_boundary":
        gaps.extend(["mechanism_boundary", "case_to_split_bucket_assignment", "split_specific_source_sink_guard"])
    elif action == "revise_mechanism_text_from_evidence":
        gaps.extend(["mechanism_scope_correction", "strong_positive_source_sink_guard", "safe_fix_semantics"])
    elif action == "collect_source_sink_guard_evidence":
        gaps.extend(["case_source_shape", "sink_or_sensitive_effect", "missing_guard", "safe_fix_semantics"])
    elif action == "keep_as_control_group":
        gaps.extend(["control_case_invariant"])
    else:
        gaps.append("manual_review_scope")

    if not cases:
        gaps.append("assigned_case_examples")
    counts = evidence_counts(cases)
    if counts["missing_trace_evidence"] or counts["review_entry_only"]:
        gaps.append("source_level_trace_evidence")
    flags = group_row.get("flags") if isinstance(group_row.get("flags"), list) else []
    if any(flag in {"mixed_hcvr", "mixed_cwe"} for flag in flags):
        gaps.append("mixed_membership_boundary")
    if backlog_row.get("split_suggestions"):
        gaps.append("candidate_split_validation")
    return sorted(set(gaps))


def reviewer_action(row: dict[str, Any]) -> str:
    action = str(row.get("recommended_action") or "")
    if action == "split_mechanism_boundary":
        return (
            "Assign each example case to a concrete mechanism bucket, then keep only buckets with "
            "case-level source, sink, missing-guard, exploit-precondition, and fix evidence."
        )
    if action == "revise_mechanism_text_from_evidence":
        return (
            "Use the strongest evidenced cases to rewrite scope after checking source/sink/guard/fix; "
            "do not copy judge-suggested text directly."
        )
    if action == "collect_source_sink_guard_evidence":
        return (
            "Open the listed cases and collect old-side source, sensitive sink, missing guard, and "
            "fix semantics before promoting or rewriting the guideline."
        )
    if action == "keep_as_control_group":
        return "Keep as a semantic control group and preserve it in regression review."
    return "Review manually and decide whether this is guideline quality work or recall-side debugging."


def build_worklist(
    *,
    backlog_rows: list[dict[str, Any]],
    group_rows: list[dict[str, Any]],
    max_cases_per_item: int,
    max_items: int | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    group_by_guideline = group_reports_by_guideline(group_rows)
    items: list[dict[str, Any]] = []
    for index, backlog_row in enumerate(backlog_rows, start=1):
        guideline_id = str(backlog_row.get("guideline_id") or "")
        group_row = group_by_guideline.get(guideline_id, {})
        cases = group_row.get("judge_case_examples") if isinstance(group_row.get("judge_case_examples"), list) else []
        compact_examples = [compact_case(case) for case in cases[:max_cases_per_item]]
        item = {
            "priority": index,
            "guideline_id": guideline_id,
            "mechanism_id": backlog_row.get("mechanism_id") or group_row.get("mechanism_id"),
            "mechanism_name": backlog_row.get("mechanism_name") or group_row.get("mechanism_name"),
            "decision": backlog_row.get("decision"),
            "recommended_action": backlog_row.get("recommended_action"),
            "main_issue": backlog_row.get("main_issue"),
            "evidence_gaps": derive_gaps(backlog_row, group_row, cases),
            "reviewer_action": reviewer_action(backlog_row),
            "group_flags": group_row.get("flags") if isinstance(group_row.get("flags"), list) else [],
            "assigned_case_count": group_row.get("assigned_case_count"),
            "metadata_cve_count": group_row.get("metadata_cve_count"),
            "source_cve_count": group_row.get("source_cve_count"),
            "primary_hcvr_majority": group_row.get("primary_hcvr_majority"),
            "primary_hcvr_purity": group_row.get("primary_hcvr_purity"),
            "cwe_majority": group_row.get("cwe_majority"),
            "cwe_purity": group_row.get("cwe_purity"),
            "evidence_counts": evidence_counts(cases),
            "example_cases": compact_examples,
            "split_suggestions": backlog_row.get("split_suggestions")
            if isinstance(backlog_row.get("split_suggestions"), list)
            else [],
            "judge_evidence_notes": backlog_row.get("evidence_notes")
            if isinstance(backlog_row.get("evidence_notes"), list)
            else [],
            "candidate_guideline_status": backlog_row.get("candidate_guideline_status"),
            "candidate_guideline_text": backlog_row.get("candidate_guideline_text"),
            "policy": "review_only_not_release_not_recall_input",
        }
        items.append(item)

    items.sort(key=worklist_sort_key)
    if max_items is not None:
        items = items[:max_items]
    for priority, item in enumerate(items, start=1):
        item["priority"] = priority

    action_counts: dict[str, int] = {}
    gap_counts: dict[str, int] = {}
    evidence_state_counts: dict[str, int] = {}
    for item in items:
        action = str(item.get("recommended_action") or "unknown")
        action_counts[action] = action_counts.get(action, 0) + 1
        for gap in item["evidence_gaps"]:
            gap_counts[gap] = gap_counts.get(gap, 0) + 1
        for state, count in item["evidence_counts"].items():
            if state != "case_examples":
                evidence_state_counts[state] = evidence_state_counts.get(state, 0) + int(count)

    summary = {
        "schema_version": "hcvr_guideline_evidence_worklist.v1",
        "worklist_count": len(items),
        "action_counts": dict(sorted(action_counts.items())),
        "evidence_gap_counts": dict(sorted(gap_counts.items())),
        "case_evidence_state_counts": dict(sorted(evidence_state_counts.items())),
        "max_cases_per_item": max_cases_per_item,
        "policy": [
            "This artifact is a reviewer worklist only.",
            "It does not change released guidelines, guideline sidecars, lexicon entries, recall ranking, or audit prompts.",
            "TraeX LLM-as-judge output is advisory semantic evidence; source/sink/guard/fix evidence must be checked before changing a guideline.",
            "Do not convert judge notes, labels, known anchors, or bad cases into hidden routing or hard gates.",
        ],
    }
    return summary, items


def worklist_sort_key(row: dict[str, Any]) -> tuple[int, int, str]:
    action = str(row.get("recommended_action") or "")
    rank = ACTION_PRIORITY.get(action, len(ACTION_PRIORITY))
    source_gap = 0 if "source_level_trace_evidence" in row.get("evidence_gaps", []) else 1
    return (rank, source_gap, str(row.get("guideline_id") or ""))


def write_readme(path: Path, summary: dict[str, Any], rows: list[dict[str, Any]]) -> None:
    lines = [
        "# Guideline Evidence Collection Worklist",
        "",
        "This artifact turns the r8 TraeX judge backlog into a source/sink/guard evidence worklist.",
        "It is review-only: it does not update released guidelines, recall sidecars, lexicon entries, rank tables, or audit prompts.",
        "",
        "## Summary",
        "",
        f"- Worklist rows: {summary['worklist_count']}",
        f"- Recommended actions: {summary['action_counts']}",
        f"- Evidence gaps: {summary['evidence_gap_counts']}",
        f"- Case evidence states: {summary['case_evidence_state_counts']}",
        "",
        "## Highest Priority Items",
        "",
        "| Priority | Guideline | Mechanism | Action | Gaps | Example identities | Reviewer action |",
        "| ---: | --- | --- | --- | --- | --- | --- |",
    ]
    for row in rows[:25]:
        examples = [
            str(case.get("identity_key") or case.get("case_id") or "")
            for case in row.get("example_cases", [])[:3]
            if case.get("identity_key") or case.get("case_id")
        ]
        reviewer = truncate(str(row.get("reviewer_action") or ""), 180).replace("|", "\\|")
        lines.append(
            f"| {row['priority']} | `{row['guideline_id']}` | `{row.get('mechanism_id')}` | "
            f"`{row.get('recommended_action')}` | {format_tsv(row.get('evidence_gaps'))} | "
            f"{format_tsv(examples)} | {reviewer} |"
        )
    lines.extend(
        [
            "",
            "## Use Policy",
            "",
            "- Use `evidence_worklist.jsonl` as the next reviewer queue for guideline-v2 evidence collection.",
            "- Check old-side source, sink, missing guard, exploit precondition, and fix semantics before editing any guideline.",
            "- Treat TraeX judge notes as semantic review hints, not recall metrics and not release gates.",
            "- Keep known anchors and bad-case examples as diagnostics only; they must not become hidden query construction rules.",
            "- Any changed guideline sidecar needs a fresh same-identity recall A/B run before a paper-facing recall claim.",
            "",
        ]
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--revision-backlog", type=Path, required=True)
    parser.add_argument("--group-report", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--max-cases-per-item", type=int, default=6)
    parser.add_argument("--max-items", type=int)
    args = parser.parse_args()
    if args.output_dir.exists() and any(args.output_dir.iterdir()):
        raise FileExistsError(f"refusing to overwrite non-empty output directory: {args.output_dir}")

    summary, rows = build_worklist(
        backlog_rows=read_jsonl(args.revision_backlog),
        group_rows=read_jsonl(args.group_report),
        max_cases_per_item=args.max_cases_per_item,
        max_items=args.max_items,
    )
    args.output_dir.mkdir(parents=True, exist_ok=True)
    write_json(args.output_dir / "summary.json", summary)
    write_jsonl(args.output_dir / "evidence_worklist.jsonl", rows)
    write_tsv(
        args.output_dir / "evidence_worklist.tsv",
        rows,
        [
            "priority",
            "guideline_id",
            "mechanism_id",
            "decision",
            "recommended_action",
            "evidence_gaps",
            "assigned_case_count",
            "primary_hcvr_majority",
            "primary_hcvr_purity",
            "cwe_majority",
            "cwe_purity",
            "main_issue",
        ],
    )
    write_readme(args.output_dir / "README.md", summary, rows)
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
