#!/usr/bin/env python3
"""Summarize source-reviewed guideline evidence coverage and next review work."""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable


SOURCE_REVIEW_ACTIONS = {
    "split_mechanism_boundary",
    "revise_mechanism_text_from_evidence",
    "collect_source_sink_guard_evidence",
}


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                rows.append(json.loads(line))
    return rows


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
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


def boundary_key(guideline_id: Any, boundary_label: Any) -> tuple[str, str]:
    return str(guideline_id or ""), str(boundary_label or "")


def boundary_from_prompt(value: Any) -> str:
    text = str(value or "")
    name = Path(text).name
    match = re.match(r"[^.]+\.(.+)\.md$", name)
    return match.group(1) if match else ""


def index_validation_rows(rows: list[dict[str, Any]]) -> dict[tuple[str, str], dict[str, Any]]:
    indexed: dict[tuple[str, str], dict[str, Any]] = {}
    for row in rows:
        key = boundary_key(row.get("guideline_id"), row.get("boundary_label"))
        if key[0] and key[1]:
            indexed[key] = row
    return indexed


def index_judge_rows(rows: list[dict[str, Any]]) -> dict[tuple[str, str], dict[str, Any]]:
    indexed: dict[tuple[str, str], dict[str, Any]] = {}
    for row in rows:
        guideline_id = str(row.get("guideline_id") or "")
        boundary_label = str(row.get("boundary_label") or "") or boundary_from_prompt(row.get("prompt_file"))
        key = boundary_key(guideline_id, boundary_label)
        if key[0] and key[1]:
            indexed[key] = row
    return indexed


def group_rows_by_guideline(rows: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        guideline_id = str(row.get("guideline_id") or "")
        if guideline_id:
            grouped[guideline_id].append(row)
    return dict(grouped)


def count_unique_representative_cases(rows: list[dict[str, Any]]) -> int:
    values: set[str] = set()
    for row in rows:
        cases = row.get("representative_cases") if isinstance(row.get("representative_cases"), list) else []
        values.update(str(case) for case in cases if case)
    return len(values)


def summarize_guideline(
    *,
    worklist_row: dict[str, Any],
    ledger_rows: list[dict[str, Any]],
    validation_by_boundary: dict[tuple[str, str], dict[str, Any]],
    judge_by_boundary: dict[tuple[str, str], dict[str, Any]],
) -> dict[str, Any]:
    guideline_id = str(worklist_row.get("guideline_id") or "")
    boundary_rows: list[dict[str, Any]] = []
    decision_counts: Counter[str] = Counter()
    validation_decision_counts: Counter[str] = Counter()
    judge_decision_counts: Counter[str] = Counter()
    valid_boundary_count = 0
    invalid_boundary_count = 0
    promotable_valid_count = 0
    promotable_judge_accept_count = 0
    promotable_missing_judge_count = 0
    nonaccept_judged_count = 0

    for ledger_row in ledger_rows:
        decision = str(ledger_row.get("boundary_decision") or "")
        label = str(ledger_row.get("boundary_label") or "")
        key = boundary_key(guideline_id, label)
        validation = validation_by_boundary.get(key)
        judge = judge_by_boundary.get(key)
        valid = validation.get("valid") if validation is not None else None
        judge_decision = str(judge.get("decision") or "") if judge is not None else ""
        decision_counts[decision] += 1
        if validation is not None:
            validation_decision_counts[decision] += 1
            if valid:
                valid_boundary_count += 1
            else:
                invalid_boundary_count += 1
        if judge_decision:
            judge_decision_counts[judge_decision] += 1
        if decision == "promote_boundary" and valid is not False:
            promotable_valid_count += 1
            if judge_decision == "accept":
                promotable_judge_accept_count += 1
            elif judge is None:
                promotable_missing_judge_count += 1
        if judge is not None and judge_decision and judge_decision != "accept":
            nonaccept_judged_count += 1
        boundary_rows.append(
            {
                "boundary_label": label,
                "boundary_decision": decision,
                "validation_valid": valid,
                "validation_errors": validation.get("errors") if validation else [],
                "judge_decision": judge_decision or None,
                "judge_min_score": judge.get("min_score") if judge else None,
                "judge_low_score": judge.get("low_score") if judge else None,
                "mechanism_id": ledger_row.get("mechanism_id"),
                "representative_case_count": len(
                    ledger_row.get("representative_cases")
                    if isinstance(ledger_row.get("representative_cases"), list)
                    else []
                ),
            }
        )

    if not ledger_rows:
        coverage_status = "not_source_reviewed"
        next_action = "fill_source_review_ledger"
    elif invalid_boundary_count:
        coverage_status = "invalid_ledger"
        next_action = "fix_invalid_ledger_rows"
    elif promotable_valid_count and promotable_judge_accept_count == promotable_valid_count:
        coverage_status = "source_reviewed_and_judge_accepted"
        next_action = "run_same_identity_recall_after_sidecar_change"
    elif promotable_valid_count and promotable_missing_judge_count:
        coverage_status = "source_reviewed_validation_only"
        next_action = "run_ledger_judge_pack"
    elif nonaccept_judged_count:
        coverage_status = "source_reviewed_needs_more_evidence"
        next_action = "collect_missing_boundary_evidence"
    else:
        coverage_status = "source_reviewed_no_promoted_boundary"
        next_action = "collect_or_assign_representative_cases"

    if str(worklist_row.get("recommended_action") or "") == "keep_as_control_group" and not ledger_rows:
        next_action = "optional_control_source_review"

    return {
        "guideline_id": guideline_id,
        "mechanism_id": worklist_row.get("mechanism_id"),
        "mechanism_name": worklist_row.get("mechanism_name"),
        "worklist_priority": worklist_row.get("priority"),
        "worklist_action": worklist_row.get("recommended_action"),
        "worklist_decision": worklist_row.get("decision"),
        "worklist_evidence_gaps": worklist_row.get("evidence_gaps") if isinstance(worklist_row.get("evidence_gaps"), list) else [],
        "coverage_status": coverage_status,
        "next_action": next_action,
        "ledger_boundary_count": len(ledger_rows),
        "ledger_decision_counts": dict(sorted(decision_counts.items())),
        "validation_decision_counts": dict(sorted(validation_decision_counts.items())),
        "judge_decision_counts": dict(sorted(judge_decision_counts.items())),
        "valid_boundary_count": valid_boundary_count,
        "invalid_boundary_count": invalid_boundary_count,
        "promotable_valid_count": promotable_valid_count,
        "promotable_judge_accept_count": promotable_judge_accept_count,
        "promotable_missing_judge_count": promotable_missing_judge_count,
        "nonaccept_judged_count": nonaccept_judged_count,
        "representative_case_count": count_unique_representative_cases(ledger_rows),
        "boundary_rows": boundary_rows,
        "policy": "diagnostic_only_not_release_not_recall_input",
    }


def review_priority(row: dict[str, Any]) -> tuple[int, int, int, int, str]:
    next_action_rank = {
        "fill_source_review_ledger": 0,
        "fix_invalid_ledger_rows": 1,
        "collect_missing_boundary_evidence": 2,
        "run_ledger_judge_pack": 3,
        "collect_or_assign_representative_cases": 4,
        "run_same_identity_recall_after_sidecar_change": 5,
        "optional_control_source_review": 6,
    }
    worklist_action_rank = {
        "split_mechanism_boundary": 0,
        "revise_mechanism_text_from_evidence": 1,
        "collect_source_sink_guard_evidence": 2,
        "keep_as_control_group": 3,
    }
    return (
        next_action_rank.get(str(row.get("next_action") or ""), 9),
        worklist_action_rank.get(str(row.get("worklist_action") or ""), 9),
        int(row.get("worklist_priority") or 10**9),
        -int(row.get("representative_case_count") or 0),
        str(row.get("guideline_id") or ""),
    )


def build_coverage(
    *,
    worklist_rows: list[dict[str, Any]],
    ledger_rows: list[dict[str, Any]],
    validation_rows: list[dict[str, Any]],
    judge_rows: list[dict[str, Any]],
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    ledger_by_guideline = group_rows_by_guideline(ledger_rows)
    validation_by_boundary = index_validation_rows(validation_rows)
    judge_by_boundary = index_judge_rows(judge_rows)
    coverage_rows = [
        summarize_guideline(
            worklist_row=row,
            ledger_rows=ledger_by_guideline.get(str(row.get("guideline_id") or ""), []),
            validation_by_boundary=validation_by_boundary,
            judge_by_boundary=judge_by_boundary,
        )
        for row in worklist_rows
    ]
    coverage_rows.sort(key=lambda row: int(row.get("worklist_priority") or 10**9))
    next_review_rows = [row for row in sorted(coverage_rows, key=review_priority) if row.get("next_action") != "run_same_identity_recall_after_sidecar_change"]

    status_counts = Counter(str(row.get("coverage_status") or "unknown") for row in coverage_rows)
    action_counts = Counter(str(row.get("next_action") or "unknown") for row in coverage_rows)
    source_review_actions = [
        row
        for row in coverage_rows
        if row.get("worklist_action") in SOURCE_REVIEW_ACTIONS
    ]
    source_review_done = [
        row
        for row in source_review_actions
        if row.get("coverage_status") == "source_reviewed_and_judge_accepted"
    ]
    validation_only = [
        row
        for row in coverage_rows
        if row.get("coverage_status") == "source_reviewed_validation_only"
    ]
    summary = {
        "schema_version": "hcvr_guideline_evidence_coverage_summary.v1",
        "worklist_count": len(worklist_rows),
        "coverage_row_count": len(coverage_rows),
        "ledger_row_count": len(ledger_rows),
        "validation_row_count": len(validation_rows),
        "judge_row_count": len(judge_rows),
        "coverage_status_counts": dict(sorted(status_counts.items())),
        "next_action_counts": dict(sorted(action_counts.items())),
        "source_review_action_count": len(source_review_actions),
        "source_review_judge_accepted_count": len(source_review_done),
        "source_review_validation_only_count": len(validation_only),
        "promotable_valid_boundary_count": sum(int(row.get("promotable_valid_count") or 0) for row in coverage_rows),
        "promotable_judge_accept_boundary_count": sum(int(row.get("promotable_judge_accept_count") or 0) for row in coverage_rows),
        "policy": [
            "This artifact audits evidence coverage only.",
            "It does not update released guidelines, guideline sidecars, lexicon entries, recall ranking, or audit prompts.",
            "TraeX LLM-as-judge rows are advisory semantic QA; they are not recall evidence and not hidden routing.",
            "Bad cases and known anchors remain post-ranking diagnostics only.",
        ],
    }
    return summary, coverage_rows, next_review_rows


def write_readme(path: Path, summary: dict[str, Any], next_review_rows: list[dict[str, Any]]) -> None:
    lines = [
        "# Guideline Evidence Coverage Summary",
        "",
        "This artifact joins the r8 evidence worklist with filled source-review ledgers, ledger validation rows, and optional TraeX judge summaries.",
        "It is an audit and planning artifact only: it does not update guideline text, sidecars, rank tables, embeddings, or audit prompts.",
        "",
        "## Summary",
        "",
        f"- Worklist rows: {summary['worklist_count']}",
        f"- Ledger rows: {summary['ledger_row_count']}",
        f"- Validation rows: {summary['validation_row_count']}",
        f"- Judge rows: {summary['judge_row_count']}",
        f"- Coverage statuses: {summary['coverage_status_counts']}",
        f"- Next actions: {summary['next_action_counts']}",
        f"- Source-review actions accepted by judge: {summary['source_review_judge_accepted_count']} / {summary['source_review_action_count']}",
        f"- Promotable boundaries accepted by judge: {summary['promotable_judge_accept_boundary_count']} / {summary['promotable_valid_boundary_count']}",
        "",
        "## Next Review Queue",
        "",
        "| Guideline | Status | Next Action | Worklist Action | Valid Promoted | Judge-Accepted Promoted | Evidence Gaps |",
        "| --- | --- | --- | --- | ---: | ---: | --- |",
    ]
    for row in next_review_rows[:30]:
        lines.append(
            f"| `{row.get('guideline_id')}` | `{row.get('coverage_status')}` | `{row.get('next_action')}` | "
            f"`{row.get('worklist_action')}` | {row.get('promotable_valid_count')} | "
            f"{row.get('promotable_judge_accept_count')} | {format_tsv(row.get('worklist_evidence_gaps'))} |"
        )
    lines.extend(
        [
            "",
            "## Use Policy",
            "",
            "- Use `next_review_queue.jsonl` to choose the next source-review or judge-pack batch.",
            "- Treat `source_reviewed_validation_only` as needing ledger-level judge if the boundary will be cited as semantic evidence.",
            "- Treat `source_reviewed_and_judge_accepted` as semantic boundary evidence only; it still needs same-identity recall after sidecar changes.",
            "- Do not convert judge decisions, bad-case identities, known anchors, labels, or example file names into hidden query construction or routing rules.",
            "",
        ]
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence-worklist", type=Path, required=True)
    parser.add_argument("--ledger", type=Path, action="append")
    parser.add_argument("--validation-rows", type=Path, action="append")
    parser.add_argument("--judge-report", type=Path, action="append")
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    if args.output_dir.exists() and any(args.output_dir.iterdir()):
        raise FileExistsError(f"refusing to overwrite non-empty output directory: {args.output_dir}")

    worklist_rows = read_jsonl(args.evidence_worklist)
    ledger_rows = [row for path in (args.ledger or []) for row in read_jsonl(path)]
    validation_rows = [row for path in (args.validation_rows or []) for row in read_json(path)]
    judge_rows = [row for path in (args.judge_report or []) for row in read_jsonl(path)]
    summary, coverage_rows, next_review_rows = build_coverage(
        worklist_rows=worklist_rows,
        ledger_rows=ledger_rows,
        validation_rows=validation_rows,
        judge_rows=judge_rows,
    )

    args.output_dir.mkdir(parents=True, exist_ok=True)
    write_json(args.output_dir / "summary.json", summary)
    write_jsonl(args.output_dir / "guideline_evidence_coverage.jsonl", coverage_rows)
    write_jsonl(args.output_dir / "next_review_queue.jsonl", next_review_rows)
    write_tsv(
        args.output_dir / "guideline_evidence_coverage.tsv",
        coverage_rows,
        [
            "guideline_id",
            "coverage_status",
            "next_action",
            "worklist_action",
            "ledger_boundary_count",
            "promotable_valid_count",
            "promotable_judge_accept_count",
            "representative_case_count",
            "worklist_evidence_gaps",
        ],
    )
    write_tsv(
        args.output_dir / "next_review_queue.tsv",
        next_review_rows,
        [
            "guideline_id",
            "coverage_status",
            "next_action",
            "worklist_action",
            "promotable_valid_count",
            "promotable_judge_accept_count",
            "worklist_evidence_gaps",
        ],
    )
    write_readme(args.output_dir / "README.md", summary, next_review_rows)
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
