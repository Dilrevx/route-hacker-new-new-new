#!/usr/bin/env python3
"""Build a review-only repair pack for split/revise guideline work items."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


TARGET_ACTIONS = {"split_mechanism_boundary", "revise_mechanism_text_from_evidence"}


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


def case_bucket(cases: list[dict[str, Any]], state: str, limit: int) -> list[dict[str, Any]]:
    selected: list[dict[str, Any]] = []
    for case in cases:
        if case.get("evidence_state") != state:
            continue
        selected.append(
            {
                "identity_key": case.get("identity_key"),
                "case_id": case.get("case_id"),
                "cve_ids": case.get("cve_ids") if isinstance(case.get("cve_ids"), list) else [],
                "primary_hcvr_type": case.get("primary_hcvr_type"),
                "first_anchor": case.get("first_anchor"),
                "first_trace_evidence": case.get("first_trace_evidence"),
            }
        )
        if len(selected) >= limit:
            break
    return selected


def proposed_boundaries(row: dict[str, Any]) -> list[dict[str, Any]]:
    suggestions = row.get("split_suggestions") if isinstance(row.get("split_suggestions"), list) else []
    if suggestions:
        return [
            {
                "boundary_label": f"candidate_boundary_{index:02d}",
                "description": str(text),
                "status": "needs_case_assignment_and_source_validation",
            }
            for index, text in enumerate(suggestions, start=1)
            if str(text).strip()
        ]
    text = str(row.get("candidate_guideline_text") or "").strip()
    if text:
        return [
            {
                "boundary_label": "candidate_revision",
                "description": text,
                "status": "needs_source_validation_before_release",
            }
        ]
    return []


def build_pack(
    *,
    worklist_rows: list[dict[str, Any]],
    max_examples_per_state: int,
    max_items: int | None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    pack_rows: list[dict[str, Any]] = []
    for row in worklist_rows:
        action = str(row.get("recommended_action") or "")
        if action not in TARGET_ACTIONS:
            continue
        examples = row.get("example_cases") if isinstance(row.get("example_cases"), list) else []
        pack_rows.append(
            {
                "priority": row.get("priority"),
                "guideline_id": row.get("guideline_id"),
                "mechanism_id": row.get("mechanism_id"),
                "mechanism_name": row.get("mechanism_name"),
                "repair_kind": action,
                "main_issue": row.get("main_issue"),
                "evidence_gaps": row.get("evidence_gaps") if isinstance(row.get("evidence_gaps"), list) else [],
                "proposed_boundaries": proposed_boundaries(row),
                "source_trace_examples": case_bucket(examples, "source_trace_present", max_examples_per_state),
                "review_entry_only_examples": case_bucket(examples, "review_entry_only", max_examples_per_state),
                "missing_trace_examples": case_bucket(examples, "missing_trace_evidence", max_examples_per_state),
                "reviewer_checklist": [
                    "assign each example case to exactly one proposed boundary or mark it out-of-scope",
                    "record old-side source, sink or sensitive effect, missing guard, exploit precondition, and safe fix",
                    "promote only boundaries supported by source-level evidence from representative cases",
                    "rerun same-identity recall after any recall-consumed guideline text changes",
                ],
                "release_policy": "review_only_not_release_not_recall_input",
            }
        )
    pack_rows.sort(key=lambda item: int(item.get("priority") or 10**9))
    if max_items is not None:
        pack_rows = pack_rows[:max_items]
    for index, row in enumerate(pack_rows, start=1):
        row["pack_priority"] = index

    summary = {
        "schema_version": "hcvr_guideline_boundary_repair_pack.v1",
        "pack_count": len(pack_rows),
        "source_worklist_count": len(worklist_rows),
        "target_actions": sorted(TARGET_ACTIONS),
        "repair_kind_counts": {},
        "example_counts": {
            "source_trace_present": 0,
            "review_entry_only": 0,
            "missing_trace_evidence": 0,
        },
        "policy": [
            "This is a review-only mechanism-boundary repair pack.",
            "It does not update released guidelines, lexicon entries, guideline sidecars, recall ranks, or audit prompts.",
            "Use it to collect source/sink/guard/fix evidence before deciding whether a split or revision belongs in the released guideline set.",
            "Any promoted sidecar text requires a fresh same-identity recall run.",
        ],
    }
    for row in pack_rows:
        kind = str(row.get("repair_kind") or "unknown")
        summary["repair_kind_counts"][kind] = summary["repair_kind_counts"].get(kind, 0) + 1
        summary["example_counts"]["source_trace_present"] += len(row["source_trace_examples"])
        summary["example_counts"]["review_entry_only"] += len(row["review_entry_only_examples"])
        summary["example_counts"]["missing_trace_evidence"] += len(row["missing_trace_examples"])
    summary["repair_kind_counts"] = dict(sorted(summary["repair_kind_counts"].items()))
    return summary, pack_rows


def write_readme(path: Path, summary: dict[str, Any], rows: list[dict[str, Any]]) -> None:
    lines = [
        "# Guideline Boundary Repair Pack",
        "",
        "This artifact extracts the split/revise items from the evidence worklist.",
        "It is review-only and does not change any released guideline, lexicon, sidecar, rank table, or audit prompt.",
        "",
        "## Summary",
        "",
        f"- Repair rows: {summary['pack_count']}",
        f"- Repair kinds: {summary['repair_kind_counts']}",
        f"- Example counts included: {summary['example_counts']}",
        "",
        "## Repair Items",
        "",
        "| Priority | Guideline | Mechanism | Kind | Proposed Boundaries | Strong Examples | Weak Examples |",
        "| ---: | --- | --- | --- | --- | --- | --- |",
    ]
    for row in rows:
        boundaries = [item["boundary_label"] for item in row.get("proposed_boundaries", [])]
        strong = [str(item.get("identity_key") or "") for item in row.get("source_trace_examples", [])]
        weak = [
            str(item.get("identity_key") or "")
            for item in (row.get("review_entry_only_examples", []) + row.get("missing_trace_examples", []))
        ]
        lines.append(
            f"| {row['pack_priority']} | `{row.get('guideline_id')}` | `{row.get('mechanism_id')}` | "
            f"`{row.get('repair_kind')}` | {format_tsv(boundaries)} | {format_tsv(strong)} | {format_tsv(weak)} |"
        )
    lines.extend(
        [
            "",
            "## Use Policy",
            "",
            "- Use this pack before editing the mechanism lexicon or guideline sidecar.",
            "- Treat proposed boundaries as hypotheses until source-level evidence assigns cases to them.",
            "- Do not convert split suggestions, judge notes, case labels, or known anchors into runtime routing.",
            "- After a boundary is promoted into recall-consumed text, rerun same-identity recall before making a paper-facing claim.",
            "",
        ]
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence-worklist", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--max-examples-per-state", type=int, default=3)
    parser.add_argument("--max-items", type=int)
    args = parser.parse_args()
    if args.output_dir.exists() and any(args.output_dir.iterdir()):
        raise FileExistsError(f"refusing to overwrite non-empty output directory: {args.output_dir}")
    summary, rows = build_pack(
        worklist_rows=read_jsonl(args.evidence_worklist),
        max_examples_per_state=args.max_examples_per_state,
        max_items=args.max_items,
    )
    args.output_dir.mkdir(parents=True, exist_ok=True)
    write_json(args.output_dir / "summary.json", summary)
    write_jsonl(args.output_dir / "boundary_repair_pack.jsonl", rows)
    write_tsv(
        args.output_dir / "boundary_repair_pack.tsv",
        rows,
        [
            "pack_priority",
            "priority",
            "guideline_id",
            "mechanism_id",
            "repair_kind",
            "evidence_gaps",
            "main_issue",
        ],
    )
    write_readme(args.output_dir / "README.md", summary, rows)
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
