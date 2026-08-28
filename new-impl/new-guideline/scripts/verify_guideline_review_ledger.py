#!/usr/bin/env python3
"""Validate filled guideline review ledger rows before promotion."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


REQUIRED_PROMOTION_FIELDS = [
    "source_shape",
    "sink_or_sensitive_effect",
    "missing_guard",
    "exploit_precondition",
    "safe_fix_semantics",
    "boundary_decision",
]

ALLOWED_DECISIONS = {
    "promote_boundary",
    "revise_boundary",
    "split_further",
    "mark_out_of_scope",
    "needs_more_evidence",
    "recall_side_debug",
}


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            row = json.loads(line)
            row["_line_no"] = line_no
            rows.append(row)
    return rows


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def is_filled(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip()) and value.strip().lower() not in {"n/a", "todo", "tbd"}
    if isinstance(value, list):
        return bool(value)
    return True


def validate_row(row: dict[str, Any]) -> dict[str, Any]:
    errors: list[str] = []
    warnings: list[str] = []
    decision = str(row.get("boundary_decision") or "").strip()
    if not row.get("guideline_id"):
        errors.append("missing_guideline_id")
    if not row.get("boundary_label"):
        errors.append("missing_boundary_label")
    if decision not in ALLOWED_DECISIONS:
        errors.append("invalid_boundary_decision")
    if decision == "promote_boundary":
        for field in REQUIRED_PROMOTION_FIELDS:
            if not is_filled(row.get(field)):
                errors.append(f"missing_{field}")
        if not is_filled(row.get("representative_cases")):
            errors.append("missing_representative_cases")
        if not is_filled(row.get("recall_follow_up")):
            warnings.append("missing_recall_follow_up")
    elif decision in {"revise_boundary", "split_further", "recall_side_debug"}:
        if not is_filled(row.get("rationale")):
            warnings.append("missing_rationale")
    elif decision in {"mark_out_of_scope", "needs_more_evidence"}:
        if not is_filled(row.get("rationale")):
            errors.append("missing_rationale")
    return {
        "line_no": row.get("_line_no"),
        "guideline_id": row.get("guideline_id"),
        "boundary_label": row.get("boundary_label"),
        "boundary_decision": decision,
        "valid": not errors,
        "errors": errors,
        "warnings": warnings,
    }


def validate_ledger(rows: list[dict[str, Any]]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    validations = [validate_row(row) for row in rows]
    decision_counts: dict[str, int] = {}
    for validation in validations:
        decision = str(validation.get("boundary_decision") or "missing")
        decision_counts[decision] = decision_counts.get(decision, 0) + 1
    invalid = [row for row in validations if not row["valid"]]
    promotable = [row for row in validations if row["valid"] and row.get("boundary_decision") == "promote_boundary"]
    summary = {
        "schema_version": "hcvr_guideline_review_ledger_validation.v1",
        "row_count": len(rows),
        "valid_count": len(validations) - len(invalid),
        "invalid_count": len(invalid),
        "promotable_count": len(promotable),
        "decision_counts": dict(sorted(decision_counts.items())),
        "policy": [
            "Only promote_boundary rows with all source/sink/guard/fix fields filled are promotable.",
            "This verifier does not update guidelines, lexicon entries, sidecars, rank tables, or audit prompts.",
            "Promotable rows still require a fresh same-identity recall run after recall-consumed text changes.",
        ],
    }
    return summary, validations


def write_readme(path: Path, summary: dict[str, Any], validations: list[dict[str, Any]]) -> None:
    lines = [
        "# Guideline Review Ledger Validation",
        "",
        "This report validates filled reviewer ledger rows before any guideline promotion.",
        "It is a gate report only and does not update released guideline artifacts.",
        "",
        "## Summary",
        "",
        f"- Rows: {summary['row_count']}",
        f"- Valid rows: {summary['valid_count']}",
        f"- Invalid rows: {summary['invalid_count']}",
        f"- Promotable rows: {summary['promotable_count']}",
        f"- Decisions: {summary['decision_counts']}",
        "",
        "## Rows",
        "",
        "| Line | Guideline | Boundary | Decision | Valid | Errors | Warnings |",
        "| ---: | --- | --- | --- | --- | --- | --- |",
    ]
    for row in validations:
        lines.append(
            f"| {row.get('line_no')} | `{row.get('guideline_id')}` | `{row.get('boundary_label')}` | "
            f"`{row.get('boundary_decision')}` | {row.get('valid')} | "
            f"{','.join(row.get('errors') or []) or 'n/a'} | {','.join(row.get('warnings') or []) or 'n/a'} |"
        )
    lines.extend(
        [
            "",
            "## Use Policy",
            "",
            "- `promote_boundary` means the semantic evidence is complete enough for a proposed guideline edit.",
            "- It does not mean the recall effect is known.",
            "- After changing recall-consumed sidecar text, run same-identity recall before reporting any retrieval claim.",
            "",
        ]
    )
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--fail-on-invalid", action="store_true")
    args = parser.parse_args()
    if args.output_dir.exists() and any(args.output_dir.iterdir()):
        raise FileExistsError(f"refusing to overwrite non-empty output directory: {args.output_dir}")
    rows = read_jsonl(args.ledger)
    summary, validations = validate_ledger(rows)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    write_json(args.output_dir / "summary.json", summary)
    write_json(args.output_dir / "validation_rows.json", validations)
    write_readme(args.output_dir / "README.md", summary, validations)
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    if args.fail_on_invalid and summary["invalid_count"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
