#!/usr/bin/env python3
"""Build a review-only recall sidecar from accepted source-reviewed boundaries."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any, Iterable


def read_json(path: Path) -> Any:
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


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


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
        boundary_label = row.get("boundary_label") or boundary_from_prompt(row.get("prompt_file"))
        key = boundary_key(row.get("guideline_id"), boundary_label)
        if key[0] and key[1]:
            indexed[key] = row
    return indexed


def load_cases(paths: list[Path]) -> dict[str, dict[str, Any]]:
    cases: dict[str, dict[str, Any]] = {}
    duplicates: set[str] = set()
    for path in paths:
        for row in read_jsonl(path):
            identity = str(row.get("identity_key") or "")
            if not identity:
                continue
            if identity in cases:
                duplicates.add(identity)
                continue
            cases[identity] = row
    if duplicates:
        raise ValueError(f"duplicate identity_key values in cases files: {sorted(duplicates)[:10]}")
    return cases


def accepted_promoted_boundaries(
    *,
    ledger_rows: list[dict[str, Any]],
    validation_by_boundary: dict[tuple[str, str], dict[str, Any]],
    judge_by_boundary: dict[tuple[str, str], dict[str, Any]],
) -> list[dict[str, Any]]:
    accepted: list[dict[str, Any]] = []
    for row in ledger_rows:
        if row.get("boundary_decision") != "promote_boundary":
            continue
        key = boundary_key(row.get("guideline_id"), row.get("boundary_label"))
        validation = validation_by_boundary.get(key)
        judge = judge_by_boundary.get(key)
        if not validation or validation.get("valid") is not True:
            continue
        if not judge or judge.get("decision") != "accept":
            continue
        accepted.append(row)
    return accepted


def build_retrieval_guideline(row: dict[str, Any]) -> str:
    mechanism_name = str(row.get("mechanism_name") or row.get("mechanism_id") or "source-reviewed mechanism").strip()
    boundary_text = str(row.get("boundary_text") or "").strip()
    missing_guard = str(row.get("missing_guard") or "").strip()
    safe_fix = str(row.get("safe_fix_semantics") or "").strip()
    parts = [
        f"Audit for {mechanism_name}.",
        boundary_text,
    ]
    if missing_guard:
        parts.append(f"Required missing-guard check: {missing_guard}")
    if safe_fix:
        parts.append(f"Safe implementation should: {safe_fix}")
    parts.append(
        "Confirm that the source, sensitive effect, and missing guard occur on the same code path before reporting."
    )
    return " ".join(part for part in parts if part).strip()


def validate_retrieval_guideline_text(text: str) -> list[str]:
    errors: list[str] = []
    if re.search(r"\bCVE-\d{4}-\d+\b", text, flags=re.IGNORECASE):
        errors.append("contains_cve_id")
    if re.search(r"(?<![A-Za-z]):\d+\b", text):
        errors.append("contains_file_line_shape")
    if "source_evidence" in text or "evidence_refs" in text:
        errors.append("contains_evidence_reference_field")
    return errors


def build_sidecar(
    *,
    boundaries: list[dict[str, Any]],
    cases_by_identity: dict[str, dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    rows_by_identity: dict[str, dict[str, Any]] = {}
    boundary_rows: list[dict[str, Any]] = []
    unmatched: list[dict[str, Any]] = []
    for row in boundaries:
        cases = row.get("representative_cases") if isinstance(row.get("representative_cases"), list) else []
        retrieval_guideline = build_retrieval_guideline(row)
        text_errors = validate_retrieval_guideline_text(retrieval_guideline)
        if text_errors:
            raise ValueError(
                "generated retrieval guideline contains forbidden diagnostic material "
                f"for {row.get('guideline_id')}.{row.get('boundary_label')}: {text_errors}"
            )
        boundary_summary = {
            "guideline_id": row.get("guideline_id"),
            "boundary_label": row.get("boundary_label"),
            "mechanism_id": row.get("mechanism_id"),
            "mechanism_name": row.get("mechanism_name"),
            "representative_cases": cases,
            "retrieval_guideline": retrieval_guideline,
            "policy": "review_only_candidate_not_recall_claim",
        }
        boundary_rows.append(boundary_summary)
        for identity in cases:
            identity = str(identity)
            case = cases_by_identity.get(identity)
            if not case:
                unmatched.append(
                    {
                        "identity_key": identity,
                        "guideline_id": row.get("guideline_id"),
                        "boundary_label": row.get("boundary_label"),
                        "mechanism_id": row.get("mechanism_id"),
                        "reason": "representative_case_missing_from_cases_file",
                    }
                )
                continue
            sidecar = rows_by_identity.setdefault(
                identity,
                {
                    "identity_key": identity,
                    "case_id": case.get("new_unified_case_id"),
                    "guideline_ids": [],
                    "boundary_labels": [],
                    "mechanism_ids": [],
                    "mechanism_names": [],
                    "retrieval_guidelines": [],
                    "policy": "review_only_candidate_requires_same_identity_recall",
                },
            )
            sidecar["guideline_ids"].append(row.get("guideline_id"))
            sidecar["boundary_labels"].append(row.get("boundary_label"))
            sidecar["mechanism_ids"].append(row.get("mechanism_id"))
            sidecar["mechanism_names"].append(row.get("mechanism_name"))
            sidecar["retrieval_guidelines"].append(retrieval_guideline)

    sidecar_rows: list[dict[str, Any]] = []
    for row in rows_by_identity.values():
        for field in ("guideline_ids", "boundary_labels", "mechanism_ids", "mechanism_names", "retrieval_guidelines"):
            row[field] = [value for value in dict.fromkeys(row[field]) if value]
        row["retrieval_guideline"] = "\n\n".join(row.pop("retrieval_guidelines"))
        sidecar_rows.append(row)
    sidecar_rows.sort(key=lambda row: str(row["identity_key"]))
    boundary_rows.sort(key=lambda row: (str(row.get("guideline_id")), str(row.get("boundary_label"))))
    unmatched.sort(key=lambda row: str(row["identity_key"]))
    return sidecar_rows, boundary_rows, unmatched


def write_readme(path: Path, summary: dict[str, Any]) -> None:
    lines = [
        "# Source-Reviewed Guideline Sidecar Candidate",
        "",
        "This artifact converts source-reviewed, verifier-valid, judge-accepted `promote_boundary` ledger rows into a review-only recall sidecar candidate.",
        "It is not a paper recall result and it does not modify any released guideline, lexicon entry, embedding, rank table, or audit prompt.",
        "",
        "## Summary",
        "",
        f"- Ledger files: {summary['ledger_file_count']}",
        f"- Ledger rows: {summary['ledger_row_count']}",
        f"- Accepted promotable boundaries: {summary['accepted_promotable_boundary_count']}",
        f"- Sidecar identities: {summary['sidecar_identity_count']}",
        f"- Unmatched representative cases: {summary['unmatched_representative_case_count']}",
        f"- Boundary counts by guideline: {summary['accepted_boundary_counts_by_guideline']}",
        "",
        "## Files",
        "",
        "- `guideline_overrides.jsonl`: review-only sidecar keyed by `identity_key` and `case_id` for same-identity recall A/B.",
        "- `boundary_overrides.jsonl`: one row per accepted boundary with the generated recall guideline text.",
        "- `unmatched_representative_cases.jsonl`: representative cases that are source-reviewed but absent from the supplied cases file.",
        "- `summary.json`: manifest and counts.",
        "",
        "## Policy",
        "",
        "- Rows are included only when the ledger decision is `promote_boundary`, verifier status is valid, and ledger judge decision is `accept`.",
        "- The generated retrieval guideline uses mechanism name, boundary text, missing guard, safe fix semantics, and a same-path confirmation reminder.",
        "- Evidence references, file names, line numbers, CVE IDs, known anchors, ranks, and labels are not inserted into the retrieval text.",
        "- Use this artifact as an explicit ablation input. Any recall claim still requires a same-identity run with fixed identities, source snapshots, candidate slicing, embedding backend, adapter state, ranking parameters, and Top-K budgets.",
        "",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ledger", type=Path, action="append", required=True)
    parser.add_argument("--validation-rows", type=Path, action="append", required=True)
    parser.add_argument("--judge-report", type=Path, action="append", required=True)
    parser.add_argument("--cases-file", type=Path, action="append", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    if args.output_dir.exists() and any(args.output_dir.iterdir()):
        raise FileExistsError(f"refusing to overwrite non-empty output directory: {args.output_dir}")

    ledger_rows = [row for path in args.ledger for row in read_jsonl(path)]
    validation_rows = [row for path in args.validation_rows for row in read_json(path)]
    judge_rows = [row for path in args.judge_report for row in read_jsonl(path)]
    cases_by_identity = load_cases(args.cases_file)
    validation_by_boundary = index_validation_rows(validation_rows)
    judge_by_boundary = index_judge_rows(judge_rows)
    accepted = accepted_promoted_boundaries(
        ledger_rows=ledger_rows,
        validation_by_boundary=validation_by_boundary,
        judge_by_boundary=judge_by_boundary,
    )
    sidecar_rows, boundary_rows, unmatched_rows = build_sidecar(
        boundaries=accepted,
        cases_by_identity=cases_by_identity,
    )
    boundary_counts = Counter(str(row.get("guideline_id") or "") for row in boundary_rows)
    summary = {
        "schema_version": "hcvr_source_reviewed_sidecar_candidate.v1",
        "ledger_file_count": len(args.ledger),
        "validation_file_count": len(args.validation_rows),
        "judge_report_file_count": len(args.judge_report),
        "cases_file_count": len(args.cases_file),
        "ledger_row_count": len(ledger_rows),
        "accepted_promotable_boundary_count": len(accepted),
        "sidecar_identity_count": len(sidecar_rows),
        "boundary_override_count": len(boundary_rows),
        "unmatched_representative_case_count": len(unmatched_rows),
        "accepted_boundary_counts_by_guideline": dict(sorted(boundary_counts.items())),
        "input_sha256": {
            str(path): sha256_file(path)
            for path in [*args.ledger, *args.validation_rows, *args.judge_report, *args.cases_file]
        },
        "policy": [
            "review_only_candidate_not_release",
            "requires_same_identity_recall_before_claim",
            "no_known_anchor_rank_or_file_line_in_retrieval_text",
        ],
        "files": {
            "guideline_overrides": "guideline_overrides.jsonl",
            "boundary_overrides": "boundary_overrides.jsonl",
            "unmatched_representative_cases": "unmatched_representative_cases.jsonl",
        },
    }

    args.output_dir.mkdir(parents=True, exist_ok=True)
    write_jsonl(args.output_dir / "guideline_overrides.jsonl", sidecar_rows)
    write_jsonl(args.output_dir / "boundary_overrides.jsonl", boundary_rows)
    write_jsonl(args.output_dir / "unmatched_representative_cases.jsonl", unmatched_rows)
    write_json(args.output_dir / "summary.json", summary)
    write_readme(args.output_dir / "README.md", summary)
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
