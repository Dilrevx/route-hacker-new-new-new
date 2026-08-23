#!/usr/bin/env python3
"""Build a conservative release-group sidecar from propagation-audited boundaries."""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable


DEFAULT_ALLOWED_STATUSES = ("group_ablation_ready",)


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


def identity(row: dict[str, Any]) -> str:
    return str(row.get("identity_key") or "").strip()


def index_cases(cases: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    indexed: dict[str, dict[str, Any]] = {}
    for case in cases:
        key = identity(case)
        if key:
            indexed[key] = case
    return indexed


def index_assignments(assignments: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    by_guideline: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in assignments:
        guideline_id = str(row.get("guideline_id") or "").strip()
        if guideline_id and identity(row):
            by_guideline[guideline_id].append(row)
    return by_guideline


def index_boundary_text(boundary_overrides: list[dict[str, Any]]) -> dict[tuple[str, str], str]:
    indexed: dict[tuple[str, str], str] = {}
    for row in boundary_overrides:
        key = (str(row.get("guideline_id") or ""), str(row.get("boundary_label") or ""))
        text = str(row.get("retrieval_guideline") or "").strip()
        if key[0] and key[1] and text:
            indexed[key] = text
    return indexed


def build_sidecar(
    *,
    propagation_rows: list[dict[str, Any]],
    boundary_overrides: list[dict[str, Any]],
    case_assignments: list[dict[str, Any]],
    cases: list[dict[str, Any]],
    allowed_statuses: set[str],
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    cases_by_identity = index_cases(cases)
    assignments_by_guideline = index_assignments(case_assignments)
    boundary_text_by_key = index_boundary_text(boundary_overrides)
    sidecar_by_identity: dict[str, dict[str, Any]] = {}
    selected_boundaries: list[dict[str, Any]] = []
    status_counts: Counter[str] = Counter()
    missing_cases: Counter[str] = Counter()

    for row in propagation_rows:
        status = str(row.get("propagation_status") or "")
        status_counts[status] += 1
        if status not in allowed_statuses:
            continue
        guideline_id = str(row.get("guideline_id") or "")
        boundary_label = str(row.get("boundary_label") or "")
        retrieval_guideline = boundary_text_by_key.get((guideline_id, boundary_label), "")
        if not retrieval_guideline:
            missing_cases["missing_boundary_text"] += 1
            continue
        group_assignments = assignments_by_guideline.get(guideline_id) or []
        if not group_assignments:
            missing_cases["no_group_assignments"] += 1
            continue

        selected_boundaries.append(
            {
                "guideline_id": guideline_id,
                "boundary_label": boundary_label,
                "mechanism_id": row.get("boundary_mechanism_id"),
                "mechanism_name": row.get("boundary_mechanism_name"),
                "propagation_status": status,
                "assigned_identity_count": len({identity(item) for item in group_assignments if identity(item)}),
                "retrieval_guideline": retrieval_guideline,
            }
        )
        for assignment in group_assignments:
            key = identity(assignment)
            if not key:
                continue
            case = cases_by_identity.get(key)
            if not case:
                missing_cases["identity_missing_from_cases_file"] += 1
                continue
            sidecar = sidecar_by_identity.setdefault(
                key,
                {
                    "identity_key": key,
                    "case_id": case.get("new_unified_case_id") or case.get("case_id") or assignment.get("case_id"),
                    "cve_ids": [],
                    "guideline_ids": [],
                    "boundary_labels": [],
                    "mechanism_ids": [],
                    "mechanism_names": [],
                    "retrieval_guidelines": [],
                    "policy": "propagated_source_reviewed_boundary_requires_same_identity_recall",
                },
            )
            sidecar["cve_ids"].extend(assignment.get("cve_ids") or [])
            sidecar["guideline_ids"].append(guideline_id)
            sidecar["boundary_labels"].append(boundary_label)
            sidecar["mechanism_ids"].append(row.get("boundary_mechanism_id"))
            sidecar["mechanism_names"].append(row.get("boundary_mechanism_name"))
            sidecar["retrieval_guidelines"].append(retrieval_guideline)

    sidecar_rows: list[dict[str, Any]] = []
    for row in sidecar_by_identity.values():
        for field in ("cve_ids", "guideline_ids", "boundary_labels", "mechanism_ids", "mechanism_names", "retrieval_guidelines"):
            row[field] = [value for value in dict.fromkeys(row[field]) if value]
        row["retrieval_guideline"] = "\n\n".join(row.pop("retrieval_guidelines"))
        sidecar_rows.append(row)
    sidecar_rows.sort(key=lambda row: row["identity_key"])
    selected_boundaries.sort(key=lambda row: (row["guideline_id"], row["boundary_label"]))
    summary = {
        "schema_version": "hcvr_propagated_boundary_sidecar.v1",
        "allowed_statuses": sorted(allowed_statuses),
        "input_boundary_count": len(propagation_rows),
        "selected_boundary_count": len(selected_boundaries),
        "sidecar_identity_count": len(sidecar_rows),
        "input_status_counts": dict(sorted(status_counts.items())),
        "skip_or_missing_counts": dict(sorted(missing_cases.items())),
        "policy": [
            "release_group_sidecar_candidate",
            "source_reviewed_boundaries_only",
            "no_bad_case_answer_key",
            "no_regex_fallback",
            "requires_same_identity_recall_before_claim",
        ],
        "files": {
            "guideline_overrides": "guideline_overrides.jsonl",
            "selected_boundaries": "selected_boundaries.jsonl",
        },
    }
    return summary, sidecar_rows, selected_boundaries


def write_readme(path: Path, summary: dict[str, Any]) -> None:
    lines = [
        "# Propagated Source-Reviewed Boundary Sidecar",
        "",
        "This artifact creates a conservative release-group recall sidecar from propagation-audited source-reviewed boundaries.",
        "It is an ablation input only. It does not update the released guideline catalog, embeddings, rank tables, or paper metrics.",
        "",
        "## Summary",
        "",
        f"- Allowed propagation statuses: {summary['allowed_statuses']}",
        f"- Input boundaries: {summary['input_boundary_count']}",
        f"- Selected boundaries: {summary['selected_boundary_count']}",
        f"- Sidecar identities: {summary['sidecar_identity_count']}",
        f"- Input status counts: {summary['input_status_counts']}",
        f"- Skip or missing counts: {summary['skip_or_missing_counts']}",
        "",
        "## Policy",
        "",
        "- The default mode selects only `group_ablation_ready` boundaries.",
        "- It applies the accepted boundary text to every current release-assigned case for that guideline group.",
        "- Boundaries requiring release regeneration are intentionally skipped until the release catalog is regenerated or reconciled.",
        "- Retrieval claims require a same-identity run against the fixed baseline after this sidecar is consumed.",
        "",
    ]
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--propagation", type=Path, required=True)
    parser.add_argument("--boundary-overrides", type=Path, required=True)
    parser.add_argument("--case-assignments", type=Path, required=True)
    parser.add_argument("--cases-file", type=Path, required=True)
    parser.add_argument("--allow-status", action="append", default=[])
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    if args.output_dir.exists() and any(args.output_dir.iterdir()):
        raise FileExistsError(f"refusing to overwrite non-empty output directory: {args.output_dir}")
    allowed_statuses = set(args.allow_status or DEFAULT_ALLOWED_STATUSES)
    summary, sidecar_rows, selected_boundaries = build_sidecar(
        propagation_rows=read_jsonl(args.propagation),
        boundary_overrides=read_jsonl(args.boundary_overrides),
        case_assignments=read_jsonl(args.case_assignments),
        cases=read_jsonl(args.cases_file),
        allowed_statuses=allowed_statuses,
    )
    args.output_dir.mkdir(parents=True, exist_ok=True)
    write_json(args.output_dir / "summary.json", summary)
    write_jsonl(args.output_dir / "guideline_overrides.jsonl", sidecar_rows)
    write_jsonl(args.output_dir / "selected_boundaries.jsonl", selected_boundaries)
    write_readme(args.output_dir / "README.md", summary)
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
