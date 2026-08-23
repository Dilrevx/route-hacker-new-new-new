#!/usr/bin/env python3
"""Audit how source-reviewed boundaries can be propagated into recall evals.

This is a diagnostic bridge between semantic source review and retrieval
experiments. It never edits released guidelines, recall sidecars, rank tables,
or training data.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
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


def identity_from_row(row: dict[str, Any]) -> str:
    return str(row.get("identity_key") or row.get("identity") or "").strip()


def load_identity_set(paths: list[Path]) -> set[str]:
    identities: set[str] = set()
    for path in paths:
        for row in read_jsonl(path):
            if isinstance(row, dict):
                identity = identity_from_row(row)
            else:
                identity = str(row).strip()
            if identity:
                identities.add(identity)
    return identities


def compact_list(values: Iterable[Any]) -> list[str]:
    return sorted({str(value).strip() for value in values if str(value or "").strip()})


def index_groups(group_rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    groups: dict[str, dict[str, Any]] = {}
    for row in group_rows:
        guideline_id = str(row.get("guideline_id") or "").strip()
        if guideline_id:
            groups[guideline_id] = row
    return groups


def index_assignments(assignments: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    indexed: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in assignments:
        identity = identity_from_row(row)
        if identity:
            indexed[identity].append(row)
    return indexed


def assignment_summary(
    *,
    guideline_id: str,
    representative_cases: list[str],
    assignments_by_identity: dict[str, list[dict[str, Any]]],
) -> dict[str, Any]:
    same_guideline: list[str] = []
    assigned_elsewhere: list[dict[str, Any]] = []
    absent: list[str] = []
    for identity in representative_cases:
        rows = assignments_by_identity.get(identity) or []
        if not rows:
            absent.append(identity)
            continue
        matched = False
        for row in rows:
            assigned_guideline = str(row.get("guideline_id") or "")
            if assigned_guideline == guideline_id:
                matched = True
            else:
                assigned_elsewhere.append(
                    {
                        "identity_key": identity,
                        "assigned_guideline_id": assigned_guideline,
                        "assigned_mechanism_id": row.get("mechanism_id"),
                        "assigned_mechanism_name": row.get("mechanism_name"),
                    }
                )
        if matched:
            same_guideline.append(identity)
    return {
        "same_guideline_representatives": compact_list(same_guideline),
        "assigned_elsewhere": sorted(assigned_elsewhere, key=lambda row: row["identity_key"]),
        "absent_from_release_assignment": compact_list(absent),
    }


def determine_status(
    *,
    release_group: dict[str, Any] | None,
    boundary: dict[str, Any],
    same_guideline_count: int,
    elsewhere_count: int,
    fixed_group_overlap_count: int | None,
    fixed_rep_overlap_count: int | None,
    min_group_representatives: int,
) -> tuple[str, str]:
    if release_group is None:
        if fixed_rep_overlap_count is not None and fixed_rep_overlap_count > 0:
            return (
                "fixed_identity_only",
                "Run a fixed sidecar-identity recall A/B; this boundary is absent from the current release group report.",
            )
        return (
            "not_recall_evaluable",
            "Source-reviewed boundary has no compatible release group and no representative overlap with the supplied fixed identities.",
        )

    group_mechanism = str(release_group.get("mechanism_id") or "")
    boundary_mechanism = str(boundary.get("mechanism_id") or "")
    if group_mechanism and boundary_mechanism and group_mechanism != boundary_mechanism:
        return (
            "requires_release_regeneration",
            "Regenerate or reconcile the release guideline before using this source-reviewed boundary in release-level recall claims.",
        )
    if elsewhere_count:
        return (
            "blocked_by_assignment_conflict",
            "Representative cases are assigned to a different release guideline; inspect grouping before recall-side changes.",
        )
    if same_guideline_count == 0:
        return (
            "fixed_identity_only",
            "The release group exists, but none of the source-reviewed representatives are joined to it in case assignments.",
        )
    if same_guideline_count < min_group_representatives:
        return (
            "group_ablation_candidate_low_support",
            "Treat as a low-support mechanism candidate; prefer additional source review before paper-facing group-level claims.",
        )
    if fixed_group_overlap_count is not None and fixed_group_overlap_count == 0:
        return (
            "group_ablation_candidate_outside_fixed_set",
            "The boundary is group-compatible, but the release group has no overlap with the supplied fixed identity set.",
        )
    return (
        "group_ablation_ready",
        "Run same-identity recall with this boundary text as the only changed variable, then compare against the fixed baseline.",
    )


def audit_propagation(
    *,
    boundary_rows: list[dict[str, Any]],
    group_rows: list[dict[str, Any]],
    assignment_rows: list[dict[str, Any]],
    fixed_identities: set[str] | None,
    min_group_representatives: int,
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, str]]]:
    groups_by_guideline = index_groups(group_rows)
    assignments_by_identity = index_assignments(assignment_rows)
    group_assigned_identities: dict[str, set[str]] = defaultdict(set)
    for row in assignment_rows:
        guideline_id = str(row.get("guideline_id") or "")
        identity = identity_from_row(row)
        if guideline_id and identity:
            group_assigned_identities[guideline_id].add(identity)

    boundary_reports: list[dict[str, Any]] = []
    group_reports: dict[str, dict[str, Any]] = {}
    fixed_identity_rows: dict[str, dict[str, str]] = {}
    status_counts: Counter[str] = Counter()

    for boundary in boundary_rows:
        guideline_id = str(boundary.get("guideline_id") or "")
        representative_cases = compact_list(boundary.get("representative_cases") or [])
        release_group = groups_by_guideline.get(guideline_id)
        assignment = assignment_summary(
            guideline_id=guideline_id,
            representative_cases=representative_cases,
            assignments_by_identity=assignments_by_identity,
        )
        fixed_rep_overlap = None
        fixed_group_overlap = None
        fixed_group_identities: list[str] = []
        if fixed_identities is not None:
            fixed_rep_overlap = len(set(representative_cases) & fixed_identities)
            fixed_group_identities = compact_list(group_assigned_identities.get(guideline_id, set()) & fixed_identities)
            fixed_group_overlap = len(fixed_group_identities)
            for identity in set(representative_cases) & fixed_identities:
                fixed_identity_rows.setdefault(
                    identity,
                    {
                        "identity_key": identity,
                        "source": "source_reviewed_representative_overlap",
                    },
                )
            for identity in fixed_group_identities:
                fixed_identity_rows.setdefault(
                    identity,
                    {
                        "identity_key": identity,
                        "source": "release_group_fixed_identity_overlap",
                    },
                )

        status, next_action = determine_status(
            release_group=release_group,
            boundary=boundary,
            same_guideline_count=len(assignment["same_guideline_representatives"]),
            elsewhere_count=len(assignment["assigned_elsewhere"]),
            fixed_group_overlap_count=fixed_group_overlap,
            fixed_rep_overlap_count=fixed_rep_overlap,
            min_group_representatives=min_group_representatives,
        )
        status_counts[status] += 1
        row = {
            "guideline_id": guideline_id,
            "boundary_label": boundary.get("boundary_label"),
            "boundary_mechanism_id": boundary.get("mechanism_id"),
            "boundary_mechanism_name": boundary.get("mechanism_name"),
            "representative_case_count": len(representative_cases),
            "representative_cases": representative_cases,
            "release_group_found": release_group is not None,
            "release_guideline_group_key": release_group.get("guideline_group_key") if release_group else None,
            "release_mechanism_id": release_group.get("mechanism_id") if release_group else None,
            "release_mechanism_name": release_group.get("mechanism_name") if release_group else None,
            "release_assigned_case_count": release_group.get("assigned_case_count") if release_group else 0,
            "release_flags": release_group.get("flags") if release_group else [],
            "same_guideline_representative_count": len(assignment["same_guideline_representatives"]),
            "same_guideline_representatives": assignment["same_guideline_representatives"],
            "assigned_elsewhere_count": len(assignment["assigned_elsewhere"]),
            "assigned_elsewhere": assignment["assigned_elsewhere"],
            "absent_from_release_assignment_count": len(assignment["absent_from_release_assignment"]),
            "absent_from_release_assignment": assignment["absent_from_release_assignment"],
            "fixed_representative_overlap_count": fixed_rep_overlap,
            "fixed_group_overlap_count": fixed_group_overlap,
            "fixed_group_overlap_identities": fixed_group_identities,
            "propagation_status": status,
            "next_action": next_action,
            "policy": "diagnostic_only_no_sidecar_or_release_mutation",
        }
        boundary_reports.append(row)

        group_key = guideline_id or str(boundary.get("mechanism_id") or boundary.get("boundary_label") or "")
        group = group_reports.setdefault(
            group_key,
            {
                "guideline_id": guideline_id,
                "release_group_found": release_group is not None,
                "release_guideline_group_key": release_group.get("guideline_group_key") if release_group else None,
                "release_mechanism_id": release_group.get("mechanism_id") if release_group else None,
                "release_mechanism_name": release_group.get("mechanism_name") if release_group else None,
                "release_assigned_case_count": release_group.get("assigned_case_count") if release_group else 0,
                "boundary_count": 0,
                "status_counts": Counter(),
                "representative_cases": set(),
                "fixed_group_overlap_identities": set(),
            },
        )
        group["boundary_count"] += 1
        group["status_counts"][status] += 1
        group["representative_cases"].update(representative_cases)
        group["fixed_group_overlap_identities"].update(fixed_group_identities)

    normalized_group_reports: list[dict[str, Any]] = []
    for row in group_reports.values():
        normalized_group_reports.append(
            {
                **{key: value for key, value in row.items() if key not in {"status_counts", "representative_cases", "fixed_group_overlap_identities"}},
                "status_counts": dict(sorted(row["status_counts"].items())),
                "representative_case_count": len(row["representative_cases"]),
                "representative_cases": compact_list(row["representative_cases"]),
                "fixed_group_overlap_count": len(row["fixed_group_overlap_identities"]),
                "fixed_group_overlap_identities": compact_list(row["fixed_group_overlap_identities"]),
            }
        )

    fixed_rows = sorted(fixed_identity_rows.values(), key=lambda row: row["identity_key"])
    summary = {
        "schema_version": "hcvr_source_reviewed_boundary_propagation_audit.v1",
        "boundary_count": len(boundary_reports),
        "group_count": len(normalized_group_reports),
        "fixed_identity_input_count": len(fixed_identities) if fixed_identities is not None else None,
        "fixed_identity_output_count": len(fixed_rows) if fixed_identities is not None else None,
        "min_group_representatives": min_group_representatives,
        "status_counts": dict(sorted(status_counts.items())),
        "policy": [
            "diagnostic_only",
            "no_bad_case_answer_key",
            "no_regex_fallback",
            "no_release_or_sidecar_mutation",
            "same_identity_recall_required_for_paper_claims",
        ],
    }
    boundary_reports.sort(key=lambda row: (row["propagation_status"], row["guideline_id"], str(row["boundary_label"])))
    normalized_group_reports.sort(key=lambda row: (row["guideline_id"], row["release_mechanism_id"] or ""))
    return summary, boundary_reports, normalized_group_reports, fixed_rows


def write_readme(path: Path, summary: dict[str, Any]) -> None:
    lines = [
        "# Source-Reviewed Boundary Propagation Audit",
        "",
        "This artifact audits how source-reviewed mechanism boundaries can be used in later recall experiments.",
        "It does not modify released guidelines, recall sidecars, rank tables, audit prompts, or training data.",
        "",
        "## Summary",
        "",
        f"- Source-reviewed boundaries: {summary['boundary_count']}",
        f"- Guideline groups touched: {summary['group_count']}",
        f"- Fixed identity input count: {summary['fixed_identity_input_count']}",
        f"- Fixed identity output count: {summary['fixed_identity_output_count']}",
        f"- Minimum representatives for group-level readiness: {summary['min_group_representatives']}",
        f"- Status counts: {summary['status_counts']}",
        "",
        "## Interpretation",
        "",
        "- `group_ablation_ready`: the boundary aligns with the current release group and has enough source-reviewed representatives for a same-identity A/B.",
        "- `group_ablation_candidate_low_support`: the boundary aligns with the release group, but the source-reviewed support is currently thin.",
        "- `group_ablation_candidate_outside_fixed_set`: the boundary aligns with the release group, but the supplied fixed identity set cannot measure it.",
        "- `fixed_identity_only`: run a separate fixed sidecar-identity experiment rather than treating it as full release evidence.",
        "- `requires_release_regeneration`: source review produced a refined mechanism that is not yet reflected by the current release group.",
        "- `blocked_by_assignment_conflict`: inspect grouping before using the boundary for recall claims.",
        "- `not_recall_evaluable`: source evidence exists, but the current case/fixed-identity material cannot evaluate it.",
        "",
        "## Files",
        "",
        "- `boundary_propagation.jsonl`: one row per source-reviewed boundary.",
        "- `group_propagation.jsonl`: guideline-level aggregation.",
        "- `fixed_identity_candidates.jsonl`: optional same-identity subset derived from overlap with the supplied fixed identity file.",
        "- `summary.json`: machine-readable counts and policy.",
        "",
        "Paper-facing retrieval claims still require a fresh same-identity recall run after any recall-consumed guideline text changes.",
        "",
    ]
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--boundary-overrides", type=Path, required=True)
    parser.add_argument("--group-report", type=Path, required=True)
    parser.add_argument("--case-assignments", type=Path, required=True)
    parser.add_argument("--fixed-identity-file", type=Path, action="append", default=[])
    parser.add_argument("--min-group-representatives", type=int, default=2)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    if args.output_dir.exists() and any(args.output_dir.iterdir()):
        raise FileExistsError(f"refusing to overwrite non-empty output directory: {args.output_dir}")
    if args.min_group_representatives < 1:
        raise ValueError("min-group-representatives must be positive")

    fixed_identities = load_identity_set(args.fixed_identity_file) if args.fixed_identity_file else None
    summary, boundary_rows, group_rows, fixed_rows = audit_propagation(
        boundary_rows=read_jsonl(args.boundary_overrides),
        group_rows=read_jsonl(args.group_report),
        assignment_rows=read_jsonl(args.case_assignments),
        fixed_identities=fixed_identities,
        min_group_representatives=args.min_group_representatives,
    )
    args.output_dir.mkdir(parents=True, exist_ok=True)
    write_json(args.output_dir / "summary.json", summary)
    write_jsonl(args.output_dir / "boundary_propagation.jsonl", boundary_rows)
    write_jsonl(args.output_dir / "group_propagation.jsonl", group_rows)
    write_jsonl(args.output_dir / "fixed_identity_candidates.jsonl", fixed_rows)
    write_readme(args.output_dir / "README.md", summary)
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
