#!/usr/bin/env python3
"""Build a source-reviewed guideline release candidate from accepted boundaries."""

from __future__ import annotations

import argparse
import hashlib
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


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def boundary_key(row: dict[str, Any]) -> tuple[str, str]:
    return str(row.get("guideline_id") or ""), str(row.get("boundary_label") or "")


def load_cases(paths: list[Path]) -> dict[str, dict[str, Any]]:
    cases: dict[str, dict[str, Any]] = {}
    for path in paths:
        for row in read_jsonl(path):
            identity = str(row.get("identity_key") or "").strip()
            if identity and identity not in cases:
                cases[identity] = row
    return cases


def load_accepted_boundaries(boundary_sidecar_dir: Path) -> list[dict[str, Any]]:
    path = boundary_sidecar_dir / "boundary_overrides.jsonl"
    if not path.is_file():
        raise FileNotFoundError(f"missing boundary overrides: {path}")
    rows = read_jsonl(path)
    if not rows:
        raise ValueError(f"no boundary rows in {path}")
    return rows


def build_guideline_text(boundary: dict[str, Any], member_count: int) -> str:
    text = str(boundary.get("retrieval_guideline") or "").strip()
    if not text:
        raise ValueError(f"missing retrieval_guideline for {boundary_key(boundary)}")
    return (
        f"{text} Treat this as a source-reviewed mechanism boundary currently supported by "
        f"{member_count} representative case(s); broaden scope only after additional source review."
    )


def case_cve_ids(case: dict[str, Any]) -> list[str]:
    vuln = case.get("vulnerability") or {}
    values = [vuln.get("id"), *(vuln.get("aliases") or [])]
    return [str(value).strip() for value in values if str(value or "").strip()]


def case_primary_hcvr(case: dict[str, Any] | None) -> str:
    if not case:
        return "missing_case_metadata"
    classification = case.get("classification") or {}
    return str(classification.get("primary_hcvr_type") or "unspecified")


def case_cwes(case: dict[str, Any] | None) -> list[str]:
    if not case:
        return ["missing_case_metadata"]
    classification = case.get("classification") or {}
    cwes = [str(value).strip() for value in classification.get("cwe_ids") or [] if str(value or "").strip()]
    return cwes or ["unspecified"]


def build_release(
    *,
    boundaries: list[dict[str, Any]],
    cases_by_identity: dict[str, dict[str, Any]],
    include_singleton_overrides: bool,
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    guideline_rows: list[dict[str, Any]] = []
    override_by_identity: dict[str, dict[str, Any]] = {}
    case_assignment_rows: list[dict[str, Any]] = []
    unresolved_rows: list[dict[str, Any]] = []
    grouped_boundary_counts: Counter[str] = Counter()
    status_counts: Counter[str] = Counter()

    for index, boundary in enumerate(sorted(boundaries, key=lambda row: boundary_key(row)), start=1):
        old_guideline_id, boundary_label = boundary_key(boundary)
        representative_cases = [
            str(value)
            for value in boundary.get("representative_cases") or []
            if str(value or "").strip()
        ]
        known_cases = [cases_by_identity[identity] for identity in representative_cases if identity in cases_by_identity]
        missing_cases = [identity for identity in representative_cases if identity not in cases_by_identity]
        if missing_cases:
            for identity in missing_cases:
                unresolved_rows.append(
                    {
                        "identity_key": identity,
                        "old_guideline_id": old_guideline_id,
                        "boundary_label": boundary_label,
                        "mechanism_id": boundary.get("mechanism_id"),
                        "reason": "representative_case_missing_from_cases_file",
                    }
                )
        release_ready = len(known_cases) > 0 and (include_singleton_overrides or len(known_cases) > 1)
        status = "release_ready" if release_ready else "review_only"
        if not release_ready:
            status_counts["review_only_singleton_or_missing_case"] += 1
        else:
            status_counts["release_ready"] += 1

        new_guideline_id = f"sr_mech_{index:04d}"
        mechanism_id = str(boundary.get("mechanism_id") or f"source_reviewed_boundary_{index:04d}")
        mechanism_name = str(boundary.get("mechanism_name") or mechanism_id)
        guideline_group_key = f"{old_guideline_id}__{boundary_label}__{mechanism_id}"
        guideline_text = build_guideline_text(boundary, len(known_cases))
        cve_ids = sorted({cve_id for case in known_cases for cve_id in case_cve_ids(case)})
        grouped_boundary_counts[old_guideline_id] += 1
        guideline_rows.append(
            {
                "guideline_id": new_guideline_id,
                "guideline_group_key": guideline_group_key,
                "old_guideline_id": old_guideline_id,
                "boundary_label": boundary_label,
                "file_name": f"{new_guideline_id}.json",
                "mechanism_id": mechanism_id,
                "mechanism_name": mechanism_name,
                "mechanism_family": "source_reviewed_boundary",
                "release_ready": release_ready,
                "release_blockers": [] if release_ready else ["singleton_or_missing_case_support"],
                "source_reviewed_representative_count": len(known_cases),
                "missing_representative_count": len(missing_cases),
                "cve_count": len(cve_ids),
                "guideline_text": guideline_text,
                "guideline_preview": guideline_text[:240],
            }
        )
        for case in known_cases:
            assignment = {
                "identity_key": case.get("identity_key"),
                "case_id": case.get("new_unified_case_id") or case.get("case_id"),
                "cve_ids": case_cve_ids(case),
                "guideline_id": new_guideline_id,
                "guideline_group_key": guideline_group_key,
                "old_guideline_id": old_guideline_id,
                "boundary_label": boundary_label,
                "mechanism_id": mechanism_id,
                "mechanism_name": mechanism_name,
                "primary_hcvr_type": case_primary_hcvr(case),
                "cwe_ids": case_cwes(case),
            }
            case_assignment_rows.append(assignment)
            if release_ready:
                key = str(case.get("identity_key") or "")
                override = override_by_identity.setdefault(
                    key,
                    {
                        "identity_key": key,
                        "case_id": case.get("new_unified_case_id") or case.get("case_id"),
                        "cve_ids": [],
                        "guideline_ids": [],
                        "old_guideline_ids": [],
                        "boundary_labels": [],
                        "mechanism_ids": [],
                        "mechanism_names": [],
                        "retrieval_guidelines": [],
                        "policy": "source_reviewed_release_candidate_requires_same_identity_recall",
                    },
                )
                override["cve_ids"].extend(case_cve_ids(case))
                override["guideline_ids"].append(new_guideline_id)
                override["old_guideline_ids"].append(old_guideline_id)
                override["boundary_labels"].append(boundary_label)
                override["mechanism_ids"].append(mechanism_id)
                override["mechanism_names"].append(mechanism_name)
                override["retrieval_guidelines"].append(guideline_text)

    override_rows: list[dict[str, Any]] = []
    for row in override_by_identity.values():
        for field in ("cve_ids", "guideline_ids", "old_guideline_ids", "boundary_labels", "mechanism_ids", "mechanism_names", "retrieval_guidelines"):
            row[field] = [value for value in dict.fromkeys(row[field]) if value]
        row["retrieval_guideline"] = "\n\n".join(row.pop("retrieval_guidelines"))
        override_rows.append(row)
    override_rows.sort(key=lambda row: row["identity_key"])
    case_assignment_rows.sort(key=lambda row: str(row.get("identity_key") or ""))
    unresolved_rows.sort(key=lambda row: str(row.get("identity_key") or ""))

    summary = {
        "schema_version": "hcvr_source_reviewed_release_candidate.v1",
        "input_boundary_count": len(boundaries),
        "guideline_count": len(guideline_rows),
        "release_ready_guideline_count": sum(1 for row in guideline_rows if row["release_ready"]),
        "review_only_guideline_count": sum(1 for row in guideline_rows if not row["release_ready"]),
        "case_assignment_count": len(case_assignment_rows),
        "override_count": len(override_rows),
        "unresolved_representative_count": len(unresolved_rows),
        "include_singleton_overrides": include_singleton_overrides,
        "old_guideline_boundary_counts": dict(sorted(grouped_boundary_counts.items())),
        "status_counts": dict(sorted(status_counts.items())),
        "policy": [
            "source_reviewed_release_candidate",
            "accepted_boundaries_only",
            "no_regex_fallback",
            "no_bad_case_answer_key",
            "requires_same_identity_recall_before_claim",
        ],
        "files": {
            "index": "index.json",
            "guideline_overrides": "guideline_overrides.jsonl" if override_rows else None,
            "case_assignments": "case_assignments.jsonl",
            "unresolved_representative_cases": "unresolved_representative_cases.jsonl" if unresolved_rows else None,
        },
    }
    return summary, guideline_rows, override_rows, case_assignment_rows, unresolved_rows


def write_guideline_payloads(output_dir: Path, guideline_rows: list[dict[str, Any]]) -> None:
    guidelines_dir = output_dir / "guidelines"
    guidelines_dir.mkdir(parents=True, exist_ok=True)
    for row in guideline_rows:
        payload = {
            "schema_version": "hcvr_source_reviewed_guideline.v1",
            "guideline_id": row["guideline_id"],
            "guideline_group_key": row["guideline_group_key"],
            "old_guideline_id": row["old_guideline_id"],
            "boundary_label": row["boundary_label"],
            "mechanism": {
                "mechanism_id": row["mechanism_id"],
                "name": row["mechanism_name"],
                "family": row["mechanism_family"],
            },
            "guideline_text": row["guideline_text"],
            "source_reviewed_representative_count": row["source_reviewed_representative_count"],
            "release_status": {
                "release_ready": row["release_ready"],
                "status": "release_ready" if row["release_ready"] else "review_only",
                "blockers": row["release_blockers"],
            },
        }
        write_json(guidelines_dir / str(row["file_name"]), payload)


def write_readme(path: Path, summary: dict[str, Any]) -> None:
    lines = [
        "# Source-Reviewed Release Candidate",
        "",
        "This directory is a candidate guideline release generated from accepted source-reviewed boundaries.",
        "It is intended for semantic review and same-identity recall ablation; it is not a final paper metric by itself.",
        "",
        "## Summary",
        "",
        f"- Input boundaries: {summary['input_boundary_count']}",
        f"- Guideline rows: {summary['guideline_count']}",
        f"- Release-ready guidelines: {summary['release_ready_guideline_count']}",
        f"- Review-only guidelines: {summary['review_only_guideline_count']}",
        f"- Case assignments: {summary['case_assignment_count']}",
        f"- Recall sidecar rows: {summary['override_count']}",
        f"- Unresolved representatives: {summary['unresolved_representative_count']}",
        f"- Include singleton overrides: {summary['include_singleton_overrides']}",
        "",
        "## Policy",
        "",
        "- Input rows come from verifier-valid, judge-accepted source-reviewed boundaries.",
        "- Each boundary becomes an explicit guideline candidate, preserving the old guideline and boundary label for traceability.",
        "- Singleton boundaries stay review-only unless `--include-singleton-overrides` is set.",
        "- No regex fallback, hidden label routing, bad-case answer keys, anchors, ranks, or file-line evidence are used to generate retrieval text.",
        "- Retrieval claims require a same-identity recall run after this sidecar is consumed.",
        "",
    ]
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-reviewed-sidecar-dir", type=Path, required=True)
    parser.add_argument("--cases-file", type=Path, action="append", required=True)
    parser.add_argument("--include-singleton-overrides", action="store_true")
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    if args.output_dir.exists() and any(args.output_dir.iterdir()):
        raise FileExistsError(f"refusing to overwrite non-empty output directory: {args.output_dir}")

    boundaries = load_accepted_boundaries(args.source_reviewed_sidecar_dir)
    cases_by_identity = load_cases(args.cases_file)
    summary, guideline_rows, override_rows, assignment_rows, unresolved_rows = build_release(
        boundaries=boundaries,
        cases_by_identity=cases_by_identity,
        include_singleton_overrides=args.include_singleton_overrides,
    )
    summary["input_sha256"] = {
        str(args.source_reviewed_sidecar_dir / "boundary_overrides.jsonl"): sha256_file(
            args.source_reviewed_sidecar_dir / "boundary_overrides.jsonl"
        ),
        **{str(path): sha256_file(path) for path in args.cases_file},
    }

    args.output_dir.mkdir(parents=True, exist_ok=True)
    write_guideline_payloads(args.output_dir, guideline_rows)
    write_json(args.output_dir / "index.json", {"summary": summary, "items": guideline_rows})
    write_json(args.output_dir / "summary.json", summary)
    if override_rows:
        write_jsonl(args.output_dir / "guideline_overrides.jsonl", override_rows)
    write_jsonl(args.output_dir / "case_assignments.jsonl", assignment_rows)
    if unresolved_rows:
        write_jsonl(args.output_dir / "unresolved_representative_cases.jsonl", unresolved_rows)
    write_readme(args.output_dir / "README.md", summary)
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
