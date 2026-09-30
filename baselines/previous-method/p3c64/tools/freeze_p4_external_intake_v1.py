#!/usr/bin/env python3
"""Freeze the fully auditable P4 external intake after generic-pool coverage.

This gate consumes only provenance-recovered cases and a completed *generic*
candidate pool.  It removes cases lacking a post-enumeration source-anchor
overlap from the external release rather than altering the file policy,
candidate views, or coverage rule for one case.

No embeddings, retrieval scores, rankings, or model updates are created here.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


SCHEMA_VERSION = "p4_external_intake_freeze_v1"


def now_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def write_json(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def normalize_text(value: Any) -> str:
    return str(value or "").strip().lower()


def normalized_project_family(repo_key: Any) -> str:
    return re.sub(
        r"__[0-9a-f]{8,64}$", "", normalize_text(repo_key), flags=re.IGNORECASE
    )


def recorded_identities(row: dict[str, Any]) -> set[str]:
    keys = (
        "case_id",
        "cve_id",
        "ghsa_id",
        "repo_key",
        "project_group",
        "repo",
        "repository_url",
        "repo_url",
    )
    return {normalize_text(row.get(key)) for key in keys if normalize_text(row.get(key))}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--external-cases", type=Path, required=True)
    parser.add_argument("--provenance-ledger", type=Path, required=True)
    parser.add_argument("--candidate-pool", type=Path, required=True)
    parser.add_argument("--coverage", type=Path, required=True)
    parser.add_argument("--pool-summary", type=Path, required=True)
    parser.add_argument("--m5-proposal", type=Path, required=True)
    parser.add_argument("--p3-cases", type=Path, required=True)
    parser.add_argument("--m8-cases", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    paths = {
        "external_cases": args.external_cases.resolve(),
        "provenance_ledger": args.provenance_ledger.resolve(),
        "candidate_pool": args.candidate_pool.resolve(),
        "coverage": args.coverage.resolve(),
        "pool_summary": args.pool_summary.resolve(),
        "m5_proposal": args.m5_proposal.resolve(),
        "p3_cases": args.p3_cases.resolve(),
        "m8_cases": args.m8_cases.resolve(),
    }
    missing = [str(path) for path in paths.values() if not path.is_file()]
    if missing:
        raise FileNotFoundError(f"missing P4 intake-freeze input(s): {missing}")
    output_dir = args.output_dir.resolve()
    if output_dir.exists():
        raise FileExistsError(f"refusing to overwrite P4 external intake: {output_dir}")

    cases = read_jsonl(paths["external_cases"])
    coverage_by_case = {
        normalize_text(row.get("case_id")): row for row in read_jsonl(paths["coverage"])
    }
    provenance_by_case = {
        normalize_text(row.get("case_id")): row
        for row in read_jsonl(paths["provenance_ledger"])
    }
    pool_summary = read_json(paths["pool_summary"])
    candidate_rows = read_jsonl(paths["candidate_pool"])
    candidate_ids = {normalize_text(row.get("candidate_id")) for row in candidate_rows}
    positive_ids_by_case: dict[str, set[str]] = {}
    for candidate in candidate_rows:
        for case_id in candidate.get("positive_case_ids") or []:
            positive_ids_by_case.setdefault(normalize_text(case_id), set()).add(
                normalize_text(candidate.get("candidate_id"))
            )

    historical_rows = [
        *read_jsonl(paths["m5_proposal"]),
        *read_jsonl(paths["p3_cases"]),
        *read_jsonl(paths["m8_cases"]),
    ]
    used_identity_values = {
        value for row in historical_rows for value in recorded_identities(row)
    }
    used_project_families = {
        normalized_project_family(row.get("repo_key"))
        for row in historical_rows
        if normalized_project_family(row.get("repo_key"))
    }

    included: list[dict[str, Any]] = []
    intake_ledger: list[dict[str, Any]] = []
    hold_rows: list[dict[str, Any]] = []
    track_counts: Counter[str] = Counter()
    for case in sorted(cases, key=lambda row: normalize_text(row.get("case_id"))):
        case_id = normalize_text(case.get("case_id"))
        coverage = coverage_by_case.get(case_id)
        provenance = provenance_by_case.get(case_id)
        reasons: list[str] = []
        if not provenance or normalize_text(provenance.get("provenance_status")) != "source_commit_recovered":
            reasons.append("source_commit_not_recovered")
        if not coverage:
            reasons.append("coverage_row_missing")
        elif not coverage.get("covered"):
            reasons.append("generic_pool_anchor_coverage_missing")
        expected_positive_ids = set(
            normalize_text(value) for value in (coverage or {}).get("positive_candidate_ids") or []
        )
        if coverage and expected_positive_ids != positive_ids_by_case.get(case_id, set()):
            reasons.append("coverage_positive_ids_disagree_with_candidate_pool")
        if not expected_positive_ids:
            reasons.append("no_generic_positive_candidates")
        if not expected_positive_ids <= candidate_ids:
            reasons.append("coverage_references_absent_candidate")
        direct_matches = sorted(recorded_identities(case) & used_identity_values)
        family = normalized_project_family(case.get("repo_key"))
        family_overlap = family in used_project_families if family else False
        if direct_matches:
            reasons.append("recorded_identity_overlap_with_m5_p3_or_m8")
        if family_overlap:
            reasons.append("project_family_overlap_with_m5_p3_or_m8")
        status = "included" if not reasons else "held"
        row = {
            "case_id": case.get("case_id"),
            "cve_id": case.get("cve_id"),
            "repo_key": case.get("repo_key"),
            "project_family": family,
            "track_id": case.get("track_id"),
            "language": case.get("language"),
            "intake_status": status,
            "hold_reasons": reasons,
            "source_commit_recovered": bool(
                provenance
                and normalize_text(provenance.get("provenance_status"))
                == "source_commit_recovered"
            ),
            "generic_pool_candidate_count": (coverage or {}).get("candidate_count"),
            "generic_positive_candidate_count": len(expected_positive_ids),
            "generic_positive_candidate_ids": sorted(expected_positive_ids),
            "recorded_identity_matches": direct_matches,
            "project_family_overlap": family_overlap,
            "admission_boundary": (
                "generic function + sliding_window pool only; anchor overlap is "
                "offline evaluation mapping; non-anchor candidates remain unknown"
            ),
        }
        intake_ledger.append(row)
        if status == "included":
            included.append(case)
            track_counts.update([normalize_text(case.get("track_id"))])
        else:
            hold_rows.append(row)

    if len(included) < 1:
        raise ValueError("P4 external intake has no fully admitted cases")
    if pool_summary.get("summary", {}).get("candidate_count") != len(candidate_rows):
        raise ValueError("pool summary candidate count disagrees with candidate pool")
    if pool_summary.get("summary", {}).get("case_count") != len(cases):
        raise ValueError("pool summary case count disagrees with external case manifest")

    output_dir.mkdir(parents=True, exist_ok=False)
    write_jsonl(output_dir / "selected_external_cases.v1.jsonl", included)
    write_jsonl(output_dir / "external_intake_ledger.v1.jsonl", intake_ledger)
    write_jsonl(output_dir / "held_external_cases.v1.jsonl", hold_rows)
    summary = {
        "schema_version": SCHEMA_VERSION,
        "status": "frozen_intake_no_embedding_or_retrieval",
        "created_at": now_utc(),
        "inputs": {
            key: {"path": str(path), "sha256": sha256_file(path)}
            for key, path in paths.items()
        },
        "candidate_pool_policy": {
            "view_types": ["function", "sliding_window"],
            "candidate_universe": "full_repository_generic_views",
            "anchor_role": "post_enumeration_offline_evaluation_mapping_only",
            "unknown_non_anchor_policy": "unknown_unlabeled_background_not_safe_negative",
            "per_case_policy_exception": "forbidden",
        },
        "historical_isolation": {
            "m5_case_count": len(read_jsonl(paths["m5_proposal"])),
            "p3_case_count": len(read_jsonl(paths["p3_cases"])),
            "m8_case_count": len(read_jsonl(paths["m8_cases"])),
            "recorded_identity_value_count": len(used_identity_values),
            "normalized_project_family_count": len(used_project_families),
            "included_identity_overlap_count": 0,
            "included_project_family_overlap_count": 0,
        },
        "intake": {
            "provenance_recovered_candidate_case_count": len(cases),
            "included_case_count": len(included),
            "held_case_count": len(hold_rows),
            "included_track_case_counts": dict(sorted(track_counts.items())),
            "held_cases": [
                {
                    "case_id": row["case_id"],
                    "cve_id": row["cve_id"],
                    "reasons": row["hold_reasons"],
                }
                for row in hold_rows
            ],
        },
        "next_gate": (
            "A separate cache-readiness audit must validate a frozen embedding "
            "cache for exactly selected_external_cases.v1.jsonl before an "
            "external B0/P3C64 one-shot spec can be frozen."
        ),
        "boundary": (
            "This freezes external-case admission only. It creates no embeddings, "
            "scores, ranks, model updates, or external retrieval claim."
        ),
    }
    write_json(output_dir / "summary.json", summary)
    manifest = {"artifact": output_dir.name, "files": {}}
    for path in sorted(output_dir.iterdir()):
        if path.is_file():
            manifest["files"][path.name] = {
                "sha256": sha256_file(path),
                "bytes": path.stat().st_size,
            }
    write_json(output_dir / "manifest.v1.json", manifest)
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
