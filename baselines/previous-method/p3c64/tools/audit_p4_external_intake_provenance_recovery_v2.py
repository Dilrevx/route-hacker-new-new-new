#!/usr/bin/env python3
"""Recover and verify source commits for isolated P4 external candidates.

This is an intake-provenance audit only.  It never creates a generic candidate
pool, embedding, retrieval score, ranking, model fit, or external result.

The v1 eligibility audit intentionally required a top-level ``pre_patch_commit``
or ``parent_commit`` field on the canonical case row.  Some otherwise eligible
phase-21 rows carry an equivalent, independently verified commit pair in their
nested source references and in the frozen source-ready intake.  This tool
accepts only the v1 rows whose *sole* failure was that top-level schema gap, and
requires all of the following before marking the commit as recovered:

* a complete pre-patch/fix commit pair in canonical nested source references;
* a matching source-ready intake row marked ``verified_fix_parent``;
* an existing pre-patch archive whose name and contents agree with the commit;
* source snapshot SHA-256 checks for every core positive label;
* candidate-reference consistency against the canonical supplement; and
* a fresh recorded-identity and project-family exclusion audit against M5/P3/M8.

Rows that cannot satisfy the chain remain ``snapshot_only_hold``.  They are not
silently promoted into an external evaluation release.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import tarfile
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


SCHEMA_VERSION = "p4_external_intake_provenance_recovery_v2"
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$", flags=re.IGNORECASE)


def now_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


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


def is_commit(value: Any) -> bool:
    return bool(COMMIT_RE.fullmatch(normalize_text(value)))


def core_labels_for_case(
    labels_by_case: dict[str, list[dict[str, Any]]], case_id: str
) -> list[dict[str, Any]]:
    return [
        label
        for label in labels_by_case[case_id]
        if label.get("core_metric_eligible") is True
        and normalize_text(label.get("metric_inclusion")) == "core_positive"
        and normalize_text(label.get("candidate_pool_status")) == "covered"
        and bool(label.get("candidate_refs"))
        and (
            label.get("source_contract_valid") is True
            or label.get("strict_source_contract") is True
            or label.get("candidate_closure_verified") is True
        )
    ]


def candidate_ref_matches(
    candidate: dict[str, Any], candidate_ref: dict[str, Any]
) -> bool:
    fields = ("repo_key", "file", "start_line", "end_line")
    return all(candidate.get(field) == candidate_ref.get(field) for field in fields)


def archive_snapshot_verification(
    archive_path: Path,
    source_path: Path,
    expected_sha256: str,
    source_relative_file: str,
) -> tuple[bool, str | None]:
    """Verify a snapshot file and its corresponding file in the source archive."""
    if not source_path.is_file():
        return False, "source_snapshot_missing"
    if sha256_file(source_path) != expected_sha256:
        return False, "source_snapshot_sha256_mismatch"
    suffix = f"/{source_relative_file.lstrip('/')}"
    try:
        with tarfile.open(archive_path, mode="r:gz") as archive:
            member_names = [
                member.name
                for member in archive.getmembers()
                if member.isfile() and member.name.endswith(suffix)
            ]
            if len(member_names) != 1:
                return False, "archive_member_missing_or_ambiguous"
            handle = archive.extractfile(member_names[0])
            if handle is None:
                return False, "archive_member_unreadable"
            with handle:
                if sha256_bytes(handle.read()) != expected_sha256:
                    return False, "archive_member_sha256_mismatch"
    except (OSError, tarfile.TarError):
        return False, "archive_unreadable"
    return True, None


def resolve_source_ready_archive(
    source_ready: dict[str, Any], route_hacker_root: Path
) -> Path | None:
    source_refs = source_ready.get("source_refs") or {}
    raw_path = source_refs.get("materialized_archive_path")
    if not raw_path:
        return None
    path = Path(raw_path)
    return path if path.is_absolute() else route_hacker_root / path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cases", type=Path, required=True)
    parser.add_argument("--labels", type=Path, required=True)
    parser.add_argument("--candidate-supplement", type=Path, required=True)
    parser.add_argument("--v1-audit-ledger", type=Path, required=True)
    parser.add_argument("--source-ready-cases", type=Path, required=True)
    parser.add_argument("--route-hacker-root", type=Path, required=True)
    parser.add_argument("--m5-proposal", type=Path, required=True)
    parser.add_argument("--p3-cases", type=Path, required=True)
    parser.add_argument("--m8-cases", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    paths = {
        "canonical_cases": args.cases.resolve(),
        "canonical_labels": args.labels.resolve(),
        "candidate_supplement": args.candidate_supplement.resolve(),
        "v1_audit_ledger": args.v1_audit_ledger.resolve(),
        "source_ready_cases": args.source_ready_cases.resolve(),
        "m5_proposal": args.m5_proposal.resolve(),
        "p3_cases": args.p3_cases.resolve(),
        "m8_cases": args.m8_cases.resolve(),
    }
    missing = [str(path) for path in paths.values() if not path.is_file()]
    route_hacker_root = args.route_hacker_root.resolve()
    if not route_hacker_root.is_dir():
        missing.append(str(route_hacker_root))
    if missing:
        raise FileNotFoundError(f"missing provenance-audit input(s): {missing}")
    output_dir = args.output_dir.resolve()
    if output_dir.exists():
        raise FileExistsError(f"refusing to overwrite provenance audit: {output_dir}")

    cases_by_id = {
        normalize_text(case.get("case_id")): case for case in read_jsonl(paths["canonical_cases"])
    }
    labels_by_case: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
    for label in read_jsonl(paths["canonical_labels"]):
        labels_by_case[normalize_text(label.get("case_id"))].append(label)
    candidates_by_id = {
        normalize_text(candidate.get("candidate_id")): candidate
        for candidate in read_jsonl(paths["candidate_supplement"])
    }
    source_ready_by_id = {
        normalize_text(case.get("case_id")): case
        for case in read_jsonl(paths["source_ready_cases"])
    }
    v1_rows = read_jsonl(paths["v1_audit_ledger"])
    v1_scope_rows = [
        row
        for row in v1_rows
        if row.get("failure_reasons") == ["no_pre_patch_or_parent_commit"]
    ]

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

    recovery_rows: list[dict[str, Any]] = []
    recovered: list[dict[str, Any]] = []
    status_counts: Counter[str] = Counter()
    failure_counts: Counter[str] = Counter()
    track_counts: Counter[str] = Counter()

    for v1_row in sorted(v1_scope_rows, key=lambda row: normalize_text(row.get("case_id"))):
        case_id = normalize_text(v1_row.get("case_id"))
        case = cases_by_id.get(case_id)
        failures: list[str] = []
        if case is None:
            failures.append("canonical_case_missing")
            case = {}
        source_ready = source_ready_by_id.get(case_id)
        if source_ready is None:
            failures.append("source_ready_case_missing")
            source_ready = {}

        nested_refs = case.get("source_refs") or {}
        nested_pre = normalize_text(nested_refs.get("pre_patch_commit"))
        nested_fix = normalize_text(nested_refs.get("fix_commit"))
        if not is_commit(nested_pre):
            failures.append("nested_pre_patch_commit_invalid")
        if not is_commit(nested_fix):
            failures.append("nested_fix_commit_invalid")

        source_pre = normalize_text(source_ready.get("pre_patch_commit"))
        source_fix = normalize_text(source_ready.get("fix_commit"))
        source_status = normalize_text(source_ready.get("pre_patch_commit_status"))
        source_refs = source_ready.get("source_refs") or {}
        if source_ready.get("source_ready") is not True:
            failures.append("source_ready_flag_not_true")
        if source_status != "verified_fix_parent":
            failures.append("source_ready_pre_patch_status_not_verified_fix_parent")
        if source_pre != nested_pre:
            failures.append("source_ready_pre_patch_commit_mismatch")
        if source_fix != nested_fix:
            failures.append("source_ready_fix_commit_mismatch")
        if normalize_text(source_refs.get("materialized_parent_commit")) != nested_pre:
            failures.append("source_ready_materialized_parent_commit_mismatch")

        canonical_archive = Path(nested_refs.get("source_archive_path") or "")
        source_ready_archive = resolve_source_ready_archive(source_ready, route_hacker_root)
        if not canonical_archive.is_file():
            failures.append("canonical_source_archive_missing")
        if source_ready_archive is None or not source_ready_archive.is_file():
            failures.append("source_ready_materialized_archive_missing")
        elif canonical_archive.is_file() and canonical_archive.resolve() != source_ready_archive.resolve():
            failures.append("canonical_and_source_ready_archive_path_mismatch")
        archive_path = canonical_archive if canonical_archive.is_file() else source_ready_archive
        if archive_path is not None and nested_pre and nested_pre not in archive_path.name.lower():
            failures.append("archive_name_does_not_contain_pre_patch_commit")

        direct_matches = sorted(recorded_identities(case) & used_identity_values)
        family = normalized_project_family(case.get("repo_key"))
        family_overlap = family in used_project_families if family else False
        if direct_matches:
            failures.append("recorded_identity_overlap_with_m5_p3_or_m8")
        if family_overlap:
            failures.append("project_family_overlap_with_m5_p3_or_m8")

        core_labels = core_labels_for_case(labels_by_case, case_id)
        if not core_labels:
            failures.append("no_source_contract_or_closure_verified_core_labels")
        snapshot_checks: list[dict[str, Any]] = []
        candidate_checks: list[dict[str, Any]] = []
        for label in core_labels:
            label_id = label.get("label_id")
            snapshot_path = Path(label.get("source_snapshot_path") or "")
            expected_sha256 = normalize_text(label.get("source_snapshot_sha256"))
            source_file = str(label.get("file") or "").strip()
            snapshot_ok = False
            snapshot_failure = "source_snapshot_sha256_invalid"
            if is_commit(expected_sha256):  # SHA-1-shaped values cannot be SHA-256.
                snapshot_failure = "source_snapshot_sha256_invalid"
            elif re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
                if archive_path is not None and archive_path.is_file():
                    snapshot_ok, snapshot_failure = archive_snapshot_verification(
                        archive_path=archive_path,
                        source_path=snapshot_path,
                        expected_sha256=expected_sha256,
                        source_relative_file=source_file,
                    )
                else:
                    snapshot_failure = "archive_unavailable_for_snapshot_verification"
            if not snapshot_ok and snapshot_failure:
                failures.append(snapshot_failure)
            snapshot_checks.append(
                {
                    "label_id": label_id,
                    "source_snapshot_path": str(snapshot_path),
                    "source_snapshot_sha256": expected_sha256 or None,
                    "verified_against_archive": snapshot_ok,
                    "failure_reason": snapshot_failure if not snapshot_ok else None,
                }
            )

            for candidate_ref in label.get("candidate_refs") or []:
                candidate_id = normalize_text(candidate_ref.get("candidate_id"))
                candidate = candidates_by_id.get(candidate_id)
                candidate_ok = candidate is not None and candidate_ref_matches(
                    candidate, candidate_ref
                )
                if not candidate_ok:
                    failures.append("candidate_supplement_reference_mismatch")
                candidate_checks.append(
                    {
                        "label_id": label_id,
                        "candidate_id": candidate_ref.get("candidate_id"),
                        "matched_canonical_supplement": candidate_ok,
                    }
                )

        unique_failures = sorted(set(failures))
        status = "source_commit_recovered" if not unique_failures else "snapshot_only_hold"
        if any(
            failure in {
                "recorded_identity_overlap_with_m5_p3_or_m8",
                "project_family_overlap_with_m5_p3_or_m8",
                "canonical_case_missing",
            }
            for failure in unique_failures
        ):
            status = "rejected"
        row = {
            "case_id": case.get("case_id") or v1_row.get("case_id"),
            "cve_id": case.get("cve_id") or v1_row.get("cve_id"),
            "repo_key": case.get("repo_key") or v1_row.get("repo_key"),
            "project_family": family,
            "track_id": case.get("track_id") or v1_row.get("track_id"),
            "language": case.get("language") or v1_row.get("language"),
            "v1_failure_reasons": v1_row.get("failure_reasons"),
            "provenance_status": status,
            "recovery_failure_reasons": unique_failures,
            "recovered_pre_patch_commit": nested_pre or None,
            "recovered_fix_commit": nested_fix or None,
            "source_ready_pre_patch_commit": source_pre or None,
            "source_ready_fix_commit": source_fix or None,
            "source_ready_pre_patch_commit_status": source_status or None,
            "source_archive_path": str(archive_path) if archive_path else None,
            "source_archive_exists": bool(archive_path and archive_path.is_file()),
            "source_archive_name_contains_pre_patch_commit": bool(
                archive_path and nested_pre and nested_pre in archive_path.name.lower()
            ),
            "core_source_contract_label_count": len(core_labels),
            "snapshot_checks": snapshot_checks,
            "candidate_supplement_checks": candidate_checks,
            "recorded_identity_matches": direct_matches,
            "project_family_overlap": family_overlap,
            "next_gate": (
                "full_repo_generic_candidate_pool_and_frozen_code_cache_required"
                if status == "source_commit_recovered"
                else "hold_or_reject_before_external_release"
            ),
        }
        recovery_rows.append(row)
        status_counts.update([status])
        failure_counts.update(unique_failures)
        if status == "source_commit_recovered":
            recovered.append(row)
            track_counts.update([normalize_text(row.get("track_id"))])

    output_dir.mkdir(parents=True, exist_ok=False)
    write_jsonl(output_dir / "provenance_recovery_ledger.v2.jsonl", recovery_rows)
    write_jsonl(
        output_dir / "source_commit_recovered_candidates.v2.jsonl",
        sorted(
            recovered,
            key=lambda row: (
                normalize_text(row.get("track_id")),
                normalize_text(row.get("cve_id")),
                normalize_text(row.get("case_id")),
            ),
        ),
    )
    summary = {
        "schema_version": SCHEMA_VERSION,
        "status": "completed_no_retrieval",
        "created_at": now_utc(),
        "inputs": {
            key: {"path": str(path), "sha256": sha256_file(path)}
            for key, path in paths.items()
        },
        "route_hacker_root": str(route_hacker_root),
        "v1_scope": {
            "require_exact_failure_reasons": ["no_pre_patch_or_parent_commit"],
            "candidate_count": len(v1_scope_rows),
        },
        "recovery_policy": {
            "requires_nested_pre_and_fix_commit_pair": True,
            "requires_source_ready_verified_fix_parent_match": True,
            "requires_existing_matching_pre_patch_archive": True,
            "requires_every_core_label_snapshot_sha256_match_archive": True,
            "requires_candidate_supplement_reference_consistency": True,
            "rechecks_recorded_identity_exclusion_against_m5_p3_m8": True,
            "rechecks_project_family_exclusion_against_m5_p3_m8": True,
            "unknown_non_anchor_policy": "unknown_not_negative",
        },
        "historical_isolation_inputs": {
            "m5_case_count": len(read_jsonl(paths["m5_proposal"])),
            "p3_case_count": len(read_jsonl(paths["p3_cases"])),
            "m8_case_count": len(read_jsonl(paths["m8_cases"])),
            "recorded_identity_value_count": len(used_identity_values),
            "normalized_project_family_count": len(used_project_families),
        },
        "provenance_recovery": {
            "status_counts": dict(sorted(status_counts.items())),
            "recovered_track_case_counts": dict(sorted(track_counts.items())),
            "failure_reason_counts": dict(sorted(failure_counts.items())),
        },
        "boundary": (
            "source_commit_recovered verifies pre-patch source provenance and "
            "anchor mapping only. It does not create or validate a full-repository "
            "generic candidate pool, frozen code cache, embedding, score, rank, "
            "model fit, or external retrieval result."
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
    write_json(output_dir / "manifest.v2.json", manifest)
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
