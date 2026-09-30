#!/usr/bin/env python3
"""Audit source-backed canonical cases for a fresh P4 external intake.

This is deliberately an intake audit, not retrieval evaluation.  It reads the
current canonical case/label view and excludes every case/project family
already recorded in M5, P3, or M8.  It emits a reason ledger so the later
release selector cannot silently turn gaps or unknown candidates into data.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


SCHEMA_VERSION = "p4_external_intake_candidate_audit_v1"


def now_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


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
    parser.add_argument("--cases", type=Path, required=True)
    parser.add_argument("--labels", type=Path, required=True)
    parser.add_argument("--m5-proposal", type=Path, required=True)
    parser.add_argument("--p3-cases", type=Path, required=True)
    parser.add_argument("--m8-cases", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    paths = {
        "canonical_cases": args.cases.resolve(),
        "canonical_labels": args.labels.resolve(),
        "m5_proposal": args.m5_proposal.resolve(),
        "p3_cases": args.p3_cases.resolve(),
        "m8_cases": args.m8_cases.resolve(),
    }
    missing = [str(path) for path in paths.values() if not path.is_file()]
    if missing:
        raise FileNotFoundError(f"missing P4 intake input(s): {missing}")
    output_dir = args.output_dir.resolve()
    if output_dir.exists():
        raise FileExistsError(f"refusing to overwrite intake audit: {output_dir}")

    cases = read_jsonl(paths["canonical_cases"])
    labels = read_jsonl(paths["canonical_labels"])
    historical_rows = [
        *read_jsonl(paths["m5_proposal"]),
        *read_jsonl(paths["p3_cases"]),
        *read_jsonl(paths["m8_cases"]),
    ]
    labels_by_case: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
    for label in labels:
        labels_by_case[normalize_text(label.get("case_id"))].append(label)

    used_identity_values = {
        value for row in historical_rows for value in recorded_identities(row)
    }
    used_project_families = {
        normalized_project_family(row.get("repo_key"))
        for row in historical_rows
        if normalized_project_family(row.get("repo_key"))
    }

    ledger: list[dict[str, Any]] = []
    accepted: list[dict[str, Any]] = []
    reason_counts: Counter[str] = Counter()
    eligible_track_counts: Counter[str] = Counter()
    for case in sorted(cases, key=lambda row: normalize_text(row.get("case_id"))):
        case_id = normalize_text(case.get("case_id"))
        case_labels = labels_by_case[case_id]
        core_labels = [
            label
            for label in case_labels
            if label.get("core_metric_eligible") is True
            and normalize_text(label.get("metric_inclusion")) == "core_positive"
            and normalize_text(label.get("candidate_pool_status")) == "covered"
            and bool(label.get("candidate_refs"))
        ]
        source_contract_labels = [
            label
            for label in core_labels
            if label.get("source_contract_valid") is True
            or label.get("strict_source_contract") is True
            or label.get("candidate_closure_verified") is True
        ]
        family = normalized_project_family(case.get("repo_key"))
        direct_matches = sorted(recorded_identities(case) & used_identity_values)
        family_overlap = family in used_project_families if family else False
        source_ready = (
            case.get("source_ready") is True
            or case.get("strict_source_contract") is True
            or normalize_text(case.get("readiness_status"))
            in {"ready_after_phase1_2", "source_ready", "ready"}
        )
        has_pre_patch_identity = bool(
            normalize_text(case.get("pre_patch_commit"))
            or normalize_text(case.get("parent_commit"))
        )
        has_repository_location = bool(
            normalize_text(case.get("repo_key"))
            and (
                normalize_text(case.get("repo_path"))
                or normalize_text(case.get("repo_url"))
                or normalize_text(case.get("repository_url"))
            )
        )
        failures: list[str] = []
        if not core_labels:
            failures.append("no_core_covered_positive_label")
        if not source_contract_labels:
            failures.append("no_source_contract_or_closure_verified_core_label")
        if not source_ready:
            failures.append("case_not_source_ready")
        if not has_pre_patch_identity:
            failures.append("no_pre_patch_or_parent_commit")
        if not has_repository_location:
            failures.append("no_repository_location")
        if direct_matches:
            failures.append("recorded_identity_overlap_with_m5_p3_or_m8")
        if family_overlap:
            failures.append("project_family_overlap_with_m5_p3_or_m8")
        track_id = normalize_text(case.get("track_id"))
        row = {
            "case_id": case.get("case_id"),
            "cve_id": case.get("cve_id"),
            "ghsa_id": case.get("ghsa_id"),
            "repo_key": case.get("repo_key"),
            "project_family": family,
            "project_group": case.get("project_group"),
            "repo_url": case.get("repo_url") or case.get("repository_url"),
            "language": case.get("language"),
            "track_id": case.get("track_id"),
            "source_lane": case.get("source_lane"),
            "readiness_status": case.get("readiness_status"),
            "pre_patch_commit": case.get("pre_patch_commit"),
            "parent_commit": case.get("parent_commit"),
            "case_label_count": len(case_labels),
            "core_covered_label_count": len(core_labels),
            "source_contract_or_closure_verified_core_label_count": len(
                source_contract_labels
            ),
            "source_ready": source_ready,
            "has_pre_patch_identity": has_pre_patch_identity,
            "has_repository_location": has_repository_location,
            "recorded_identity_matches": direct_matches,
            "project_family_overlap": family_overlap,
            "eligible_for_p4_external_intake": not failures,
            "failure_reasons": failures,
            "core_label_ids": [
                label.get("label_id") for label in core_labels if label.get("label_id")
            ],
        }
        ledger.append(row)
        if failures:
            reason_counts.update(failures)
        else:
            accepted.append(row)
            eligible_track_counts[track_id] += 1

    output_dir.mkdir(parents=True, exist_ok=False)
    write_jsonl(output_dir / "candidate_audit_ledger.v1.jsonl", ledger)
    write_jsonl(
        output_dir / "eligible_external_intake_candidates.v1.jsonl",
        sorted(
            accepted,
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
        "historical_isolation_inputs": {
            "m5_case_count": len(read_jsonl(paths["m5_proposal"])),
            "p3_case_count": len(read_jsonl(paths["p3_cases"])),
            "m8_case_count": len(read_jsonl(paths["m8_cases"])),
            "recorded_identity_value_count": len(used_identity_values),
            "normalized_project_family_count": len(used_project_families),
        },
        "candidate_audit": {
            "canonical_case_count": len(cases),
            "canonical_label_count": len(labels),
            "eligible_external_intake_case_count": len(accepted),
            "eligible_track_case_counts": dict(sorted(eligible_track_counts.items())),
            "failure_reason_counts": dict(sorted(reason_counts.items())),
        },
        "eligibility_policy": {
            "requires_core_covered_positive_label": True,
            "requires_source_contract_or_closure_verified_core_label": True,
            "requires_source_ready_case": True,
            "requires_pre_patch_or_parent_commit": True,
            "requires_repository_location": True,
            "excludes_recorded_identity_overlap_with_m5_p3_m8": True,
            "excludes_project_family_overlap_with_m5_p3_m8": True,
            "unknown_non_anchor_policy": "unknown_not_negative",
        },
        "boundary": (
            "This is an eligibility audit only. It creates no candidate pool, "
            "embedding, retrieval score, ranking, model fit, or external claim. "
            "Eligible rows require a separate source/pool/cache readiness gate "
            "before any external release can be frozen."
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
