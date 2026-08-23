#!/usr/bin/env python3
"""Build a current per-case IRIS coverage ledger from canonical artifacts.

The older coverage matrix mixed queue identifiers and historical locations. This
tool instead starts from the strict Compile Builder v2 eligibility manifest and
derives every status from the most recent dispatcher receipt, repaired-DB
manifest, and native IRIS summary available under one artifact root.
"""
from __future__ import annotations

import argparse
import collections
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if line.strip():
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError(f"{path}:{line_number} is not an object")
            rows.append(value)
    return rows


def parse_time(value: Any) -> datetime:
    if not isinstance(value, str):
        return datetime.min.replace(tzinfo=timezone.utc)
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return datetime.min.replace(tzinfo=timezone.utc)


def latest_by_case(records: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    latest: dict[str, dict[str, Any]] = {}
    for record in records:
        case_id = record.get("case_id")
        if not isinstance(case_id, str):
            continue
        if case_id not in latest or parse_time(record.get("recorded_at")) >= parse_time(
            latest[case_id].get("recorded_at")
        ):
            latest[case_id] = record
    return latest


def database_evidence(record: dict[str, Any]) -> dict[str, Any]:
    attempt = record.get("repair_attempt")
    if not isinstance(attempt, dict):
        return {"strict_db_admitted": False, "reason": "no_repair_attempt"}

    database = Path(str(attempt.get("database_dir") or ""))
    source_integrity = attempt.get("source_integrity_evidence")
    source_revision = record.get("source_revision_evidence")
    metadata = database / "codeql-database.yml"
    relation_root = database / "db-java" / "default"
    metadata_text = metadata.read_text(encoding="utf-8") if metadata.is_file() else ""
    relation_count = sum(1 for _ in relation_root.rglob("*.rel")) if relation_root.is_dir() else 0
    return {
        "database_dir": str(database),
        "database_exists": database.is_dir(),
        "database_valid": attempt.get("database_valid") is True,
        "codeql_returncode": (attempt.get("bounded_process") or {}).get("returncode"),
        "source_integrity_verified": isinstance(source_integrity, dict)
        and source_integrity.get("verified") is True,
        "changed_path_count": source_integrity.get("changed_path_count")
        if isinstance(source_integrity, dict)
        else None,
        "source_revision_verified": isinstance(source_revision, dict)
        and source_revision.get("verified") is True,
        "finalised": "finalised: true" in metadata_text,
        "java_relation_file_count": relation_count,
        "strict_db_admitted": (
            record.get("status") == "codeql_db_repaired"
            and attempt.get("database_valid") is True
            and (attempt.get("bounded_process") or {}).get("returncode") == 0
            and isinstance(source_integrity, dict)
            and source_integrity.get("verified") is True
            and source_integrity.get("changed_path_count") == 0
            and isinstance(source_revision, dict)
            and source_revision.get("verified") is True
            and "finalised: true" in metadata_text
            and relation_count > 0
        ),
    }


def native_receipts(roots: list[Path]) -> tuple[dict[str, dict[str, Any]], dict[tuple[str, str], dict[str, Any]]]:
    """Read case-level runner receipts and summaries, never aggregate batch summaries."""
    latest_by_case_id: dict[str, tuple[datetime, dict[str, Any]]] = {}
    latest_by_project_revision: dict[tuple[str, str], tuple[datetime, dict[str, Any]]] = {}
    for root in roots:
        for path in root.glob("**/summary.json"):
            try:
                summary = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if not isinstance(summary, dict) or summary.get("status") != "completed_verified":
                continue
            if summary.get("verified_completion") is not True:
                continue
            artifact_gate = summary.get("artifact_gate")
            label_audit = summary.get("label_response_audit")
            case = summary.get("case")
            if (
                not isinstance(case, dict)
                or not isinstance(case.get("case_id"), str)
                or not isinstance(artifact_gate, dict)
                or artifact_gate.get("all_required_artifacts_present") is not True
                or not isinstance(label_audit, dict)
                or label_audit.get("all_valid") is not True
                or summary.get("returncode") != 0
                or summary.get("timed_out") is not False
            ):
                continue
            case_id = case["case_id"]
            result = {
                "receipt_path": None,
                "summary_path": str(path),
                "receipt": {
                    "case_id": case_id,
                    "project_slug": case.get("project_slug"),
                    "status": "completed_verified",
                    "verified_completion": True,
                    "summary_path": str(path),
                    "artifact_gate": artifact_gate,
                    "label_response_audit": label_audit,
                    "recorded_at": summary.get("created_at"),
                },
            }
            recorded_at = parse_time(summary.get("created_at"))
            if case_id not in latest_by_case_id or recorded_at >= latest_by_case_id[case_id][0]:
                latest_by_case_id[case_id] = (recorded_at, result)
        for path in root.glob("**/receipts.jsonl"):
            for receipt in read_jsonl(path):
                if receipt.get("status") != "completed_verified":
                    continue
                if receipt.get("verified_completion") is not True:
                    continue
                artifact_gate = receipt.get("artifact_gate")
                label_audit = receipt.get("label_response_audit")
                if not isinstance(artifact_gate, dict) or artifact_gate.get(
                    "all_required_artifacts_present"
                ) is not True:
                    continue
                if not isinstance(label_audit, dict) or label_audit.get("all_valid") is not True:
                    continue
                result = {
                    "receipt_path": str(path),
                    "summary_path": receipt.get("summary_path"),
                    "receipt": receipt,
                }
                recorded_at = parse_time(receipt.get("recorded_at"))
                case_id = receipt.get("case_id")
                if isinstance(case_id, str) and (
                    case_id not in latest_by_case_id
                    or recorded_at >= latest_by_case_id[case_id][0]
                ):
                    latest_by_case_id[case_id] = (recorded_at, result)
                revisions = receipt.get("revisions")
                project_slug = receipt.get("project_slug")
                revision = revisions.get("official_buggy_commit_id") if isinstance(revisions, dict) else None
                if isinstance(project_slug, str) and isinstance(revision, str):
                    key = (project_slug, revision)
                    if key not in latest_by_project_revision or recorded_at >= latest_by_project_revision[key][0]:
                        latest_by_project_revision[key] = (recorded_at, result)
    return (
        {case_id: value for case_id, (_, value) in latest_by_case_id.items()},
        {key: value for key, (_, value) in latest_by_project_revision.items()},
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--strict-admission", type=Path, required=True)
    parser.add_argument("--artifact-root", type=Path, required=True)
    parser.add_argument(
        "--native-root",
        type=Path,
        action="append",
        help="Additional root to scan for native IRIS case summaries. Defaults to artifact root.",
    )
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    admissions = read_jsonl(args.strict_admission)
    eligible = {
        row["case_id"]: row
        for row in admissions
        if row.get("eligible_for_compile_builder_v2") is True and isinstance(row.get("case_id"), str)
    }
    repair_records: list[dict[str, Any]] = []
    for receipt_path in args.artifact_root.glob("compile-repair-run-*/dispatch/w1_llm_repair_receipts.jsonl"):
        for record in read_jsonl(receipt_path):
            record["_receipt_path"] = str(receipt_path)
            repair_records.append(record)
    repairs = latest_by_case(repair_records)
    native_roots = args.native_root or [args.artifact_root]
    native_by_case_id, native_by_project_revision = native_receipts(native_roots)

    ledger: list[dict[str, Any]] = []
    for case_id, admission in sorted(eligible.items()):
        repair = repairs.get(case_id)
        evidence = database_evidence(repair) if repair else {
            "strict_db_admitted": False,
            "reason": "no_dispatcher_receipt",
        }
        revision = (admission.get("revisions") or {}).get("declared_buggy_commit")
        native = native_by_case_id.get(case_id)
        native_match = "case_id" if native else None
        if native is None and isinstance(revision, str):
            native = native_by_project_revision.get((str(admission.get("project_slug")), revision))
            native_match = "project_slug_and_buggy_revision" if native else None
        native_receipt = (native or {}).get("receipt") or {}
        native_status = native_receipt.get("status")
        ledger.append(
            {
                "case_id": case_id,
                "project_slug": admission.get("project_slug"),
                "cve_id": admission.get("cve_id"),
                "cwe_id": admission.get("cwe_id"),
                "iris_query": admission.get("iris_query"),
                "latest_repair": {
                    "receipt_path": repair.get("_receipt_path") if repair else None,
                    "recorded_at": repair.get("recorded_at") if repair else None,
                    "status": repair.get("status") if repair else "not_dispatched",
                },
                "strict_database": evidence,
                "native_iris": {
                    "receipt_path": native.get("receipt_path") if native else None,
                    "summary_path": native.get("summary_path") if native else None,
                    "match_basis": native_match,
                    "status": native_status or "not_completed",
                    "completed_verified": native_status == "completed_verified",
                },
            }
        )

    db_counts = collections.Counter(
        "admitted" if row["strict_database"]["strict_db_admitted"] else row["latest_repair"]["status"]
        for row in ledger
    )
    native_counts = collections.Counter(row["native_iris"]["status"] for row in ledger)
    report = {
        "schema_version": "iris213_current_coverage_ledger.v1",
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "inputs": {
            "strict_admission": str(args.strict_admission.resolve()),
            "artifact_root": str(args.artifact_root.resolve()),
            "native_roots": [str(path.resolve()) for path in native_roots],
        },
        "counts": {
            "strict_eligible_cases": len(ledger),
            "strict_database_statuses": dict(sorted(db_counts.items())),
            "strict_database_admitted": sum(
                row["strict_database"]["strict_db_admitted"] for row in ledger
            ),
            "native_iris_statuses": dict(sorted(native_counts.items())),
            "native_completed_verified": sum(
                row["native_iris"]["completed_verified"] for row in ledger
            ),
        },
    }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "iris213_current_coverage_ledger.jsonl").write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in ledger),
        encoding="utf-8",
    )
    (args.output_dir / "summary.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
