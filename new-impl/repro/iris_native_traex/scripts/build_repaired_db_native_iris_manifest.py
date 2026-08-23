#!/usr/bin/env python3
"""Bind one verified Compile Builder DB to a standalone native-IRIS manifest."""
from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError(f"{path}:{line_no} is not a JSON object")
        rows.append(value)
    return rows


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def find_unique(rows: list[dict[str, Any]], case_id: str, description: str) -> dict[str, Any]:
    matches = [row for row in rows if row.get("case_id") == case_id]
    if len(matches) != 1:
        raise ValueError(f"expected exactly one {description} for {case_id}, found {len(matches)}")
    return matches[0]


def required_true(container: dict[str, Any], keys: tuple[str, ...], description: str) -> None:
    missing = [key for key in keys if container.get(key) is not True]
    if missing:
        raise ValueError(f"{description} is missing verified fields: {', '.join(missing)}")


def relation_file_count(database: Path) -> int:
    required = (database / "codeql-database.yml", database / "db-java" / "default")
    missing = [str(path) for path in required if not path.exists()]
    if missing:
        raise ValueError("repaired CodeQL database is incomplete: " + ", ".join(missing))
    count = sum(1 for _ in (database / "db-java" / "default").rglob("*.rel"))
    if count == 0:
        raise ValueError(f"repaired CodeQL database has no Java relation files: {database}")
    return count


def build_manifest_row(
    admission: dict[str, Any],
    source_receipt: dict[str, Any],
    repair_receipt: dict[str, Any],
    repair_ledger: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    official = admission.get("official_iris_admission")
    if not isinstance(official, dict):
        raise ValueError("strict admission row lacks official_iris_admission")
    required_true(
        official,
        (
            "exact_source_receipt",
            "fix_info_present",
            "native_query_supported",
            "package_names_present",
            "project_info_present",
        ),
        "official IRIS admission",
    )
    source_status = source_receipt.get("status")
    if source_status != "source_materialized_exact_archive_snapshot":
        raise ValueError(f"source receipt has unacceptable status: {source_status!r}")
    if source_receipt.get("project_slug") != admission.get("project_slug"):
        raise ValueError("source receipt project_slug does not match strict admission")

    repair_attempt = repair_receipt.get("repair_attempt")
    if repair_receipt.get("status") != "codeql_db_repaired" or not isinstance(repair_attempt, dict):
        raise ValueError("repair receipt is not a successful CodeQL repair")
    if repair_attempt.get("database_valid") is not True:
        raise ValueError("repair receipt does not mark the database valid")
    source_integrity = repair_attempt.get("source_integrity_evidence")
    source_revision = repair_receipt.get("source_revision_evidence")
    if not isinstance(source_integrity, dict) or source_integrity.get("verified") is not True:
        raise ValueError("repair receipt lacks verified source-integrity evidence")
    if not isinstance(source_revision, dict) or source_revision.get("verified") is not True:
        raise ValueError("repair receipt lacks verified exact-source evidence")
    database = Path(str(repair_attempt.get("database_dir") or "")).resolve()
    if not database.is_dir():
        raise ValueError("repair receipt database_dir is missing or not a directory")
    relation_count = relation_file_count(database)

    input_paths = admission.get("input_paths")
    revisions = admission.get("revisions")
    if not isinstance(input_paths, dict) or not isinstance(revisions, dict):
        raise ValueError("strict admission row lacks input_paths or revisions")
    source = Path(str(input_paths.get("source") or "")).resolve()
    package_names = Path(str(input_paths.get("package_names") or "")).resolve()
    if not source.is_dir() or not package_names.is_file():
        raise ValueError("strict admission source or package-name input no longer exists")
    project_slug = str(admission.get("project_slug") or "")
    cve_id = str(admission.get("cve_id") or "")
    iris_query = str(admission.get("iris_query") or "")
    declared_revision = str(revisions.get("declared_buggy_commit") or "")
    if not all((project_slug, cve_id, iris_query, declared_revision)):
        raise ValueError("strict admission row lacks project, CVE, query, or declared revision")

    owner_repository = project_slug.split("_CVE-", 1)[0]
    identity_key = f"{owner_repository}::{cve_id}"
    binding = {
        "repair_case_status": repair_receipt["status"],
        "repair_ledger_path": str(repair_ledger.resolve()),
        "repair_ledger_sha256": sha256_path(repair_ledger),
        "repair_attempt_database_dir": str(database),
        "repair_attempt_database_valid": True,
        "relation_file_count": relation_count,
        "repair_source_integrity_evidence": source_integrity,
        "repair_source_revision_evidence": source_revision,
        "repair_source_receipt_sha256": sha256_path_from_row(source_receipt),
        "repair_validated_decision_sha256": (
            (repair_receipt.get("validated_decision") or {}).get("decision_sha256")
        ),
    }
    row = {
        "schema_version": "iris213_native_iris_repaired_db_manifest.v1",
        "case_id": admission["case_id"],
        "identity_key": identity_key,
        "project_slug": project_slug,
        "cve_id": cve_id,
        "cwe_id": admission.get("cwe_id"),
        "iris_query": iris_query,
        "input_paths": {
            "source": str(source),
            "codeql_db": str(database),
            "package_names": str(package_names),
        },
        "input_status": {
            "preflight_status": "iris213_preflight_ready_repaired_codeql_db",
            "codeql_db_status": "codeql_db_created_by_compile_builder_v2",
            "source_status": source_status,
            "package_names_file_exists": True,
            "blockers": [],
        },
        "revisions": {
            "v2_checkout_revision": declared_revision,
            "official_buggy_commit_id": revisions.get("official_buggy_commit_id"),
            "clean_iris_commit": revisions.get("clean_iris_commit"),
            "clean_iris_tree": revisions.get("clean_iris_tree"),
        },
        "selection_evidence": {
            "official_iris_admission": official,
            "rule": "strict iris213 admission plus a verified archive-isolated Compile Builder v2 database",
        },
        "source_provenance": [admission.get("source_provenance"), source_receipt],
        "derived_db_binding": binding,
    }
    return row, binding


def sha256_path_from_row(row: dict[str, Any]) -> str:
    encoded = json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--strict-admission", type=Path, required=True)
    parser.add_argument("--source-receipts", type=Path, required=True)
    parser.add_argument("--repair-ledger", type=Path, required=True)
    parser.add_argument("--case-id", required=True)
    parser.add_argument("--output-manifest", type=Path, required=True)
    parser.add_argument("--binding-receipt", type=Path, required=True)
    args = parser.parse_args()

    admission = find_unique(read_jsonl(args.strict_admission), args.case_id, "strict admission row")
    source_receipt = find_unique(read_jsonl(args.source_receipts), args.case_id, "source receipt")
    repair_receipt = find_unique(read_jsonl(args.repair_ledger), args.case_id, "repair receipt")
    row, binding = build_manifest_row(
        admission,
        source_receipt,
        repair_receipt,
        args.repair_ledger,
    )

    args.output_manifest.parent.mkdir(parents=True, exist_ok=True)
    args.output_manifest.write_text(
        json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    receipt = {
        "schema_version": "iris213_native_iris_repaired_db_binding.v1",
        "created_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "strict_admission": {
            "path": str(args.strict_admission.resolve()),
            "sha256": sha256_path(args.strict_admission),
        },
        "source_receipts": {
            "path": str(args.source_receipts.resolve()),
            "sha256": sha256_path(args.source_receipts),
        },
        "derived_manifest": {
            "path": str(args.output_manifest.resolve()),
            "sha256": sha256_path(args.output_manifest),
        },
        "binding": binding,
    }
    args.binding_receipt.parent.mkdir(parents=True, exist_ok=True)
    args.binding_receipt.write_text(
        json.dumps(receipt, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(receipt, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
