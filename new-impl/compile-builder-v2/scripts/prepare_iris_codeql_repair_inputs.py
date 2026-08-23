#!/usr/bin/env python3
"""Prepare auditable Compile Builder v2 inputs from an IRIS case manifest.

The historical CodeQL build receipts use ``v8:<project_slug>`` identifiers,
while the current IRIS manifest uses stable ``case::`` identifiers.  This
tool performs that identity binding without modifying the original receipts:
it emits a selected receipt copy with the IRIS case ID and records the
upstream receipt path, identifier, and SHA-256 on every generated row.

Only cases with an exact source snapshot, a failed CodeQL receipt, and no
native-IRIS blocker other than a missing CodeQL database are admitted.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any, Iterable


SCHEMA_VERSION = "route_hacker_iris_codeql_repair_input.v1"
DETERMINISTIC_SCHEMA = "route_hacker_codeql_repair_dispatch.v1:case_completion"
SOURCE_SUCCESS_STATUSES = frozenset(
    {
        "source_materialized_exact_archive_snapshot",
        "source_materialized_exact_clean_snapshot",
        "source_reused_exact_clean_snapshot",
    }
)
NON_CODEQL_BLOCKER_PREFIXES = (
    "iris_query_name_not_found",
    "project_slug_missing",
    "package_names_file_missing",
)


def stable_json_sha256(value: Any) -> str:
    payload = json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def read_jsonl(paths: Iterable[Path]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in paths:
        with path.open(encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                value = json.loads(line)
                if not isinstance(value, dict):
                    raise ValueError(f"non-object row at {path}:{line_number}")
                rows.append(value)
    return rows


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True))
            handle.write("\n")


def index_unique_by_slug(rows: Iterable[dict[str, Any]], label: str) -> dict[str, dict[str, Any]]:
    indexed: dict[str, dict[str, Any]] = {}
    for row in rows:
        slug = row.get("project_slug")
        if not isinstance(slug, str) or not slug:
            continue
        previous = indexed.get(slug)
        if previous is None:
            indexed[slug] = row
        elif stable_json_sha256(previous) != stable_json_sha256(row):
            raise ValueError(f"conflicting {label} rows for project slug {slug}")
    return indexed


def is_native_iris_repair_candidate(row: dict[str, Any]) -> bool:
    inputs = row.get("input_status")
    if not isinstance(inputs, dict):
        return False
    if inputs.get("codeql_db_status") != "codeql_db_failed":
        return False
    blockers = inputs.get("blockers")
    if not isinstance(blockers, list) or not all(isinstance(item, str) for item in blockers):
        return False
    return not any(
        blocker.startswith(prefix)
        for blocker in blockers
        for prefix in NON_CODEQL_BLOCKER_PREFIXES
    )


def bound_receipt(
    upstream: dict[str, Any],
    *,
    iris_case: dict[str, Any],
    upstream_path: Path,
    kind: str,
) -> dict[str, Any]:
    case_id = iris_case["case_id"]
    if not isinstance(case_id, str) or not case_id:
        raise ValueError("IRIS manifest row lacks case_id")
    result = dict(upstream)
    result["case_id"] = case_id
    result["project_slug"] = iris_case["project_slug"]
    result["iris_manifest_identity"] = {
        "case_id": case_id,
        "identity_key": iris_case.get("identity_key"),
        "project_slug": iris_case["project_slug"],
        "cve_id": iris_case.get("cve_id"),
        "cwe_id": iris_case.get("cwe_id"),
        "iris_query": iris_case.get("iris_query"),
    }
    result["upstream_receipt_binding"] = {
        "kind": kind,
        "upstream_case_id": upstream.get("case_id"),
        "upstream_receipt_path": str(upstream_path.resolve()),
        "upstream_receipt_sha256": stable_json_sha256(upstream),
        "identity_binding": "project_slug_exact_match",
    }
    return result


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iris-manifest", type=Path, required=True)
    parser.add_argument("--failed-receipts", type=Path, action="append", required=True)
    parser.add_argument("--source-receipts", type=Path, action="append", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--expected-candidate-count", type=int)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    all_paths = [args.iris_manifest, *args.failed_receipts, *args.source_receipts]
    for path in all_paths:
        if not path.is_file():
            raise SystemExit(f"missing input: {path}")

    manifest_rows = read_jsonl([args.iris_manifest])
    failed_rows = read_jsonl(args.failed_receipts)
    source_rows = read_jsonl(args.source_receipts)
    failed_by_slug = index_unique_by_slug(failed_rows, "failed receipt")
    source_by_slug = index_unique_by_slug(source_rows, "source receipt")
    candidates = [row for row in manifest_rows if is_native_iris_repair_candidate(row)]
    if args.expected_candidate_count is not None and len(candidates) != args.expected_candidate_count:
        raise SystemExit(
            f"expected {args.expected_candidate_count} eligible candidates, found {len(candidates)}"
        )

    generated_failed: list[dict[str, Any]] = []
    generated_source: list[dict[str, Any]] = []
    generated_ledger: list[dict[str, Any]] = []
    dispositions: list[dict[str, Any]] = []
    for case in candidates:
        slug = case["project_slug"]
        failed = failed_by_slug.get(slug)
        source = source_by_slug.get(slug)
        disposition: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "case_id": case["case_id"],
            "project_slug": slug,
            "manifest_row_sha256": stable_json_sha256(case),
            "status": None,
        }
        if failed is None:
            disposition["status"] = "failed_receipt_missing"
        elif source is None:
            disposition["status"] = "source_receipt_missing"
        elif source.get("status") not in SOURCE_SUCCESS_STATUSES:
            disposition["status"] = "source_receipt_not_exact"
            disposition["source_status"] = source.get("status")
        elif failed.get("status") != "codeql_db_failed":
            disposition["status"] = "failed_receipt_not_codeql_failure"
            disposition["failed_status"] = failed.get("status")
        elif failed.get("resolved_buggy_commit") != source.get("resolved_buggy_commit"):
            disposition["status"] = "source_revision_mismatch"
        else:
            bound_failed = bound_receipt(
                failed,
                iris_case=case,
                upstream_path=next(
                    path
                    for path in args.failed_receipts
                    if any(
                        value.get("project_slug") == slug
                        for value in read_jsonl([path])
                    )
                ),
                kind="failed_codeql_receipt",
            )
            bound_source = bound_receipt(
                source,
                iris_case=case,
                upstream_path=next(
                    path
                    for path in args.source_receipts
                    if any(
                        value.get("project_slug") == slug
                        for value in read_jsonl([path])
                    )
                ),
                kind="exact_source_receipt",
            )
            generated_failed.append(bound_failed)
            generated_source.append(bound_source)
            generated_ledger.append(
                {
                    "schema_version": DETERMINISTIC_SCHEMA,
                    "case_id": case["case_id"],
                    "status": "no_safe_deterministic_repair",
                    "failed_receipt_sha256": stable_json_sha256(bound_failed),
                    "source_receipt_sha256": stable_json_sha256(bound_source),
                    "input_binding": {
                        "schema_version": SCHEMA_VERSION,
                        "manifest_row_sha256": stable_json_sha256(case),
                        "upstream_failed_receipt_sha256": stable_json_sha256(failed),
                        "upstream_source_receipt_sha256": stable_json_sha256(source),
                    },
                }
            )
            disposition["status"] = "eligible_for_compile_builder_v2"
            disposition["failed_receipt_sha256"] = stable_json_sha256(bound_failed)
            disposition["source_receipt_sha256"] = stable_json_sha256(bound_source)
        dispositions.append(disposition)

    args.output_dir.mkdir(parents=True, exist_ok=True)
    write_jsonl(args.output_dir / "failed_receipts.jsonl", generated_failed)
    write_jsonl(args.output_dir / "source_receipts.jsonl", generated_source)
    write_jsonl(args.output_dir / "prior_ledger.jsonl", generated_ledger)
    write_jsonl(args.output_dir / "dispositions.jsonl", dispositions)
    summary = {
        "schema_version": SCHEMA_VERSION,
        "iris_manifest": {
            "path": str(args.iris_manifest.resolve()),
            "sha256": sha256_file(args.iris_manifest),
        },
        "candidate_count": len(candidates),
        "eligible_count": len(generated_ledger),
        "disposition_counts": dict(Counter(row["status"] for row in dispositions)),
        "input_receipt_files": {
            "failed": [str(path.resolve()) for path in args.failed_receipts],
            "source": [str(path.resolve()) for path in args.source_receipts],
        },
        "outputs": {
            name: {
                "path": str((args.output_dir / name).resolve()),
                "sha256": sha256_file(args.output_dir / name),
            }
            for name in (
                "failed_receipts.jsonl",
                "source_receipts.jsonl",
                "prior_ledger.jsonl",
                "dispositions.jsonl",
            )
        },
    }
    (args.output_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
