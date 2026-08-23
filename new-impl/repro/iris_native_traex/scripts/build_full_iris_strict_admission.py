#!/usr/bin/env python3
"""Build strict native-IRIS admission rows from frozen public IRIS inputs."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import subprocess
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError(f"{path}:{line_number} is not an object")
        rows.append(value)
    return rows


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def supported_queries(path: Path) -> set[str]:
    return set(
        re.findall(
            r'^\s*["\'](cwe-\d+wLLM)["\']\s*:',
            path.read_text(encoding="utf-8"),
            flags=re.MULTILINE,
        )
    )


def clean_iris_commit(clean_iris_root: Path) -> str:
    completed = subprocess.run(
        ["git", "-C", str(clean_iris_root), "rev-parse", "HEAD"],
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"cannot resolve pinned clean IRIS revision: {completed.stderr.strip()[-500:]}"
        )
    return completed.stdout.strip()


def matching_rows(
    rows: list[dict[str, str]], project_slug: str, cve_id: str
) -> list[dict[str, str]]:
    return [
        row
        for row in rows
        if row.get("project_slug") == project_slug and row.get("cve_id") == cve_id
    ]


def source_evidence(source: dict[str, Any], project_slug: str, revision: str) -> bool:
    return (
        source.get("project_slug") == project_slug
        and source.get("status") == "source_materialized_exact_archive_snapshot"
        and source.get("declared_buggy_commit") == revision
        and source.get("resolved_buggy_commit") == revision
        and Path(str(source.get("source_dir") or "")).is_dir()
    )


def build_rows(
    *,
    frozen_cases: list[dict[str, Any]],
    source_receipts: list[dict[str, Any]],
    project_rows: list[dict[str, str]],
    fix_rows: list[dict[str, str]],
    source_sink_rows: list[dict[str, str]],
    package_names_dir: Path,
    supported_query_names: set[str],
    clean_commit: str,
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    source_by_case = {str(row.get("case_id")): row for row in source_receipts}
    admissions: list[dict[str, Any]] = []
    reasons: Counter[str] = Counter()

    for frozen in frozen_cases:
        case_id = str(frozen.get("case_id") or "")
        project_slug = str(frozen.get("project_slug") or "")
        query = str(frozen.get("iris_query") or "")
        project_matches = [row for row in project_rows if row.get("project_slug") == project_slug]
        if len(project_matches) != 1:
            reasons["project_info_missing_or_ambiguous"] += 1
            continue
        project = project_matches[0]
        cve_id = str(project.get("cve_id") or "")
        revision = str(project.get("buggy_commit_id") or "")
        source = source_by_case.get(case_id)
        package_names = package_names_dir / f"{project_slug}.txt"
        fixes = matching_rows(fix_rows, project_slug, cve_id)
        source_sink_fixes = matching_rows(source_sink_rows, project_slug, cve_id)
        official = {
            "exact_source_receipt": isinstance(source, dict)
            and source_evidence(source, project_slug, revision),
            "fix_info_present": bool(fixes or source_sink_fixes),
            "native_query_supported": query in supported_query_names,
            "package_names_present": package_names.is_file(),
            "project_info_present": True,
        }
        missing = [key for key, value in official.items() if value is not True]
        if missing:
            reasons[";".join(sorted(missing))] += 1
            continue
        if not isinstance(source, dict):
            raise AssertionError("verified source evidence must have a source receipt")
        case_index = (frozen.get("full213_matrix_evidence") or {}).get("case_index")
        admissions.append(
            {
                "schema_version": "iris213_full_strict_native_admission.v1",
                "case_id": case_id,
                "identity_key": frozen.get("identity_key") or project_slug,
                "project_slug": project_slug,
                "cve_id": cve_id,
                "cwe_id": project.get("cwe_id"),
                "iris_query": query,
                "input_paths": {
                    "source": str(Path(str(source["source_dir"])).resolve()),
                    "package_names": str(package_names.resolve()),
                },
                "revisions": {
                    "declared_buggy_commit": revision,
                    "official_buggy_commit_id": revision,
                    "clean_iris_commit": clean_commit,
                },
                "official_iris_admission": official,
                "official_table_evidence": {
                    "project_info_row_count": 1,
                    "fix_info_row_count": len(fixes),
                    "fix_info_source_sink_row_count": len(source_sink_fixes),
                    "frozen_full213_case_index": case_index,
                },
                "source_provenance": {
                    "source_receipt_case_id": source["case_id"],
                    "source_receipt_status": source["status"],
                    "source_receipt_sha256": hashlib.sha256(
                        json.dumps(source, sort_keys=True, separators=(",", ":")).encode()
                    ).hexdigest(),
                    "source_archive_result": source.get("archive_result"),
                },
            }
        )
    admissions.sort(key=lambda row: str(row["case_id"]))
    return admissions, dict(sorted(reasons.items()))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--frozen-cases", type=Path, required=True)
    parser.add_argument("--source-receipts", type=Path, required=True)
    parser.add_argument("--project-info", type=Path, required=True)
    parser.add_argument("--fix-info", type=Path, required=True)
    parser.add_argument("--source-sink", type=Path, required=True)
    parser.add_argument("--package-names-dir", type=Path, required=True)
    parser.add_argument("--queries", type=Path, required=True)
    parser.add_argument("--clean-iris-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--summary-output", type=Path, required=True)
    args = parser.parse_args()

    frozen_cases = read_jsonl(args.frozen_cases)
    sources = read_jsonl(args.source_receipts)
    project_rows = list(csv.DictReader(args.project_info.open(newline="", encoding="utf-8")))
    fix_rows = list(csv.DictReader(args.fix_info.open(newline="", encoding="utf-8")))
    source_sink_rows = list(csv.DictReader(args.source_sink.open(newline="", encoding="utf-8")))
    rows, rejections = build_rows(
        frozen_cases=frozen_cases,
        source_receipts=sources,
        project_rows=project_rows,
        fix_rows=fix_rows,
        source_sink_rows=source_sink_rows,
        package_names_dir=args.package_names_dir,
        supported_query_names=supported_queries(args.queries),
        clean_commit=clean_iris_commit(args.clean_iris_root),
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )
    summary = {
        "schema_version": "iris213_full_strict_native_admission_summary.v1",
        "created_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "frozen_case_count": len(frozen_cases),
        "strict_admitted_count": len(rows),
        "rejection_counts": rejections,
        "rule": (
            "frozen 213-case queue joined to official project_info and "
            "(fix_info or fix_info_source_sink), a supported native IRIS query, "
            "an exact archive-source receipt, and an official package-name file"
        ),
        "inputs": {
            name: {"path": str(path.resolve()), "sha256": sha256_path(path)}
            for name, path in {
                "frozen_cases": args.frozen_cases,
                "source_receipts": args.source_receipts,
                "project_info": args.project_info,
                "fix_info": args.fix_info,
                "source_sink": args.source_sink,
                "queries": args.queries,
            }.items()
        },
        "package_names_dir": str(args.package_names_dir.resolve()),
        "clean_iris_root": str(args.clean_iris_root.resolve()),
        "clean_iris_commit": clean_iris_commit(args.clean_iris_root),
        "output": {"path": str(args.output.resolve()), "sha256": sha256_path(args.output)},
    }
    args.summary_output.parent.mkdir(parents=True, exist_ok=True)
    args.summary_output.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
