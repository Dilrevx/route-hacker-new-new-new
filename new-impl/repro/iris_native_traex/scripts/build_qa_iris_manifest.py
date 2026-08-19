#!/usr/bin/env python3
"""Freeze the v2 paper-eval IRIS-derived cohort from audited source tables."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows = []
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError(f"{path}:{line_no} is not an object")
        rows.append(value)
    return rows


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def identity_parts(identity_key: str) -> tuple[str, str, str]:
    repo, vulnerability_id = identity_key.split("::", 1)
    owner, repository = repo.split("__", 1)
    return owner.casefold(), repository.casefold(), vulnerability_id.casefold()


def csv_key(row: dict[str, str]) -> tuple[str, str, str]:
    return (
        row["github_username"].casefold(),
        row["github_repository_name"].casefold(),
        row["cve_id"].casefold(),
    )


def source_provenance(case: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        value
        for value in case.get("source_provenance", [])
        if isinstance(value, dict)
    ]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cases", type=Path, required=True)
    parser.add_argument("--allowlist", type=Path, required=True)
    parser.add_argument("--project-info", type=Path, required=True)
    parser.add_argument("--fix-info", type=Path, required=True)
    parser.add_argument("--source-sink", type=Path, required=True)
    parser.add_argument("--preflight", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--summary-output", type=Path, required=True)
    args = parser.parse_args()

    cases = {
        row["identity_key"]: row
        for row in read_jsonl(args.cases)
        if row.get("identity_key")
    }
    allowlist = read_jsonl(args.allowlist)
    allowlist_by_identity = {
        row["identity_key"]: row
        for row in allowlist
        if row.get("identity_key")
    }
    project_rows = list(csv.DictReader(args.project_info.open(newline="", encoding="utf-8")))
    fix_rows = list(csv.DictReader(args.fix_info.open(newline="", encoding="utf-8")))
    source_sink_rows = list(csv.DictReader(args.source_sink.open(newline="", encoding="utf-8")))
    preflight_rows = read_jsonl(args.preflight)
    project_by_key = {csv_key(row): row for row in project_rows}
    fix_keys = {csv_key(row) for row in fix_rows}
    source_sink_keys = {csv_key(row) for row in source_sink_rows}
    preflight_by_slug = {
        row["project_slug"]: row
        for row in preflight_rows
        if row.get("project_slug")
    }

    selected = []
    tag_only = []
    for identity_key, allow_row in allowlist_by_identity.items():
        case = cases.get(identity_key)
        if not case:
            continue
        types = (case.get("classification") or {}).get("hcvr_types", [])
        if "iris" not in types:
            continue
        project = project_by_key.get(identity_parts(identity_key))
        if not project:
            raise ValueError(f"IRIS-tagged allowlist case lacks project_info row: {identity_key}")
        key = identity_parts(identity_key)
        hit_fix = key in fix_keys
        hit_source_sink = key in source_sink_keys
        if not (hit_fix or hit_source_sink):
            tag_only.append(identity_key)
            continue
        preflight = preflight_by_slug.get(project["project_slug"])
        if not preflight:
            raise ValueError(f"IRIS case lacks preflight row: {identity_key}")
        revisions = case.get("revisions") or {}
        provenance = source_provenance(case)
        selected.append(
            {
                "schema_version": "hcvr_v2_qa_iris_manifest.v1",
                "case_id": case.get("new_unified_case_id") or identity_key,
                "identity_key": identity_key,
                "project_slug": project["project_slug"],
                "cve_id": project["cve_id"],
                "cwe_id": preflight.get("cwe_id_normalized"),
                "iris_query": preflight.get("iris_query"),
                "input_paths": {
                    "source": preflight.get("source_dir"),
                    "codeql_db": preflight.get("codeql_db_dir"),
                    "package_names": preflight.get("package_names_file"),
                },
                "input_status": {
                    "preflight_status": preflight.get("status"),
                    "codeql_db_status": preflight.get("codeql_db_status"),
                    "source_status": preflight.get("source_status"),
                    "package_names_file_exists": preflight.get("package_names_file_exists"),
                    "blockers": preflight.get("blockers") or [],
                },
                "revisions": {
                    "v2_checkout_revision": revisions.get("checkout_revision"),
                    "official_buggy_commit_id": project.get("buggy_commit_id"),
                    "clean_iris_commit": preflight.get("clean_iris_commit"),
                    "clean_iris_tree": preflight.get("clean_iris_tree"),
                },
                "selection_evidence": {
                    "project_info": True,
                    "fix_info": hit_fix,
                    "fix_info_source_sink": hit_source_sink,
                    "rule": "v2 allowlist identity joined to official IRIS project_info and at least one official fix table",
                },
                "source_provenance": provenance,
                "allowlist_review": {
                    "paper_eval_decision": allow_row.get("paper_eval_decision"),
                    "allowlist_identity_key": allow_row.get("identity_key"),
                },
            }
        )

    selected.sort(key=lambda row: row["identity_key"])
    if len(selected) != 45:
        raise ValueError(f"expected 45 hard-joined IRIS cases, found {len(selected)}")
    if len(tag_only) != 4:
        raise ValueError(f"expected 4 tag-only IRIS cases, found {len(tag_only)}")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as handle:
        for row in selected:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")

    summary = {
        "schema_version": "hcvr_v2_qa_iris_manifest_summary.v1",
        "created_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "case_count": len(selected),
        "selection_rule": "v2 allowlist ∩ official project_info ∩ (official fix_info ∪ official fix_info_source_sink)",
        "official_table_counts": {
            "project_info": len(project_rows),
            "fix_info": len(fix_rows),
            "fix_info_source_sink": len(source_sink_rows),
        },
        "selection_source_counts": {
            "fix_info": sum(row["selection_evidence"]["fix_info"] for row in selected),
            "fix_info_source_sink": sum(
                row["selection_evidence"]["fix_info_source_sink"] for row in selected
            ),
            "union": len(selected),
        },
        "tag_only_excluded": sorted(tag_only),
        "preflight_status_counts": {},
        "codeql_db_status_counts": {},
        "inputs": {
            name: {"path": str(path.resolve()), "sha256": sha256_path(path)}
            for name, path in {
                "cases": args.cases,
                "allowlist": args.allowlist,
                "project_info": args.project_info,
                "fix_info": args.fix_info,
                "fix_info_source_sink": args.source_sink,
                "preflight": args.preflight,
            }.items()
        },
        "manifest": {
            "path": str(args.output.resolve()),
            "sha256": sha256_path(args.output),
        },
    }
    for row in selected:
        status = row["input_status"]["preflight_status"] or "missing"
        db_status = row["input_status"]["codeql_db_status"] or "missing"
        summary["preflight_status_counts"][status] = (
            summary["preflight_status_counts"].get(status, 0) + 1
        )
        summary["codeql_db_status_counts"][db_status] = (
            summary["codeql_db_status_counts"].get(db_status, 0) + 1
        )
    args.summary_output.parent.mkdir(parents=True, exist_ok=True)
    args.summary_output.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
