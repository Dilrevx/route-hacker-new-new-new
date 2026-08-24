#!/usr/bin/env python3
"""Build a current unified-v2 native-IRIS queue from strict admission evidence."""
from __future__ import annotations

import argparse
import csv
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


VULN_RE = re.compile(r"(CVE-\d{4}-\d+|GHSA-[A-Z0-9-]+)", re.IGNORECASE)


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError(f"non-object JSONL row at {path}:{line_no}")
        rows.append(value)
    return rows


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def norm_vuln(value: Any) -> str:
    return str(value or "").strip().upper()


def vuln_ids_from_values(*values: Any) -> set[str]:
    out: set[str] = set()
    for value in values:
        if isinstance(value, list):
            out.update(vuln_ids_from_values(*value))
            continue
        text = str(value or "")
        out.update(match.group(1).upper() for match in VULN_RE.finditer(text))
    return out


def row_vuln_ids(row: dict[str, Any]) -> set[str]:
    return vuln_ids_from_values(
        row.get("vulnerability_id"),
        row.get("vuln_ids_for_lookup"),
        row.get("cve_id"),
        row.get("identity_key"),
        row.get("case_id"),
        row.get("project_slug"),
    )


def checkout_revision(row: dict[str, Any]) -> str:
    revisions = row.get("revisions") if isinstance(row.get("revisions"), dict) else {}
    return str(
        row.get("checkout_revision")
        or revisions.get("declared_buggy_commit")
        or revisions.get("official_buggy_commit_id")
        or ""
    ).strip().lower()


def iris_status_vuln_ids(row: dict[str, str]) -> set[str]:
    return vuln_ids_from_values(row.get("project_slug"), row.get("case_id"))


def strict_admission_ready(row: dict[str, Any]) -> bool:
    admission = row.get("official_iris_admission") or {}
    required = (
        "exact_source_receipt",
        "fix_info_present",
        "native_query_supported",
        "package_names_present",
        "project_info_present",
    )
    return all(admission.get(key) is True for key in required)


def bool_text(value: Any) -> bool:
    return str(value).strip().lower() == "true"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--current-review", type=Path, required=True)
    parser.add_argument("--codeql-manifest", type=Path, required=True)
    parser.add_argument("--strict-admission", type=Path, required=True)
    parser.add_argument("--iris213-case-status", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()

    args.out_dir.mkdir(parents=True, exist_ok=True)
    current_rows = read_jsonl(args.current_review)
    manifest_rows = read_jsonl(args.codeql_manifest)
    strict_rows = [row for row in read_jsonl(args.strict_admission) if strict_admission_ready(row)]
    iris_status_rows = read_csv(args.iris213_case_status)

    current_keys = {row["identity_key"] for row in current_rows}
    strict_by_vuln_rev: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for row in strict_rows:
        revision = checkout_revision(row)
        for vuln_id in row_vuln_ids(row):
            strict_by_vuln_rev.setdefault((vuln_id, revision), []).append(row)

    status_by_project_slug = {row["project_slug"]: row for row in iris_status_rows}
    iris213_vulns: set[str] = set()
    for row in iris_status_rows:
        iris213_vulns.update(iris_status_vuln_ids(row))
    ready_rows: list[dict[str, Any]] = []
    case_rows: list[dict[str, Any]] = []
    categories: Counter[str] = Counter()
    matched_strict_project_slugs: set[str] = set()

    for manifest in manifest_rows:
        revision = checkout_revision(manifest)
        matches: list[dict[str, Any]] = []
        for vuln_id in row_vuln_ids(manifest):
            matches.extend(strict_by_vuln_rev.get((vuln_id, revision), []))
        unique_matches = {row["project_slug"]: row for row in matches}
        status = "not_in_iris213_native_scope"
        strict_row: dict[str, Any] | None = None
        iris_status: dict[str, str] | None = None
        manifest_vuln_ids = row_vuln_ids(manifest)
        if len(unique_matches) == 1:
            strict_row = next(iter(unique_matches.values()))
            matched_strict_project_slugs.add(str(strict_row["project_slug"]))
            iris_status = status_by_project_slug.get(str(strict_row["project_slug"]))
            native_status = (iris_status or {}).get("native_status", "")
            if native_status == "completed_verified":
                status = "native_iris_completed_reusable"
            else:
                status = "native_iris_admitted_needs_run"
        elif len(unique_matches) > 1:
            status = "strict_admission_ambiguous"
        elif manifest_vuln_ids & iris213_vulns:
            status = "iris213_same_vuln_not_strict_admitted"

        categories[status] += 1
        base = {
            "identity_key": manifest.get("identity_key"),
            "new_unified_case_id": manifest.get("new_unified_case_id"),
            "repo_key": manifest.get("repo_key"),
            "vulnerability_id": manifest.get("vulnerability_id"),
            "vuln_ids_for_lookup": ";".join(sorted(row_vuln_ids(manifest))),
            "checkout_revision": manifest.get("checkout_revision"),
            "fix_revision": manifest.get("fix_revision"),
            "codeql_language": manifest.get("codeql_language"),
            "db_dir": manifest.get("db_dir"),
            "source_root": manifest.get("source_root"),
            "iris_current_status": status,
            "iris_project_slug": (strict_row or {}).get("project_slug"),
            "iris_case_id": (strict_row or {}).get("case_id"),
            "iris_query": (strict_row or {}).get("iris_query"),
            "iris_native_status": (iris_status or {}).get("native_status"),
            "iris_vanilla_hit": bool_text((iris_status or {}).get("vanilla_recall_method")),
            "iris_posthoc_hit": bool_text((iris_status or {}).get("posthoc_recall_method")),
            "iris_official_codeql_hit": bool_text((iris_status or {}).get("official_codeql_recall_method")),
        }
        case_rows.append(base)

        if status == "native_iris_admitted_needs_run" and strict_row is not None:
            queued = dict(strict_row)
            queued["status"] = "current_v2_native_iris_ready"
            queued["schema_version"] = "current_unified_v2_native_iris_queue.v1"
            queued["current_unified_v2"] = {
                "identity_key": manifest.get("identity_key"),
                "new_unified_case_id": manifest.get("new_unified_case_id"),
                "checkout_revision": manifest.get("checkout_revision"),
                "fix_revision": manifest.get("fix_revision"),
                "codeql_language": manifest.get("codeql_language"),
                "source_manifest_path": str(args.codeql_manifest),
            }
            inputs = dict(queued.get("input_paths") or {})
            if manifest.get("db_dir"):
                inputs["codeql_db"] = manifest.get("db_dir")
            if manifest.get("source_root"):
                inputs.setdefault("source", manifest.get("source_root"))
            queued["input_paths"] = inputs
            ready_rows.append(queued)

    matched_completed = [row for row in case_rows if row["iris_current_status"] == "native_iris_completed_reusable"]
    summary = {
        "schema_version": "current_unified_v2_native_iris_queue_summary.v1",
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "inputs": {
            "current_review": str(args.current_review),
            "codeql_manifest": str(args.codeql_manifest),
            "strict_admission": str(args.strict_admission),
            "iris213_case_status": str(args.iris213_case_status),
        },
        "counts": {
            "current_unified_v2_selected_cases": len(current_keys),
            "codeql_denominator_cases": len(manifest_rows),
            "strict_admitted_rows": len(strict_rows),
            "matched_strict_project_slugs": len(matched_strict_project_slugs),
            "queue_ready_cases": len(ready_rows),
            "category_counts": dict(sorted(categories.items())),
        },
        "reusable_completed": {
            "case_count": len(matched_completed),
            "vanilla_hits": sum(row["iris_vanilla_hit"] for row in matched_completed),
            "posthoc_hits": sum(row["iris_posthoc_hit"] for row in matched_completed),
            "lower_bound_vanilla_recall_on_codeql_denominator": (
                sum(row["iris_vanilla_hit"] for row in matched_completed) / len(manifest_rows)
                if manifest_rows else 0.0
            ),
            "lower_bound_posthoc_recall_on_codeql_denominator": (
                sum(row["iris_posthoc_hit"] for row in matched_completed) / len(manifest_rows)
                if manifest_rows else 0.0
            ),
            "precision_boundary": "Native IRIS fix-method labels are positive-only in the reused 213 snapshot, so false-positive-complete precision is not available from this artifact.",
        },
    }

    write_jsonl(args.out_dir / "current_v2_native_iris_ready_queue.jsonl", ready_rows)
    write_jsonl(args.out_dir / "current_v2_native_iris_case_status.jsonl", case_rows)
    with (args.out_dir / "current_v2_native_iris_case_status.csv").open("w", encoding="utf-8", newline="") as handle:
        fieldnames = [
            "identity_key",
            "new_unified_case_id",
            "repo_key",
            "vulnerability_id",
            "vuln_ids_for_lookup",
            "checkout_revision",
            "fix_revision",
            "codeql_language",
            "db_dir",
            "source_root",
            "iris_current_status",
            "iris_project_slug",
            "iris_case_id",
            "iris_query",
            "iris_native_status",
            "iris_vanilla_hit",
            "iris_posthoc_hit",
            "iris_official_codeql_hit",
        ]
        writer = csv.DictWriter(handle, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        writer.writerows(case_rows)
    (args.out_dir / "current_v2_native_iris_queue_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
