#!/usr/bin/env python3
"""Build a full-213 best-effort IRIS/CodeQL comparison report.

The 213-case universe stays fixed. Native IRIS and official CodeQL artifacts
are discovered recursively and de-duplicated by project slug, keeping the most
recent verified receipt for each case.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


NATIVE_SCHEMA = "iris_native_traex_run.v1"
CODEQL_SCHEMA = "iris_native_traex_official_codeql_baseline.v1"


def read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError(f"expected JSON object at {path}:{line_number}")
        rows.append(value)
    return rows


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def timestamp(summary: dict[str, Any]) -> str:
    value = summary.get("created_at") or summary.get("generated_at")
    return str(value) if value else ""


def project_slug(summary: dict[str, Any]) -> str | None:
    case = summary.get("case")
    if isinstance(case, dict) and isinstance(case.get("project_slug"), str):
        return case["project_slug"]
    return None


def verified(summary: dict[str, Any]) -> bool:
    return summary.get("status") == "completed_verified" and summary.get("verified_completion") is True


def discover_latest_summaries(
    roots: list[Path],
    *,
    schema: str,
    universe_slugs: set[str],
) -> dict[str, tuple[Path, dict[str, Any]]]:
    latest: dict[str, tuple[Path, dict[str, Any]]] = {}
    for root in roots:
        for path in sorted(root.rglob("summary.json")):
            try:
                summary = read_json(path)
            except (OSError, json.JSONDecodeError, ValueError):
                continue
            if summary.get("schema_version") != schema or not verified(summary):
                continue
            slug = project_slug(summary)
            if not slug or slug not in universe_slugs:
                continue
            current = latest.get(slug)
            if current is None or timestamp(summary) >= timestamp(current[1]):
                latest[slug] = (path, summary)
    return latest


def metric_bool(value: Any) -> bool:
    return value is True


def metric_number(value: Any) -> int:
    return value if isinstance(value, int) else 0


def native_case_metrics(summary: dict[str, Any], prefix: str) -> dict[str, Any]:
    stats = summary.get("iris_statistics") or {}
    return {
        f"{prefix}_paths": stats.get(f"{prefix}_paths"),
        f"{prefix}_results": stats.get(f"{prefix}_results"),
        f"{prefix}_tp_paths_method": stats.get(f"{prefix}_tp_paths_method"),
        f"{prefix}_recall_method": stats.get(f"{prefix}_recall_method"),
    }


def codeql_case_metrics(summary: dict[str, Any]) -> dict[str, Any]:
    evaluation = summary.get("evaluation") or {}
    return {
        "codeql_paths": evaluation.get("num_paths"),
        "codeql_results": evaluation.get("num_results"),
        "codeql_tp_paths_method": evaluation.get("num_tp_paths_method"),
        "codeql_recall_method": evaluation.get("recall_method"),
    }


def case_row(
    universe_row: dict[str, Any],
    native: dict[str, tuple[Path, dict[str, Any]]],
    codeql: dict[str, tuple[Path, dict[str, Any]]],
) -> dict[str, Any]:
    slug = str(universe_row["project_slug"])
    row: dict[str, Any] = {
        "case_index": universe_row.get("case_index"),
        "project_slug": slug,
        "case_id": universe_row.get("native_case_id")
        or universe_row.get("strict_case_id")
        or universe_row.get("queue_case_id"),
        "cve_id": universe_row.get("cve_id"),
        "cwe_id": universe_row.get("cwe_id"),
        "iris_query": universe_row.get("iris_query"),
        "strict_projection_eligible": universe_row.get("strict_projection_eligible"),
        "strict_repair_database_valid": universe_row.get("strict_repair_database_valid"),
        "matrix_recommended_next_action": universe_row.get("recommended_next_action"),
        "native_status": "not_completed",
        "codeql_status": "not_completed",
    }
    if slug in native:
        native_path, native_summary = native[slug]
        native_case = native_summary.get("case") or {}
        row.update(
            {
                "case_id": native_case.get("case_id") or row["case_id"],
                "cve_id": native_case.get("cve_id") or row["cve_id"],
                "iris_query": native_case.get("iris_query") or row["iris_query"],
                "native_status": "completed_verified",
                "native_created_at": native_summary.get("created_at"),
                "native_workspace": native_summary.get("workspace"),
                "native_summary_path": str(native_path),
                "native_summary_sha256": sha256_file(native_path),
            }
        )
        row.update(native_case_metrics(native_summary, "vanilla"))
        row.update(native_case_metrics(native_summary, "posthoc"))
    if slug in codeql:
        codeql_path, codeql_summary = codeql[slug]
        row.update(
            {
                "codeql_status": "completed_verified",
                "codeql_created_at": codeql_summary.get("created_at"),
                "official_codeql_query": codeql_summary.get("official_codeql_query"),
                "codeql_summary_path": str(codeql_path),
                "codeql_summary_sha256": sha256_file(codeql_path),
            }
        )
        row.update(codeql_case_metrics(codeql_summary))
    return row


def totals(rows: list[dict[str, Any]], stage: str, denominator: int) -> dict[str, Any]:
    if stage == "codeql":
        status_key = "codeql_status"
        hit_key = "codeql_recall_method"
        paths_key = "codeql_paths"
        results_key = "codeql_results"
        overlap_key = "codeql_tp_paths_method"
    else:
        status_key = "native_status"
        hit_key = f"{stage}_recall_method"
        paths_key = f"{stage}_paths"
        results_key = f"{stage}_results"
        overlap_key = f"{stage}_tp_paths_method"
    completed = [row for row in rows if row.get(status_key) == "completed_verified"]
    hits = sum(metric_bool(row.get(hit_key)) for row in completed)
    paths = sum(metric_number(row.get(paths_key)) for row in completed)
    overlap = sum(metric_number(row.get(overlap_key)) for row in completed)
    results = sum(metric_number(row.get(results_key)) for row in completed)
    return {
        "denominator_case_count": denominator,
        "completed_verified_case_count": len(completed),
        "unavailable_or_not_completed_case_count": denominator - len(completed),
        "case_hits": hits,
        "best_effort_recall_method": hits / denominator if denominator else None,
        "completed_subset_recall_method": hits / len(completed) if completed else None,
        "reported_paths": paths,
        "method_overlap_paths": overlap,
        "path_overlap_rate_completed_subset": overlap / paths if paths else None,
        "reported_results": results,
        "precision": None,
        "precision_note": (
            "IRIS fix methods are positive-only labels. They support method recall "
            "and path-overlap accounting, not false-positive-complete precision."
        ),
    }


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    fieldnames: list[str] = []
    seen: set[str] = set()
    for row in rows:
        for key in row:
            if key not in seen:
                seen.add(key)
                fieldnames.append(key)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def fmt_ratio(value: Any) -> str:
    return "n/a" if value is None else f"{value:.3f}"


def markdown_report(report: dict[str, Any]) -> str:
    metrics = report["metrics"]
    labels = {
        "codeql": "Official CodeQL",
        "vanilla": "Native IRIS (vanilla)",
        "posthoc": "Native IRIS (posthoc)",
    }
    lines = [
        "# IRIS 213 Best-Effort Comparison",
        "",
        "| Method | Denominator | Completed | Hits | Best-effort method recall | Completed-subset recall | Reported paths | Fix-method overlap paths | Path overlap rate | Precision |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |",
    ]
    for key in ("codeql", "vanilla", "posthoc"):
        item = metrics[key]
        lines.append(
            f"| {labels[key]} | {item['denominator_case_count']} | "
            f"{item['completed_verified_case_count']} | {item['case_hits']} | "
            f"{fmt_ratio(item['best_effort_recall_method'])} | "
            f"{fmt_ratio(item['completed_subset_recall_method'])} | "
            f"{item['reported_paths']} | {item['method_overlap_paths']} | "
            f"{fmt_ratio(item['path_overlap_rate_completed_subset'])} | unavailable* |"
        )
    coverage = report["coverage"]
    lines.extend(
        [
            "",
            "| Coverage status | Count |",
            "| --- | ---: |",
            f"| Universe cases | {coverage['universe_case_count']} |",
            f"| Native IRIS completed verified | {coverage['native_completed_verified_case_count']} |",
            f"| Official CodeQL completed verified | {coverage['codeql_completed_verified_case_count']} |",
            f"| Paired completed verified | {coverage['paired_completed_verified_case_count']} |",
            f"| Native completed but missing CodeQL | {coverage['native_completed_missing_codeql_count']} |",
            "",
            "* Precision is unavailable under the official IRIS fix-method labels because the "
            "labels are not a complete false-positive annotation set.",
        ]
    )
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--universe-jsonl", type=Path, required=True)
    parser.add_argument("--artifact-root", type=Path, action="append", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    universe_rows = read_jsonl(args.universe_jsonl.resolve())
    universe_slugs = [str(row.get("project_slug")) for row in universe_rows if row.get("project_slug")]
    if len(universe_slugs) != len(universe_rows):
        raise SystemExit("every universe row must contain project_slug")
    duplicates = [slug for slug, count in Counter(universe_slugs).items() if count > 1]
    if duplicates:
        raise SystemExit(f"duplicate project_slug values in universe: {duplicates[:10]}")

    artifact_roots = [path.resolve() for path in args.artifact_root]
    native = discover_latest_summaries(
        artifact_roots,
        schema=NATIVE_SCHEMA,
        universe_slugs=set(universe_slugs),
    )
    codeql = discover_latest_summaries(
        artifact_roots,
        schema=CODEQL_SCHEMA,
        universe_slugs=set(universe_slugs),
    )
    rows = [case_row(row, native, codeql) for row in universe_rows]
    denominator = len(rows)
    native_slugs = set(native)
    codeql_slugs = set(codeql)
    report = {
        "schema_version": "iris213_best_effort_comparison.v1",
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "inputs": {
            "universe_jsonl": str(args.universe_jsonl.resolve()),
            "universe_jsonl_sha256": sha256_file(args.universe_jsonl.resolve()),
            "artifact_roots": [str(path) for path in artifact_roots],
        },
        "metric_contract": {
            "denominator": "all rows in the fixed 213-case IRIS universe",
            "success_credit": "completed verified method-level hit on at least one official IRIS fix method",
            "unavailable_policy": (
                "native failures, unavailable CodeQL databases, unsupported queries, incomplete runs, "
                "and unstarted cases remain in the 213 denominator"
            ),
            "precision": "unavailable without false-positive-complete labels",
        },
        "coverage": {
            "universe_case_count": denominator,
            "native_completed_verified_case_count": len(native_slugs),
            "codeql_completed_verified_case_count": len(codeql_slugs),
            "paired_completed_verified_case_count": len(native_slugs & codeql_slugs),
            "native_completed_missing_codeql_count": len(native_slugs - codeql_slugs),
            "codeql_completed_without_native_count": len(codeql_slugs - native_slugs),
            "native_completed_missing_codeql_project_slugs": sorted(native_slugs - codeql_slugs),
            "codeql_completed_without_native_project_slugs": sorted(codeql_slugs - native_slugs),
            "case_status_counts": {
                "native_status": dict(sorted(Counter(str(row.get("native_status")) for row in rows).items())),
                "codeql_status": dict(sorted(Counter(str(row.get("codeql_status")) for row in rows).items())),
            },
        },
        "metrics": {
            "codeql": totals(rows, "codeql", denominator),
            "vanilla": totals(rows, "vanilla", denominator),
            "posthoc": totals(rows, "posthoc", denominator),
        },
        "cases": rows,
    }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "comparison.213.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    write_csv(args.output_dir / "comparison.213.csv", rows)
    (args.output_dir / "comparison.213.md").write_text(markdown_report(report), encoding="utf-8")
    print(json.dumps(report["coverage"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
