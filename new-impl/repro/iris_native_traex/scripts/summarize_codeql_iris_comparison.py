#!/usr/bin/env python3
"""Build an auditable, paired CodeQL-vs-native-IRIS metric report."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def native_summaries(root: Path) -> dict[str, tuple[Path, dict[str, Any]]]:
    rows: dict[str, tuple[Path, dict[str, Any]]] = {}
    for path in sorted(root.glob("*/summary.json")):
        summary = read_json(path)
        case = summary.get("case") or {}
        slug = case.get("project_slug")
        if isinstance(slug, str) and summary.get("verified_completion") is True:
            rows[slug] = (path, summary)
    return rows


def codeql_summaries(root: Path) -> dict[str, tuple[Path, dict[str, Any]]]:
    rows: dict[str, tuple[Path, dict[str, Any]]] = {}
    for path in sorted(root.glob("*/summary.json")):
        summary = read_json(path)
        case = summary.get("case") or {}
        slug = case.get("project_slug")
        if isinstance(slug, str) and summary.get("verified_completion") is True:
            rows[slug] = (path, summary)
    return rows


def metric_row(
    slug: str,
    native_path: Path,
    native: dict[str, Any],
    codeql_path: Path,
    codeql: dict[str, Any],
) -> dict[str, Any]:
    case = native["case"]
    native_metrics = native.get("iris_statistics") or {}
    codeql_metrics = codeql.get("evaluation") or {}
    return {
        "project_slug": slug,
        "case_id": case.get("case_id"),
        "cve_id": case.get("cve_id"),
        "iris_query": case.get("iris_query"),
        "official_codeql_query": codeql.get("official_codeql_query"),
        "native_summary_path": str(native_path),
        "native_summary_sha256": sha256_file(native_path),
        "codeql_summary_path": str(codeql_path),
        "codeql_summary_sha256": sha256_file(codeql_path),
        "codeql_paths": codeql_metrics.get("num_paths"),
        "codeql_results": codeql_metrics.get("num_results"),
        "codeql_tp_paths_method": codeql_metrics.get("num_tp_paths_method"),
        "codeql_tp_results_method": codeql_metrics.get("num_tp_results_method"),
        "codeql_recall_method": codeql_metrics.get("recall_method"),
        "iris_vanilla_paths": native_metrics.get("vanilla_paths"),
        "iris_vanilla_results": native_metrics.get("vanilla_results"),
        "iris_vanilla_tp_paths_method": native_metrics.get("vanilla_tp_paths_method"),
        "iris_vanilla_recall_method": native_metrics.get("vanilla_recall_method"),
        "iris_posthoc_paths": native_metrics.get("posthoc_paths"),
        "iris_posthoc_results": native_metrics.get("posthoc_results"),
        "iris_posthoc_tp_paths_method": native_metrics.get("posthoc_tp_paths_method"),
        "iris_posthoc_recall_method": native_metrics.get("posthoc_recall_method"),
    }


def numeric(rows: list[dict[str, Any]], key: str) -> int:
    return sum(value for row in rows if isinstance((value := row.get(key)), int))


def stage_metrics(rows: list[dict[str, Any]], stage: str) -> dict[str, Any]:
    fields = {
        "codeql": ("codeql_paths", "codeql_results", "codeql_tp_paths_method", "codeql_recall_method"),
        "iris_vanilla": (
            "iris_vanilla_paths",
            "iris_vanilla_results",
            "iris_vanilla_tp_paths_method",
            "iris_vanilla_recall_method",
        ),
        "iris_posthoc": (
            "iris_posthoc_paths",
            "iris_posthoc_results",
            "iris_posthoc_tp_paths_method",
            "iris_posthoc_recall_method",
        ),
    }
    paths_key, results_key, overlap_paths_key, hit_key = fields[stage]
    case_hits = sum(row.get(hit_key) is True for row in rows)
    paths = numeric(rows, paths_key)
    overlap_paths = numeric(rows, overlap_paths_key)
    results = numeric(rows, results_key)
    return {
        "paired_case_count": len(rows),
        "case_hits": case_hits,
        "case_recall_method": case_hits / len(rows) if rows else None,
        "reported_paths": paths,
        "method_overlap_paths": overlap_paths,
        "path_overlap_rate": overlap_paths / paths if paths else None,
        "reported_results": results,
        "precision": None,
        "precision_note": (
            "IRIS fix methods are positive-only ground truth. "
            "Method-overlap paths are not a false-positive-complete prediction unit, "
            "so this report intentionally does not fabricate precision."
        ),
    }


def markdown_table(metrics: dict[str, dict[str, Any]]) -> str:
    lines = [
        "| Method | Paired cases | Method Recall | Reported paths | Fix-method overlap paths | Path overlap rate | Precision |",
        "| --- | ---: | ---: | ---: | ---: | ---: | --- |",
    ]
    labels = {
        "codeql": "Official CodeQL",
        "iris_vanilla": "Native IRIS (vanilla)",
        "iris_posthoc": "Native IRIS (posthoc)",
    }
    for key in ("codeql", "iris_vanilla", "iris_posthoc"):
        item = metrics[key]
        recall = item["case_recall_method"]
        overlap = item["path_overlap_rate"]
        lines.append(
            f"| {labels[key]} | {item['paired_case_count']} | "
            f"{recall:.3f} ({item['case_hits']}/{item['paired_case_count']}) | "
            f"{item['reported_paths']} | {item['method_overlap_paths']} | "
            f"{overlap:.3f} | unavailable* |"
        )
    lines.extend(
        [
            "",
            "* Precision is unavailable under the official IRIS fix-method labels: they provide "
            "positive overlap evidence but no complete false-positive annotation set. The report "
            "therefore presents method-level recall and path-overlap rate without inventing a "
            "precision value.",
        ]
    )
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--native-cases-dir", type=Path, required=True)
    parser.add_argument("--codeql-results-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--require-identical-complete-set", action="store_true")
    args = parser.parse_args()

    native = native_summaries(args.native_cases_dir.resolve())
    codeql = codeql_summaries(args.codeql_results_dir.resolve())
    paired_slugs = sorted(native.keys() & codeql.keys())
    native_only = sorted(native.keys() - codeql.keys())
    codeql_only = sorted(codeql.keys() - native.keys())
    if args.require_identical_complete_set and (native_only or codeql_only):
        raise SystemExit(
            "incomplete paired set: "
            f"native_only={len(native_only)} codeql_only={len(codeql_only)}"
        )

    rows = [
        metric_row(slug, native[slug][0], native[slug][1], codeql[slug][0], codeql[slug][1])
        for slug in paired_slugs
    ]
    metrics = {stage: stage_metrics(rows, stage) for stage in ("codeql", "iris_vanilla", "iris_posthoc")}
    report = {
        "schema_version": "iris_native_traex_codeql_comparison.v1",
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "inputs": {
            "native_cases_dir": str(args.native_cases_dir.resolve()),
            "codeql_results_dir": str(args.codeql_results_dir.resolve()),
        },
        "coverage": {
            "native_verified_case_count": len(native),
            "codeql_verified_case_count": len(codeql),
            "paired_verified_case_count": len(rows),
            "native_only_case_count": len(native_only),
            "codeql_only_case_count": len(codeql_only),
            "native_only_project_slugs": native_only,
            "codeql_only_project_slugs": codeql_only,
        },
        "metric_contract": {
            "recall_unit": "case-level hit on at least one official IRIS fix method",
            "path_overlap_unit": "official evaluator code-flow path overlapping an official fix method",
            "precision": "unavailable without a false-positive-complete ground truth annotation set",
        },
        "metrics": metrics,
        "cases": rows,
    }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "comparison.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (args.output_dir / "comparison.csv").write_text("", encoding="utf-8")
    with (args.output_dir / "comparison.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]) if rows else ["project_slug"])
        writer.writeheader()
        writer.writerows(rows)
    (args.output_dir / "comparison.md").write_text(markdown_table(metrics), encoding="utf-8")
    print(json.dumps(report["coverage"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
