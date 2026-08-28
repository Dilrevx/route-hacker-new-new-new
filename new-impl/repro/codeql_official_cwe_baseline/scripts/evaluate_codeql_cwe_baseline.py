#!/usr/bin/env python3
"""Evaluate CodeQL SARIF results against unified dataset anchors."""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from pathlib import Path
from typing import Any


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--run-ledger", required=True, type=Path)
    parser.add_argument("--out-dir", required=True, type=Path)
    parser.add_argument("--nearby-lines", type=int, default=50)
    return parser.parse_args()


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def normalize_path(value: str | None, source_root: str = "") -> str:
    value = (value or "").replace("\\", "/").strip()
    if value.startswith("file://"):
        value = value[7:]
    source_root = source_root.replace("\\", "/").rstrip("/")
    if source_root and value.startswith(source_root + "/"):
        value = value[len(source_root) + 1 :]
    while value.startswith("./"):
        value = value[2:]
    return value.lstrip("/") if source_root and value.startswith("/") else value


def as_int(value: Any) -> int | None:
    try:
        return int(value) if value not in (None, "") else None
    except (TypeError, ValueError):
        return None


def span_overlaps(a_start: int | None, a_end: int | None, b_start: int | None, b_end: int | None) -> bool:
    return (
        a_start is not None
        and a_end is not None
        and b_start is not None
        and b_end is not None
        and a_start <= b_end
        and b_start <= a_end
    )


def span_distance(a_start: int | None, a_end: int | None, b_start: int | None, b_end: int | None) -> int | None:
    if None in (a_start, a_end, b_start, b_end):
        return None
    if span_overlaps(a_start, a_end, b_start, b_end):
        return 0
    assert a_start is not None and a_end is not None and b_start is not None and b_end is not None
    return b_start - a_end if a_end < b_start else a_start - b_end


def write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in fields})


def region_to_loc(location: dict[str, Any], source_root: str, source: str) -> dict[str, Any] | None:
    physical = location.get("physicalLocation") or {}
    artifact = physical.get("artifactLocation") or {}
    region = physical.get("region") or {}
    path = normalize_path(artifact.get("uri"), source_root)
    start = as_int(region.get("startLine"))
    end = as_int(region.get("endLine")) or start
    if not path or start is None:
        return None
    return {
        "path": path,
        "start": start,
        "end": end,
        "source": source,
    }


def result_locations(result: dict[str, Any], source_root: str) -> list[dict[str, Any]]:
    locations: list[dict[str, Any]] = []
    for loc in result.get("locations") or []:
        parsed = region_to_loc(loc, source_root, "primary")
        if parsed:
            locations.append(parsed)
    for loc in result.get("relatedLocations") or []:
        parsed = region_to_loc(loc, source_root, "related")
        if parsed:
            locations.append(parsed)
    for code_flow in result.get("codeFlows") or []:
        for thread_flow in code_flow.get("threadFlows") or []:
            for item in thread_flow.get("locations") or []:
                parsed = region_to_loc(item.get("location") or {}, source_root, "codeFlow")
                if parsed:
                    locations.append(parsed)
    unique: dict[tuple[str, int, int, str], dict[str, Any]] = {}
    for loc in locations:
        unique.setdefault((loc["path"], loc["start"], loc["end"], loc["source"]), loc)
    return list(unique.values())


def load_sarif(path: Path) -> tuple[list[dict[str, Any]], str]:
    if not path.exists():
        return [], "missing_sarif"
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [], f"invalid_sarif:{exc!r}"
    results: list[dict[str, Any]] = []
    for run in document.get("runs") or []:
        for result in run.get("results") or []:
            if isinstance(result, dict):
                results.append(result)
    return results, "ok"


def normalized_run_status(run: dict[str, Any]) -> str:
    status = str(run.get("status", ""))
    if status != "failed":
        return status
    log_path = Path(str(run.get("log_path") or ""))
    if not log_path.exists():
        return status
    log_text = log_path.read_text(encoding="utf-8", errors="replace")
    if (
        "needs to be finalized" in log_text
        and "could not process any of it using the 'none' build mode" in log_text
    ):
        return "db_unfinalized_unusable"
    if "needs to be finalized" in log_text:
        return "db_finalize_failed"
    return status


def evaluate_result(result: dict[str, Any], anchors: list[dict[str, Any]], source_root: str, nearby_lines: int) -> dict[str, Any]:
    locs = result_locations(result, source_root)
    matches: list[dict[str, Any]] = []
    for loc in locs:
        for anchor in anchors:
            if loc["path"] != anchor["path"]:
                continue
            distance = span_distance(loc["start"], loc["end"], anchor["start"], anchor["end"])
            matches.append({**loc, "anchor": anchor, "distance": distance})
    exact = any(m["distance"] == 0 for m in matches)
    nearby = any(m["distance"] is not None and m["distance"] <= nearby_lines for m in matches)
    same_file = bool(matches)
    closest = min((m["distance"] for m in matches if m["distance"] is not None), default=None)
    tier = (
        "anchor_overlap"
        if exact
        else f"within_{nearby_lines}_lines"
        if nearby
        else "same_anchor_file"
        if same_file
        else "different_file"
    )
    return {
        "rule_id": result.get("ruleId", ""),
        "message": ((result.get("message") or {}).get("text") or "")[:500],
        "location_count": len(locs),
        "primary_location": ";".join(f"{loc['path']}:{loc['start']}-{loc['end']}" for loc in locs if loc["source"] == "primary"),
        "exact_anchor_overlap": exact,
        f"within_{nearby_lines}_lines": nearby,
        "same_anchor_file": same_file,
        "strongest_relation": tier,
        "closest_anchor_distance_lines": closest if closest is not None else "",
        "matched_anchor_ids": ";".join(m["anchor"]["anchor_id"] for m in matches if m["distance"] == 0),
    }


def metrics(case_tp: int, alarm_tp: int, case_count: int, alarms: int) -> dict[str, Any]:
    recall = case_tp / case_count if case_count else 0.0
    precision = alarm_tp / alarms if alarms else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "recall": recall,
        "precision": precision,
        "f1": f1,
        "true_positive_cases": case_tp,
        "true_positive_alarms": alarm_tp,
        "case_count": case_count,
        "alarms": alarms,
    }


def main() -> None:
    args = parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)
    manifest = read_jsonl(args.manifest)
    latest_run: dict[str, dict[str, Any]] = {}
    for row in read_jsonl(args.run_ledger):
        latest_run[row["identity_key"]] = row

    case_rows: list[dict[str, Any]] = []
    finding_rows: list[dict[str, Any]] = []
    counts: Counter[str] = Counter()
    exact_case_hits = 0
    nearby_case_hits = 0
    same_file_case_hits = 0
    exact_alarm_hits = 0
    nearby_alarm_hits = 0
    same_file_alarm_hits = 0
    alarm_count = 0

    for case in manifest:
        identity = case["identity_key"]
        run = latest_run.get(identity, {"status": "not_run", "sarif_path": ""})
        run_status = normalized_run_status(run)
        anchors = [
            {
                "anchor_id": str(anchor.get("anchor_id", "")),
                "path": normalize_path(anchor.get("file"), ""),
                "start": as_int(anchor.get("start_line")),
                "end": as_int(anchor.get("end_line")) or as_int(anchor.get("start_line")),
            }
            for anchor in case.get("recall_anchors") or []
            if isinstance(anchor, dict)
        ]
        sarif_results, sarif_status = load_sarif(Path(run.get("sarif_path") or ""))
        case_alarm_count = len(sarif_results) if run_status in {"succeeded", "skipped_existing"} else 0
        alarm_count += case_alarm_count
        case_exact = False
        case_nearby = False
        case_same_file = False
        for index, result in enumerate(sarif_results):
            evaluated = evaluate_result(result, anchors, case.get("source_root", ""), args.nearby_lines)
            exact_alarm_hits += int(evaluated["exact_anchor_overlap"])
            nearby_alarm_hits += int(evaluated[f"within_{args.nearby_lines}_lines"])
            same_file_alarm_hits += int(evaluated["same_anchor_file"])
            case_exact = case_exact or evaluated["exact_anchor_overlap"]
            case_nearby = case_nearby or evaluated[f"within_{args.nearby_lines}_lines"]
            case_same_file = case_same_file or evaluated["same_anchor_file"]
            finding_rows.append(
                {
                    "identity_key": identity,
                    "result_index": index,
                    "run_status": run_status,
                    **evaluated,
                }
            )

        exact_case_hits += int(case_exact)
        nearby_case_hits += int(case_nearby)
        same_file_case_hits += int(case_same_file)
        strongest = (
            "anchor_overlap"
            if case_exact
            else f"within_{args.nearby_lines}_lines"
            if case_nearby
            else "same_anchor_file"
            if case_same_file
            else "alerts_elsewhere"
            if case_alarm_count
            else "no_alerts"
        )
        counts[run_status or "not_run"] += 1
        counts[f"case_{strongest}"] += 1
        case_rows.append(
            {
                "identity_key": identity,
                "codeql_language": case.get("codeql_language", ""),
                "cwe_ids": ";".join(case.get("cwe_ids") or []),
                "cwe_source": case.get("cwe_source", ""),
                "run_status": run_status,
                "raw_run_status": run.get("status", ""),
                "sarif_status": sarif_status,
                "query_count": run.get("query_count", 0),
                "alarm_count": case_alarm_count,
                "anchor_count": len(anchors),
                "exact_anchor_hit": case_exact,
                f"within_{args.nearby_lines}_lines_hit": case_nearby,
                "same_anchor_file_hit": case_same_file,
                "strongest_relation": strongest,
                "sarif_path": run.get("sarif_path", ""),
            }
        )

    summary = {
        "case_count": len(manifest),
        "run_status_counts": dict(Counter(row["run_status"] for row in case_rows)),
        "case_relation_counts": dict(Counter(row["strongest_relation"] for row in case_rows)),
        "alarm_count": alarm_count,
        "effective_executed_case_count": sum(
            1 for row in case_rows if row["run_status"] in {"succeeded", "skipped_existing"}
        ),
        "exact_anchor_overlap": metrics(exact_case_hits, exact_alarm_hits, len(manifest), alarm_count),
        f"within_{args.nearby_lines}_lines": metrics(nearby_case_hits, nearby_alarm_hits, len(manifest), alarm_count),
        "same_anchor_file": metrics(same_file_case_hits, same_file_alarm_hits, len(manifest), alarm_count),
        "alarm_level_hits": {
            "exact_anchor_overlap": exact_alarm_hits,
            f"within_{args.nearby_lines}_lines": nearby_alarm_hits,
            "same_anchor_file": same_file_alarm_hits,
        },
    }
    summary["paper_table_row"] = {
        "method": "Official CodeQL CWE queries",
        "match_tier": "exact_anchor_overlap",
        "denominator": len(manifest),
        "recall": summary["exact_anchor_overlap"]["recall"],
        "precision": summary["exact_anchor_overlap"]["precision"],
        "f1": summary["exact_anchor_overlap"]["f1"],
        "alarms": alarm_count,
        "true_positive_cases": summary["exact_anchor_overlap"]["true_positive_cases"],
        "true_positive_alarms": summary["exact_anchor_overlap"]["true_positive_alarms"],
    }
    (args.out_dir / "evaluation_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    write_csv(
        args.out_dir / "case_results.csv",
        case_rows,
        [
            "identity_key",
            "codeql_language",
            "cwe_ids",
            "cwe_source",
            "run_status",
            "raw_run_status",
            "sarif_status",
            "query_count",
            "alarm_count",
            "anchor_count",
            "exact_anchor_hit",
            f"within_{args.nearby_lines}_lines_hit",
            "same_anchor_file_hit",
            "strongest_relation",
            "sarif_path",
        ],
    )
    write_csv(
        args.out_dir / "finding_results.csv",
        finding_rows,
        [
            "identity_key",
            "result_index",
            "run_status",
            "rule_id",
            "message",
            "location_count",
            "primary_location",
            "exact_anchor_overlap",
            f"within_{args.nearby_lines}_lines",
            "same_anchor_file",
            "strongest_relation",
            "closest_anchor_distance_lines",
            "matched_anchor_ids",
        ],
    )
    md = [
        "# Official CodeQL CWE Baseline Evaluation",
        "",
        f"- Cases: {summary['case_count']}",
        f"- Effective executed cases: {summary['effective_executed_case_count']}",
        f"- Alarms: {summary['alarm_count']}",
        f"- Run status: {summary['run_status_counts']}",
        f"- Case relation: {summary['case_relation_counts']}",
        "",
        "| Match tier | Recall | Precision | F1 | TP cases | Alarms |",
        "| --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for key, label in [
        ("exact_anchor_overlap", "Exact anchor overlap"),
        (f"within_{args.nearby_lines}_lines", f"Within {args.nearby_lines} lines"),
        ("same_anchor_file", "Same anchor file"),
    ]:
        row = summary[key]
        md.append(
            f"| {label} | {row['recall']:.4f} | {row['precision']:.4f} | {row['f1']:.4f} | "
            f"{row['true_positive_cases']} | {row['alarms']} |"
        )
    (args.out_dir / "evaluation_summary.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
