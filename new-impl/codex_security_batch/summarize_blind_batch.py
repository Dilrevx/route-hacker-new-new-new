#!/usr/bin/env python3
"""Summarize a Codex Security blind batch without copying runtime secrets."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any


TERMINAL_STATE_SUFFIXES = ("accepted", "partial", "failed", "stopped")
ARTIFACT_NAMES = (
    "report.md",
    "findings.json",
    "coverage.json",
    "scan-manifest.json",
    "exports/results.sarif",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Create a portable result snapshot from a blind batch run."
    )
    parser.add_argument("--queue", required=True, type=Path)
    parser.add_argument("--records", required=True, type=Path)
    parser.add_argument("--state-dir", required=True, type=Path)
    parser.add_argument("--log-dir", required=True, type=Path)
    parser.add_argument("--out-dir", required=True, type=Path)
    return parser.parse_args()


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def read_header_fields(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    fields: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = re.fullmatch(r"([A-Z_]+)=(.*)", line)
        if match:
            fields[match.group(1)] = match.group(2).strip()
    return fields


def load_json(path_value: str | None) -> dict[str, Any] | None:
    if not path_value:
        return None
    path = Path(path_value)
    if not path.exists():
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def normalize_severity(value: Any) -> str:
    if isinstance(value, dict):
        value = value.get("level")
    if not isinstance(value, str) or not value.strip():
        return "unknown"
    return value.strip().lower()


def terminal_state(case_id: str, state_dir: Path) -> str | None:
    for suffix in TERMINAL_STATE_SUFFIXES:
        if (state_dir / f"{case_id}.{suffix}").exists():
            return suffix
    return None


def portable_case_row(
    queue_row: dict[str, Any],
    record: dict[str, Any] | None,
    state_dir: Path,
    log_dir: Path,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    case_id = queue_row["case_id"]
    header = read_header_fields(log_dir / f"{case_id}.log.header")
    state = terminal_state(case_id, state_dir)

    if record is None:
        status = state or "pending"
        return (
            {
                **queue_row,
                "status": status,
                "record_status": None,
                "model": None,
                "effort": None,
                "exec_mode": None,
                "elapsed_seconds": None,
                "coverage": None,
                "findings_total": 0,
                "severity_counts": {},
                "scan_id": None,
                "scan_status": None,
                "producer": None,
                "artifact_presence": {},
            },
            [],
        )

    artifacts = record.get("artifacts") or {}
    artifact_presence = {
        name: bool(artifacts.get(name) and Path(artifacts[name]).exists())
        for name in ARTIFACT_NAMES
    }
    manifest = load_json(artifacts.get("scan-manifest.json"))
    scan = manifest.get("scan", {}) if manifest else {}
    producer = scan.get("producer") or {}
    findings_document = load_json(artifacts.get("findings.json"))
    findings_values = (
        findings_document.get("findings", []) if findings_document else []
    )
    if not isinstance(findings_values, list):
        findings_values = []

    finding_rows: list[dict[str, Any]] = []
    severity_counts: Counter[str] = Counter()
    for finding in findings_values:
        if not isinstance(finding, dict):
            continue
        severity = normalize_severity(finding.get("severity"))
        severity_counts[severity] += 1
        locations = finding.get("locations") or []
        primary = locations[0] if locations and isinstance(locations[0], dict) else {}
        taxonomy = finding.get("taxonomy") or {}
        cwe = taxonomy.get("cwe") if isinstance(taxonomy, dict) else None
        if isinstance(cwe, list):
            cwe = ", ".join(str(value) for value in cwe)
        finding_rows.append(
            {
                "case_id": case_id,
                "rank": queue_row["rank"],
                "repo_key": queue_row["repo_key"],
                "vulnerability_id": queue_row["vulnerability_id"],
                "finding_id": finding.get("findingId"),
                "severity": severity,
                "confidence": normalize_severity(finding.get("confidence")),
                "rule_id": finding.get("ruleId"),
                "cwe": cwe,
                "title": finding.get("title"),
                "primary_path": primary.get("path"),
                "primary_start_line": primary.get("startLine"),
            }
        )

    record_status = record.get("status")
    if record_status == "source_prepare_failed":
        status = record_status
    else:
        status = state or record_status or "unknown"
    if status == "partial":
        status = "partial_artifacts"
    producer_text = None
    if producer:
        producer_text = f"{producer.get('name', 'unknown')}@{producer.get('version', 'unknown')}"

    return (
        {
            **queue_row,
            "status": status,
            "record_status": record_status,
            "model": header.get("MODEL"),
            "effort": header.get("EFFORT"),
            "exec_mode": header.get("CODEX_EXEC_MODE"),
            "elapsed_seconds": record.get("elapsed_seconds"),
            "coverage": record.get("coverage"),
            "findings_total": len(finding_rows),
            "severity_counts": dict(sorted(severity_counts.items())),
            "scan_id": scan.get("id"),
            "scan_status": scan.get("status"),
            "producer": producer_text,
            "artifact_presence": artifact_presence,
        },
        finding_rows,
    )


def write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=fields,
            extrasaction="ignore",
            lineterminator="\n",
        )
        writer.writeheader()
        for row in rows:
            output = dict(row)
            for field in fields:
                if isinstance(output.get(field), (dict, list)):
                    output[field] = json.dumps(
                        output[field], ensure_ascii=False, sort_keys=True
                    )
            writer.writerow(output)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_summary(
    queue_path: Path,
    records_path: Path,
    cases: list[dict[str, Any]],
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    status_counts = Counter(row["status"] for row in cases)
    model_counts = Counter(
        row["model"] or "unknown"
        for row in cases
        if row["record_status"] not in (None, "source_prepare_failed")
    )
    coverage_counts = Counter(
        row["coverage"] or "unknown" for row in cases if row["record_status"]
    )
    severity_counts = Counter(row["severity"] for row in findings)
    producer_counts = Counter(
        row["producer"] or "unknown" for row in cases if row["record_status"]
    )
    processed = len(cases) - status_counts.get("pending", 0)
    return {
        "schema": "codex-security-blind-batch-summary.v1",
        "queue": {
            "cases": len(cases),
            "sha256": sha256(queue_path),
        },
        "records": {
            "raw_rows": len(read_jsonl(records_path)),
            "unique_cases": sum(1 for row in cases if row["record_status"]),
            "sha256": sha256(records_path),
        },
        "processed_cases": processed,
        "status_counts": dict(sorted(status_counts.items())),
        "model_counts": dict(sorted(model_counts.items())),
        "coverage_counts": dict(sorted(coverage_counts.items())),
        "producer_counts": dict(sorted(producer_counts.items())),
        "findings_total": len(findings),
        "severity_counts": dict(sorted(severity_counts.items())),
        "elapsed_seconds": sum(
            int(row["elapsed_seconds"] or 0) for row in cases
        ),
        "boundaries": [
            "All scans are repository-level blind audits at dataset revisions.",
            "Dataset vulnerability IDs and types are joined after execution for evaluation bookkeeping.",
            "Findings are Codex Security candidates and are not runtime-confirmed vulnerabilities.",
            "partial_artifacts means core artifacts exist after a non-zero scanner exit.",
            "No credentials, auth state, local logs, source trees, or absolute artifact paths are included.",
        ],
    }


def write_markdown(path: Path, summary: dict[str, Any], cases: list[dict[str, Any]]) -> None:
    status = summary["status_counts"]
    models = summary["model_counts"]
    coverage = summary["coverage_counts"]
    severity = summary["severity_counts"]
    scan_in_progress = [
        row["case_id"] for row in cases if row.get("scan_status") == "in_progress"
    ]
    text = f"""# Codex Security Native Blind Batch Snapshot

## Scope

- Queue denominator: {summary["queue"]["cases"]} HCVR v2 cases.
- Current terminal coverage: {summary["processed_cases"]}/{summary["queue"]["cases"]} cases.
- Execution policy: native Codex Security full-repository blind audit.
- Dataset vulnerability identifiers and types are joined only after execution for evaluation.

## Aggregate Results

| Metric | Value |
| --- | ---: |
| Accepted | {status.get("accepted", 0)} |
| Partial artifacts | {status.get("partial_artifacts", 0)} |
| Failed after scan attempt | {status.get("failed", 0)} |
| Source preparation failed | {status.get("source_prepare_failed", 0)} |
| Stopped | {status.get("stopped", 0)} |
| Pending | {status.get("pending", 0)} |
| Finding candidates | {summary["findings_total"]} |
| Elapsed scanner seconds | {summary["elapsed_seconds"]} |

## Models

| Model | Cases |
| --- | ---: |
"""
    for model, count in sorted(models.items()):
        text += f"| `{model}` | {count} |\n"

    text += """
## Coverage

| Coverage | Cases |
| --- | ---: |
"""
    for value, count in sorted(coverage.items()):
        text += f"| `{value}` | {count} |\n"

    text += """
## Finding Severity

| Severity | Candidates |
| --- | ---: |
"""
    for value, count in sorted(severity.items()):
        text += f"| `{value}` | {count} |\n"

    text += f"""
## Integrity

- Queue SHA256: `{summary["queue"]["sha256"]}`
- Raw records: {summary["records"]["raw_rows"]} rows, {summary["records"]["unique_cases"]} unique cases.
- Records SHA256: `{summary["records"]["sha256"]}`
- Manifest still marked `in_progress`: {", ".join(scan_in_progress) if scan_in_progress else "none"}.

## Interpretation Boundary

- Finding counts represent source-backed Codex Security candidates, not runtime-confirmed vulnerabilities.
- `partial_artifacts` preserves usable findings, coverage, and manifest evidence after a non-zero scanner exit.
- The snapshot excludes credentials, authentication state, local source trees, logs, and absolute artifact paths.
"""
    path.write_text(text, encoding="utf-8")


def main() -> int:
    args = parse_args()
    queue = read_jsonl(args.queue)
    records = read_jsonl(args.records)
    latest_records: dict[str, dict[str, Any]] = {}
    for record in records:
        latest_records[record["case_id"]] = record

    cases: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    for queue_row in queue:
        case_row, finding_rows = portable_case_row(
            queue_row,
            latest_records.get(queue_row["case_id"]),
            args.state_dir,
            args.log_dir,
        )
        cases.append(case_row)
        findings.extend(finding_rows)

    args.out_dir.mkdir(parents=True, exist_ok=True)
    summary = build_summary(args.queue, args.records, cases, findings)
    (args.out_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    write_csv(
        args.out_dir / "cases.csv",
        cases,
        [
            "rank",
            "case_id",
            "repo_key",
            "vulnerability_id",
            "vulnerability_type",
            "paper_eval_decision",
            "status",
            "record_status",
            "model",
            "effort",
            "exec_mode",
            "elapsed_seconds",
            "coverage",
            "findings_total",
            "severity_counts",
            "scan_id",
            "scan_status",
            "producer",
            "artifact_presence",
        ],
    )
    write_csv(
        args.out_dir / "findings.csv",
        findings,
        [
            "rank",
            "case_id",
            "repo_key",
            "vulnerability_id",
            "finding_id",
            "severity",
            "confidence",
            "rule_id",
            "cwe",
            "title",
            "primary_path",
            "primary_start_line",
        ],
    )
    write_markdown(args.out_dir / "summary.md", summary, cases)
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
