#!/usr/bin/env python3
"""Evaluate blind-audit findings against unified-v2 recall anchors offline.

This evaluator deliberately consumes ground truth only after a Codex Security
blind audit has finished. It reports a strict, reproducible localization metric:
a finding is an anchor hit only when its exported primary source line falls
inside a recall-anchor line span for the same repository/CVE case.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Offline strict overlap evaluation for Codex Security findings."
    )
    parser.add_argument("--cases", required=True, type=Path)
    parser.add_argument("--findings", required=True, type=Path)
    parser.add_argument("--unified-cases", required=True, type=Path)
    parser.add_argument("--out-dir", required=True, type=Path)
    return parser.parse_args()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def normalize_path(value: str | None) -> str:
    value = (value or "").replace("\\", "/").strip()
    while value.startswith("./"):
        value = value[2:]
    return value


def as_int(value: str | int | None) -> int | None:
    try:
        return int(value) if value not in (None, "") else None
    except (TypeError, ValueError):
        return None


def write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in fields})


def main() -> None:
    args = parse_args()
    audited_cases = read_csv(args.cases)
    findings = read_csv(args.findings)
    unified_cases = read_jsonl(args.unified_cases)

    gt_by_identity: dict[str, dict[str, Any]] = {}
    for case in unified_cases:
        identity = case.get("identity_key")
        if isinstance(identity, str) and identity:
            gt_by_identity[identity] = case

    findings_by_case: dict[str, list[dict[str, str]]] = {}
    for finding in findings:
        findings_by_case.setdefault(finding["case_id"], []).append(finding)

    case_rows: list[dict[str, Any]] = []
    finding_rows: list[dict[str, Any]] = []
    counts: Counter[str] = Counter()

    for case in audited_cases:
        identity = f"{case['repo_key']}::{case['vulnerability_id']}"
        gt = gt_by_identity.get(identity)
        anchors = (gt or {}).get("recall_anchors") or []
        normalized_anchors = [
            {
                "anchor_id": str(anchor.get("anchor_id", "")),
                "path": normalize_path(anchor.get("file")),
                "start": as_int(anchor.get("start_line")),
                "end": as_int(anchor.get("end_line")),
            }
            for anchor in anchors
            if isinstance(anchor, dict)
        ]
        case_findings = findings_by_case.get(case["case_id"], [])
        strict_hits = 0
        same_file = 0

        for finding in case_findings:
            path = normalize_path(finding.get("primary_path"))
            line = as_int(finding.get("primary_start_line"))
            same_path = [anchor for anchor in normalized_anchors if anchor["path"] == path]
            strict = [
                anchor
                for anchor in same_path
                if line is not None
                and anchor["start"] is not None
                and anchor["end"] is not None
                and anchor["start"] <= line <= anchor["end"]
            ]
            relation = (
                "strict_anchor_overlap"
                if strict
                else "same_anchor_file_nonoverlap"
                if same_path
                else "different_file"
            )
            counts[relation] += 1
            strict_hits += bool(strict)
            same_file += bool(same_path)
            finding_rows.append(
                {
                    **finding,
                    "identity_key": identity,
                    "relation": relation,
                    "matched_anchor_ids": ";".join(a["anchor_id"] for a in strict),
                    "matched_anchor_spans": ";".join(
                        f"{a['path']}:{a['start']}-{a['end']}" for a in strict
                    ),
                }
            )

        if gt is None:
            case_relation = "missing_gt_identity"
        elif strict_hits:
            case_relation = "strict_anchor_hit"
        elif same_file:
            case_relation = "same_anchor_file_only"
        elif case_findings:
            case_relation = "findings_elsewhere"
        else:
            case_relation = "no_findings"
        counts[f"case_{case_relation}"] += 1
        case_rows.append(
            {
                **case,
                "identity_key": identity,
                "gt_anchor_count": len(normalized_anchors),
                "finding_count": len(case_findings),
                "strict_finding_hits": strict_hits,
                "same_anchor_file_findings": same_file,
                "case_relation": case_relation,
            }
        )

    args.out_dir.mkdir(parents=True, exist_ok=True)
    case_fields = list(audited_cases[0].keys()) + [
        "identity_key",
        "gt_anchor_count",
        "finding_count",
        "strict_finding_hits",
        "same_anchor_file_findings",
        "case_relation",
    ]
    finding_fields = list(findings[0].keys()) + [
        "identity_key",
        "relation",
        "matched_anchor_ids",
        "matched_anchor_spans",
    ]
    write_csv(args.out_dir / "case_gt_alignment.csv", case_rows, case_fields)
    write_csv(args.out_dir / "finding_gt_alignment.csv", finding_rows, finding_fields)

    strict_cases = counts["case_strict_anchor_hit"]
    gt_cases = len(case_rows) - counts["case_missing_gt_identity"]
    summary = {
        "schema": "codex-security-unified-v2-anchor-overlap.v1",
        "method": {
            "name": "strict_primary_location_anchor_overlap",
            "definition": "A hit requires exact normalized relative path equality and a finding primary_start_line within an offline unified-v2 recall-anchor [start_line, end_line] span for the same repo_key::vulnerability_id.",
            "boundary": "This is a post-hoc localization proxy, not semantic CVE adjudication or runtime confirmation. Ground truth is not supplied to the blind audit.",
        },
        "inputs": {
            "cases_csv": {"path": str(args.cases), "sha256": sha256(args.cases)},
            "findings_csv": {"path": str(args.findings), "sha256": sha256(args.findings)},
            "unified_cases_jsonl": {"path": str(args.unified_cases), "sha256": sha256(args.unified_cases)},
        },
        "counts": {
            "audited_cases": len(case_rows),
            "gt_joined_cases": gt_cases,
            "findings": len(finding_rows),
            "strict_anchor_hit_cases": strict_cases,
            "strict_anchor_hit_rate": strict_cases / gt_cases if gt_cases else 0.0,
            "same_anchor_file_only_cases": counts["case_same_anchor_file_only"],
            "findings_elsewhere_cases": counts["case_findings_elsewhere"],
            "no_findings_cases": counts["case_no_findings"],
            "strict_anchor_overlap_findings": counts["strict_anchor_overlap"],
            "same_anchor_file_nonoverlap_findings": counts["same_anchor_file_nonoverlap"],
            "different_file_findings": counts["different_file"],
        },
    }
    (args.out_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    c = summary["counts"]
    (args.out_dir / "summary.md").write_text(
        "# Codex Security vs Unified v2 Ground-Truth Anchor Alignment\n\n"
        "## Metric\n\n"
        "A strict hit requires the finding's exported primary path to equal a GT recall-anchor path and its primary start line to fall inside that anchor's labeled line span. This is evaluated after blind scanning and is a localization proxy, not semantic CVE confirmation.\n\n"
        "| Metric | Value |\n| --- | ---: |\n"
        f"| GT-joined cases | {c['gt_joined_cases']} |\n"
        f"| Strict anchor-hit cases | {c['strict_anchor_hit_cases']} |\n"
        f"| Strict anchor-hit rate | {c['strict_anchor_hit_rate']:.2%} |\n"
        f"| Same-anchor-file only cases | {c['same_anchor_file_only_cases']} |\n"
        f"| Findings elsewhere cases | {c['findings_elsewhere_cases']} |\n"
        f"| No-findings cases | {c['no_findings_cases']} |\n"
        f"| Strict-overlap findings | {c['strict_anchor_overlap_findings']} |\n"
        f"| Same-file non-overlap findings | {c['same_anchor_file_nonoverlap_findings']} |\n"
        f"| Different-file findings | {c['different_file_findings']} |\n\n"
        "## Outputs\n\n"
        "- `case_gt_alignment.csv`: one GT alignment row per audited case.\n"
        "- `finding_gt_alignment.csv`: one relation label per emitted finding.\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
