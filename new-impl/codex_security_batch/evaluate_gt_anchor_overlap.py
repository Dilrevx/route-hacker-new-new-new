#!/usr/bin/env python3
"""Evaluate completed Codex Security blind audits against unified-v2 anchors.

Ground truth is deliberately consumed only after the blind audit. The evaluator
reports several localization proxies rather than treating a finding's emitted
locations as a complete call graph or equating a location match with semantic
CVE confirmation.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any


NEARBY_LINES = 50


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Offline multi-tier GT localization evaluation for Codex Security."
    )
    parser.add_argument("--cases", required=True, type=Path)
    parser.add_argument("--findings", required=True, type=Path)
    parser.add_argument("--unified-cases", required=True, type=Path)
    parser.add_argument(
        "--records",
        type=Path,
        help="Raw runner records JSONL. Enables full locations/codeEvidence matching.",
    )
    parser.add_argument("--nearby-lines", type=int, default=NEARBY_LINES)
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


def load_full_locations(records: Path | None) -> dict[tuple[str, str], list[dict[str, Any]]]:
    """Return canonical reported locations keyed by (case_id, finding_id)."""
    if records is None:
        return {}
    latest: dict[str, dict[str, Any]] = {}
    for record in read_jsonl(records):
        case_id = record.get("case_id")
        if isinstance(case_id, str):
            latest[case_id] = record
    result: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for case_id, record in latest.items():
        artifact = (record.get("artifacts") or {}).get("findings.json")
        if not artifact or not Path(artifact).exists():
            continue
        try:
            document = json.loads(Path(artifact).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        values = document.get("findings", []) if isinstance(document, dict) else []
        for finding in values if isinstance(values, list) else []:
            if not isinstance(finding, dict) or not isinstance(finding.get("findingId"), str):
                continue
            locations: list[dict[str, Any]] = []
            for source, raw_locations in (
                ("location", finding.get("locations")),
                ("evidence", finding.get("codeEvidence")),
            ):
                for raw in raw_locations if isinstance(raw_locations, list) else []:
                    if not isinstance(raw, dict):
                        continue
                    path = normalize_path(raw.get("path"))
                    start = as_int(raw.get("startLine"))
                    end = as_int(raw.get("endLine")) or start
                    if path and start is not None:
                        locations.append({
                            "path": path, "start": start, "end": end,
                            "source": source, "role": raw.get("role", ""),
                        })
            # Deduplicate the duplicate location/evidence records while preserving role/source.
            unique: dict[tuple[str, int, int, str], dict[str, Any]] = {}
            for loc in locations:
                unique.setdefault((loc["path"], loc["start"], loc["end"], str(loc["role"])), loc)
            result[(case_id, finding["findingId"])] = list(unique.values())
    return result


def main() -> None:
    args = parse_args()
    if args.nearby_lines < 0:
        raise SystemExit("--nearby-lines must be non-negative")
    audited_cases = read_csv(args.cases)
    findings = read_csv(args.findings)
    unified_cases = read_jsonl(args.unified_cases)
    full_locations = load_full_locations(args.records)

    gt_by_identity = {case["identity_key"]: case for case in unified_cases if case.get("identity_key")}
    findings_by_case: dict[str, list[dict[str, str]]] = {}
    for finding in findings:
        findings_by_case.setdefault(finding["case_id"], []).append(finding)

    case_rows: list[dict[str, Any]] = []
    finding_rows: list[dict[str, Any]] = []
    counts: Counter[str] = Counter()

    for case in audited_cases:
        identity = f"{case['repo_key']}::{case['vulnerability_id']}"
        gt = gt_by_identity.get(identity)
        anchors = [
            {
                "anchor_id": str(a.get("anchor_id", "")),
                "path": normalize_path(a.get("file")),
                "start": as_int(a.get("start_line")),
                "end": as_int(a.get("end_line")),
            }
            for a in ((gt or {}).get("recall_anchors") or [])
            if isinstance(a, dict)
        ]
        case_findings = findings_by_case.get(case["case_id"], [])
        tier_counts: Counter[str] = Counter()

        for finding in case_findings:
            primary = {
                "path": normalize_path(finding.get("primary_path")),
                "start": as_int(finding.get("primary_start_line")),
                "end": as_int(finding.get("primary_start_line")),
                "source": "primary",
                "role": "primary",
            }
            reported = full_locations.get((case["case_id"], finding.get("finding_id", "")), [])
            all_locations = [primary] + reported
            matches: list[dict[str, Any]] = []
            for loc in all_locations:
                for anchor in anchors:
                    if loc["path"] != anchor["path"]:
                        continue
                    distance = span_distance(loc["start"], loc["end"], anchor["start"], anchor["end"])
                    matches.append({**loc, "anchor": anchor, "distance": distance})

            primary_overlap = any(
                m["source"] == "primary"
                and span_overlaps(m["start"], m["end"], m["anchor"]["start"], m["anchor"]["end"])
                for m in matches
            )
            any_overlap = any(m["distance"] == 0 for m in matches)
            nearby = any(m["distance"] is not None and m["distance"] <= args.nearby_lines for m in matches)
            same_file = bool(matches)
            strongest = (
                "primary_anchor_overlap" if primary_overlap else
                "reported_location_anchor_overlap" if any_overlap else
                f"reported_location_within_{args.nearby_lines}_lines" if nearby else
                "reported_location_same_anchor_file" if same_file else
                "different_file"
            )
            counts[strongest] += 1
            tier_counts["primary"] += primary_overlap
            tier_counts["any_overlap"] += any_overlap
            tier_counts["nearby"] += nearby
            tier_counts["same_file"] += same_file
            matched = [m for m in matches if m["distance"] == 0]
            closest = min((m["distance"] for m in matches if m["distance"] is not None), default=None)
            finding_rows.append({
                **finding,
                "identity_key": identity,
                "primary_anchor_overlap": primary_overlap,
                "any_reported_location_anchor_overlap": any_overlap,
                f"any_reported_location_within_{args.nearby_lines}_lines": nearby,
                "any_reported_location_same_anchor_file": same_file,
                "strongest_relation": strongest,
                "closest_anchor_distance_lines": closest if closest is not None else "",
                "matched_anchor_ids": ";".join(m["anchor"]["anchor_id"] for m in matched),
                "matched_anchor_spans": ";".join(
                    f"{m['anchor']['path']}:{m['anchor']['start']}-{m['anchor']['end']}" for m in matched
                ),
                "matched_reported_locations": ";".join(
                    f"{m['source']}:{m['role']}:{m['path']}:{m['start']}-{m['end']}" for m in matched
                ),
            })

        if gt is None:
            relation = "missing_gt_identity"
        elif tier_counts["any_overlap"]:
            relation = "any_reported_location_anchor_hit"
        elif tier_counts["nearby"]:
            relation = f"reported_location_within_{args.nearby_lines}_lines"
        elif tier_counts["same_file"]:
            relation = "reported_location_same_anchor_file"
        elif case_findings:
            relation = "findings_elsewhere"
        else:
            relation = "no_findings"
        counts[f"case_{relation}"] += 1
        case_rows.append({
            **case, "identity_key": identity, "gt_anchor_count": len(anchors),
            "finding_count": len(case_findings),
            "primary_anchor_overlap_findings": tier_counts["primary"],
            "any_reported_location_anchor_overlap_findings": tier_counts["any_overlap"],
            f"any_reported_location_within_{args.nearby_lines}_lines_findings": tier_counts["nearby"],
            "any_reported_location_same_anchor_file_findings": tier_counts["same_file"],
            "case_relation": relation,
        })

    args.out_dir.mkdir(parents=True, exist_ok=True)
    case_fields = list(audited_cases[0]) + [
        "identity_key", "gt_anchor_count", "finding_count",
        "primary_anchor_overlap_findings", "any_reported_location_anchor_overlap_findings",
        f"any_reported_location_within_{args.nearby_lines}_lines_findings",
        "any_reported_location_same_anchor_file_findings", "case_relation",
    ]
    finding_fields = list(findings[0]) + [
        "identity_key", "primary_anchor_overlap", "any_reported_location_anchor_overlap",
        f"any_reported_location_within_{args.nearby_lines}_lines",
        "any_reported_location_same_anchor_file", "strongest_relation",
        "closest_anchor_distance_lines", "matched_anchor_ids", "matched_anchor_spans",
        "matched_reported_locations",
    ]
    write_csv(args.out_dir / "case_gt_alignment.csv", case_rows, case_fields)
    write_csv(args.out_dir / "finding_gt_alignment.csv", finding_rows, finding_fields)

    gt_cases = len(case_rows) - counts["case_missing_gt_identity"]
    any_cases = counts["case_any_reported_location_anchor_hit"]
    nearby_cases = any_cases + counts[f"case_reported_location_within_{args.nearby_lines}_lines"]
    summary = {
        "schema": "codex-security-unified-v2-anchor-alignment.v2",
        "method": {
            "primary_only_lower_bound": "Primary finding path/start-line overlaps a GT anchor span.",
            "reported_location_overlap_proxy": "Any emitted Codex Security location or code-evidence span overlaps a GT anchor span; emitted locations are not assumed exhaustive.",
            "nearby_diagnostic": f"Any exported location is in the same file and at most {args.nearby_lines} lines from an anchor span.",
            "boundary": "All tiers are post-hoc localization proxies. None independently establishes semantic CVE equivalence or runtime exploitability; GT is not supplied to the blind audit.",
        },
        "inputs": {
            "cases_csv": {"sha256": sha256(args.cases)},
            "findings_csv": {"sha256": sha256(args.findings)},
            "unified_cases_jsonl": {"sha256": sha256(args.unified_cases)},
            "raw_records_jsonl": {"sha256": sha256(args.records)} if args.records else None,
        },
        "counts": {
            "gt_joined_cases": gt_cases, "findings": len(finding_rows),
            "primary_only_hit_cases": sum(r["primary_anchor_overlap_findings"] > 0 for r in case_rows),
            "any_reported_location_hit_cases": any_cases,
            "any_reported_location_hit_rate": any_cases / gt_cases if gt_cases else 0.0,
            f"nearby_{args.nearby_lines}_line_cases_including_hits": nearby_cases,
            f"nearby_{args.nearby_lines}_line_rate_including_hits": nearby_cases / gt_cases if gt_cases else 0.0,
            "same_anchor_file_cases_including_nearby": nearby_cases + counts["case_reported_location_same_anchor_file"],
            "findings_elsewhere_cases": counts["case_findings_elsewhere"],
            "no_findings_cases": counts["case_no_findings"],
            "primary_anchor_overlap_findings": sum(r["primary_anchor_overlap"] for r in finding_rows),
            "any_reported_location_anchor_overlap_findings": sum(r["any_reported_location_anchor_overlap"] for r in finding_rows),
            f"any_reported_location_within_{args.nearby_lines}_lines_findings": sum(r[f"any_reported_location_within_{args.nearby_lines}_lines"] for r in finding_rows),
        },
    }
    (args.out_dir / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    c = summary["counts"]
    (args.out_dir / "summary.md").write_text(
        "# Codex Security vs Unified v2 Ground-Truth Anchor Alignment\n\n"
        "## Post-hoc localization tiers\n\n"
        "The blind scan never receives GT. The broader reported-location overlap proxy considers every finding location and code-evidence span explicitly emitted by Codex Security; emitted locations are not assumed exhaustive. Primary-only overlap is retained as a conservative lower bound. Neither tier alone is semantic CVE confirmation.\n\n"
        "| Metric | Value |\n| --- | ---: |\n"
        f"| GT-joined cases | {c['gt_joined_cases']} |\n"
        f"| Primary-only lower-bound hit cases | {c['primary_only_hit_cases']} |\n"
        f"| Any reported-location anchor-overlap cases (proxy) | {c['any_reported_location_hit_cases']} |\n"
        f"| Any reported-location anchor-overlap rate (proxy) | {c['any_reported_location_hit_rate']:.2%} |\n"
        f"| Same-file within {args.nearby_lines} lines, including hits (diagnostic) | {c[f'nearby_{args.nearby_lines}_line_cases_including_hits']} |\n"
        f"| Same-file within {args.nearby_lines} lines rate (diagnostic) | {c[f'nearby_{args.nearby_lines}_line_rate_including_hits']:.2%} |\n"
        f"| Same-anchor-file cases, including nearby | {c['same_anchor_file_cases_including_nearby']} |\n"
        f"| Findings elsewhere cases | {c['findings_elsewhere_cases']} |\n"
        f"| No-findings cases | {c['no_findings_cases']} |\n"
        f"| Primary-only overlap findings | {c['primary_anchor_overlap_findings']} |\n"
        f"| Any reported-location overlap findings | {c['any_reported_location_anchor_overlap_findings']} |\n\n"
        "## Outputs\n\n- `case_gt_alignment.csv`: tier counts and strongest relation per case.\n- `finding_gt_alignment.csv`: tier labels, closest GT-anchor distance, and matched locations per finding.\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
