#!/usr/bin/env python3
"""Summarize validated semantic-CVE judge answers into JSON, CSV, and Markdown."""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from pathlib import Path
from typing import Any


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", required=True, type=Path)
    parser.add_argument("--out-dir", required=True, type=Path)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    manifest = json.loads((args.run_dir / "manifest.json").read_text(encoding="utf-8"))
    args.out_dir.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, Any]] = []
    for item in manifest:
        case_id = item["case_id"]
        answer_path = args.run_dir / "outputs" / f"{case_id}.json"
        try:
            answer = json.loads(answer_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            rows.append({**item, "case_verdict": "not_adjudicated", "confidence": "", "matching_finding_ids": [], "reasoning": ""})
            continue
        rows.append({
            **item,
            "case_verdict": answer.get("case_verdict", "invalid_answer"),
            "confidence": answer.get("confidence", ""),
            "matching_finding_ids": answer.get("matching_finding_ids", []),
            "reasoning": answer.get("reasoning", ""),
            "finding_judgments": answer.get("finding_judgments", []),
        })
    counts = Counter(row["case_verdict"] for row in rows)
    finding_counts = Counter(
        judgment.get("verdict", "invalid")
        for row in rows for judgment in row.get("finding_judgments", [])
        if isinstance(judgment, dict)
    )
    summary = {
        "scope": "45 post-scan cases selected by reported-location/GT-anchor overlap",
        "warning": "This is LLM semantic adjudication, not an independently verified CVE-reproduction result. The selection proxy is not a semantic recall metric.",
        "case_count": len(rows),
        "case_verdict_counts": dict(counts),
        "finding_verdict_counts": dict(finding_counts),
        "same_vulnerability_cases": counts["same_vulnerability"],
    }
    (args.out_dir / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    fields = ["case_id", "rank", "identity_key", "historical_cve", "case_verdict", "confidence", "matching_finding_ids", "selected_findings", "reasoning"]
    with (args.out_dir / "case_semantic_adjudication.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        for row in rows:
            rendered = dict(row)
            rendered["matching_finding_ids"] = ";".join(row.get("matching_finding_ids", []))
            rendered["selected_findings"] = ";".join(row.get("selected_findings", []))
            writer.writerow({field: rendered.get(field, "") for field in fields})
    lines = [
        "# LLM semantic adjudication of Codex Security findings",
        "",
        "This post-scan review compares selected Security findings to the corresponding historical CVE. Cases were selected solely because a reported finding location overlapped a GT anchor; that filter is not evidence of equivalence.",
        "",
        f"- Cases reviewed: {len(rows)}",
        f"- `same_vulnerability`: {counts['same_vulnerability']}",
        f"- `related_but_different`: {counts['related_but_different']}",
        f"- `different_vulnerability`: {counts['different_vulnerability']}",
        f"- `insufficient_evidence`: {counts['insufficient_evidence']}",
        f"- not adjudicated/invalid: {counts['not_adjudicated'] + counts['invalid_answer']}",
        "",
        "The judgments are LLM-as-a-judge results and should be reported as such; they do not replace source-level validation or a CVE reproduction.",
        "",
        "| Case | Historical CVE | Verdict | Confidence | Matching finding(s) |",
        "| --- | --- | --- | --- | --- |",
    ]
    for row in rows:
        lines.append(f"| {row['case_id']} | {row['historical_cve']} | {row['case_verdict']} | {row['confidence']} | {', '.join(row.get('matching_finding_ids', [])) or '-'} |")
    (args.out_dir / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False))


if __name__ == "__main__":
    main()
