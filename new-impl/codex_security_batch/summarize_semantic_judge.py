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
    finding_rows: list[dict[str, Any]] = []
    for item in manifest:
        case_id = item["case_id"]
        if not item.get("judge_required", True):
            rows.append({
                **item,
                "case_verdict": item.get("automatic_verdict", "no_finding_candidate"),
                "confidence": "not_applicable",
                "matching_finding_ids": [],
                "reasoning": item.get("automatic_reason", "No finding candidate was available for LLM review."),
                "finding_judgments": [],
            })
            continue
        answer_path = args.run_dir / "outputs" / f"{case_id}.json"
        try:
            answer = json.loads(answer_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            rows.append({**item, "case_verdict": "not_adjudicated", "confidence": "", "matching_finding_ids": [], "reasoning": ""})
            continue
        # A few Codex Security producers omit findingId. Preserve the raw judge
        # label but map it back to the canonical input finding by ordinal, which
        # is the order required by the prompt. This avoids treating a missing or
        # slightly retyped model identifier as a different candidate.
        packet_path = args.run_dir / "packets" / f"{case_id}.json"
        try:
            packet = json.loads(packet_path.read_text(encoding="utf-8"))
            canonical = packet.get("codex_security_findings_to_compare", [])
        except (OSError, json.JSONDecodeError):
            canonical = []
        judgments = answer.get("finding_judgments", [])
        for index, judgment in enumerate(judgments if isinstance(judgments, list) else []):
            if not isinstance(judgment, dict):
                continue
            finding = canonical[index] if index < len(canonical) and isinstance(canonical[index], dict) else {}
            canonical_id = finding.get("findingId") or finding.get("ruleId") or finding.get("title") or f"ordinal:{index + 1}"
            finding_rows.append({
                "case_id": case_id, "historical_cve": item.get("historical_cve", ""),
                "ordinal": index + 1, "canonical_finding_id": canonical_id,
                "model_reported_finding_id": judgment.get("finding_id", ""),
                "title": finding.get("title", ""), "verdict": judgment.get("verdict", ""),
                "confidence": judgment.get("confidence", ""),
                "reasoning": judgment.get("reasoning", ""),
            })
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
        "scope": "Full 143-case post-scan evaluation: all canonical findings for every case with a finding artifact are supplied to the LLM judge; zero-finding cases are coded no_finding_candidate.",
        "warning": "This is LLM semantic adjudication, not an independently verified CVE-reproduction result. Case verdicts do not replace source-level validation.",
        "case_count": len(rows),
        "case_verdict_counts": dict(counts),
        "finding_verdict_counts": dict(finding_counts),
        "same_vulnerability_cases": counts["same_vulnerability"],
        "no_finding_candidate_cases": counts["no_finding_candidate"],
        "llm_judged_semantic_accuracy": counts["same_vulnerability"] / len(rows) if rows else 0.0,
        "llm_judged_semantic_accuracy_percent": round(100 * counts["same_vulnerability"] / len(rows), 2) if rows else 0.0,
    }
    (args.out_dir / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    fields = ["case_id", "rank", "identity_key", "historical_cve", "case_verdict", "confidence", "matching_finding_ids", "selected_findings", "reasoning"]
    with (args.out_dir / "case_semantic_adjudication.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        for row in rows:
            rendered = dict(row)
            rendered["matching_finding_ids"] = ";".join(str(value) for value in row.get("matching_finding_ids", []) if value)
            rendered["selected_findings"] = ";".join(str(value) for value in row.get("selected_findings", []) if value)
            writer.writerow({field: rendered.get(field, "") for field in fields})
    finding_fields = ["case_id", "historical_cve", "ordinal", "canonical_finding_id", "model_reported_finding_id", "title", "verdict", "confidence", "reasoning"]
    with (args.out_dir / "finding_semantic_adjudication.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=finding_fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(finding_rows)
    lines = [
        "# LLM semantic adjudication of Codex Security findings",
        "",
        "This post-scan review supplies every canonical Codex Security finding for every case with a finding artifact to the LLM judge. Cases without a finding artifact or with zero findings are marked `no_finding_candidate` without an LLM call.",
        "",
        f"- Cases reviewed: {len(rows)}",
        f"- LLM-judged semantic accuracy (same historical CVE): {counts['same_vulnerability']}/{len(rows)} ({100 * counts['same_vulnerability'] / len(rows):.2f}%)",
        f"- `same_vulnerability`: {counts['same_vulnerability']}",
        f"- `related_but_different`: {counts['related_but_different']}",
        f"- `different_vulnerability`: {counts['different_vulnerability']}",
        f"- `insufficient_evidence`: {counts['insufficient_evidence']}",
        f"- `no_finding_candidate`: {counts['no_finding_candidate']}",
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
