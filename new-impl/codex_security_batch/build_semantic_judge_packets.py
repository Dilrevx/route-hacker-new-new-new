#!/usr/bin/env python3
"""Build post-scan LLM-as-a-judge packets for Codex Security findings.

This tool intentionally consumes ground truth only after a blind repository
audit has completed.  It selects cases whose *reported* finding locations
overlap a unified-v2 recall anchor, then asks a judge whether the reported
behavior is actually the historical CVE.  Location overlap is used solely to
bound post-hoc adjudication cost; it is not supplied to the judge as proof.
"""

from __future__ import annotations

import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path
from typing import Any


PROMPT_TEMPLATE = """You are evaluating a repository-level security-audit finding against a known
historical CVE *after the audit has completed*. Decide whether the audit report
describes the same underlying vulnerability as the historical CVE.

Do not treat a shared file, nearby line, similar CWE, severity, or a common
component as sufficient. Compare the vulnerable behavior, trust boundary or
attack surface, root cause, and harmful effect. The audit report did not receive
the historical CVE information during its scan.

Use exactly one case verdict:
- same_vulnerability: at least one finding identifies substantially the same
  vulnerable behavior/root cause and attack surface as the CVE.
- related_but_different: it concerns a materially different weakness in the
  same component, repair area, or attack chain.
- different_vulnerability: the finding describes a distinct vulnerability.
- insufficient_evidence: the supplied evidence cannot support a reliable
  comparison.

For every finding, give one of the same four labels. A case can be
same_vulnerability only if you name at least one matching finding_id. Be
conservative: do not infer equivalence from location alone.

Return ONLY a valid JSON object, no Markdown fence and no prose outside JSON:
{
  "case_id": "...",
  "historical_cve": "...",
  "case_verdict": "same_vulnerability|related_but_different|different_vulnerability|insufficient_evidence",
  "confidence": "high|medium|low",
  "matching_finding_ids": ["..."],
  "reasoning": "concise comparison that cites both GT and report evidence",
  "finding_judgments": [
    {
      "finding_id": "...",
      "verdict": "same_vulnerability|related_but_different|different_vulnerability|insufficient_evidence",
      "confidence": "high|medium|low",
      "gt_evidence": "specific GT behavior/rationale or trace node",
      "finding_evidence": "specific finding behavior/evidence",
      "reasoning": "why these do or do not describe the same CVE"
    }
  ]
}

Here is the adjudication packet:

"""


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def compact(value: Any, limit: int = 1800) -> Any:
    """Keep packets bounded while retaining structured audit evidence."""
    if isinstance(value, str):
        return value if len(value) <= limit else value[:limit] + "\n[truncated]"
    return value


def finding_for_judge(finding: dict[str, Any]) -> dict[str, Any]:
    keep = (
        "findingId", "title", "summary", "ruleId", "taxonomy", "severity",
        "confidence", "rootCause", "attackPath", "validation", "remediation",
        "preventiveControls", "locations",
    )
    result = {key: finding.get(key) for key in keep if finding.get(key) not in (None, "", [], {})}
    evidence = []
    for raw in finding.get("codeEvidence", []) if isinstance(finding.get("codeEvidence"), list) else []:
        if not isinstance(raw, dict):
            continue
        item = {key: raw.get(key) for key in ("id", "label", "path", "startLine", "endLine", "role", "explanation", "code") if raw.get(key) not in (None, "")}
        if "code" in item:
            item["code"] = compact(item["code"], 1200)
        evidence.append(item)
    result["codeEvidence"] = evidence
    return result


def gt_for_judge(case: dict[str, Any]) -> dict[str, Any]:
    vulnerability = case.get("vulnerability") or {}
    classification = case.get("classification") or {}
    anchors = []
    for raw in case.get("recall_anchors") or []:
        if not isinstance(raw, dict):
            continue
        anchors.append({
            key: raw.get(key)
            for key in ("anchor_id", "file", "start_line", "end_line", "symbol", "span_kind")
            if raw.get(key) is not None
        })
    nodes = []
    trace = case.get("vulnerability_trace") or {}
    for raw in trace.get("nodes", []) if isinstance(trace, dict) else []:
        if not isinstance(raw, dict):
            continue
        provenance = raw.get("provenance") if isinstance(raw.get("provenance"), dict) else {}
        node = {
            key: raw.get(key)
            for key in ("trace_node_id", "file", "start_line", "end_line", "symbol", "span_kind", "rationale")
            if raw.get(key) not in (None, "")
        }
        if provenance.get("rationale"):
            node["provenance_rationale"] = compact(provenance["rationale"], 2200)
        nodes.append(node)
    source_provenance = case.get("source_provenance") or {}
    return {
        "identity_key": case.get("identity_key"),
        "historical_cve": vulnerability.get("id"),
        "aliases": vulnerability.get("aliases") or [],
        "description": compact(vulnerability.get("description") or "", 1800),
        "classification": {
            "cwe_ids": classification.get("cwe_ids") or [],
            "primary_hcvr_type": classification.get("primary_hcvr_type"),
            "hcvr_types": classification.get("hcvr_types") or [],
        },
        "revision": (case.get("revisions") or {}).get("target_revision") or (case.get("revisions") or {}).get("checkout_revision"),
        "source_provenance": source_provenance,
        "recall_anchors": anchors,
        "vulnerability_trace_nodes": nodes,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case-alignment", required=True, type=Path)
    parser.add_argument("--finding-alignment", required=True, type=Path)
    parser.add_argument("--unified-cases", required=True, type=Path)
    parser.add_argument("--records", required=True, type=Path)
    parser.add_argument("--out-dir", required=True, type=Path)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    selected_cases = {
        row["case_id"]: row
        for row in read_csv(args.case_alignment)
        if row.get("case_relation") == "any_reported_location_anchor_hit"
    }
    selected_findings: dict[str, set[str]] = defaultdict(set)
    for row in read_csv(args.finding_alignment):
        if row.get("case_id") in selected_cases and row.get("any_reported_location_anchor_overlap") == "True":
            selected_findings[row["case_id"]].add(row["finding_id"])

    gt_by_identity = {row.get("identity_key"): row for row in read_jsonl(args.unified_cases) if row.get("identity_key")}
    records: dict[str, dict[str, Any]] = {}
    for record in read_jsonl(args.records):
        if isinstance(record.get("case_id"), str):
            records[record["case_id"]] = record

    args.out_dir.mkdir(parents=True, exist_ok=True)
    packet_dir = args.out_dir / "packets"
    prompt_dir = args.out_dir / "prompts"
    packet_dir.mkdir(exist_ok=True)
    prompt_dir.mkdir(exist_ok=True)
    manifest: list[dict[str, Any]] = []

    for case_id, alignment in sorted(selected_cases.items(), key=lambda pair: int(pair[1].get("rank") or 0)):
        identity = alignment.get("identity_key")
        gt = gt_by_identity.get(identity)
        artifact = (records.get(case_id, {}).get("artifacts") or {}).get("findings.json")
        if gt is None or not artifact or not Path(artifact).exists():
            raise SystemExit(f"missing GT or canonical finding artifact for {case_id}")
        document = json.loads(Path(artifact).read_text(encoding="utf-8"))
        wanted = selected_findings[case_id]
        findings = [finding_for_judge(item) for item in document.get("findings", []) if item.get("findingId") in wanted]
        if not findings:
            raise SystemExit(f"no selected canonical findings for {case_id}")
        packet = {
            "case_id": case_id,
            "selection_note": "Post-scan selection: the following findings had at least one reported location overlapping a GT recall anchor. This is a review-scope filter, not evidence of semantic equivalence.",
            "ground_truth_historical_cve": gt_for_judge(gt),
            "codex_security_findings_to_compare": findings,
        }
        packet_path = packet_dir / f"{case_id}.json"
        prompt_path = prompt_dir / f"{case_id}.txt"
        packet_path.write_text(json.dumps(packet, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        prompt_path.write_text(
            PROMPT_TEMPLATE + json.dumps(packet, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        manifest.append({
            "case_id": case_id,
            "rank": alignment.get("rank"),
            "identity_key": identity,
            "historical_cve": (gt.get("vulnerability") or {}).get("id"),
            "selected_findings": [item.get("findingId") for item in findings],
            "packet": str(packet_path),
            "prompt": str(prompt_path),
        })

    (args.out_dir / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (args.out_dir / "README.md").write_text(
        "# Post-scan semantic CVE adjudication packets\n\n"
        f"- Cases: {len(manifest)}\n"
        f"- Findings selected by reported-location overlap: {sum(len(x['selected_findings']) for x in manifest)}\n"
        "- Selection uses GT only after blind scans; semantic equivalence is decided by an LLM judge.\n"
        "- Packets retain GT rationale and structured finding evidence. Do not treat packet selection as a recall metric.\n",
        encoding="utf-8",
    )
    print(json.dumps({"cases": len(manifest), "findings": sum(len(x["selected_findings"]) for x in manifest), "out_dir": str(args.out_dir)}))


if __name__ == "__main__":
    main()
