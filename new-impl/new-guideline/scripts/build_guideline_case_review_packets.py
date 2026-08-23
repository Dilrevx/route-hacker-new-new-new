#!/usr/bin/env python3
"""Render per-guideline source-evidence review packets from a boundary repair pack."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                rows.append(json.loads(line))
    return rows


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def slug(text: str) -> str:
    value = re.sub(r"[^A-Za-z0-9._-]+", "-", text).strip("-")
    return value or "unknown"


def md_escape(text: Any) -> str:
    return str(text or "").replace("|", "\\|").replace("\n", " ")


def format_anchor(anchor: Any) -> str:
    if not isinstance(anchor, dict):
        return "n/a"
    file_name = anchor.get("file") or "unknown"
    start = anchor.get("start_line")
    end = anchor.get("end_line")
    symbol = anchor.get("symbol") or anchor.get("span_kind") or ""
    if start and end:
        return f"{file_name}:{start}-{end} {symbol}".strip()
    return f"{file_name} {symbol}".strip()


def render_case_table(title: str, rows: list[dict[str, Any]]) -> list[str]:
    lines = [f"## {title}", ""]
    if not rows:
        lines.extend(["No examples in this bucket.", ""])
        return lines
    lines.extend(
        [
            "| Identity | CVE | HCVR Type | Anchor | Evidence Snippet |",
            "| --- | --- | --- | --- | --- |",
        ]
    )
    for row in rows:
        cves = ",".join(str(item) for item in row.get("cve_ids", [])) or "n/a"
        lines.append(
            f"| `{md_escape(row.get('identity_key') or row.get('case_id'))}` | {md_escape(cves)} | "
            f"{md_escape(row.get('primary_hcvr_type'))} | {md_escape(format_anchor(row.get('first_anchor')))} | "
            f"{md_escape(row.get('first_trace_evidence'))} |"
        )
    lines.append("")
    return lines


def render_packet(row: dict[str, Any]) -> str:
    lines = [
        f"# {row.get('guideline_id')} Evidence Review Packet",
        "",
        "This packet is review-only. It must not be copied into the released guideline sidecar or lexicon until source evidence is checked.",
        "",
        "## Current Item",
        "",
        f"- Guideline: `{row.get('guideline_id')}`",
        f"- Mechanism: `{row.get('mechanism_id')}`",
        f"- Repair kind: `{row.get('repair_kind')}`",
        f"- Main issue: {row.get('main_issue') or 'n/a'}",
        f"- Evidence gaps: {', '.join(str(item) for item in row.get('evidence_gaps', [])) or 'n/a'}",
        "",
        "## Candidate Boundaries",
        "",
    ]
    boundaries = row.get("proposed_boundaries") if isinstance(row.get("proposed_boundaries"), list) else []
    if not boundaries:
        lines.extend(["No candidate boundary text was supplied by the upstream review artifact.", ""])
    for item in boundaries:
        lines.extend(
            [
                f"### {item.get('boundary_label')}",
                "",
                str(item.get("description") or ""),
                "",
                f"Status: `{item.get('status')}`",
                "",
            ]
        )
    lines.extend(render_case_table("Source-Trace Examples", row.get("source_trace_examples", [])))
    lines.extend(render_case_table("Review-Entry-Only Examples", row.get("review_entry_only_examples", [])))
    lines.extend(render_case_table("Missing-Trace Examples", row.get("missing_trace_examples", [])))
    lines.extend(
        [
            "## Reviewer Evidence Fields",
            "",
            "- Source shape:",
            "- Sink or sensitive effect:",
            "- Missing guard:",
            "- Exploit precondition:",
            "- Safe fix semantics:",
            "- Boundary decision:",
            "- Recall follow-up needed:",
            "",
            "## Guardrails",
            "",
            "- Assign each example case to exactly one proposed boundary or mark it out-of-scope.",
            "- Promote only boundaries supported by source-level evidence from representative cases.",
            "- Do not convert split suggestions, judge notes, case labels, known anchors, or bad cases into runtime routing.",
            "- Rerun same-identity recall after any recall-consumed guideline text changes.",
            "",
        ]
    )
    return "\n".join(lines)


def build_packets(rows: list[dict[str, Any]], output_dir: Path) -> dict[str, Any]:
    packet_dir = output_dir / "packets"
    packet_dir.mkdir(parents=True, exist_ok=True)
    index_rows: list[dict[str, Any]] = []
    for row in rows:
        guideline_id = str(row.get("guideline_id") or "unknown")
        filename = f"{int(row.get('pack_priority') or len(index_rows) + 1):02d}-{slug(guideline_id)}.md"
        path = packet_dir / filename
        path.write_text(render_packet(row), encoding="utf-8")
        index_rows.append(
            {
                "packet": f"packets/{filename}",
                "guideline_id": guideline_id,
                "mechanism_id": row.get("mechanism_id"),
                "repair_kind": row.get("repair_kind"),
                "source_trace_examples": len(row.get("source_trace_examples", [])),
                "review_entry_only_examples": len(row.get("review_entry_only_examples", [])),
                "missing_trace_examples": len(row.get("missing_trace_examples", [])),
                "release_policy": "review_only_not_release_not_recall_input",
            }
        )
    return {
        "schema_version": "hcvr_guideline_case_review_packets.v1",
        "packet_count": len(index_rows),
        "packets": index_rows,
        "policy": [
            "Packets are review-only handoff material.",
            "Filled packets may inform a later lexicon or sidecar edit only after source evidence is checked.",
            "Any changed recall-consumed guideline text requires a fresh same-identity recall run.",
        ],
    }


def write_readme(path: Path, summary: dict[str, Any]) -> None:
    lines = [
        "# Guideline Case Review Packets",
        "",
        "These packets make the boundary repair pack actionable at reviewer level.",
        "They are review-only and do not change released guidelines, lexicon entries, sidecars, ranking, or audit prompts.",
        "",
        f"- Packet count: {summary['packet_count']}",
        "",
        "| Packet | Guideline | Mechanism | Repair Kind | Strong | Weak | Missing |",
        "| --- | --- | --- | --- | ---: | ---: | ---: |",
    ]
    for row in summary["packets"]:
        lines.append(
            f"| [{row['packet']}]({row['packet']}) | `{row['guideline_id']}` | `{row.get('mechanism_id')}` | "
            f"`{row.get('repair_kind')}` | {row['source_trace_examples']} | "
            f"{row['review_entry_only_examples']} | {row['missing_trace_examples']} |"
        )
    lines.extend(
        [
            "",
            "## Use Policy",
            "",
            "- Fill the evidence fields after checking old-side source and patch/fix semantics.",
            "- Do not treat an unfilled packet as a release-ready guideline change.",
            "- Keep semantic guideline decisions separate from same-identity recall metrics.",
            "",
        ]
    )
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--boundary-repair-pack", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    if args.output_dir.exists() and any(args.output_dir.iterdir()):
        raise FileExistsError(f"refusing to overwrite non-empty output directory: {args.output_dir}")
    rows = read_jsonl(args.boundary_repair_pack)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    summary = build_packets(rows, args.output_dir)
    write_json(args.output_dir / "summary.json", summary)
    write_readme(args.output_dir / "README.md", summary)
    print(json.dumps({"packet_count": summary["packet_count"]}, sort_keys=True))


if __name__ == "__main__":
    main()
