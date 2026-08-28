#!/usr/bin/env python3
"""Extract PoC-agent handoff packets from risk audit reports."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any, Iterable


FILE_LINE_RE = re.compile(
    r"(?P<file>[A-Za-z0-9_./@+-]+\.(?:java|kt|scala|py|go|ts|tsx|js|jsx|c|cc|cpp|h|hpp|rs|rb|php))"
    r"(?::|#L| line )(?P<line>[1-9][0-9]*)"
)


def read_jsonl(path: Path) -> Iterable[dict[str, Any]]:
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                yield json.loads(line)


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def extract_file_lines(text: str) -> list[dict[str, Any]]:
    seen: set[tuple[str, int]] = set()
    locations: list[dict[str, Any]] = []
    for match in FILE_LINE_RE.finditer(text):
        file = match.group("file")
        line = int(match.group("line"))
        key = (file, line)
        if key in seen:
            continue
        seen.add(key)
        locations.append({"file": file, "line": line})
    return locations


def build_handoff_rows(audit_index: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for audit in read_jsonl(audit_index):
        if audit.get("state") != "completed" or audit.get("decision") != "risk":
            continue
        report_path = Path(str(audit["report"]))
        report_text = report_path.read_text(encoding="utf-8") if report_path.is_file() else ""
        rows.append(
            {
                "schema_version": "guideline_agent_poc_handoff.v1",
                "identity_key": audit.get("identity_key"),
                "case_id": audit.get("case_id"),
                "hcvr_type": audit.get("hcvr_type"),
                "repo_url": audit.get("repo_url"),
                "checkout_revision": audit.get("checkout_revision"),
                "anchor": {
                    "anchor_id": audit.get("anchor_id"),
                    "file": audit.get("file"),
                    "start_line": audit.get("start_line"),
                    "end_line": audit.get("end_line"),
                },
                "audit": {
                    "confidence": audit.get("confidence"),
                    "report": str(report_path),
                    "events": audit.get("events"),
                },
                "candidate_instrumentation_locations": extract_file_lines(report_text),
                "poc_agent_instruction": (
                    "Use the audit report as the source of branch predicates, "
                    "runtime values, and instrumentation points. Instrument the "
                    "listed locations only as starting candidates, then confirm "
                    "or reject the risk with dynamic evidence."
                ),
            }
        )
    return rows


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--audit-index", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    rows = build_handoff_rows(args.audit_index.resolve())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    write_jsonl(args.output, rows)
    summary = {
        "schema_version": "guideline_agent_poc_handoff_summary.v1",
        "audit_index": str(args.audit_index.resolve()),
        "output": str(args.output.resolve()),
        "handoff_count": len(rows),
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
