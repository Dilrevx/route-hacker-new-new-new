#!/usr/bin/env python3
"""Build an index of official CodeQL queries keyed by language and CWE."""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


CWE_TAG_RE = re.compile(r"external/cwe/cwe-(\d+)", re.IGNORECASE)
ID_RE = re.compile(r"^\s*\*\s*@id\s+(.+?)\s*$", re.MULTILINE)
KIND_RE = re.compile(r"^\s*\*\s*@kind\s+(.+?)\s*$", re.MULTILINE)
PRECISION_RE = re.compile(r"^\s*\*\s*@precision\s+(.+?)\s*$", re.MULTILINE)
TAG_LINE_RE = re.compile(r"^\s*\*\s*@tags\s+(.+?)\s*$", re.MULTILINE)


LANG_DIRS = {
    "java-kotlin": "java",
    "javascript-typescript": "javascript",
    "python": "python",
    "csharp": "csharp",
    "ruby": "ruby",
    "go": "go",
    "cpp": "cpp",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--codeql-repo", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument(
        "--include-kinds",
        nargs="*",
        default=["problem", "path-problem"],
        help="Only include query kinds suitable for alert SARIF output.",
    )
    parser.add_argument(
        "--require-security-path",
        action="store_true",
        help="Restrict to queries under Security/CWE or Security Features/CWE directories.",
    )
    parser.add_argument(
        "--include-experimental",
        action="store_true",
        help="Include queries under experimental/ directories.",
    )
    return parser.parse_args()


def normalize_cwe(raw: str) -> str:
    return f"CWE-{int(raw)}"


def metadata_value(pattern: re.Pattern[str], text: str) -> str:
    match = pattern.search(text)
    return match.group(1).strip() if match else ""


def query_record(
    codeql_repo: Path,
    lang_key: str,
    lang_dir: str,
    path: Path,
    include_kinds: set[str],
    require_security_path: bool,
    include_experimental: bool,
) -> dict[str, Any] | None:
    rel = path.relative_to(codeql_repo)
    rel_text = str(rel).replace("\\", "/")
    if not include_experimental and "/experimental/" in rel_text:
        return None
    if require_security_path and "/Security/" not in rel_text and "/Security Features/" not in rel_text:
        return None
    text = path.read_text(encoding="utf-8", errors="ignore")
    cwes = sorted({normalize_cwe(raw) for raw in CWE_TAG_RE.findall(text)}, key=lambda c: int(c.split("-")[1]))
    if not cwes:
        return None
    kind = metadata_value(KIND_RE, text)
    if include_kinds and kind not in include_kinds:
        return None
    return {
        "language": lang_key,
        "language_dir": lang_dir,
        "query_path": str(path),
        "query_relpath": rel_text,
        "query_id": metadata_value(ID_RE, text),
        "kind": kind,
        "precision": metadata_value(PRECISION_RE, text),
        "cwe_ids": cwes,
        "tags": sorted(set(CWE_TAG_RE.findall(text))),
    }


def main() -> None:
    args = parse_args()
    rows: list[dict[str, Any]] = []
    include_kinds = set(args.include_kinds or [])
    for lang_key, lang_dir in LANG_DIRS.items():
        src = args.codeql_repo / lang_dir / "ql" / "src"
        if not src.exists():
            continue
        for path in src.rglob("*.ql"):
            record = query_record(
                args.codeql_repo,
                lang_key,
                lang_dir,
                path,
                include_kinds,
                args.require_security_path,
                args.include_experimental,
            )
            if record:
                rows.append(record)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
    summary = {
        "query_count": len(rows),
        "language_counts": dict(Counter(row["language"] for row in rows)),
        "cwe_counts": dict(Counter(cwe for row in rows for cwe in row["cwe_ids"])),
        "codeql_repo": str(args.codeql_repo),
        "require_security_path": args.require_security_path,
        "include_experimental": args.include_experimental,
        "include_kinds": sorted(include_kinds),
    }
    summary_path = args.out.with_suffix(".summary.json")
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
