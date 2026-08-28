#!/usr/bin/env python3
"""Build a blind Codex Security scan queue from an HCVR QA receipt.

The queue intentionally keeps only scheduling metadata: repository URL,
checkout revision, project key, and coarse vulnerability type. It must not
carry dataset target paths, source/sink annotations, anchors, or known findings.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


FORBIDDEN_KEY_PARTS = (
    "anchor",
    "finding",
    "ground_truth",
    "known",
    "line",
    "path",
    "sink",
    "source",
    "target",
    "trace",
)


def load_records(path: Path) -> list[dict[str, Any]]:
    text = path.read_text(encoding="utf-8")
    stripped = text.lstrip()
    if not stripped:
        return []

    if stripped.startswith("[") or stripped.startswith("{"):
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            data = None
        if isinstance(data, list):
            return [require_mapping(item, path) for item in data]
        if isinstance(data, dict):
            records = get_records_from_envelope(path, data)
            if records is not None:
                return records
            return [data]

    records = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        item = json.loads(line)
        if not isinstance(item, dict):
            raise ValueError(f"expected object at {path}:{line_number}")
        records.append(item)
    return records


def require_mapping(value: Any, path: Path) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"expected object entries in {path}")
    return value


def get_records_from_envelope(path: Path, data: dict[str, Any]) -> list[dict[str, Any]] | None:
    for key in ("records", "cases", "queue"):
        value = data.get(key)
        if isinstance(value, list):
            return [require_mapping(item, path) for item in value]

    files = data.get("files")
    if not isinstance(files, dict):
        return None
    allowlist = files.get("v2_allowlist") or files.get("allowlist") or files.get("review")
    if not isinstance(allowlist, dict) or not allowlist.get("path"):
        return None

    nested_path = Path(str(allowlist["path"]))
    if not nested_path.is_absolute():
        nested_path = path.parent / nested_path
    return load_records(nested_path)


def get_nested(record: dict[str, Any], paths: list[tuple[str, ...]]) -> Any:
    for path in paths:
        current: Any = record
        for key in path:
            if not isinstance(current, dict) or key not in current:
                break
            current = current[key]
        else:
            if current not in (None, ""):
                return current
    return None


def as_text(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    return str(value)


def first_text(record: dict[str, Any], paths: list[tuple[str, ...]]) -> str | None:
    return as_text(get_nested(record, paths))


def repo_url_from_key(repo_key: str | None) -> str | None:
    if not repo_key or "__" not in repo_key:
        return None
    owner, repo = repo_key.split("__", 1)
    owner = owner.strip()
    repo = repo.strip()
    if not owner or not repo:
        return None
    return f"https://github.com/{owner}/{repo}.git"


def detect_leaky_keys(value: Any, prefix: str = "") -> list[str]:
    if isinstance(value, dict):
        leaks: list[str] = []
        for key, child in value.items():
            child_path = f"{prefix}.{key}" if prefix else key
            lowered = key.lower()
            if any(part in lowered for part in FORBIDDEN_KEY_PARTS):
                leaks.append(child_path)
            leaks.extend(detect_leaky_keys(child, child_path))
        return leaks
    if isinstance(value, list):
        leaks = []
        for index, child in enumerate(value):
            leaks.extend(detect_leaky_keys(child, f"{prefix}[{index}]"))
        return leaks
    return []


def build_queue_row(record: dict[str, Any], rank: int, case_prefix: str) -> dict[str, Any]:
    repo_key = first_text(
        record,
        [
            ("repo_key",),
            ("project",),
            ("project_name",),
            ("repository", "name"),
            ("repo", "name"),
        ],
    )
    repo_url = first_text(
        record,
        [
            ("repo_url",),
            ("repository_url",),
            ("git_url",),
            ("source", "repo_url"),
            ("source", "repository_url"),
            ("repository", "url"),
            ("repo", "url"),
        ],
    )
    if not repo_url:
        repo_url = repo_url_from_key(repo_key)
    revision = first_text(
        record,
        [
            ("checkout_revision",),
            ("revision",),
            ("commit",),
            ("commit_sha",),
            ("source", "checkout_revision"),
            ("source", "revision"),
            ("repository", "revision"),
            ("repo", "revision"),
        ],
    )
    if not repo_url or not revision:
        raise ValueError(f"missing repo URL or checkout revision at rank {rank}")

    case_id = first_text(record, [("case_id",), ("id",), ("target_id",), ("cve_id",)])
    if not case_id:
        case_id = f"{case_prefix}_{rank:03d}"
    vulnerability_type = first_text(
        record,
        [
            ("vulnerability_type",),
            ("vuln_type",),
            ("cwe",),
            ("category",),
            ("classification",),
            ("vulnerability_id",),
        ],
    )

    return {
        "rank": rank,
        "case_id": case_id,
        "repo_key": repo_key or repo_url,
        "repo_url": repo_url,
        "checkout_revision": revision,
        "vulnerability_type": vulnerability_type or "unclassified",
    }


def validate_queue_row(row: dict[str, Any]) -> None:
    leaks = detect_leaky_keys(row)
    if leaks:
        raise ValueError(f"queue row contains forbidden hint keys: {', '.join(leaks)}")


def keep_record(record: dict[str, Any], include_aux_fix_only: bool) -> bool:
    usable = record.get("usable_for_fix_revision_evidence")
    if usable is False:
        return False
    decision = as_text(record.get("paper_eval_decision"))
    if decision is None:
        return True
    allowed = {"paper_ready_direct_pair"}
    if include_aux_fix_only:
        allowed.add("paper_ready_aux_fix_only")
    return decision in allowed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qa", required=True, type=Path, help="HCVR QA receipt JSON/JSONL")
    parser.add_argument("--out", required=True, type=Path, help="Output queue JSONL path")
    parser.add_argument("--limit", type=int, default=None, help="Optional first-N case limit")
    parser.add_argument("--case-prefix", default="case", help="Generated case id prefix")
    parser.add_argument(
        "--usable-fix-revision-only",
        action="store_true",
        help="Keep only rows marked usable_for_fix_revision_evidence.",
    )
    parser.add_argument(
        "--direct-only",
        action="store_true",
        help="Keep only paper_ready_direct_pair rows; default also includes aux fix-only rows.",
    )
    args = parser.parse_args()

    records = load_records(args.qa)
    if args.usable_fix_revision_only or args.direct_only:
        records = [
            record
            for record in records
            if keep_record(record, include_aux_fix_only=not args.direct_only)
        ]
    if args.limit is not None:
        records = records[: args.limit]

    rows: list[dict[str, Any]] = []
    for rank, record in enumerate(records, start=1):
        row = build_queue_row(record, rank, args.case_prefix)
        validate_queue_row(row)
        rows.append(row)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")

    digest = hashlib.sha256(args.out.read_bytes()).hexdigest()
    print(f"wrote {len(rows)} blind queue rows to {args.out}")
    print(f"sha256={digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
