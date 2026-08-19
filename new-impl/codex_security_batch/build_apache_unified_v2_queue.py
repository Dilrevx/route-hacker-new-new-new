#!/usr/bin/env python3
"""Build a project-deduplicated Apache queue from unified v2 cases.

The resulting queue keeps only the scheduling metadata accepted by the blind
batch runner.  It deliberately excludes anchors, target locations, patches,
and every other evaluation-only label.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


def is_apache_repository(case: dict[str, Any]) -> bool:
    repository = case.get("repository") or {}
    repo_key = str(repository.get("repo_key") or "").lower()
    repo_url = str(repository.get("repo_url") or "").lower()
    return repo_key.startswith("apache__") or "github.com/apache/" in repo_url


def queue_row(case: dict[str, Any], rank: int) -> dict[str, Any]:
    repository = case.get("repository") or {}
    revisions = case.get("revisions") or {}
    classification = case.get("classification") or {}
    repo_key = str(repository.get("repo_key") or "")
    repo_url = str(repository.get("repo_url") or "")
    revision = str(revisions.get("checkout_revision") or "")
    if not repo_key or not repo_url or not revision:
        raise ValueError(f"missing scheduling metadata for {case.get('identity_key')!r}")
    return {
        "rank": rank,
        "case_id": f"apache_{rank:03d}",
        "repo_key": repo_key,
        "repo_url": repo_url,
        "checkout_revision": revision,
        "vulnerability_type": str(classification.get("primary_hcvr_type") or "unclassified"),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--limit", type=int, default=30)
    args = parser.parse_args()
    if args.limit < 1:
        raise ValueError("--limit must be positive")

    cases = [json.loads(line) for line in args.cases.read_text(encoding="utf-8").splitlines() if line.strip()]
    selected: list[dict[str, Any]] = []
    seen_repositories: set[str] = set()
    for case in cases:
        if not is_apache_repository(case):
            continue
        repo_url = str((case.get("repository") or {}).get("repo_url") or "")
        if repo_url in seen_repositories:
            continue
        seen_repositories.add(repo_url)
        selected.append(case)
        if len(selected) == args.limit:
            break

    rows = [queue_row(case, rank) for rank, case in enumerate(selected, start=1)]
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")

    digest = hashlib.sha256(args.out.read_bytes()).hexdigest()
    print(f"wrote {len(rows)} Apache project rows to {args.out}")
    print(f"sha256={digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
