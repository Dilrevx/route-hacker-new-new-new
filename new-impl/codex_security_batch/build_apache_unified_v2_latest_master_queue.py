#!/usr/bin/env python3
"""Build an Apache-only latest-master audit queue from unified v2 repositories.

Unified v2 supplies the project selection only.  Each selected repository is
resolved at execution time through its remote ``master`` ref, so this queue is
explicitly separate from the dataset's historical source snapshots.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any


def is_apache_repository(case: dict[str, Any]) -> bool:
    repository = case.get("repository") or {}
    repo_key = str(repository.get("repo_key") or "").lower()
    repo_url = str(repository.get("repo_url") or "").lower()
    return repo_key.startswith("apache__") or "github.com/apache/" in repo_url


def resolve_latest_default_branch(repo_url: str) -> tuple[str, str]:
    completed = subprocess.run(
        ["git", "ls-remote", "--symref", repo_url, "HEAD"],
        check=True,
        capture_output=True,
        text=True,
        timeout=90,
    )
    lines = [line.split() for line in completed.stdout.splitlines() if line.strip()]
    head_ref = next(
        (fields[1] for fields in lines if len(fields) == 3 and fields[0] == "ref:" and fields[2] == "HEAD"),
        None,
    )
    revision = next(
        (fields[0] for fields in lines if len(fields) == 2 and fields[1] == "HEAD"),
        None,
    )
    if not head_ref or not revision or not head_ref.startswith("refs/heads/"):
        raise ValueError(f"remote default branch not found: {repo_url}")
    if len(revision) != 40 or any(char not in "0123456789abcdef" for char in revision):
        raise ValueError(f"invalid default revision for {repo_url}: {revision!r}")
    return head_ref.removeprefix("refs/heads/"), revision


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--limit", type=int, default=50)
    args = parser.parse_args()
    if args.limit < 1:
        raise ValueError("--limit must be positive")

    cases = [
        json.loads(line)
        for line in args.cases.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    selected: list[dict[str, Any]] = []
    seen_urls: set[str] = set()
    for case in cases:
        if not is_apache_repository(case):
            continue
        repository = case.get("repository") or {}
        repo_url = str(repository.get("repo_url") or "")
        if not repo_url or repo_url in seen_urls:
            continue
        seen_urls.add(repo_url)
        selected.append(case)
        if len(selected) == args.limit:
            break

    rows: list[dict[str, Any]] = []
    for rank, case in enumerate(selected, start=1):
        repository = case.get("repository") or {}
        repo_key = str(repository.get("repo_key") or "")
        repo_url = str(repository.get("repo_url") or "")
        if not repo_key or not repo_url:
            raise ValueError(f"missing repository metadata: {case.get('identity_key')!r}")
        print(f"resolving {rank}/{len(selected)} default branch: {repo_key}", flush=True)
        branch, revision = resolve_latest_default_branch(repo_url)
        rows.append(
            {
                "rank": rank,
                "case_id": f"apache_master_{rank:03d}",
                "repo_key": repo_key,
                "repo_url": repo_url,
                "checkout_revision": revision,
                "checkout_revision_kind": "latest_default_branch_resolved",
                "checkout_branch": branch,
                "source_selection": "unified_v2_apache_repository_dedup",
                "vulnerability_type": "latest_default_branch_audit",
            }
        )

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
    print(f"wrote {len(rows)} latest-default-branch Apache rows to {args.out}")
    print(f"sha256={hashlib.sha256(args.out.read_bytes()).hexdigest()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
