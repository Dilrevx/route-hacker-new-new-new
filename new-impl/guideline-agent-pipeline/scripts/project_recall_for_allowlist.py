#!/usr/bin/env python3
"""Project a full recall JSONL artifact to an ordered allowlist and Top-K."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


RETAINED_FIELDS = (
    "identity_key",
    "case_id",
    "repo_key",
    "repo_url",
    "checkout_revision",
    "hcvr_type",
    "guideline",
    "state",
    "candidate_count",
    "known_anchor_count",
    "best_known_anchor_rank",
    "hit_at_top_k",
    "index",
    "duration_seconds",
    "snapshot",
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--recall-results", type=Path, required=True)
    parser.add_argument("--allowlist", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--top-k", type=int, required=True)
    args = parser.parse_args()
    if args.top_k < 1:
        raise SystemExit("--top-k must be positive")

    identities = [
        json.loads(line)["identity_key"]
        for line in args.allowlist.open(encoding="utf-8")
        if line.strip()
    ]
    if len(identities) != len(set(identities)):
        raise SystemExit("allowlist contains duplicate identity_key values")
    wanted = set(identities)
    selected: dict[str, dict[str, object]] = {}
    source_rows = 0
    with args.recall_results.open(encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            source_rows += 1
            row = json.loads(line)
            identity = row.get("identity_key")
            if identity not in wanted:
                continue
            compact = {key: row.get(key) for key in RETAINED_FIELDS if key in row}
            compact["top_anchors"] = list(row.get("top_anchors") or [])[: args.top_k]
            selected[str(identity)] = compact

    missing = [identity for identity in identities if identity not in selected]
    empty = [identity for identity in identities if not selected.get(identity, {}).get("top_anchors")]
    if missing or empty:
        raise SystemExit(f"invalid recall projection: missing={missing[:10]} empty={empty[:10]}")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as handle:
        for identity in identities:
            handle.write(json.dumps(selected[identity], ensure_ascii=False, sort_keys=True) + "\n")
    manifest = {
        "schema_version": "hcvr_recall_allowlist_projection.v1",
        "source_recall_results": str(args.recall_results.resolve()),
        "source_recall_sha256": sha256_file(args.recall_results),
        "source_row_count": source_rows,
        "allowlist": str(args.allowlist.resolve()),
        "allowlist_sha256": sha256_file(args.allowlist),
        "case_count": len(identities),
        "top_k": args.top_k,
        "output": str(args.output.resolve()),
        "output_sha256": sha256_file(args.output),
    }
    manifest_path = args.output.with_suffix(".manifest.json")
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(manifest, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
