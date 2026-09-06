#!/usr/bin/env python3
"""Build the fixed 71-case P3C64 Top160 stratified audit subset."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Iterable


DEFAULT_SEED = "p3c64-half-fixed-case-top160-v1"
DEFAULT_TOTAL = 71
DEFAULT_PRIMARY_BUDGET = 160


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                rows.append(json.loads(line))
    return rows


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def stable_sample_key(seed: str, identity_key: str) -> str:
    return hashlib.sha256(f"{seed}\0{identity_key}".encode("utf-8")).hexdigest()


def rank_value(row: dict[str, Any]) -> int | None:
    value = row.get("best_known_anchor_rank")
    if isinstance(value, int) and value > 0:
        return value
    if isinstance(value, str) and value.isdigit() and int(value) > 0:
        return int(value)
    return None


def index_rank_rows(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    indexed: dict[str, dict[str, Any]] = {}
    duplicates: list[str] = []
    for index, row in enumerate(rows):
        identity = row.get("identity_key")
        if not isinstance(identity, str) or not identity:
            raise ValueError(f"rank row {index} missing identity_key")
        if identity in indexed:
            duplicates.append(identity)
            continue
        indexed[identity] = row
    if duplicates:
        raise ValueError(f"duplicate rank-table identities: {sorted(duplicates)[:10]}")
    return indexed


def compute_stratum_targets(hit_count: int, miss_count: int, total: int) -> tuple[int, int]:
    full_total = hit_count + miss_count
    if full_total < 1:
        raise ValueError("full_total must be positive")
    if total < 1 or total > full_total:
        raise ValueError("sample total must be between 1 and the full case count")
    hit_target = round(total * hit_count / full_total)
    hit_target = min(max(hit_target, 0), hit_count)
    miss_target = total - hit_target
    if miss_target > miss_count:
        miss_target = miss_count
        hit_target = total - miss_target
    return hit_target, miss_target


def make_subset(
    *,
    rank_rows: list[dict[str, Any]],
    identity_rows: list[dict[str, Any]],
    seed: str,
    total: int,
    primary_budget: int,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    rank_by_identity = index_rank_rows(rank_rows)
    selected_identities: list[str] = []
    seen: set[str] = set()
    for index, row in enumerate(identity_rows):
        identity = row.get("identity_key")
        if not isinstance(identity, str) or not identity:
            raise ValueError(f"identity row {index} missing identity_key")
        if identity in seen:
            raise ValueError(f"duplicate identity allowlist row: {identity}")
        if identity not in rank_by_identity:
            raise ValueError(f"identity missing from rank table: {identity}")
        selected_identities.append(identity)
        seen.add(identity)

    extra_rank_identities = sorted(set(rank_by_identity) - seen)
    if extra_rank_identities:
        raise ValueError(f"rank table has identities outside allowlist: {extra_rank_identities[:10]}")

    annotated: list[dict[str, Any]] = []
    for original_index, identity in enumerate(selected_identities, start=1):
        row = dict(rank_by_identity[identity])
        rank = rank_value(row)
        is_hit = rank is not None and rank <= primary_budget
        row["original_index"] = original_index
        row["topk_budget"] = primary_budget
        row["topk_hit"] = is_hit
        row["topk_stratum"] = "hit" if is_hit else "miss"
        row["sample_key"] = stable_sample_key(seed, identity)
        annotated.append(row)

    hit_pool = [row for row in annotated if row["topk_hit"]]
    miss_pool = [row for row in annotated if not row["topk_hit"]]
    hit_target, miss_target = compute_stratum_targets(len(hit_pool), len(miss_pool), total)
    picked = set()
    for row in sorted(hit_pool, key=lambda item: item["sample_key"])[:hit_target]:
        picked.add(row["identity_key"])
    for row in sorted(miss_pool, key=lambda item: item["sample_key"])[:miss_target]:
        picked.add(row["identity_key"])

    selected_rows: list[dict[str, Any]] = []
    for row in annotated:
        if row["identity_key"] in picked:
            output = dict(row)
            output["selection_index"] = len(selected_rows) + 1
            selected_rows.append(output)

    manifest = {
        "schema_version": "hcvr_p3c64_half_fixed_case_subset.v1",
        "seed": seed,
        "selection_method": (
            "Split fixed143 identities by P3C64 best_known_anchor_rank <= primary_budget, "
            "sample each stratum by sha256(seed + NUL + identity_key), then emit selected rows "
            "in original fixed143 order."
        ),
        "primary_budget": primary_budget,
        "full_case_count": len(annotated),
        "sample_case_count": len(selected_rows),
        "full_strata": {
            "top160_hit": len(hit_pool),
            "top160_miss": len(miss_pool),
        },
        "sample_strata": {
            "top160_hit": sum(1 for row in selected_rows if row["topk_hit"]),
            "top160_miss": sum(1 for row in selected_rows if not row["topk_hit"]),
        },
        "target_strata": {
            "top160_hit": hit_target,
            "top160_miss": miss_target,
        },
        "selected_identity_count": len({row["identity_key"] for row in selected_rows}),
        "selected_identity_order": [row["identity_key"] for row in selected_rows],
    }
    return selected_rows, manifest


def markdown_report(manifest: dict[str, Any]) -> str:
    lines = [
        "# P3C64 Half Fixed Case Subset",
        "",
        "This directory defines the fixed 71-case subset for Backend-B model ablation probes.",
        "The split preserves the P3C64 Top160 recalled/not-recalled ratio from the frozen Unified V2 143-case paper-eval set.",
        "",
        "## Selection",
        "",
        f"- Seed: `{manifest['seed']}`",
        f"- Primary budget: Top{manifest['primary_budget']}",
        f"- Full set: {manifest['full_case_count']} cases",
        (
            "- Full strata: "
            f"{manifest['full_strata']['top160_hit']} Top160-hit, "
            f"{manifest['full_strata']['top160_miss']} Top160-miss"
        ),
        (
            "- Half subset: "
            f"{manifest['sample_case_count']} cases "
            f"({manifest['sample_strata']['top160_hit']} Top160-hit, "
            f"{manifest['sample_strata']['top160_miss']} Top160-miss)"
        ),
        "",
        "## Input Hashes",
        "",
        "| Input | SHA256 |",
        "| --- | --- |",
    ]
    for item in manifest["inputs"]:
        lines.append(f"| `{item['path']}` | `{item['sha256']}` |")
    lines.extend(
        [
            "",
            "## Artifacts",
            "",
            "- `selected_identity_allowlist.jsonl`: identity allowlist for the 71-case audit run.",
            "- `selected_case_rank_table.jsonl`: selected rank rows with original index, sample key, and Top160 stratum.",
            "- `manifest.json`: machine-readable provenance for the split.",
            "",
            "## Reproduce",
            "",
            "```bash",
            "python3 new-impl/new-guideline/scripts/make_p3c64_half_fixed_case_subset.py \\",
            "  --rank-table new-impl/new-guideline/results/p3c64-fixed143-paper-eval-20260820/p3c64_case_rank_table.jsonl \\",
            "  --identity-file new-impl/new-guideline/results/p3c64-fixed143-paper-eval-20260820/paper_eval_143_identities.jsonl \\",
            "  --output-dir new-impl/new-guideline/results/p3c64-half-fixed-case-top160-v1",
            "```",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rank-table", type=Path, required=True)
    parser.add_argument("--identity-file", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--seed", default=DEFAULT_SEED)
    parser.add_argument("--total", type=int, default=DEFAULT_TOTAL)
    parser.add_argument("--primary-budget", type=int, default=DEFAULT_PRIMARY_BUDGET)
    args = parser.parse_args()

    rank_rows = read_jsonl(args.rank_table)
    identity_rows = read_jsonl(args.identity_file)
    selected_rows, manifest = make_subset(
        rank_rows=rank_rows,
        identity_rows=identity_rows,
        seed=args.seed,
        total=args.total,
        primary_budget=args.primary_budget,
    )
    manifest["inputs"] = [
        {
            "path": str(args.rank_table),
            "sha256": sha256_file(args.rank_table),
            "row_count": len(rank_rows),
        },
        {
            "path": str(args.identity_file),
            "sha256": sha256_file(args.identity_file),
            "row_count": len(identity_rows),
        },
    ]

    output_dir = args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)
    write_jsonl(
        output_dir / "selected_identity_allowlist.jsonl",
        ({"identity_key": row["identity_key"]} for row in selected_rows),
    )
    write_jsonl(output_dir / "selected_case_rank_table.jsonl", selected_rows)
    write_json(output_dir / "manifest.json", manifest)
    (output_dir / "README.md").write_text(markdown_report(manifest), encoding="utf-8")

    print(
        json.dumps(
            {
                "output_dir": str(output_dir),
                "sample_case_count": manifest["sample_case_count"],
                "sample_strata": manifest["sample_strata"],
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
