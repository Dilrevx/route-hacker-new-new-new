#!/usr/bin/env python3
"""Freeze a deterministic multi-GPU code-cache plan for the P4 external intake.

This plans only frozen code embedding.  It assigns the already-admitted P4
repositories to a fixed small GPU set by longest-processing-time greedy load
balancing over their generic candidate counts.  The plan has no query text,
anchor text, retrieval score, model fit, or ranking.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


SCHEMA_VERSION = "p4_external_cache_plan_v1"


def now_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def write_json(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def normalize_text(value: Any) -> str:
    return str(value or "").strip()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--selected-cases", type=Path, required=True)
    parser.add_argument("--coverage", type=Path, required=True)
    parser.add_argument("--candidate-pool", type=Path, required=True)
    parser.add_argument("--pool-summary", type=Path, required=True)
    parser.add_argument("--gpu-indices", default="0,1,2,3")
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    paths = {
        "selected_cases": args.selected_cases.resolve(),
        "coverage": args.coverage.resolve(),
        "candidate_pool": args.candidate_pool.resolve(),
        "pool_summary": args.pool_summary.resolve(),
    }
    missing = [str(path) for path in paths.values() if not path.is_file()]
    if missing:
        raise FileNotFoundError(f"missing P4 cache-plan input(s): {missing}")
    output_dir = args.output_dir.resolve()
    if output_dir.exists():
        raise FileExistsError(f"refusing to overwrite P4 cache plan: {output_dir}")
    gpu_indices = [int(value) for value in args.gpu_indices.split(",") if value.strip()]
    if not gpu_indices or len(set(gpu_indices)) != len(gpu_indices):
        raise ValueError(f"invalid GPU indices: {args.gpu_indices}")

    cases = read_jsonl(paths["selected_cases"])
    coverage_by_case = {
        normalize_text(row.get("case_id")): row for row in read_jsonl(paths["coverage"])
    }
    pool_summary = read_json(paths["pool_summary"])
    expected_pool_candidates = int(pool_summary.get("summary", {}).get("candidate_count") or 0)
    pool_repo_counts: Counter[str] = Counter()
    for row in read_jsonl(paths["candidate_pool"]):
        pool_repo_counts[normalize_text(row.get("repo_key"))] += 1
    if sum(pool_repo_counts.values()) != expected_pool_candidates:
        raise ValueError("pool summary candidate count disagrees with parsed candidate pool")

    repo_rows: list[dict[str, Any]] = []
    for case in cases:
        case_id = normalize_text(case.get("case_id"))
        repo_key = normalize_text(case.get("repo_key"))
        coverage = coverage_by_case.get(case_id)
        if coverage is None or not coverage.get("covered"):
            raise ValueError(f"selected external case is not generic-covered: {case_id}")
        candidate_count = int(pool_repo_counts.get(repo_key) or 0)
        if candidate_count != int(coverage.get("candidate_count") or 0):
            raise ValueError(f"candidate count mismatch for {case_id}/{repo_key}")
        if candidate_count <= 0:
            raise ValueError(f"selected external repo has no candidates: {repo_key}")
        repo_rows.append(
            {
                "case_id": case_id,
                "repo_key": repo_key,
                "track_id": normalize_text(case.get("track_id")),
                "candidate_count": candidate_count,
                "positive_candidate_count": int(
                    coverage.get("positive_candidate_count") or 0
                ),
            }
        )

    workers = [
        {"worker_id": f"p4-cache-gpu-{index}", "gpu_index": index, "candidate_count": 0, "repos": []}
        for index in gpu_indices
    ]
    for repo_row in sorted(
        repo_rows,
        key=lambda row: (-int(row["candidate_count"]), row["repo_key"]),
    ):
        worker = min(
            workers,
            key=lambda item: (
                int(item["candidate_count"]),
                int(item["gpu_index"]),
            ),
        )
        worker["repos"].append(repo_row)
        worker["candidate_count"] += int(repo_row["candidate_count"])
    for worker in workers:
        worker["repos"] = sorted(worker["repos"], key=lambda row: row["repo_key"])
        worker["repo_count"] = len(worker["repos"])

    output_dir.mkdir(parents=True, exist_ok=False)
    write_jsonl(output_dir / "selected_repositories.v1.jsonl", sorted(repo_rows, key=lambda row: row["repo_key"]))
    write_json(output_dir / "cache_worker_plan.v1.json", {"workers": workers})
    summary = {
        "schema_version": SCHEMA_VERSION,
        "status": "frozen_plan_no_embedding_or_retrieval",
        "created_at": now_utc(),
        "inputs": {
            key: {"path": str(path), "sha256": sha256_file(path)}
            for key, path in paths.items()
        },
        "cache_contract": {
            "model": "Qwen3-Embedding-0.6B frozen base",
            "code_encoder_training": False,
            "query_encoder_training": False,
            "candidate_scope": "exactly selected_external_cases.v1.jsonl repository keys",
            "candidate_text_serialization": "candidate text field truncated to 4000 chars",
            "expected_embedding": "float32 L2-normalized 1024d",
            "worker_assignment": "deterministic LPT by generic candidate count",
        },
        "scope": {
            "selected_case_count": len(cases),
            "selected_repo_count": len(repo_rows),
            "selected_candidate_count": sum(int(row["candidate_count"]) for row in repo_rows),
            "gpu_indices": gpu_indices,
            "worker_candidate_counts": {
                worker["worker_id"]: worker["candidate_count"] for worker in workers
            },
            "worker_repo_counts": {
                worker["worker_id"]: worker["repo_count"] for worker in workers
            },
        },
        "boundary": (
            "This is a frozen code-cache plan only. It does not create query "
            "embeddings, source-point features, rankings, model updates, or "
            "external evaluation results."
        ),
    }
    write_json(output_dir / "summary.json", summary)
    manifest = {"artifact": output_dir.name, "files": {}}
    for path in sorted(output_dir.iterdir()):
        if path.is_file():
            manifest["files"][path.name] = {
                "sha256": sha256_file(path),
                "bytes": path.stat().st_size,
            }
    write_json(output_dir / "manifest.v1.json", manifest)
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
