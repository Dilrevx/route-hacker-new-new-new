#!/usr/bin/env python3
"""Evaluate BM25, frozen embedding, and simple fusion on an expanded split manifest."""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np

try:
    from scripts.eval_guideline_m5_53_strict_generic_bm25_v1 import percentile, tokenize, write_json, write_jsonl
    from scripts.eval_guideline_m5_54_strict_generic_embedding_v1 import (
        DEFAULT_MODEL_PATH,
        candidate_text,
        encode_repo_docs,
        encode_with_sentence_transformer,
        load_sentence_transformer,
        normalize_vectors,
    )
    from scripts.eval_guideline_m5_56_strict_generic_fusion_v1 import bm25_score_array, rank_order, ranks_from_scores, write_text, zscore
    from scripts.eval_guideline_m5_65_residual_fusion_lane_v1 import load_needed_candidates, read_jsonl
except ModuleNotFoundError:
    from eval_guideline_m5_53_strict_generic_bm25_v1 import percentile, tokenize, write_json, write_jsonl
    from eval_guideline_m5_54_strict_generic_embedding_v1 import (
        DEFAULT_MODEL_PATH,
        candidate_text,
        encode_repo_docs,
        encode_with_sentence_transformer,
        load_sentence_transformer,
        normalize_vectors,
    )
    from eval_guideline_m5_56_strict_generic_fusion_v1 import bm25_score_array, rank_order, ranks_from_scores, write_text, zscore
    from eval_guideline_m5_65_residual_fusion_lane_v1 import load_needed_candidates, read_jsonl


SCHEMA_VERSION = "1.0"
K_VALUES = (10, 30, 100, 200, 500)
METHODS = ("bm25", "embedding", "rrf_bm25_embedding", "zscore_sum")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def split_rows(path: Path, split: str) -> list[dict[str, Any]]:
    return [row for row in read_jsonl(path) if str(row.get("inner_split")) == split]


def first_positive(order: np.ndarray, scores: np.ndarray, candidate_ids: list[str], positive_ids: set[str]) -> tuple[int | None, str | None, float | None]:
    for rank, index in enumerate(order, start=1):
        candidate_id = candidate_ids[int(index)]
        if candidate_id in positive_ids:
            return rank, candidate_id, float(scores[int(index)])
    return None, None, None


def add_method_result(row: dict[str, Any], method: str, order: np.ndarray, scores: np.ndarray, candidate_ids: list[str], positive_ids: set[str]) -> None:
    rank, candidate_id, score = first_positive(order, scores, candidate_ids, positive_ids)
    row[f"{method}_rank"] = rank
    row[f"{method}_candidate_id"] = candidate_id
    row[f"{method}_score"] = score
    for k in K_VALUES:
        row[f"{method}_hit_at_{k}"] = bool(rank is not None and rank <= k)


def summarize(rows: list[dict[str, Any]], method: str) -> dict[str, Any]:
    ranks = [float(row[f"{method}_rank"]) for row in rows if row.get(f"{method}_rank")]
    out: dict[str, Any] = {
        "case_count": len(rows),
        "MRR": sum(1.0 / rank for rank in ranks) / len(rows) if rows else None,
        "first_rank_p50": percentile(ranks, 0.50),
        "first_rank_p75": percentile(ranks, 0.75),
        "first_rank_p90": percentile(ranks, 0.90),
        "first_rank_p95": percentile(ranks, 0.95),
        "first_rank_p99": percentile(ranks, 0.99),
    }
    for k in K_VALUES:
        out[f"R@{k}"] = sum(1 for row in rows if row[f"{method}_hit_at_{k}"]) / len(rows) if rows else None
    return out


def compare_at_k(rows: list[dict[str, Any]], left: str, right: str, k: int) -> dict[str, Any]:
    rescues: list[dict[str, Any]] = []
    regressions: list[dict[str, Any]] = []
    for row in rows:
        left_hit = bool(row[f"{left}_hit_at_{k}"])
        right_hit = bool(row[f"{right}_hit_at_{k}"])
        item = {
            "case_id": row["case_id"],
            "track_id": row["track_id"],
            "repo_key": row["repo_key"],
            f"{left}_rank": row[f"{left}_rank"],
            f"{right}_rank": row[f"{right}_rank"],
        }
        if right_hit and not left_hit:
            rescues.append(item)
        if left_hit and not right_hit:
            regressions.append(item)
    return {
        "left": left,
        "right": right,
        "k": k,
        "rescues": len(rescues),
        "regressions": len(regressions),
        "rescue_rows": rescues,
        "regression_rows": regressions,
    }


def track_metrics(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    by_track: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_track[str(row["track_id"])].append(row)
    return {
        track: {method: summarize(track_rows, method) for method in METHODS}
        for track, track_rows in sorted(by_track.items())
    }


def evaluate(
    split_manifest: Path,
    generic_pool: Path,
    *,
    split: str,
    model_path: str,
    device: str | None,
    batch_size: int,
    chunk_size: int,
    max_seq_length: int,
    text_field: str,
    max_chars: int,
    cache_dir: Path | None,
    model: Any | None = None,
    encode_fn=encode_with_sentence_transformer,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    rows = split_rows(split_manifest, split)
    repos_needed = {str(row["repo_key"]) for row in rows}
    candidates_by_repo = load_needed_candidates(generic_pool, repos_needed)
    missing_repos = sorted(repos_needed - set(candidates_by_repo))
    if missing_repos:
        raise ValueError(f"candidate pool missing repos: {missing_repos[:10]}")

    if model is None:
        model = load_sentence_transformer(model_path, device, max_seq_length)

    cache_key = {
        "model_path": model_path,
        "text_field": text_field,
        "max_chars": max_chars,
        "normalized": True,
        "schema": "1.0",
    }
    repo_embeddings: dict[str, np.ndarray] = {}
    repo_candidate_ids: dict[str, list[str]] = {}
    repo_cache_status: dict[str, str] = {}
    repo_items = sorted(candidates_by_repo.items())
    for repo_index, (repo_key, candidates) in enumerate(repo_items, start=1):
        docs = [candidate_text(candidate, text_field=text_field, max_chars=max_chars) for candidate in candidates]
        candidate_ids = [str(candidate.get("candidate_id") or "") for candidate in candidates]
        vectors, status = encode_repo_docs(
            repo_key=repo_key,
            docs=docs,
            candidate_ids=candidate_ids,
            model=model,
            encode_fn=encode_fn,
            batch_size=batch_size,
            chunk_size=chunk_size,
            cache_dir=cache_dir,
            cache_key=cache_key,
            repo_index=repo_index,
            repo_total=len(repo_items),
        )
        repo_embeddings[repo_key] = vectors
        repo_candidate_ids[repo_key] = candidate_ids
        repo_cache_status[repo_key] = status

    query_cache: dict[str, np.ndarray] = {}
    case_rows: list[dict[str, Any]] = []
    for source_row in rows:
        repo_key = str(source_row["repo_key"])
        candidates = candidates_by_repo[repo_key]
        candidate_ids = repo_candidate_ids[repo_key]
        positive_ids = {str(candidate_id) for candidate_id in source_row["positive_candidate_ids"]}
        query = str(source_row["query_text"])
        bm25 = bm25_score_array(tokenize(query), candidates)
        query_vec = query_cache.get(query)
        if query_vec is None:
            query_vec = normalize_vectors(encode_fn(model, [query], 1))[0]
            query_cache[query] = query_vec
        embedding = repo_embeddings[repo_key] @ query_vec
        bm25_ranks = ranks_from_scores(bm25, candidate_ids)
        embedding_ranks = ranks_from_scores(embedding, candidate_ids)
        rrf = (1.0 / (60 + bm25_ranks)) + (1.0 / (60 + embedding_ranks))
        zsum = zscore(bm25) + zscore(embedding)
        method_scores = {
            "bm25": bm25,
            "embedding": embedding,
            "rrf_bm25_embedding": rrf.astype("float32", copy=False),
            "zscore_sum": zsum.astype("float32", copy=False),
        }
        row = {
            "case_id": source_row["case_id"],
            "original_case_id": source_row.get("original_case_id"),
            "track_id": source_row["track_id"],
            "repo_key": repo_key,
            "inner_split": source_row["inner_split"],
            "candidate_count": len(candidates),
            "positive_candidate_count": len(positive_ids),
            "source_label_ids": source_row.get("source_label_ids"),
            "source_target_count": source_row.get("source_target_count"),
            "query_text": query,
        }
        for method, scores in method_scores.items():
            add_method_result(row, method, rank_order(scores, candidate_ids), scores, candidate_ids, positive_ids)
        case_rows.append(row)

    metrics = {method: summarize(case_rows, method) for method in METHODS}
    comparisons = {
        method: compare_at_k(case_rows, "bm25", method, 500)
        for method in METHODS
        if method != "bm25"
    }
    summary = {
        "schema_version": SCHEMA_VERSION,
        "status": "completed",
        "created_at": utc_now(),
        "decision": "m5_86_expanded_split_bm25_embedding_completed",
        "scope": {
            "split_manifest": str(split_manifest),
            "split": split,
            "cases": len(case_rows),
            "repos": len(repos_needed),
            "generic_pool": str(generic_pool),
        },
        "counts": {
            "candidate_rows_loaded": sum(len(v) for v in candidates_by_repo.values()),
            "query_texts_encoded": len(query_cache),
            "embedding_repos_loaded": len(repo_embeddings),
        },
        "metrics": metrics,
        "track_metrics": track_metrics(case_rows),
        "comparisons_at_500_vs_bm25": comparisons,
        "cache_status_counts": {
            status: list(repo_cache_status.values()).count(status)
            for status in sorted(set(repo_cache_status.values()))
        },
        "model": {
            "model_path": model_path,
            "device": device,
            "batch_size": batch_size,
            "chunk_size": chunk_size,
            "max_seq_length": max_seq_length,
            "text_field": text_field,
            "max_chars": max_chars,
            "cache_dir": str(cache_dir) if cache_dir else None,
        },
        "method_boundary": {
            "candidate_universe": "expanded bridge full-repo generic function+sliding_window plus explicit materialized generic supplement",
            "uses_training": False,
            "uses_frozen_zero_shot_embedding": True,
            "uses_bm25_keyword_baseline": True,
            "deployable_fusion_without_oracle_labels": True,
            "non_anchor_candidates_are_unknown_not_negative": True,
            "frozen_test_touched": False,
        },
    }
    return summary, sorted(case_rows, key=lambda row: (str(row["track_id"]), str(row["case_id"])))


def fmt(value: Any) -> str:
    if value is None:
        return "n/a"
    if isinstance(value, float):
        return f"{value:.6f}"
    return str(value)


def render_markdown(summary: dict[str, Any]) -> str:
    lines = [
        "# Guideline Anchor Retrieval M5.86: Expanded Split BM25/Embedding Baselines",
        "",
        f"**Status:** {summary['status']}",
        f"**Decision:** `{summary['decision']}`",
        "",
        "## Purpose",
        "",
        "M5.86 evaluates deployable BM25, frozen embedding, and simple BM25+embedding fusion baselines directly on the M5.84 expanded split manifest.",
        "",
        "## Scope",
        "",
        "```json",
        json.dumps(summary["scope"], ensure_ascii=False, indent=2, sort_keys=True),
        "```",
        "",
        "## Metrics",
        "",
        "| Method | R@10 | R@30 | R@100 | R@200 | R@500 | MRR | p50 rank | p90 rank | p99 rank |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for method in METHODS:
        metric = summary["metrics"][method]
        lines.append(
            f"| {method} | {fmt(metric['R@10'])} | {fmt(metric['R@30'])} | {fmt(metric['R@100'])} | "
            f"{fmt(metric['R@200'])} | {fmt(metric['R@500'])} | {fmt(metric['MRR'])} | "
            f"{fmt(metric['first_rank_p50'])} | {fmt(metric['first_rank_p90'])} | {fmt(metric['first_rank_p99'])} |"
        )
    lines.extend(
        [
            "",
            "## Top-500 Comparison Against BM25",
            "",
            "```json",
            json.dumps(summary["comparisons_at_500_vs_bm25"], ensure_ascii=False, indent=2, sort_keys=True),
            "```",
            "",
            "## Cache",
            "",
            "```json",
            json.dumps(summary["cache_status_counts"], ensure_ascii=False, indent=2, sort_keys=True),
            "```",
            "",
            "## Boundary",
            "",
            "```json",
            json.dumps(summary["method_boundary"], ensure_ascii=False, indent=2, sort_keys=True),
            "```",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--split-manifest", type=Path, default=Path("/tmp/m5_83_expanded_inner_split_manifest_v1/split_manifest.jsonl"))
    parser.add_argument("--generic-pool", type=Path, default=Path("/tmp/m5_83_expanded_inner_split_manifest_v1/candidate_pool.v1.jsonl"))
    parser.add_argument("--split", default="inner_val")
    parser.add_argument("--output-dir", type=Path, default=Path("/tmp/m5_86_expanded_split_bm25_embedding_v1"))
    parser.add_argument("--model-path", default=DEFAULT_MODEL_PATH)
    parser.add_argument("--device", default="cpu")
    parser.add_argument("--batch-size", type=int, default=64)
    parser.add_argument("--chunk-size", type=int, default=8192)
    parser.add_argument("--max-seq-length", type=int, default=512)
    parser.add_argument("--text-field", default="text")
    parser.add_argument("--max-chars", type=int, default=4000)
    parser.add_argument("--cache-dir", type=Path, default=Path("/tmp/m5_86_expanded_split_bm25_embedding_v1/cache"))
    args = parser.parse_args()
    summary, rows = evaluate(
        args.split_manifest,
        args.generic_pool,
        split=args.split,
        model_path=args.model_path,
        device=args.device,
        batch_size=args.batch_size,
        chunk_size=args.chunk_size,
        max_seq_length=args.max_seq_length,
        text_field=args.text_field,
        max_chars=args.max_chars,
        cache_dir=args.cache_dir,
    )
    write_json(args.output_dir / "summary.json", summary)
    write_jsonl(args.output_dir / "case_ranks.jsonl", rows)
    write_text(args.output_dir / "expanded_split_bm25_embedding.md", render_markdown(summary))
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
