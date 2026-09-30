#!/usr/bin/env python3
"""Evaluate deployable BM25/embedding fusion baselines on M5.52 strict bindings."""

from __future__ import annotations

import argparse
import json
import math
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np

try:
    from scripts.eval_guideline_m5_53_strict_generic_bm25_v1 import (
        FALLBACK_TRACK_QUERIES,
        build_case_targets,
        load_track_queries,
        percentile,
        read_json,
        read_jsonl,
        tokenize,
        write_json,
        write_jsonl,
    )
    from scripts.eval_guideline_m5_54_strict_generic_embedding_v1 import (
        candidate_text,
        fingerprint_docs,
        normalize_vectors,
        read_cached_embeddings,
        stable_name,
    )
except ModuleNotFoundError:
    from eval_guideline_m5_53_strict_generic_bm25_v1 import (
        FALLBACK_TRACK_QUERIES,
        build_case_targets,
        load_track_queries,
        percentile,
        read_json,
        read_jsonl,
        tokenize,
        write_json,
        write_jsonl,
    )
    from eval_guideline_m5_54_strict_generic_embedding_v1 import (
        candidate_text,
        fingerprint_docs,
        normalize_vectors,
        read_cached_embeddings,
        stable_name,
    )


SCHEMA_VERSION = "1.0"
K_VALUES = (10, 30, 100, 200, 500)
METHODS = ("bm25", "embedding", "rrf_bm25_embedding", "zscore_sum")
DEFAULT_MODEL_PATH = "/data/lhq/.cache/huggingface/hub/models--Qwen--Qwen3-Embedding-0.6B/snapshots/97b0c614be4d77ee51c0cef4e5f07c00f9eb65b3"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def bm25_score_array(query_tokens: list[str], docs: list[dict[str, Any]]) -> np.ndarray:
    tokenized = [tokenize(str(doc.get("text") or "")) for doc in docs]
    lengths = [len(tokens) for tokens in tokenized]
    avgdl = sum(lengths) / len(lengths) if lengths else 0.0
    df: Counter[str] = Counter()
    for tokens in tokenized:
        df.update(set(tokens))
    n_docs = len(docs)
    query_counts = Counter(query_tokens)
    scores = np.zeros(n_docs, dtype="float32")
    k1 = 1.5
    b = 0.75
    for index, tokens in enumerate(tokenized):
        tf = Counter(tokens)
        doc_len = lengths[index]
        score = 0.0
        for token, qtf in query_counts.items():
            freq = tf.get(token, 0)
            if freq == 0:
                continue
            idf = math.log(1.0 + (n_docs - df[token] + 0.5) / (df[token] + 0.5))
            denom = freq + k1 * (1.0 - b + b * (doc_len / avgdl if avgdl else 0.0))
            score += qtf * idf * ((freq * (k1 + 1.0)) / denom)
        scores[index] = score
    return scores


def rank_order(scores: np.ndarray, candidate_ids: list[str]) -> np.ndarray:
    return np.lexsort((np.asarray(candidate_ids), -scores))


def ranks_from_scores(scores: np.ndarray, candidate_ids: list[str]) -> np.ndarray:
    order = rank_order(scores, candidate_ids)
    ranks = np.empty(len(order), dtype=np.int64)
    ranks[order] = np.arange(1, len(order) + 1, dtype=np.int64)
    return ranks


def zscore(scores: np.ndarray) -> np.ndarray:
    if len(scores) == 0:
        return scores.astype("float32", copy=False)
    mean = float(np.mean(scores))
    std = float(np.std(scores))
    if std <= 1e-12:
        return np.zeros_like(scores, dtype="float32")
    return ((scores - mean) / std).astype("float32", copy=False)


def load_query_embedding(query_embeddings_path: Path, query_text: str) -> np.ndarray:
    payload = read_json(query_embeddings_path)
    vectors = payload.get("vectors") or {}
    vector = vectors.get(query_text)
    if vector is None:
        raise ValueError(f"query embedding missing for text: {query_text[:80]!r}")
    return normalize_vectors(np.asarray([vector], dtype="float32"))[0]


def load_repo_embeddings(
    *,
    repo_key: str,
    candidates: list[dict[str, Any]],
    cache_dir: Path,
    model_path: str,
    text_field: str,
    max_chars: int,
) -> np.ndarray:
    docs = [candidate_text(row, text_field=text_field, max_chars=max_chars) for row in candidates]
    candidate_ids = [str(row.get("candidate_id") or "") for row in candidates]
    metadata = {
        "repo_key": repo_key,
        "doc_count": len(docs),
        "fingerprint": fingerprint_docs(docs, candidate_ids),
        "cache_key": {
            "model_path": model_path,
            "text_field": text_field,
            "max_chars": max_chars,
            "normalized": True,
            "schema": "1.0",
        },
    }
    cache_path = cache_dir / f"{stable_name(repo_key)}.npz"
    embeddings, status = read_cached_embeddings(cache_path, metadata)
    if embeddings is None:
        raise ValueError(f"missing or stale embedding cache for {repo_key}: {cache_path} status={status}")
    return embeddings


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


def evaluate(
    binding_dir: Path,
    generic_pool: Path,
    track_queries_path: Path | None,
    query_embeddings_path: Path,
    cache_dir: Path,
    *,
    model_path: str = DEFAULT_MODEL_PATH,
    text_field: str = "text",
    max_chars: int = 4000,
    rrf_k: int = 60,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    binding_summary = read_json(binding_dir / "summary.json")
    bindings = read_jsonl(binding_dir / "generic_target_bindings.jsonl")
    cases = build_case_targets(bindings)
    repos_needed = {str(case["repo_key"]) for case in cases.values()}
    candidates_by_repo: dict[str, list[dict[str, Any]]] = defaultdict(list)
    rows_scanned = 0
    with generic_pool.open(encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            rows_scanned += 1
            row = json.loads(line)
            repo_key = str(row.get("repo_key") or "")
            if repo_key in repos_needed:
                candidates_by_repo[repo_key].append(row)

    track_queries = load_track_queries(track_queries_path)
    repo_embeddings = {
        repo_key: load_repo_embeddings(
            repo_key=repo_key,
            candidates=candidates,
            cache_dir=cache_dir,
            model_path=model_path,
            text_field=text_field,
            max_chars=max_chars,
        )
        for repo_key, candidates in sorted(candidates_by_repo.items())
    }

    case_rows: list[dict[str, Any]] = []
    for case in cases.values():
        repo_key = str(case["repo_key"])
        candidates = candidates_by_repo[repo_key]
        candidate_ids = [str(row.get("candidate_id") or "") for row in candidates]
        positive_ids = set(case["positive_candidate_ids"])
        query = track_queries.get(
            str(case["track_id"]) or "",
            FALLBACK_TRACK_QUERIES.get(str(case["track_id"]) or "", "Find security-relevant code matching the guideline."),
        )
        bm25 = bm25_score_array(tokenize(query), candidates)
        query_vec = load_query_embedding(query_embeddings_path, query)
        embedding = repo_embeddings[repo_key] @ query_vec
        bm25_ranks = ranks_from_scores(bm25, candidate_ids)
        embedding_ranks = ranks_from_scores(embedding, candidate_ids)
        rrf = (1.0 / (rrf_k + bm25_ranks)) + (1.0 / (rrf_k + embedding_ranks))
        zsum = zscore(bm25) + zscore(embedding)
        method_scores = {
            "bm25": bm25,
            "embedding": embedding,
            "rrf_bm25_embedding": rrf.astype("float32", copy=False),
            "zscore_sum": zsum.astype("float32", copy=False),
        }
        row: dict[str, Any] = {
            "case_id": case["case_id"],
            "track_id": case["track_id"],
            "repo_key": repo_key,
            "candidate_count": len(candidates),
            "positive_candidate_count": len(positive_ids),
            "source_target_count": case["source_target_count"],
        }
        for method, scores in method_scores.items():
            order = rank_order(scores, candidate_ids)
            first_rank = None
            first_candidate_id = None
            first_score = None
            for rank, index in enumerate(order, start=1):
                candidate_id = candidate_ids[int(index)]
                if candidate_id in positive_ids:
                    first_rank = rank
                    first_candidate_id = candidate_id
                    first_score = float(scores[int(index)])
                    break
            row[f"{method}_rank"] = first_rank
            row[f"{method}_candidate_id"] = first_candidate_id
            row[f"{method}_score"] = first_score
            for k in K_VALUES:
                row[f"{method}_hit_at_{k}"] = bool(first_rank and first_rank <= k)
        case_rows.append(row)

    metrics = {method: summarize(case_rows, method) for method in METHODS}
    by_track: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in case_rows:
        by_track[str(row["track_id"])].append(row)
    track_metrics = {
        track: {method: summarize(rows, method) for method in METHODS}
        for track, rows in sorted(by_track.items())
    }
    summary = {
        "schema_version": SCHEMA_VERSION,
        "status": "completed",
        "created_at": utc_now(),
        "decision": "strict_generic_deployable_fusion_baselines_completed",
        "binding_decision": binding_summary.get("decision"),
        "binding_counts": binding_summary.get("counts"),
        "generic_pool": str(generic_pool),
        "rows_scanned": rows_scanned,
        "counts": {
            "eval_cases": len(case_rows),
            "repos": len(repos_needed),
            "candidate_rows_loaded": sum(len(v) for v in candidates_by_repo.values()),
            "embedding_cache_repos_loaded": len(repo_embeddings),
        },
        "metrics": metrics,
        "track_metrics": track_metrics,
        "fusion_config": {
            "methods": list(METHODS),
            "rrf_k": rrf_k,
            "zscore_sum": "per-case per-repo zscore(bm25_score) + zscore(embedding_cosine)",
        },
        "model": {
            "embedding_cache_dir": str(cache_dir),
            "query_embeddings_path": str(query_embeddings_path),
            "model_path": model_path,
            "text_field": text_field,
            "max_chars": max_chars,
        },
        "method_boundary": {
            "candidate_universe": "frozen v39 full-repository generic function/sliding_window pool",
            "target_binding": "M5.52 strict full-overlap generic target bindings",
            "uses_supplement_pool_for_ranking": False,
            "uses_training": False,
            "uses_cached_frozen_embedding_scores": True,
            "deployable_fusion_without_oracle_labels": True,
            "non_anchor_candidates_are_unknown_not_negative": True,
        },
    }
    return summary, sorted(case_rows, key=lambda row: (str(row["track_id"]), str(row["case_id"])))


def render_markdown(summary: dict[str, Any]) -> str:
    lines = [
        "# Guideline Anchor Retrieval M5.56: Strict Generic Fusion Baselines",
        "",
        f"**Status:** {summary['status']}",
        f"**Decision:** `{summary['decision']}`",
        "",
        "## Purpose",
        "",
        "M5.56 turns the M5.55 oracle-complementarity finding into deployable, label-free fusion baselines over the same strict generic retrieval surface.",
        "",
        "## Counts",
        "",
        "| Metric | Value |",
        "| --- | ---: |",
    ]
    for key, value in summary["counts"].items():
        lines.append(f"| {key} | {value} |")
    lines.extend(["", "## Method Metrics", "", "| Method | @10 | @30 | @100 | @200 | @500 | MRR | p50 rank | p95 rank |", "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |"])
    for method in METHODS:
        m = summary["metrics"][method]
        lines.append(
            f"| {method} | {m['R@10']:.6f} | {m['R@30']:.6f} | {m['R@100']:.6f} | {m['R@200']:.6f} | {m['R@500']:.6f} | {m['MRR']:.6f} | {m['first_rank_p50']:.6f} | {m['first_rank_p95']:.6f} |"
        )
    lines.extend(
        [
            "",
            "## Fusion Config",
            "",
            "```json",
            json.dumps(summary["fusion_config"], ensure_ascii=False, indent=2, sort_keys=True),
            "```",
            "",
            "## Method Boundary",
            "",
            "```json",
            json.dumps(summary["method_boundary"], ensure_ascii=False, indent=2, sort_keys=True),
            "```",
            "",
            "## Interpretation",
            "",
            "These are deployable score/rank fusion baselines because they do not inspect target labels at ranking time. They should be compared against the M5.55 oracle union as an upper bound, not conflated with it.",
        ]
    )
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binding-dir", type=Path, default=Path("/tmp/m5_52_generic_target_binding_manifest_v1"))
    parser.add_argument("--generic-pool", type=Path, default=Path("/data/lhq/workspace/route-hacker/output/phase1_guideline_retrieval/multitrack_merged_source_ready_v39/candidate_pool_v3/candidate_pool.jsonl"))
    parser.add_argument("--track-queries", type=Path, default=Path("/data/lhq/workspace/route-hacker/assets/guideline_tracks_v1.yaml"))
    parser.add_argument("--query-embeddings", type=Path, default=Path("/tmp/m5_56_strict_generic_fusion_v1/query_embeddings.json"))
    parser.add_argument("--embedding-cache-dir", type=Path, default=Path("/tmp/m5_54_strict_generic_embedding_v1/cache"))
    parser.add_argument("--output-dir", type=Path, default=Path("/tmp/m5_56_strict_generic_fusion_v1"))
    parser.add_argument("--model-path", default=DEFAULT_MODEL_PATH)
    parser.add_argument("--text-field", default="text")
    parser.add_argument("--max-chars", type=int, default=4000)
    parser.add_argument("--rrf-k", type=int, default=60)
    args = parser.parse_args()

    summary, rows = evaluate(
        args.binding_dir,
        args.generic_pool,
        args.track_queries,
        args.query_embeddings,
        args.embedding_cache_dir,
        model_path=args.model_path,
        text_field=args.text_field,
        max_chars=args.max_chars,
        rrf_k=args.rrf_k,
    )
    write_json(args.output_dir / "summary.json", summary)
    write_jsonl(args.output_dir / "case_ranks.jsonl", rows)
    write_text(args.output_dir / "strict_generic_fusion_baselines.md", render_markdown(summary))
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
