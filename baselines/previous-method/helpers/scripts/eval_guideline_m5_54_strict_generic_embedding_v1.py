#!/usr/bin/env python3
"""Evaluate frozen embedding retrieval on M5.52 strict generic bindings."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

import numpy as np

try:
    from scripts.eval_guideline_m5_53_strict_generic_bm25_v1 import (
        FALLBACK_TRACK_QUERIES,
        build_case_targets,
        load_track_queries,
        percentile,
        read_json,
        read_jsonl,
        write_json,
        write_jsonl,
    )
except ModuleNotFoundError:
    from eval_guideline_m5_53_strict_generic_bm25_v1 import (
        FALLBACK_TRACK_QUERIES,
        build_case_targets,
        load_track_queries,
        percentile,
        read_json,
        read_jsonl,
        write_json,
        write_jsonl,
    )


SCHEMA_VERSION = "1.0"
DEFAULT_MODEL_PATH = "/data/lhq/.cache/huggingface/hub/models--Qwen--Qwen3-Embedding-0.6B/snapshots/97b0c614be4d77ee51c0cef4e5f07c00f9eb65b3"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def stable_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("_") or "repo"


def fingerprint_docs(docs: list[str], candidate_ids: list[str]) -> str:
    digest = hashlib.sha256()
    for candidate_id, doc in zip(candidate_ids, docs):
        digest.update(candidate_id.encode("utf-8", errors="replace"))
        digest.update(b"\0")
        data = doc.encode("utf-8", errors="replace")
        digest.update(str(len(data)).encode("ascii"))
        digest.update(b"\0")
        digest.update(data)
        digest.update(b"\0")
    return digest.hexdigest()


def candidate_text(row: dict[str, Any], *, text_field: str, max_chars: int) -> str:
    text = str(row.get(text_field) or row.get("text") or "")
    if max_chars > 0:
        return text[:max_chars]
    return text


def normalize_vectors(vectors: np.ndarray) -> np.ndarray:
    vectors = vectors.astype("float32", copy=False)
    norms = np.linalg.norm(vectors, axis=1, keepdims=True)
    norms[norms == 0.0] = 1.0
    return vectors / norms


def load_sentence_transformer(model_path: str, device: str | None, max_seq_length: int):
    from sentence_transformers import SentenceTransformer

    kwargs = {}
    if device:
        kwargs["device"] = device
    model = SentenceTransformer(model_path, **kwargs)
    if max_seq_length > 0:
        model.max_seq_length = max_seq_length
    return model


def encode_with_sentence_transformer(model: Any, texts: list[str], batch_size: int) -> np.ndarray:
    vectors = model.encode(
        texts,
        batch_size=batch_size,
        normalize_embeddings=True,
        show_progress_bar=False,
        convert_to_numpy=True,
    )
    return vectors.astype("float32", copy=False)


def read_cached_embeddings(path: Path, metadata: dict[str, Any]) -> tuple[np.ndarray | None, str]:
    if not path.exists():
        return None, "miss"
    try:
        with np.load(path, allow_pickle=False) as data:
            cached_metadata = json.loads(str(data["metadata"].item()))
            if cached_metadata != metadata:
                return None, "stale"
            return data["embeddings"].astype("float32", copy=False), "hit"
    except Exception:
        return None, "invalid"


def write_cached_embeddings(path: Path, embeddings: np.ndarray, metadata: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("wb") as handle:
        np.savez(
            handle,
            embeddings=embeddings.astype("float32", copy=False),
            metadata=json.dumps(metadata, sort_keys=True),
        )
    tmp.replace(path)


def encode_repo_docs(
    *,
    repo_key: str,
    docs: list[str],
    candidate_ids: list[str],
    model: Any,
    encode_fn: Callable[[Any, list[str], int], np.ndarray],
    batch_size: int,
    chunk_size: int,
    cache_dir: Path | None,
    cache_key: dict[str, Any],
    repo_index: int,
    repo_total: int,
) -> tuple[np.ndarray, str]:
    metadata = {
        "repo_key": repo_key,
        "doc_count": len(docs),
        "fingerprint": fingerprint_docs(docs, candidate_ids),
        "cache_key": cache_key,
    }
    if cache_dir is not None:
        cache_path = cache_dir / f"{stable_name(repo_key)}.npz"
        cached, status = read_cached_embeddings(cache_path, metadata)
        if cached is not None:
            return cached, f"cache_{status}"
    else:
        cache_path = None
        status = "disabled"

    if chunk_size <= 0:
        chunk_size = len(docs) or 1
    chunks: list[np.ndarray] = []
    for start in range(0, len(docs), chunk_size):
        end = min(start + chunk_size, len(docs))
        chunks.append(encode_fn(model, docs[start:end], batch_size))
        print(
            json.dumps(
                {
                    "event": "repo_chunk_encoded",
                    "repo_index": repo_index,
                    "repo_total": repo_total,
                    "repo_key": repo_key,
                    "chunk_start": start,
                    "chunk_end": end,
                    "candidate_count": len(docs),
                },
                ensure_ascii=False,
                sort_keys=True,
            ),
            flush=True,
        )
    embeddings = normalize_vectors(np.vstack(chunks)) if chunks else np.empty((0, 0), dtype="float32")
    if cache_path is not None:
        write_cached_embeddings(cache_path, embeddings, metadata)
    return embeddings, f"cache_{status}"


def rank_from_scores(scores: np.ndarray, candidate_ids: list[str]) -> np.ndarray:
    return np.lexsort((np.asarray(candidate_ids), -scores))


def evaluate(
    binding_dir: Path,
    generic_pool: Path,
    track_queries_path: Path | None,
    *,
    model_path: str = DEFAULT_MODEL_PATH,
    device: str | None = None,
    batch_size: int = 64,
    chunk_size: int = 8192,
    max_seq_length: int = 512,
    text_field: str = "text",
    max_chars: int = 4000,
    cache_dir: Path | None = None,
    model: Any | None = None,
    encode_fn: Callable[[Any, list[str], int], np.ndarray] | None = None,
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

    if model is None:
        model = load_sentence_transformer(model_path, device, max_seq_length)
    if encode_fn is None:
        encode_fn = encode_with_sentence_transformer

    track_queries = load_track_queries(track_queries_path)
    query_cache: dict[str, np.ndarray] = {}
    repo_cache_status: dict[str, str] = {}
    repo_embeddings: dict[str, np.ndarray] = {}
    repo_candidate_ids: dict[str, list[str]] = {}

    cache_key = {
        "model_path": model_path,
        "text_field": text_field,
        "max_chars": max_chars,
        "normalized": True,
        "schema": SCHEMA_VERSION,
    }
    repo_items = sorted(candidates_by_repo.items())
    for repo_index, (repo_key, candidates) in enumerate(repo_items, start=1):
        docs = [candidate_text(row, text_field=text_field, max_chars=max_chars) for row in candidates]
        candidate_ids = [str(row.get("candidate_id") or "") for row in candidates]
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
        print(
            json.dumps(
                {
                    "event": "repo_encoded",
                    "repo_index": repo_index,
                    "repo_total": len(repo_items),
                    "repo_key": repo_key,
                    "candidate_count": len(candidates),
                    "cache_status": status,
                },
                ensure_ascii=False,
                sort_keys=True,
            ),
            flush=True,
        )

    k_values = [10, 30, 100, 200, 500]
    case_rows: list[dict[str, Any]] = []
    for case in cases.values():
        repo_key = str(case["repo_key"])
        candidates = candidates_by_repo.get(repo_key, [])
        candidate_ids = repo_candidate_ids.get(repo_key, [])
        positive_ids = set(case["positive_candidate_ids"])
        query = track_queries.get(
            str(case["track_id"]) or "",
            FALLBACK_TRACK_QUERIES.get(str(case["track_id"]) or "", "Find security-relevant code matching the guideline."),
        )
        query_vec = query_cache.get(query)
        if query_vec is None:
            query_vec = normalize_vectors(encode_fn(model, [query], 1))[0]
            query_cache[query] = query_vec
        scores = repo_embeddings.get(repo_key, np.empty((0, 0), dtype="float32")) @ query_vec
        order = rank_from_scores(scores, candidate_ids) if len(scores) else np.asarray([], dtype=np.int64)
        first_rank = None
        first_candidate_id = None
        first_score = None
        for idx, candidate_index in enumerate(order, start=1):
            candidate_id = candidate_ids[int(candidate_index)]
            if candidate_id in positive_ids:
                first_rank = idx
                first_candidate_id = candidate_id
                first_score = float(scores[int(candidate_index)])
                break
        row = {
            "case_id": case["case_id"],
            "track_id": case["track_id"],
            "repo_key": repo_key,
            "candidate_count": len(candidates),
            "positive_candidate_count": len(positive_ids),
            "source_target_count": case["source_target_count"],
            "query": query,
            "first_positive_rank": first_rank,
            "first_positive_candidate_id": first_candidate_id,
            "first_positive_score": first_score,
            "mrr": 1.0 / first_rank if first_rank else 0.0,
        }
        for k in k_values:
            row[f"hit_at_{k}"] = bool(first_rank and first_rank <= k)
        case_rows.append(row)

    ranks = [row["first_positive_rank"] for row in case_rows if row["first_positive_rank"]]
    summary: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "status": "completed",
        "created_at": utc_now(),
        "decision": "strict_generic_embedding_baseline_completed",
        "binding_decision": binding_summary.get("decision"),
        "binding_counts": binding_summary.get("counts"),
        "generic_pool": str(generic_pool),
        "rows_scanned": rows_scanned,
        "counts": {
            "eval_cases": len(case_rows),
            "repos": len(repos_needed),
            "cases_with_hit": len(ranks),
            "cases_without_hit": len(case_rows) - len(ranks),
            "candidate_rows_loaded": sum(len(v) for v in candidates_by_repo.values()),
            "query_texts_encoded": len(query_cache),
        },
        "metrics": {
            **{
                f"E@{k}": sum(1 for row in case_rows if row[f"hit_at_{k}"]) / len(case_rows)
                if case_rows
                else None
                for k in k_values
            },
            "MRR": sum(row["mrr"] for row in case_rows) / len(case_rows) if case_rows else None,
            "first_rank_p50": percentile([float(v) for v in ranks], 0.50),
            "first_rank_p75": percentile([float(v) for v in ranks], 0.75),
            "first_rank_p90": percentile([float(v) for v in ranks], 0.90),
            "first_rank_p95": percentile([float(v) for v in ranks], 0.95),
            "first_rank_p99": percentile([float(v) for v in ranks], 0.99),
        },
        "track_metrics": {},
        "cache_status_counts": dict(sorted({status: list(repo_cache_status.values()).count(status) for status in set(repo_cache_status.values())}.items())),
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
            "candidate_universe": "frozen v39 full-repository generic function/sliding_window pool",
            "target_binding": "M5.52 strict full-overlap generic target bindings",
            "uses_supplement_pool_for_ranking": False,
            "uses_bm25_keyword_baseline": False,
            "uses_frozen_zero_shot_embedding": True,
            "uses_training": False,
            "non_anchor_candidates_are_unknown_not_negative": True,
        },
    }
    by_track: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in case_rows:
        by_track[str(row["track_id"])].append(row)
    for track, rows in sorted(by_track.items()):
        summary["track_metrics"][track] = {
            "case_count": len(rows),
            **{f"E@{k}": sum(1 for row in rows if row[f"hit_at_{k}"]) / len(rows) for k in k_values},
            "MRR": sum(row["mrr"] for row in rows) / len(rows),
        }
    return summary, sorted(case_rows, key=lambda row: (str(row["track_id"]), str(row["case_id"])))


def render_markdown(summary: dict[str, Any]) -> str:
    lines = [
        "# Guideline Anchor Retrieval M5.54: Strict Generic Embedding Baseline",
        "",
        f"**Status:** {summary['status']}",
        f"**Decision:** `{summary['decision']}`",
        "",
        "## Purpose",
        "",
        "M5.54 runs a frozen zero-shot embedding baseline over the same M5.52 strict generic target bindings and frozen v39 full-repository generic candidate pool used by M5.53 BM25.",
        "",
        "## Counts",
        "",
        "| Metric | Value |",
        "| --- | ---: |",
    ]
    for key, value in summary["counts"].items():
        lines.append(f"| {key} | {value} |")
    lines.extend(["", "## Metrics", "", "| Metric | Value |", "| --- | ---: |"])
    for key, value in summary["metrics"].items():
        rendered = "null" if value is None else f"{value:.6f}"
        lines.append(f"| {key} | {rendered} |")
    lines.extend(
        [
            "",
            "## Track Metrics",
            "",
            "```json",
            json.dumps(summary["track_metrics"], ensure_ascii=False, indent=2, sort_keys=True),
            "```",
            "",
            "## Method Boundary",
            "",
            "```json",
            json.dumps(summary["method_boundary"], ensure_ascii=False, indent=2, sort_keys=True),
            "```",
            "",
            "## Decision",
            "",
            "This is a frozen zero-shot embedding baseline over strict generic-pool bindings. It is directly comparable to M5.53 BM25 and is not a trained method result.",
        ]
    )
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binding-dir", type=Path, default=Path("/tmp/m5_52_generic_target_binding_manifest_v1"))
    parser.add_argument("--generic-pool", type=Path, default=Path("/data/lhq/workspace/route-hacker/output/phase1_guideline_retrieval/multitrack_merged_source_ready_v39/candidate_pool_v3/candidate_pool.jsonl"))
    parser.add_argument("--track-queries", type=Path, default=Path("/data/lhq/workspace/route-hacker/assets/guideline_tracks_v1.yaml"))
    parser.add_argument("--output-dir", type=Path, default=Path("/tmp/m5_54_strict_generic_embedding_v1"))
    parser.add_argument("--model-path", default=DEFAULT_MODEL_PATH)
    parser.add_argument("--device", default="cpu")
    parser.add_argument("--batch-size", type=int, default=64)
    parser.add_argument("--chunk-size", type=int, default=8192)
    parser.add_argument("--max-seq-length", type=int, default=512)
    parser.add_argument("--text-field", default="text")
    parser.add_argument("--max-chars", type=int, default=4000)
    parser.add_argument("--cache-dir", type=Path, default=Path("/tmp/m5_54_strict_generic_embedding_v1/cache"))
    args = parser.parse_args()

    summary, rows = evaluate(
        args.binding_dir,
        args.generic_pool,
        args.track_queries,
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
    (args.output_dir / "strict_generic_embedding_baseline.md").write_text(render_markdown(summary), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
