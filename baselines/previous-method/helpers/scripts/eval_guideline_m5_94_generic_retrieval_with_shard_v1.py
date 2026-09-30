#!/usr/bin/env python3
"""Run generic retrieval after the M5.92 additive shard repair."""

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
    from scripts.eval_guideline_m5_54_strict_generic_embedding_v1 import (
        DEFAULT_MODEL_PATH,
        candidate_text,
        fingerprint_docs,
        read_cached_embeddings,
        stable_name,
    )
    from scripts.eval_guideline_m5_56_strict_generic_fusion_v1 import (
        bm25_score_array,
        rank_order,
        ranks_from_scores,
        zscore,
    )
    from scripts.eval_guideline_m5_65_residual_fusion_lane_v1 import read_jsonl
    from scripts.eval_guideline_m5_86_expanded_split_bm25_embedding_v1 import add_method_result
    from scripts.eval_guideline_m5_88_fixed_bridge_learned_router_v1 import (
        load_or_encode_queries,
        split_metrics,
        write_json,
        write_jsonl,
        write_text,
    )
    from scripts.eval_guideline_m5_89_generic_source_lane_audit_v1 import (
        GENERIC_VIEW_TYPES,
        map_positive_ids_to_generic,
        summarize_mapping,
        tokenize,
    )
except ModuleNotFoundError:
    from eval_guideline_m5_54_strict_generic_embedding_v1 import (
        DEFAULT_MODEL_PATH,
        candidate_text,
        fingerprint_docs,
        read_cached_embeddings,
        stable_name,
    )
    from eval_guideline_m5_56_strict_generic_fusion_v1 import (
        bm25_score_array,
        rank_order,
        ranks_from_scores,
        zscore,
    )
    from eval_guideline_m5_65_residual_fusion_lane_v1 import read_jsonl
    from eval_guideline_m5_86_expanded_split_bm25_embedding_v1 import add_method_result
    from eval_guideline_m5_88_fixed_bridge_learned_router_v1 import (
        load_or_encode_queries,
        split_metrics,
        write_json,
        write_jsonl,
        write_text,
    )
    from eval_guideline_m5_89_generic_source_lane_audit_v1 import (
        GENERIC_VIEW_TYPES,
        map_positive_ids_to_generic,
        summarize_mapping,
        tokenize,
    )


SCHEMA_VERSION = "1.0"
BM25_METHODS = ("bm25",)
EMBEDDING_METHODS = ("embedding", "rrf_bm25_embedding", "zscore_sum")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def is_generic_candidate(row: dict[str, Any], generic_view_types: set[str]) -> bool:
    return str(row.get("view_type") or "") in generic_view_types


def load_needed_candidates_multi(pool_paths: list[Path], repos_needed: set[str]) -> dict[str, list[dict[str, Any]]]:
    candidates_by_repo: dict[str, list[dict[str, Any]]] = defaultdict(list)
    seen_candidate_ids: set[str] = set()
    for pool_path in pool_paths:
        with pool_path.open(encoding="utf-8") as handle:
            for line in handle:
                if not line.strip():
                    continue
                row = json.loads(line)
                if not isinstance(row, dict):
                    continue
                repo_key = str(row.get("repo_key") or "")
                if repo_key not in repos_needed:
                    continue
                candidate_id = str(row.get("candidate_id") or "")
                if not candidate_id or candidate_id in seen_candidate_ids:
                    continue
                seen_candidate_ids.add(candidate_id)
                candidates_by_repo[repo_key].append(row)
    return dict(candidates_by_repo)


def embedding_metadata(
    repo_key: str,
    candidates: list[dict[str, Any]],
    *,
    model_path: str,
    text_field: str,
    max_chars: int,
) -> dict[str, Any]:
    docs = [candidate_text(row, text_field=text_field, max_chars=max_chars) for row in candidates]
    candidate_ids = [str(row.get("candidate_id") or "") for row in candidates]
    return {
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


class BM25Corpus:
    def __init__(self, docs: list[dict[str, Any]]):
        self.docs = docs
        self.tokenized = [tokenize(str(doc.get("text") or "")) for doc in docs]
        self.term_counts = [Counter(tokens) for tokens in self.tokenized]
        self.lengths = [len(tokens) for tokens in self.tokenized]
        self.avgdl = sum(self.lengths) / len(self.lengths) if self.lengths else 0.0
        self.df: Counter[str] = Counter()
        self.postings: dict[str, list[tuple[int, int]]] = defaultdict(list)
        for index, tf in enumerate(self.term_counts):
            self.df.update(tf.keys())
            for token, freq in tf.items():
                self.postings[token].append((index, int(freq)))

    def score(self, query_tokens: list[str]) -> np.ndarray:
        n_docs = len(self.docs)
        query_counts = Counter(query_tokens)
        scores = np.zeros(n_docs, dtype="float32")
        k1 = 1.5
        b = 0.75
        for token, qtf in query_counts.items():
            postings = self.postings.get(token)
            if not postings:
                continue
            idf = math.log(1.0 + (n_docs - self.df[token] + 0.5) / (self.df[token] + 0.5))
            for index, freq in postings:
                doc_len = self.lengths[index]
                denom = freq + k1 * (1.0 - b + b * (doc_len / self.avgdl if self.avgdl else 0.0))
                scores[index] += qtf * idf * ((freq * (k1 + 1.0)) / denom)
        return scores


def audit_embedding_cache(
    candidates_by_repo: dict[str, list[dict[str, Any]]],
    *,
    embedding_cache_dirs: list[Path] | Path,
    model_path: str,
    text_field: str,
    max_chars: int,
) -> tuple[dict[str, Any], dict[str, np.ndarray]]:
    status_counts: Counter[str] = Counter()
    repo_rows: list[dict[str, Any]] = []
    ready_embeddings: dict[str, np.ndarray] = {}
    for repo_key, candidates in sorted(candidates_by_repo.items()):
        metadata = embedding_metadata(repo_key, candidates, model_path=model_path, text_field=text_field, max_chars=max_chars)
        attempted: list[dict[str, str]] = []
        embeddings = None
        status = "miss"
        cache_path = embedding_cache_dirs[0] / f"{stable_name(repo_key)}.npz"
        for cache_dir in embedding_cache_dirs:
            candidate_cache_path = cache_dir / f"{stable_name(repo_key)}.npz"
            candidate_embeddings, candidate_status = read_cached_embeddings(candidate_cache_path, metadata)
            attempted.append({"cache_path": str(candidate_cache_path), "status": candidate_status})
            if candidate_embeddings is not None:
                embeddings = candidate_embeddings
                status = "hit"
                cache_path = candidate_cache_path
                break
            if candidate_status != "miss" and status == "miss":
                status = candidate_status
                cache_path = candidate_cache_path
        status_counts[status] += 1
        if embeddings is not None:
            ready_embeddings[repo_key] = embeddings
        repo_rows.append(
            {
                "repo_key": repo_key,
                "candidate_count": len(candidates),
                "cache_path": str(cache_path),
                "cache_status": status,
                "attempted_caches": attempted,
            }
        )
    blocked = sum(count for status, count in status_counts.items() if status != "hit")
    return (
        {
            "embedding_cache_dirs": [str(path) for path in embedding_cache_dirs],
            "status_counts": dict(sorted(status_counts.items())),
            "ready": blocked == 0,
            "blocked_repo_count": blocked,
            "repo_rows": repo_rows,
        },
        ready_embeddings,
    )


def evaluate_case_bm25(
    *,
    source_row: dict[str, Any],
    candidates: list[dict[str, Any]],
    generic_candidates: list[dict[str, Any]],
    bm25_scores: np.ndarray,
    positive_ids: list[str],
    map_diagnostics: dict[str, Any],
) -> dict[str, Any]:
    candidate_ids = [str(candidate.get("candidate_id") or "") for candidate in generic_candidates]
    query = str(source_row["query_text"])
    positive_set = set(positive_ids)
    row = {
        "case_id": source_row["case_id"],
        "original_case_id": source_row.get("original_case_id"),
        "track_id": source_row["track_id"],
        "repo_key": source_row["repo_key"],
        "inner_split": source_row["inner_split"],
        "candidate_count": len(generic_candidates),
        "original_candidate_count": len(candidates),
        "source_positive_candidate_count": len(source_row.get("positive_candidate_ids") or []),
        "positive_candidate_count": len(positive_set),
        "source_label_ids": source_row.get("source_label_ids"),
        "source_target_count": source_row.get("source_target_count"),
        "query_text": query,
        "generic_mapping_status": "covered" if positive_set else "uncovered",
        "generic_mapping": map_diagnostics,
    }
    add_method_result(row, "bm25", rank_order(bm25_scores, candidate_ids), bm25_scores, candidate_ids, positive_set)
    row["_candidate_ids"] = candidate_ids
    row["_bm25_scores"] = bm25_scores
    row["_positive_candidate_ids"] = sorted(positive_set)
    row["_generic_indices"] = [
        index for index, candidate in enumerate(candidates) if is_generic_candidate(candidate, GENERIC_VIEW_TYPES)
    ]
    return row


def add_embedding_results(
    row: dict[str, Any],
    *,
    repo_embeddings: np.ndarray,
    query_vector: np.ndarray,
) -> None:
    candidate_ids = row["_candidate_ids"]
    positive_set = set(row["_positive_candidate_ids"])
    bm25 = row["_bm25_scores"]
    generic_indices = row["_generic_indices"]
    generic_embeddings = repo_embeddings[generic_indices]
    embedding = generic_embeddings @ query_vector
    bm25_ranks = ranks_from_scores(bm25, candidate_ids)
    embedding_ranks = ranks_from_scores(embedding, candidate_ids)
    rrf = (1.0 / (60 + bm25_ranks)) + (1.0 / (60 + embedding_ranks))
    zsum = zscore(bm25) + zscore(embedding)
    method_scores = {
        "embedding": embedding,
        "rrf_bm25_embedding": rrf.astype("float32", copy=False),
        "zscore_sum": zsum.astype("float32", copy=False),
    }
    for method, scores in method_scores.items():
        add_method_result(row, method, rank_order(scores, candidate_ids), scores, candidate_ids, positive_set)


def strip_private_fields(row: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in row.items() if not key.startswith("_")}


def evaluate(
    split_manifest: Path,
    pool_paths: list[Path],
    embedding_cache_dirs: list[Path],
    *,
    model_path: str,
    device: str | None,
    max_seq_length: int,
    text_field: str,
    max_chars: int,
    generic_view_types: set[str],
    run_embedding: bool,
    split_filter: str | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    source_rows = read_jsonl(split_manifest)
    if split_filter:
        source_rows = [row for row in source_rows if str(row.get("inner_split")) == split_filter]
    if isinstance(embedding_cache_dirs, Path):
        embedding_cache_dirs = [embedding_cache_dirs]
    repos_needed = {str(row["repo_key"]) for row in source_rows}
    candidates_by_repo = load_needed_candidates_multi(pool_paths, repos_needed)
    missing_repos = sorted(repos_needed - set(candidates_by_repo))
    if missing_repos:
        raise ValueError(f"candidate pool missing repos: {missing_repos[:10]}")

    cache_audit, ready_embeddings = audit_embedding_cache(
        candidates_by_repo,
        embedding_cache_dirs=embedding_cache_dirs,
        model_path=model_path,
        text_field=text_field,
        max_chars=max_chars,
    )
    if run_embedding and not cache_audit["ready"]:
        raise ValueError(f"embedding cache is not ready for repaired pool: {cache_audit['status_counts']}")

    query_vectors: dict[str, np.ndarray] = {}
    if run_embedding:
        query_texts = sorted({str(row["query_text"]) for row in source_rows})
        query_vectors = load_or_encode_queries(query_texts, model_path=model_path, device=device, max_seq_length=max_seq_length)

    rows: list[dict[str, Any]] = []
    source_family_counts: Counter[str] = Counter()
    generic_candidate_counts: Counter[str] = Counter()
    bm25_corpora: dict[str, BM25Corpus] = {}
    bm25_score_cache: dict[tuple[str, str], np.ndarray] = {}
    for source_row in source_rows:
        repo_key = str(source_row["repo_key"])
        candidates = candidates_by_repo[repo_key]
        by_id = {str(candidate.get("candidate_id") or ""): candidate for candidate in candidates}
        generic_candidates = [candidate for candidate in candidates if is_generic_candidate(candidate, generic_view_types)]
        for candidate in candidates:
            source_family_counts[str(candidate.get("view_type") or "")] += 1
        for candidate in generic_candidates:
            generic_candidate_counts[str(candidate.get("view_type") or "")] += 1
        if repo_key not in bm25_corpora:
            bm25_corpora[repo_key] = BM25Corpus(generic_candidates)
        query_text = str(source_row["query_text"])
        bm25_key = (repo_key, query_text)
        if bm25_key not in bm25_score_cache:
            bm25_score_cache[bm25_key] = bm25_corpora[repo_key].score(tokenize(query_text))
        positive_ids, diagnostics = map_positive_ids_to_generic(
            positive_ids=[str(candidate_id) for candidate_id in source_row.get("positive_candidate_ids") or []],
            candidates=candidates,
            by_id=by_id,
            generic_candidates=generic_candidates,
            generic_view_types=generic_view_types,
        )
        row = evaluate_case_bm25(
            source_row=source_row,
            candidates=candidates,
            generic_candidates=generic_candidates,
            bm25_scores=bm25_score_cache[bm25_key],
            positive_ids=positive_ids,
            map_diagnostics=diagnostics,
        )
        if run_embedding:
            add_embedding_results(row, repo_embeddings=ready_embeddings[repo_key], query_vector=query_vectors[str(source_row["query_text"])])
        rows.append(row)

    covered_rows = [row for row in rows if row["positive_candidate_count"] > 0]
    methods = BM25_METHODS + (EMBEDDING_METHODS if run_embedding else ())
    summary = {
        "schema_version": SCHEMA_VERSION,
        "status": "completed",
        "created_at": utc_now(),
        "decision": "m5_94_generic_retrieval_with_shard_completed",
        "scope": {
            "split_manifest": str(split_manifest),
            "pool_paths": [str(path) for path in pool_paths],
            "embedding_cache_dirs": [str(path) for path in embedding_cache_dirs],
            "split_filter": split_filter,
            "cases": len(rows),
            "covered_cases": len(covered_rows),
            "repos": len(repos_needed),
            "candidate_rows_loaded": sum(len(candidates) for candidates in candidates_by_repo.values()),
        },
        "config": {
            "generic_view_types": sorted(generic_view_types),
            "model_path": model_path,
            "device": device,
            "max_seq_length": max_seq_length,
            "text_field": text_field,
            "max_chars": max_chars,
            "run_embedding": run_embedding,
        },
        "candidate_view_type_counts": dict(sorted(source_family_counts.items())),
        "generic_candidate_view_type_counts": dict(sorted(generic_candidate_counts.items())),
        "mapping": summarize_mapping(rows),
        "embedding_cache_audit": {key: value for key, value in cache_audit.items() if key != "repo_rows"},
        "metrics_on_generic_covered_cases": split_metrics(covered_rows, methods),
        "method_boundary": {
            "development_only": True,
            "frozen_test_touched": False,
            "candidate_pool_mutated": False,
            "uses_additive_generic_shard": True,
            "generic_only_evaluation": True,
            "positive_mapping": "same_repo_same_file_line_overlap_or_direct_generic_id",
            "source_lane_features_used": False,
            "updates_code_encoder": False,
            "embedding_metrics_reported": run_embedding,
            "embedding_blocked_when_cache_not_ready": not run_embedding and not cache_audit["ready"],
            "uncovered_cases_excluded_from_retrieval_metrics_but_reported_in_mapping": True,
        },
    }
    return summary, [strip_private_fields(row) for row in rows], cache_audit["repo_rows"]


def metric_row(summary: dict[str, Any], split: str, method: str) -> dict[str, Any]:
    return summary.get("metrics_on_generic_covered_cases", {}).get(split, {}).get("all", {}).get(method, {})


def render_markdown(summary: dict[str, Any]) -> str:
    methods = BM25_METHODS + (EMBEDDING_METHODS if summary["config"]["run_embedding"] else ())
    lines = [
        "# Guideline Anchor Retrieval M5.94: Generic Retrieval With Shard",
        "",
        f"**Status:** {summary['status']}",
        f"**Decision:** `{summary['decision']}`",
        "",
        "## Why This Run Exists",
        "",
        "M5.93 repaired source-lane coverage with an additive generic shard but did not run retrieval. M5.94 reruns the deployable generic retrieval baseline on the repaired candidate universe.",
        "",
        "## Mapping Coverage",
        "",
        "```json",
        json.dumps(summary["mapping"]["all"], ensure_ascii=False, indent=2, sort_keys=True),
        "```",
        "",
        "## Inner-Val Metrics",
        "",
        "| Method | R@10 | R@30 | R@100 | R@200 | R@500 | MRR | p50 rank | p90 rank | p99 rank |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for method in methods:
        item = metric_row(summary, "inner_val", method)
        lines.append(
            "| {method} | {r10:.6f} | {r30:.6f} | {r100:.6f} | {r200:.6f} | {r500:.6f} | {mrr:.6f} | {p50:.6f} | {p90:.6f} | {p99:.6f} |".format(
                method=method,
                r10=item.get("R@10") or 0.0,
                r30=item.get("R@30") or 0.0,
                r100=item.get("R@100") or 0.0,
                r200=item.get("R@200") or 0.0,
                r500=item.get("R@500") or 0.0,
                mrr=item.get("MRR") or 0.0,
                p50=item.get("first_rank_p50") or 0.0,
                p90=item.get("first_rank_p90") or 0.0,
                p99=item.get("first_rank_p99") or 0.0,
            )
        )
    lines.extend(
        [
            "",
            "## Embedding Cache Audit",
            "",
            "```json",
            json.dumps(summary["embedding_cache_audit"], ensure_ascii=False, indent=2, sort_keys=True),
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
    parser.add_argument("--split-manifest", type=Path, default=Path("/tmp/m5_88_expanded_inner_split_manifest_fixed_repo_key_v1/split_manifest.jsonl"))
    parser.add_argument(
        "--pool",
        type=Path,
        action="append",
        dest="pools",
        default=[],
        help="Candidate pool path. Pass multiple times; order is preserved.",
    )
    parser.add_argument(
        "--embedding-cache-dir",
        type=Path,
        action="append",
        dest="embedding_cache_dirs",
        default=[],
        help="Embedding cache directory. Pass multiple times; first matching fingerprint wins.",
    )
    parser.add_argument("--output-dir", type=Path, default=Path("/tmp/m5_94_generic_retrieval_with_shard_v1"))
    parser.add_argument("--model-path", default=DEFAULT_MODEL_PATH)
    parser.add_argument("--device", default="cpu")
    parser.add_argument("--max-seq-length", type=int, default=512)
    parser.add_argument("--text-field", default="text")
    parser.add_argument("--max-chars", type=int, default=4000)
    parser.add_argument("--run-embedding", action="store_true")
    parser.add_argument("--split-filter", default=None)
    args = parser.parse_args()
    pools = args.pools or [
        Path("/tmp/m5_83_expanded_inner_split_manifest_v1/candidate_pool.v1.jsonl"),
        Path("/tmp/m5_92_gap_generic_candidate_shard_v1/gap_generic_candidate_shard.v1.jsonl"),
    ]
    summary, rows, cache_rows = evaluate(
        args.split_manifest,
        pools,
        args.embedding_cache_dirs or [Path("/tmp/m5_86_expanded_split_bm25_embedding_v1/cache")],
        model_path=args.model_path,
        device=args.device,
        max_seq_length=args.max_seq_length,
        text_field=args.text_field,
        max_chars=args.max_chars,
        generic_view_types=GENERIC_VIEW_TYPES,
        run_embedding=args.run_embedding,
        split_filter=args.split_filter,
    )
    args.output_dir.mkdir(parents=True, exist_ok=True)
    write_json(args.output_dir / "summary.json", summary)
    write_jsonl(args.output_dir / "case_ranks.jsonl", rows)
    write_jsonl(args.output_dir / "embedding_cache_audit_rows.jsonl", cache_rows)
    write_text(args.output_dir / "generic_retrieval_with_shard.md", render_markdown(summary))
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
