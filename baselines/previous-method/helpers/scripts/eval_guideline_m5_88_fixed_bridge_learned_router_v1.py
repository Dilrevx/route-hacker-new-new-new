#!/usr/bin/env python3
"""Train a development-only BM25/embedding feature router on the fixed bridge."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np

try:
    from scripts.eval_guideline_m5_53_strict_generic_bm25_v1 import percentile, tokenize, write_json, write_jsonl
    from scripts.eval_guideline_m5_54_strict_generic_embedding_v1 import (
        DEFAULT_MODEL_PATH,
        encode_with_sentence_transformer,
        load_sentence_transformer,
        normalize_vectors,
    )
    from scripts.eval_guideline_m5_56_strict_generic_fusion_v1 import (
        bm25_score_array,
        load_repo_embeddings,
        rank_order,
        ranks_from_scores,
        write_text,
        zscore,
    )
    from scripts.eval_guideline_m5_65_residual_fusion_lane_v1 import K_VALUES, load_needed_candidates, read_jsonl
except ModuleNotFoundError:
    from eval_guideline_m5_53_strict_generic_bm25_v1 import percentile, tokenize, write_json, write_jsonl
    from eval_guideline_m5_54_strict_generic_embedding_v1 import (
        DEFAULT_MODEL_PATH,
        encode_with_sentence_transformer,
        load_sentence_transformer,
        normalize_vectors,
    )
    from eval_guideline_m5_56_strict_generic_fusion_v1 import (
        bm25_score_array,
        load_repo_embeddings,
        rank_order,
        ranks_from_scores,
        write_text,
        zscore,
    )
    from eval_guideline_m5_65_residual_fusion_lane_v1 import K_VALUES, load_needed_candidates, read_jsonl


SCHEMA_VERSION = "1.0"
METHOD = "learned_router"
BASE_METHODS = ("bm25", "embedding", "rrf_bm25_embedding", "zscore_sum")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def split_rows(path: Path, split: str | None = None) -> list[dict[str, Any]]:
    rows = read_jsonl(path)
    if split is None:
        return rows
    return [row for row in rows if str(row.get("inner_split")) == split]


def stable_unit_float(value: str) -> float:
    digest = hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()
    return int(digest[:16], 16) / float(16**16 - 1)


def sigmoid(x: np.ndarray) -> np.ndarray:
    return np.where(x >= 0, 1.0 / (1.0 + np.exp(-x)), np.exp(x) / (1.0 + np.exp(x)))


def first_positive(
    order: np.ndarray,
    scores: np.ndarray,
    candidate_ids: list[str],
    positive_ids: set[str],
) -> tuple[int | None, str | None, float | None]:
    for rank, index in enumerate(order, start=1):
        candidate_id = candidate_ids[int(index)]
        if candidate_id in positive_ids:
            return rank, candidate_id, float(scores[int(index)])
    return None, None, None


def add_method_result(
    row: dict[str, Any],
    method: str,
    scores: np.ndarray,
    candidate_ids: list[str],
    positive_ids: set[str],
) -> None:
    rank, candidate_id, score = first_positive(rank_order(scores, candidate_ids), scores, candidate_ids, positive_ids)
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


def candidate_pool_bucket(candidate_count: int) -> str:
    if candidate_count <= 2:
        return "tiny"
    if candidate_count <= 500:
        return "small"
    return "large"


def one_hot(value: str, vocabulary: list[str]) -> list[float]:
    return [1.0 if value == item else 0.0 for item in vocabulary]


def feature_matrix(
    *,
    bm25: np.ndarray,
    embedding: np.ndarray,
    candidate_ids: list[str],
    candidates: list[dict[str, Any]],
    track_id: str,
    tracks: list[str],
    view_types: list[str],
    include_view_type_features: bool = True,
) -> tuple[np.ndarray, list[str]]:
    bm25_ranks = ranks_from_scores(bm25, candidate_ids)
    embedding_ranks = ranks_from_scores(embedding, candidate_ids)
    rrf = (1.0 / (60.0 + bm25_ranks)) + (1.0 / (60.0 + embedding_ranks))
    z_bm25 = zscore(bm25)
    z_embedding = zscore(embedding)
    z_rrf = zscore(rrf.astype("float32", copy=False))
    z_sum = z_bm25 + z_embedding
    inv_bm25 = (1.0 / np.sqrt(bm25_ranks.astype("float32"))).astype("float32")
    inv_embedding = (1.0 / np.sqrt(embedding_ranks.astype("float32"))).astype("float32")
    lane_columns = [z_bm25, z_embedding, z_rrf, z_sum, inv_bm25, inv_embedding]
    lane_names = ["z_bm25", "z_embedding", "z_rrf", "z_sum", "inv_bm25_rank", "inv_embedding_rank"]
    base = np.column_stack(lane_columns).astype("float32")
    names = list(lane_names)

    track_vector = np.asarray(one_hot(track_id, tracks), dtype="float32")
    if len(track_vector):
        interactions = [base[:, index : index + 1] * track_vector[None, :] for index in range(base.shape[1])]
        base = np.column_stack([base, *interactions]).astype("float32")
        for lane_name in lane_names:
            names.extend(f"{lane_name}__track={track}" for track in tracks)

    if include_view_type_features:
        view_vocab = {view: i for i, view in enumerate(view_types)}
        view = np.zeros((len(candidates), len(view_types)), dtype="float32")
        for index, candidate in enumerate(candidates):
            view_type = str(candidate.get("view_type") or "")
            if view_type in view_vocab:
                view[index, view_vocab[view_type]] = 1.0
        if view.shape[1]:
            base = np.column_stack([base, view]).astype("float32")
            names.extend(f"view={view_type}" for view_type in view_types)
    return base, names


def selected_indices(
    *,
    candidate_ids: list[str],
    positive_ids: set[str],
    scores_by_lane: dict[str, np.ndarray],
    top_k: int,
    tail_k: int,
    seed: str,
) -> list[int]:
    selected: set[int] = set()
    id_to_index = {candidate_id: index for index, candidate_id in enumerate(candidate_ids)}
    for candidate_id in positive_ids:
        if candidate_id in id_to_index:
            selected.add(id_to_index[candidate_id])
    for scores in scores_by_lane.values():
        for index in rank_order(scores, candidate_ids)[:top_k]:
            selected.add(int(index))
    tail_candidates = [
        (stable_unit_float(f"{seed}\0{candidate_id}"), index)
        for index, candidate_id in enumerate(candidate_ids)
        if index not in selected
    ]
    for _, index in sorted(tail_candidates)[:tail_k]:
        selected.add(index)
    return sorted(selected)


def build_pairwise_diffs(
    case_feature_rows: list[dict[str, Any]],
    *,
    top_k: int,
    tail_k: int,
    max_pairs_per_case: int,
    seed: str,
) -> tuple[np.ndarray, dict[str, Any]]:
    diffs: list[np.ndarray] = []
    cases_with_pairs = 0
    competitor_count = 0
    positive_count = 0
    for row in case_feature_rows:
        candidate_ids = row["candidate_ids"]
        positive_ids = set(row["positive_ids"])
        selected = selected_indices(
            candidate_ids=candidate_ids,
            positive_ids=positive_ids,
            scores_by_lane={
                "bm25": row["bm25"],
                "embedding": row["embedding"],
                "rrf": row["rrf"],
                "zsum": row["zsum"],
            },
            top_k=top_k,
            tail_k=tail_k,
            seed=f"{seed}\0{row['case_id']}",
        )
        positive_indices = [index for index in selected if candidate_ids[index] in positive_ids]
        competitor_indices = [index for index in selected if candidate_ids[index] not in positive_ids]
        positive_count += len(positive_indices)
        competitor_count += len(competitor_indices)
        if not positive_indices or not competitor_indices:
            continue
        pairs_for_case: list[np.ndarray] = []
        for positive_index in positive_indices:
            for competitor_index in competitor_indices:
                pairs_for_case.append(row["features"][positive_index] - row["features"][competitor_index])
        if len(pairs_for_case) > max_pairs_per_case:
            pairs_for_case = [
                item
                for _, item in sorted(
                    (
                        stable_unit_float(f"{seed}\0{row['case_id']}\0{idx}"),
                        item,
                    )
                    for idx, item in enumerate(pairs_for_case)
                )[:max_pairs_per_case]
            ]
        diffs.extend(pairs_for_case)
        cases_with_pairs += 1
    if not diffs:
        raise ValueError("no pairwise training rows were produced")
    matrix = np.vstack(diffs).astype("float32")
    summary = {
        "pairwise_rows": int(matrix.shape[0]),
        "feature_count": int(matrix.shape[1]),
        "cases_with_pairs": cases_with_pairs,
        "sampled_positive_indices": positive_count,
        "sampled_competitor_indices": competitor_count,
        "top_k_per_lane": top_k,
        "tail_k": tail_k,
        "max_pairs_per_case": max_pairs_per_case,
    }
    return matrix, summary


def train_pairwise_router(
    diffs: np.ndarray,
    *,
    epochs: int,
    learning_rate: float,
    l2: float,
) -> tuple[np.ndarray, list[dict[str, float]]]:
    weights = np.zeros(diffs.shape[1], dtype="float32")
    history: list[dict[str, float]] = []
    for epoch in range(1, epochs + 1):
        margins = diffs @ weights
        probs = sigmoid(-margins).astype("float32")
        grad = -(probs[:, None] * diffs).mean(axis=0) + l2 * weights
        weights -= learning_rate * grad.astype("float32")
        loss = float(np.logaddexp(0.0, -margins).mean() + 0.5 * l2 * float(weights @ weights))
        accuracy = float(np.mean(margins > 0.0))
        history.append({"epoch": epoch, "loss": loss, "pairwise_accuracy": accuracy})
    return weights.astype("float32", copy=False), history


def compute_case_features(
    source_rows: list[dict[str, Any]],
    candidates_by_repo: dict[str, list[dict[str, Any]]],
    repo_embeddings: dict[str, np.ndarray],
    query_vectors: dict[str, np.ndarray],
    *,
    tracks: list[str],
    view_types: list[str],
    include_view_type_features: bool,
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for source in source_rows:
        repo_key = str(source["repo_key"])
        candidates = candidates_by_repo[repo_key]
        candidate_ids = [str(candidate.get("candidate_id") or "") for candidate in candidates]
        query = str(source["query_text"])
        bm25 = bm25_score_array(tokenize(query), candidates)
        embedding = repo_embeddings[repo_key] @ query_vectors[query]
        bm25_ranks = ranks_from_scores(bm25, candidate_ids)
        embedding_ranks = ranks_from_scores(embedding, candidate_ids)
        rrf = (1.0 / (60.0 + bm25_ranks)) + (1.0 / (60.0 + embedding_ranks))
        zsum = zscore(bm25) + zscore(embedding)
        features, feature_names = feature_matrix(
            bm25=bm25,
            embedding=embedding,
            candidate_ids=candidate_ids,
            candidates=candidates,
            track_id=str(source["track_id"]),
            tracks=tracks,
            view_types=view_types,
            include_view_type_features=include_view_type_features,
        )
        out.append(
            {
                "case_id": source["case_id"],
                "original_case_id": source.get("original_case_id"),
                "track_id": source["track_id"],
                "repo_key": repo_key,
                "inner_split": source["inner_split"],
                "candidate_count": len(candidates),
                "positive_candidate_count": len(source["positive_candidate_ids"]),
                "source_label_ids": source.get("source_label_ids"),
                "source_target_count": source.get("source_target_count"),
                "query_text": query,
                "candidate_ids": candidate_ids,
                "positive_ids": [str(candidate_id) for candidate_id in source["positive_candidate_ids"]],
                "bm25": bm25.astype("float32", copy=False),
                "embedding": embedding.astype("float32", copy=False),
                "rrf": rrf.astype("float32", copy=False),
                "zsum": zsum.astype("float32", copy=False),
                "features": features,
                "feature_names": feature_names,
            }
        )
    return out


def evaluate_case_rows(case_feature_rows: list[dict[str, Any]], weights: np.ndarray | None = None) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for source in case_feature_rows:
        candidate_ids = source["candidate_ids"]
        positive_ids = set(source["positive_ids"])
        method_scores = {
            "bm25": source["bm25"],
            "embedding": source["embedding"],
            "rrf_bm25_embedding": source["rrf"],
            "zscore_sum": source["zsum"],
        }
        if weights is not None:
            method_scores[METHOD] = source["features"] @ weights
        row = {
            "case_id": source["case_id"],
            "original_case_id": source.get("original_case_id"),
            "track_id": source["track_id"],
            "repo_key": source["repo_key"],
            "inner_split": source["inner_split"],
            "candidate_count": source["candidate_count"],
            "positive_candidate_count": source["positive_candidate_count"],
            "source_label_ids": source.get("source_label_ids"),
            "source_target_count": source.get("source_target_count"),
            "query_text": source["query_text"],
        }
        for method, scores in method_scores.items():
            add_method_result(row, method, scores, candidate_ids, positive_ids)
        rows.append(row)
    return sorted(rows, key=lambda row: (str(row["inner_split"]), str(row["track_id"]), str(row["case_id"])))


def slice_rows(rows: list[dict[str, Any]], candidate_count_gt: int | None) -> list[dict[str, Any]]:
    if candidate_count_gt is None:
        return rows
    return [row for row in rows if int(row["candidate_count"]) > candidate_count_gt]


def split_metrics(rows: list[dict[str, Any]], methods: tuple[str, ...]) -> dict[str, dict[str, dict[str, Any]]]:
    by_split: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_split[str(row["inner_split"])].append(row)
    out: dict[str, dict[str, dict[str, Any]]] = {}
    for split, split_part in sorted(by_split.items()):
        out[split] = {}
        for slice_name, threshold in (("all", None), ("candidate_count_gt_2", 2), ("candidate_count_gt_500", 500)):
            slice_part = slice_rows(split_part, threshold)
            out[split][slice_name] = {
                method: summarize(slice_part, method)
                for method in methods
            }
    return out


def split_comparisons(rows: list[dict[str, Any]], right: str) -> dict[str, dict[str, Any]]:
    by_split: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_split[str(row["inner_split"])].append(row)
    out: dict[str, dict[str, Any]] = {}
    for split, split_part in sorted(by_split.items()):
        out[split] = {}
        for k in (100, 500):
            out[split][f"vs_bm25_at_{k}"] = compare_at_k(split_part, "bm25", right, k)
            out[split][f"vs_rrf_at_{k}"] = compare_at_k(split_part, "rrf_bm25_embedding", right, k)
    return out


def load_or_encode_queries(
    queries: list[str],
    *,
    model_path: str,
    device: str | None,
    max_seq_length: int,
) -> dict[str, np.ndarray]:
    model = load_sentence_transformer(model_path, device, max_seq_length)
    vectors = normalize_vectors(encode_with_sentence_transformer(model, queries, 1))
    return {query: vectors[index] for index, query in enumerate(queries)}


def evaluate(
    split_manifest: Path,
    generic_pool: Path,
    embedding_cache_dir: Path,
    *,
    model_path: str,
    device: str | None,
    max_seq_length: int,
    text_field: str,
    max_chars: int,
    sample_top_k: int,
    sample_tail_k: int,
    max_pairs_per_case: int,
    seed: str,
    epochs: int,
    learning_rate: float,
    l2: float,
    include_view_type_features: bool,
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    source_rows = split_rows(split_manifest)
    train_source = [row for row in source_rows if str(row.get("inner_split")) == "inner_train"]
    val_source = [row for row in source_rows if str(row.get("inner_split")) == "inner_val"]
    repos_needed = {str(row["repo_key"]) for row in source_rows}
    candidates_by_repo = load_needed_candidates(generic_pool, repos_needed)
    missing_repos = sorted(repos_needed - set(candidates_by_repo))
    if missing_repos:
        raise ValueError(f"candidate pool missing repos: {missing_repos[:10]}")
    repo_embeddings = {
        repo_key: load_repo_embeddings(
            repo_key=repo_key,
            candidates=candidates,
            cache_dir=embedding_cache_dir,
            model_path=model_path,
            text_field=text_field,
            max_chars=max_chars,
        )
        for repo_key, candidates in sorted(candidates_by_repo.items())
    }
    query_texts = sorted({str(row["query_text"]) for row in source_rows})
    query_vectors = load_or_encode_queries(query_texts, model_path=model_path, device=device, max_seq_length=max_seq_length)
    tracks = sorted({str(row["track_id"]) for row in train_source})
    view_types = sorted({str(candidate.get("view_type") or "") for candidates in candidates_by_repo.values() for candidate in candidates})
    train_features = compute_case_features(
        train_source,
        candidates_by_repo,
        repo_embeddings,
        query_vectors,
        tracks=tracks,
        view_types=view_types,
        include_view_type_features=include_view_type_features,
    )
    val_features = compute_case_features(
        val_source,
        candidates_by_repo,
        repo_embeddings,
        query_vectors,
        tracks=tracks,
        view_types=view_types,
        include_view_type_features=include_view_type_features,
    )
    diffs, sample_summary = build_pairwise_diffs(
        train_features,
        top_k=sample_top_k,
        tail_k=sample_tail_k,
        max_pairs_per_case=max_pairs_per_case,
        seed=seed,
    )
    weights, history = train_pairwise_router(diffs, epochs=epochs, learning_rate=learning_rate, l2=l2)
    rows = evaluate_case_rows(train_features, weights) + evaluate_case_rows(val_features, weights)
    feature_names = train_features[0]["feature_names"] if train_features else []
    methods = BASE_METHODS + (METHOD,)
    metrics = split_metrics(rows, methods)
    comparisons = split_comparisons(rows, METHOD)
    val_gate = metrics.get("inner_val", {}).get("all", {})
    router_val = val_gate.get(METHOD, {})
    rrf_val = val_gate.get("rrf_bm25_embedding", {})
    bm25_comp_500 = comparisons.get("inner_val", {}).get("vs_bm25_at_500", {})
    rrf_comp_500 = comparisons.get("inner_val", {}).get("vs_rrf_at_500", {})
    gate = {
        "beats_rrf_R@100_all": router_val.get("R@100") is not None and rrf_val.get("R@100") is not None and router_val["R@100"] > rrf_val["R@100"],
        "does_not_lower_rrf_R@500_all": router_val.get("R@500") is not None and rrf_val.get("R@500") is not None and router_val["R@500"] >= rrf_val["R@500"],
        "top500_regressions_vs_bm25": bm25_comp_500.get("regressions"),
        "top500_regressions_vs_rrf": rrf_comp_500.get("regressions"),
    }
    gate["passes_inner_val_router_gate"] = bool(
        gate["beats_rrf_R@100_all"]
        and gate["does_not_lower_rrf_R@500_all"]
        and gate["top500_regressions_vs_bm25"] == 0
    )
    summary = {
        "schema_version": SCHEMA_VERSION,
        "status": "completed",
        "created_at": utc_now(),
        "decision": "m5_88_fixed_bridge_learned_router_evaluated",
        "scope": {
            "split_manifest": str(split_manifest),
            "generic_pool": str(generic_pool),
            "embedding_cache_dir": str(embedding_cache_dir),
            "train_cases": len(train_source),
            "val_cases": len(val_source),
            "repos": len(repos_needed),
            "candidate_rows_loaded": sum(len(candidates) for candidates in candidates_by_repo.values()),
        },
        "config": {
            "model_path": model_path,
            "device": device,
            "max_seq_length": max_seq_length,
            "text_field": text_field,
            "max_chars": max_chars,
            "sample_top_k": sample_top_k,
            "sample_tail_k": sample_tail_k,
            "max_pairs_per_case": max_pairs_per_case,
            "seed": seed,
            "epochs": epochs,
            "learning_rate": learning_rate,
            "l2": l2,
            "include_view_type_features": include_view_type_features,
        },
        "training_sample": sample_summary,
        "training_history": history,
        "feature_names": feature_names,
        "weights": {
            name: float(weights[index])
            for index, name in enumerate(feature_names)
        },
        "metrics": metrics,
        "comparisons": comparisons,
        "selection_gate": gate,
        "method_boundary": {
            "development_only": True,
            "uses_inner_train_for_training": True,
            "uses_inner_val_for_gate": True,
            "frozen_test_touched": False,
            "updates_code_encoder": False,
            "uses_frozen_embedding_cache": True,
            "uses_view_type_features": include_view_type_features,
            "candidate_pool_mutated": False,
            "non_anchor_candidates_are_unknown_not_negative": True,
            "sampled_competitors_are_ranking_competitors_not_safe_negatives": True,
        },
    }
    return summary, rows, [{"epoch": item["epoch"], "loss": item["loss"], "pairwise_accuracy": item["pairwise_accuracy"]} for item in history]


def fmt(value: Any) -> str:
    if value is None:
        return "n/a"
    if isinstance(value, float):
        return f"{value:.6f}"
    return str(value)


def render_markdown(summary: dict[str, Any]) -> str:
    methods = BASE_METHODS + (METHOD,)
    lines = [
        "# Guideline Anchor Retrieval M5.88: Fixed-Bridge Learned Router",
        "",
        f"**Status:** {summary['status']}",
        f"**Decision:** `{summary['decision']}`",
        "",
        "## Scope",
        "",
        "```json",
        json.dumps(summary["scope"], ensure_ascii=False, indent=2, sort_keys=True),
        "```",
        "",
        "## Inner-Val Metrics",
        "",
        "| Slice | Method | R@30 | R@100 | R@500 | MRR | p90 rank | p99 rank |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    inner_val = summary["metrics"].get("inner_val", {})
    for slice_name in ("all", "candidate_count_gt_2", "candidate_count_gt_500"):
        for method in methods:
            metric = inner_val.get(slice_name, {}).get(method, {})
            lines.append(
                f"| {slice_name} | {method} | {fmt(metric.get('R@30'))} | {fmt(metric.get('R@100'))} | "
                f"{fmt(metric.get('R@500'))} | {fmt(metric.get('MRR'))} | "
                f"{fmt(metric.get('first_rank_p90'))} | {fmt(metric.get('first_rank_p99'))} |"
            )
    lines.extend(
        [
            "",
            "## Selection Gate",
            "",
            "```json",
            json.dumps(summary["selection_gate"], ensure_ascii=False, indent=2, sort_keys=True),
            "```",
            "",
            "## Training Sample",
            "",
            "```json",
            json.dumps(summary["training_sample"], ensure_ascii=False, indent=2, sort_keys=True),
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
    parser.add_argument("--generic-pool", type=Path, default=Path("/tmp/m5_88_expanded_inner_split_manifest_fixed_repo_key_v1/candidate_pool.v1.jsonl"))
    parser.add_argument("--embedding-cache-dir", type=Path, default=Path("/tmp/m5_86_expanded_split_bm25_embedding_v1/cache"))
    parser.add_argument("--output-dir", type=Path, default=Path("/tmp/m5_88_fixed_bridge_learned_router_v1"))
    parser.add_argument("--model-path", default=DEFAULT_MODEL_PATH)
    parser.add_argument("--device", default="cpu")
    parser.add_argument("--max-seq-length", type=int, default=512)
    parser.add_argument("--text-field", default="text")
    parser.add_argument("--max-chars", type=int, default=4000)
    parser.add_argument("--sample-top-k", type=int, default=300)
    parser.add_argument("--sample-tail-k", type=int, default=64)
    parser.add_argument("--max-pairs-per-case", type=int, default=2000)
    parser.add_argument("--seed", default="m5_88_fixed_bridge_router_v1")
    parser.add_argument("--epochs", type=int, default=200)
    parser.add_argument("--learning-rate", type=float, default=0.05)
    parser.add_argument("--l2", type=float, default=0.001)
    parser.add_argument(
        "--drop-view-type-features",
        action="store_true",
        help="Ablation: train only on score/rank and track interaction features, without candidate view_type/source-lane indicators.",
    )
    args = parser.parse_args()
    summary, rows, history = evaluate(
        args.split_manifest,
        args.generic_pool,
        args.embedding_cache_dir,
        model_path=args.model_path,
        device=args.device,
        max_seq_length=args.max_seq_length,
        text_field=args.text_field,
        max_chars=args.max_chars,
        sample_top_k=args.sample_top_k,
        sample_tail_k=args.sample_tail_k,
        max_pairs_per_case=args.max_pairs_per_case,
        seed=args.seed,
        epochs=args.epochs,
        learning_rate=args.learning_rate,
        l2=args.l2,
        include_view_type_features=not args.drop_view_type_features,
    )
    args.output_dir.mkdir(parents=True, exist_ok=True)
    write_json(args.output_dir / "summary.json", summary)
    write_jsonl(args.output_dir / "case_ranks.jsonl", rows)
    write_jsonl(args.output_dir / "training_history.jsonl", history)
    write_text(args.output_dir / "fixed_bridge_learned_router.md", render_markdown(summary))
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
