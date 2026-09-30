#!/usr/bin/env python3
"""Evaluate query-centroid residual as an extra retrieval lane/fusion signal."""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np

try:
    from scripts.eval_guideline_m5_53_strict_generic_bm25_v1 import (
        percentile,
        tokenize,
        write_json,
        write_jsonl,
    )
    from scripts.eval_guideline_m5_56_strict_generic_fusion_v1 import (
        DEFAULT_MODEL_PATH,
        bm25_score_array,
        load_query_embedding,
        load_repo_embeddings,
        rank_order,
        ranks_from_scores,
        summarize,
        write_text,
        zscore,
    )
    from scripts.eval_guideline_m5_63_query_centroid_residual_v1 import (
        normalize,
        score_query,
        train_track_centroids,
    )
except ModuleNotFoundError:
    from eval_guideline_m5_53_strict_generic_bm25_v1 import (
        percentile,
        tokenize,
        write_json,
        write_jsonl,
    )
    from eval_guideline_m5_56_strict_generic_fusion_v1 import (
        DEFAULT_MODEL_PATH,
        bm25_score_array,
        load_query_embedding,
        load_repo_embeddings,
        rank_order,
        ranks_from_scores,
        summarize,
        write_text,
        zscore,
    )
    from eval_guideline_m5_63_query_centroid_residual_v1 import (
        normalize,
        score_query,
        train_track_centroids,
    )


SCHEMA_VERSION = "1.0"
K_VALUES = (10, 30, 100, 200, 500)
BASE_METHODS = ("bm25", "embedding", "query_centroid_residual")
FUSION_METHODS = ("rrf_bm25_embedding_residual", "zscore_sum_residual")
METHODS = BASE_METHODS + FUSION_METHODS + ("lane_allocation_residual",)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                value = json.loads(line)
                if not isinstance(value, dict):
                    raise ValueError(f"expected object row: {path}")
                rows.append(value)
    return rows


def load_needed_candidates(generic_pool: Path, repos_needed: set[str]) -> dict[str, list[dict[str, Any]]]:
    candidates_by_repo: dict[str, list[dict[str, Any]]] = defaultdict(list)
    with generic_pool.open(encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            row = json.loads(line)
            repo_key = str(row.get("repo_key") or "")
            if repo_key in repos_needed:
                candidates_by_repo[repo_key].append(row)
    return candidates_by_repo


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
    order: np.ndarray,
    scores: np.ndarray,
    candidate_ids: list[str],
    positive_ids: set[str],
) -> None:
    rank, candidate_id, score = first_positive(order, scores, candidate_ids, positive_ids)
    row[f"{method}_rank"] = rank
    row[f"{method}_candidate_id"] = candidate_id
    row[f"{method}_score"] = score
    for k in K_VALUES:
        row[f"{method}_hit_at_{k}"] = bool(rank and rank <= k)


def lane_queue(
    orders: dict[str, np.ndarray],
    candidate_ids: list[str],
    budgets: dict[str, int],
    lane_order: tuple[str, ...] = BASE_METHODS,
) -> list[str]:
    queue: list[str] = []
    seen: set[str] = set()
    for lane in lane_order:
        for index in orders[lane][: budgets.get(lane, 0)]:
            candidate_id = candidate_ids[int(index)]
            if candidate_id in seen:
                continue
            seen.add(candidate_id)
            queue.append(candidate_id)
    return queue


def first_positive_in_queue(queue: list[str], positive_ids: set[str]) -> tuple[int | None, str | None]:
    for rank, candidate_id in enumerate(queue, start=1):
        if candidate_id in positive_ids:
            return rank, candidate_id
    return None, None


def allocation_candidates(k: int) -> list[dict[str, int]]:
    out: list[dict[str, int]] = []
    for bm25_budget in range(k + 1):
        for embedding_budget in range(k - bm25_budget + 1):
            residual_budget = k - bm25_budget - embedding_budget
            out.append(
                {
                    "bm25": bm25_budget,
                    "embedding": embedding_budget,
                    "query_centroid_residual": residual_budget,
                }
            )
    return out


def case_level_hit(row: dict[str, Any], budgets: dict[str, int]) -> bool:
    for lane, budget in budgets.items():
        rank = row.get(f"{lane}_rank")
        if budget > 0 and rank is not None and int(rank) <= budget:
            return True
    return False


def budget_tie_key(item: dict[str, Any]) -> tuple[int, int, int, int]:
    budgets = item["budgets"]
    # Prefer solutions that preserve the original two lanes when the train hit count ties.
    return (
        int(item["hit_count"]),
        -int(budgets["query_centroid_residual"]),
        int(budgets["embedding"]),
        -int(budgets["bm25"]),
    )


def select_lane_budgets(train_rows: list[dict[str, Any]]) -> tuple[dict[int, dict[str, int]], list[dict[str, Any]]]:
    selected: dict[int, dict[str, int]] = {}
    sweep_rows: list[dict[str, Any]] = []
    for k in K_VALUES:
        best: dict[str, Any] | None = None
        for budgets in allocation_candidates(k):
            hit_count = sum(1 for row in train_rows if case_level_hit(row, budgets))
            item = {
                "K": k,
                "budgets": budgets,
                "hit_count": hit_count,
                "hit_rate": hit_count / len(train_rows) if train_rows else None,
                "selection_split": "inner_train",
                "selection_signal": "case_level_first_positive_rank",
            }
            sweep_rows.append(item)
            if best is None or budget_tie_key(item) > budget_tie_key(best):
                best = item
        if best is None:
            raise ValueError(f"empty lane budget sweep for K={k}")
        selected[k] = dict(best["budgets"])
    return selected, sweep_rows


def apply_lane_allocation(rows: list[dict[str, Any]], selected_budgets: dict[int, dict[str, int]]) -> None:
    for row in rows:
        positive_ids = set(str(candidate_id) for candidate_id in row.pop("_positive_candidate_ids"))
        candidate_ids = row.pop("_candidate_ids")
        orders = row.pop("_orders")
        best_rank = None
        best_candidate_id = None
        for k in K_VALUES:
            budgets = selected_budgets[k]
            queue = lane_queue(orders, candidate_ids, budgets)
            rank, candidate_id = first_positive_in_queue(queue, positive_ids)
            row[f"lane_allocation_residual_{k}_bm25_budget"] = budgets["bm25"]
            row[f"lane_allocation_residual_{k}_embedding_budget"] = budgets["embedding"]
            row[f"lane_allocation_residual_{k}_residual_budget"] = budgets["query_centroid_residual"]
            row[f"lane_allocation_residual_{k}_queue_size"] = len(queue)
            row[f"lane_allocation_residual_rank_at_{k}"] = rank
            row[f"lane_allocation_residual_candidate_at_{k}"] = candidate_id
            row[f"lane_allocation_residual_hit_at_{k}"] = bool(rank and rank <= k)
            if k == max(K_VALUES):
                best_rank = rank
                best_candidate_id = candidate_id
        row["lane_allocation_residual_rank"] = best_rank
        row["lane_allocation_residual_candidate_id"] = best_candidate_id
        row["lane_allocation_residual_score"] = None


def metrics_by_split(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    by_split: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_split[str(row["inner_split"])].append(row)
    return {
        split: {method: summarize(split_rows, method) for method in METHODS}
        for split, split_rows in sorted(by_split.items())
    }


def metric_delta(left: dict[str, Any], right: dict[str, Any], key: str) -> float | None:
    if left.get(key) is None or right.get(key) is None:
        return None
    return float(left[key]) - float(right[key])


def best_method(metrics: dict[str, dict[str, Any]], methods: tuple[str, ...], key: str) -> str:
    return max(methods, key=lambda method: float(metrics[method][key]))


def gate_against_m5_64(summary: dict[str, Any], m5_64_summary: dict[str, Any]) -> dict[str, Any]:
    val_metrics = summary["split_metrics"]["inner_val"]
    residual_methods = FUSION_METHODS + ("lane_allocation_residual",)
    best_residual_r100 = best_method(val_metrics, residual_methods, "R@100")
    best_residual_r30 = best_method(val_metrics, residual_methods, "R@30")
    best_residual_r500 = best_method(val_metrics, residual_methods, "R@500")
    fixed_metrics = m5_64_summary["split_metrics"]["inner_val"]
    fixed_methods = tuple(method for method in fixed_metrics if method != "query_centroid_residual")
    best_fixed_r100 = best_method(fixed_metrics, fixed_methods, "R@100")
    best_fixed_r30 = best_method(fixed_metrics, fixed_methods, "R@30")
    best_fixed_r500 = best_method(fixed_metrics, fixed_methods, "R@500")
    gate = {
        "best_residual_fusion_R@100_method": best_residual_r100,
        "best_residual_fusion_R@100": val_metrics[best_residual_r100]["R@100"],
        "best_residual_fusion_R@30_method": best_residual_r30,
        "best_residual_fusion_R@30": val_metrics[best_residual_r30]["R@30"],
        "best_residual_fusion_R@500_method": best_residual_r500,
        "best_residual_fusion_R@500": val_metrics[best_residual_r500]["R@500"],
        "best_fixed_R@100_method": best_fixed_r100,
        "best_fixed_R@100": fixed_metrics[best_fixed_r100]["R@100"],
        "best_fixed_R@30_method": best_fixed_r30,
        "best_fixed_R@30": fixed_metrics[best_fixed_r30]["R@30"],
        "best_fixed_R@500_method": best_fixed_r500,
        "best_fixed_R@500": fixed_metrics[best_fixed_r500]["R@500"],
    }
    gate["beats_best_fixed_R@100"] = gate["best_residual_fusion_R@100"] > gate["best_fixed_R@100"]
    gate["does_not_lower_vs_best_fixed_R@30"] = gate["best_residual_fusion_R@30"] >= gate["best_fixed_R@30"]
    gate["does_not_lower_vs_best_fixed_R@500"] = gate["best_residual_fusion_R@500"] >= gate["best_fixed_R@500"]
    gate["passes_residual_fusion_inner_val_gate"] = bool(
        gate["beats_best_fixed_R@100"]
        and gate["does_not_lower_vs_best_fixed_R@30"]
        and gate["does_not_lower_vs_best_fixed_R@500"]
    )
    return gate


def evaluate(
    split_manifest: Path,
    generic_pool: Path,
    query_embeddings_path: Path,
    embedding_cache_dir: Path,
    residual_summary_path: Path,
    m5_64_summary_path: Path,
    *,
    model_path: str = DEFAULT_MODEL_PATH,
    text_field: str = "text",
    max_chars: int = 4000,
    rrf_k: int = 60,
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    split_rows = read_jsonl(split_manifest)
    residual_summary = read_json(residual_summary_path)
    m5_64_summary = read_json(m5_64_summary_path)
    selected_alpha = float(residual_summary["gate"]["selected_alpha"])
    repos_needed = {str(row["repo_key"]) for row in split_rows}
    candidates_by_repo = load_needed_candidates(generic_pool, repos_needed)
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
    centroids = train_track_centroids(split_rows, candidates_by_repo, repo_embeddings)
    rows: list[dict[str, Any]] = []
    for source in split_rows:
        repo_key = str(source["repo_key"])
        candidates = candidates_by_repo[repo_key]
        candidate_ids = [str(row.get("candidate_id") or "") for row in candidates]
        positive_ids = set(str(candidate_id) for candidate_id in source["positive_candidate_ids"])
        query_vec = load_query_embedding(query_embeddings_path, str(source["query_text"]))
        residual_query = score_query(query_vec, centroids.get(str(source["track_id"])), selected_alpha)
        bm25 = bm25_score_array(tokenize(str(source["query_text"])), candidates)
        embedding = repo_embeddings[repo_key] @ query_vec
        residual = repo_embeddings[repo_key] @ residual_query
        bm25_ranks = ranks_from_scores(bm25, candidate_ids)
        embedding_ranks = ranks_from_scores(embedding, candidate_ids)
        residual_ranks = ranks_from_scores(residual, candidate_ids)
        rrf3 = (1.0 / (rrf_k + bm25_ranks)) + (1.0 / (rrf_k + embedding_ranks)) + (1.0 / (rrf_k + residual_ranks))
        zsum3 = zscore(bm25) + zscore(embedding) + zscore(residual)
        method_scores = {
            "bm25": bm25,
            "embedding": embedding,
            "query_centroid_residual": residual,
            "rrf_bm25_embedding_residual": rrf3.astype("float32", copy=False),
            "zscore_sum_residual": zsum3.astype("float32", copy=False),
        }
        row: dict[str, Any] = {
            "case_id": source["case_id"],
            "inner_split": source["inner_split"],
            "track_id": source["track_id"],
            "repo_key": repo_key,
            "candidate_count": len(candidates),
            "positive_candidate_count": len(positive_ids),
            "source_target_count": source["source_target_count"],
            "selected_alpha": selected_alpha,
            "track_has_train_centroid": str(source["track_id"]) in centroids,
            "_candidate_ids": candidate_ids,
            "_positive_candidate_ids": list(positive_ids),
            "_orders": {},
        }
        for method, scores in method_scores.items():
            order = rank_order(scores, candidate_ids)
            add_method_result(row, method, order, scores, candidate_ids, positive_ids)
            if method in BASE_METHODS:
                row["_orders"][method] = order
        rows.append(row)
    train_rows = [row for row in rows if row["inner_split"] == "inner_train"]
    selected_budgets, budget_sweep = select_lane_budgets(train_rows)
    apply_lane_allocation(rows, selected_budgets)
    split_metrics = metrics_by_split(rows)
    summary = {
        "schema_version": SCHEMA_VERSION,
        "status": "completed",
        "created_at": utc_now(),
        "decision": "m5_65_residual_fusion_lane_evaluated",
        "counts": {
            "cases": len(rows),
            "inner_train_cases": len([row for row in rows if row["inner_split"] == "inner_train"]),
            "inner_val_cases": len([row for row in rows if row["inner_split"] == "inner_val"]),
            "repos": len(repos_needed),
            "tracks": len({row["track_id"] for row in rows}),
            "tracks_with_train_centroid": len(centroids),
        },
        "config": {
            "selected_alpha": selected_alpha,
            "rrf_k": rrf_k,
            "residual_source": "M5.63 inner_train positive centroid by track_id",
            "lane_budget_selection": "select per-K bm25/embedding/residual budgets on inner_train case-level first-positive ranks; evaluate candidate-level queues on inner_val",
            "lane_order": list(BASE_METHODS),
        },
        "selected_lane_budgets": {str(k): budgets for k, budgets in selected_budgets.items()},
        "split_metrics": split_metrics,
        "comparison_gate": {},
        "method_boundary": {
            "analysis_only": True,
            "uses_frozen_code_embeddings": True,
            "updates_code_encoder": False,
            "uses_inner_train_for_lane_budget_selection": True,
            "uses_inner_val_for_gate": True,
            "frozen_test_touched": False,
            "paper_safe_final_test": False,
            "non_anchor_candidates_are_unknown_not_negative": True,
            "source_point_trace_patch_not_used_for_candidate_admission": True,
            "candidate_universe": "frozen v39 full-repository generic function/sliding_window pool",
        },
    }
    summary["comparison_gate"] = gate_against_m5_64(summary, m5_64_summary)
    return summary, rows, budget_sweep


def fmt(value: Any) -> str:
    return "n/a" if value is None else f"{float(value):.6f}"


def render_markdown(summary: dict[str, Any]) -> str:
    lines = [
        "# Guideline Anchor Retrieval M5.65: Residual Fusion Lane",
        "",
        f"**Status:** {summary['status']}",
        f"**Decision:** `{summary['decision']}`",
        "",
        "## Purpose",
        "",
        "M5.65 tests the M5.63 query-centroid residual as an additional retrieval signal instead of treating it as a standalone replacement. It recomputes candidate-level BM25, base embedding, and residual embedding scores over the same full-repository generic candidate pool, then evaluates three-signal RRF, three-signal z-score fusion, and an inner-train-selected three-lane queue.",
        "",
        "## Counts",
        "",
        "| Metric | Value |",
        "| --- | ---: |",
    ]
    for key, value in summary["counts"].items():
        lines.append(f"| {key} | {value} |")
    lines.extend(["", "## Inner Val Metrics", "", "| Method | R@30 | R@100 | R@500 | MRR | p50 rank | p95 rank |", "| --- | ---: | ---: | ---: | ---: | ---: | ---: |"])
    for method in METHODS:
        metric = summary["split_metrics"]["inner_val"][method]
        lines.append(
            f"| {method} | {fmt(metric['R@30'])} | {fmt(metric['R@100'])} | {fmt(metric['R@500'])} | "
            f"{fmt(metric['MRR'])} | {fmt(metric['first_rank_p50'])} | {fmt(metric['first_rank_p95'])} |"
        )
    lines.extend(
        [
            "",
            "## Selected Lane Budgets",
            "",
            "```json",
            json.dumps(summary["selected_lane_budgets"], ensure_ascii=False, indent=2, sort_keys=True),
            "```",
            "",
            "## Gate",
            "",
            "```json",
            json.dumps(summary["comparison_gate"], ensure_ascii=False, indent=2, sort_keys=True),
            "```",
            "",
            "## Boundary",
            "",
            "```json",
            json.dumps(summary["method_boundary"], ensure_ascii=False, indent=2, sort_keys=True),
            "```",
            "",
            "## Interpretation",
            "",
            "This remains an inner-split development experiment. A positive gate would indicate that residual provides complementary first-stage recall signal; a failed gate means the residual should not yet be promoted beyond a diagnostic lane.",
        ]
    )
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--split-manifest", type=Path, default=Path("/tmp/m5_62_inner_split_manifest_v1/split_manifest.jsonl"))
    parser.add_argument("--generic-pool", type=Path, default=Path("/data/lhq/workspace/route-hacker/output/phase1_guideline_retrieval/multitrack_merged_source_ready_v39/candidate_pool_v3/candidate_pool.jsonl"))
    parser.add_argument("--query-embeddings", type=Path, default=Path("/tmp/m5_56_strict_generic_fusion_v1/query_embeddings.json"))
    parser.add_argument("--embedding-cache-dir", type=Path, default=Path("/tmp/m5_54_strict_generic_embedding_v1/cache"))
    parser.add_argument("--residual-summary", type=Path, default=Path("/tmp/m5_63_query_centroid_residual_v1/summary.json"))
    parser.add_argument("--m5-64-summary", type=Path, default=Path("/tmp/m5_64_inner_split_baseline_comparison_v1/summary.json"))
    parser.add_argument("--output-dir", type=Path, default=Path("/tmp/m5_65_residual_fusion_lane_v1"))
    parser.add_argument("--model-path", default=DEFAULT_MODEL_PATH)
    parser.add_argument("--text-field", default="text")
    parser.add_argument("--max-chars", type=int, default=4000)
    parser.add_argument("--rrf-k", type=int, default=60)
    args = parser.parse_args()
    summary, rows, budget_sweep = evaluate(
        args.split_manifest,
        args.generic_pool,
        args.query_embeddings,
        args.embedding_cache_dir,
        args.residual_summary,
        args.m5_64_summary,
        model_path=args.model_path,
        text_field=args.text_field,
        max_chars=args.max_chars,
        rrf_k=args.rrf_k,
    )
    args.output_dir.mkdir(parents=True, exist_ok=True)
    write_json(args.output_dir / "summary.json", summary)
    write_jsonl(args.output_dir / "case_ranks.jsonl", rows)
    write_jsonl(args.output_dir / "lane_budget_sweep.jsonl", budget_sweep)
    write_text(args.output_dir / "residual_fusion_lane.md", render_markdown(summary))
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
