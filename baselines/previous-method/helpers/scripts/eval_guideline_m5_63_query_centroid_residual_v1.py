#!/usr/bin/env python3
"""Evaluate a closed-form query-side centroid residual over frozen code embeddings."""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np

try:
    from scripts.eval_guideline_m5_53_strict_generic_bm25_v1 import write_json, write_jsonl
    from scripts.eval_guideline_m5_56_strict_generic_fusion_v1 import (
        DEFAULT_MODEL_PATH,
        load_query_embedding,
        load_repo_embeddings,
        rank_order,
        summarize,
        write_text,
    )
except ModuleNotFoundError:
    from eval_guideline_m5_53_strict_generic_bm25_v1 import write_json, write_jsonl
    from eval_guideline_m5_56_strict_generic_fusion_v1 import (
        DEFAULT_MODEL_PATH,
        load_query_embedding,
        load_repo_embeddings,
        rank_order,
        summarize,
        write_text,
    )


SCHEMA_VERSION = "1.0"
K_VALUES = (10, 30, 100, 200, 500)
ALPHAS = (0.0, 0.1, 0.25, 0.5, 0.75, 1.0)


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
                    raise ValueError(f"expected JSON object row: {path}")
                rows.append(value)
    return rows


def normalize(vec: np.ndarray) -> np.ndarray:
    norm = float(np.linalg.norm(vec))
    if norm <= 1e-12:
        return vec.astype("float32", copy=False)
    return (vec / norm).astype("float32", copy=False)


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


def train_track_centroids(
    rows: list[dict[str, Any]],
    candidates_by_repo: dict[str, list[dict[str, Any]]],
    repo_embeddings: dict[str, np.ndarray],
) -> dict[str, np.ndarray]:
    positive_vectors: dict[str, list[np.ndarray]] = defaultdict(list)
    for row in rows:
        if row["inner_split"] != "inner_train":
            continue
        repo_key = str(row["repo_key"])
        candidate_ids = [str(item.get("candidate_id") or "") for item in candidates_by_repo[repo_key]]
        index_by_id = {candidate_id: index for index, candidate_id in enumerate(candidate_ids)}
        for candidate_id in row["positive_candidate_ids"]:
            index = index_by_id.get(str(candidate_id))
            if index is not None:
                positive_vectors[str(row["track_id"])].append(repo_embeddings[repo_key][index])
    return {
        track_id: normalize(np.mean(np.stack(vectors, axis=0), axis=0))
        for track_id, vectors in positive_vectors.items()
        if vectors
    }


def score_query(query_vec: np.ndarray, centroid: np.ndarray | None, alpha: float) -> np.ndarray:
    if centroid is None or alpha <= 0.0:
        return normalize(query_vec)
    return normalize((1.0 - alpha) * query_vec + alpha * centroid)


def evaluate_rows(
    rows: list[dict[str, Any]],
    candidates_by_repo: dict[str, list[dict[str, Any]]],
    repo_embeddings: dict[str, np.ndarray],
    query_embeddings_path: Path,
    centroids: dict[str, np.ndarray],
    *,
    alpha: float,
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for row in rows:
        repo_key = str(row["repo_key"])
        candidate_ids = [str(item.get("candidate_id") or "") for item in candidates_by_repo[repo_key]]
        positive_ids = set(str(candidate_id) for candidate_id in row["positive_candidate_ids"])
        query_vec = load_query_embedding(query_embeddings_path, str(row["query_text"]))
        residual_query = score_query(query_vec, centroids.get(str(row["track_id"])), alpha)
        scores = repo_embeddings[repo_key] @ residual_query
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
        item = {
            "case_id": row["case_id"],
            "inner_split": row["inner_split"],
            "track_id": row["track_id"],
            "repo_key": repo_key,
            "candidate_count": row["candidate_count"],
            "positive_candidate_count": row["positive_candidate_count"],
            "source_target_count": row["source_target_count"],
            "query_centroid_residual_rank": first_rank,
            "query_centroid_residual_candidate_id": first_candidate_id,
            "query_centroid_residual_score": first_score,
            "alpha": alpha,
            "track_has_train_centroid": str(row["track_id"]) in centroids,
        }
        for k in K_VALUES:
            item[f"query_centroid_residual_hit_at_{k}"] = bool(first_rank and first_rank <= k)
        out.append(item)
    return out


def metrics_by_split(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    by_split: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_split[str(row["inner_split"])].append(row)
    return {
        split: summarize(split_rows, "query_centroid_residual")
        for split, split_rows in sorted(by_split.items())
    }


def select_alpha(sweep_rows: list[dict[str, Any]]) -> dict[str, Any]:
    candidates = []
    for row in sweep_rows:
        train = row["metrics"]["inner_train"]
        val = row["metrics"]["inner_val"]
        candidates.append(
            (
                val["R@100"],
                val["R@30"],
                val["R@500"],
                train["R@100"],
                -float(row["alpha"]),
                row,
            )
        )
    return max(candidates)[-1]


def evaluate(
    split_manifest: Path,
    split_summary_path: Path,
    generic_pool: Path,
    query_embeddings_path: Path,
    embedding_cache_dir: Path,
    *,
    model_path: str = DEFAULT_MODEL_PATH,
    text_field: str = "text",
    max_chars: int = 4000,
    alphas: tuple[float, ...] = ALPHAS,
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    split_summary = read_json(split_summary_path)
    if split_summary.get("method_boundary", {}).get("repo_disjoint_inner_split") is not True:
        raise ValueError("M5.63 requires a repo-disjoint inner split")
    rows = read_jsonl(split_manifest)
    repos_needed = {str(row["repo_key"]) for row in rows}
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
    centroids = train_track_centroids(rows, candidates_by_repo, repo_embeddings)
    sweep: list[dict[str, Any]] = []
    per_case_rows: list[dict[str, Any]] = []
    for alpha in alphas:
        evaluated = evaluate_rows(
            rows,
            candidates_by_repo,
            repo_embeddings,
            query_embeddings_path,
            centroids,
            alpha=alpha,
        )
        metrics = metrics_by_split(evaluated)
        sweep.append(
            {
                "alpha": alpha,
                "metrics": metrics,
                "tracks_with_train_centroid": len(centroids),
            }
        )
        per_case_rows.extend(evaluated)
    selected = select_alpha(sweep)
    baseline = split_summary["split_metrics"]
    val = selected["metrics"]["inner_val"]
    gate = {
        "selected_alpha": selected["alpha"],
        "inner_val_R@100_delta_vs_embedding_baseline": val["R@100"] - baseline["inner_val"]["R@100"],
        "inner_val_R@30_delta_vs_embedding_baseline": val["R@30"] - baseline["inner_val"]["R@30"],
        "inner_val_R@500_delta_vs_embedding_baseline": val["R@500"] - baseline["inner_val"]["R@500"],
        "beats_embedding_baseline_R@100": val["R@100"] > baseline["inner_val"]["R@100"],
        "does_not_lower_R@30": val["R@30"] >= baseline["inner_val"]["R@30"],
        "does_not_lower_R@500": val["R@500"] >= baseline["inner_val"]["R@500"],
    }
    gate["passes_minimal_inner_val_gate"] = bool(
        gate["beats_embedding_baseline_R@100"]
        and gate["does_not_lower_R@30"]
        and gate["does_not_lower_R@500"]
    )
    summary = {
        "schema_version": SCHEMA_VERSION,
        "status": "completed",
        "created_at": utc_now(),
        "decision": "m5_63_query_centroid_residual_evaluated",
        "counts": {
            "cases": len(rows),
            "repos": len(repos_needed),
            "tracks": len({row["track_id"] for row in rows}),
            "tracks_with_train_centroid": len(centroids),
            "inner_train_cases": sum(1 for row in rows if row["inner_split"] == "inner_train"),
            "inner_val_cases": sum(1 for row in rows if row["inner_split"] == "inner_val"),
        },
        "config": {
            "alphas": list(alphas),
            "centroid_source": "inner_train positive candidate embeddings grouped by track_id",
            "selection_rule": "best inner_val R@100, then R@30, R@500, train R@100, smaller alpha",
        },
        "baseline_inner_split_metrics": baseline,
        "sweep": sweep,
        "selected": selected,
        "gate": gate,
        "method_boundary": {
            "uses_frozen_code_embeddings": True,
            "updates_code_encoder": False,
            "uses_inner_val_for_selection": True,
            "frozen_test_touched": False,
            "paper_safe_final_test": False,
            "non_anchor_candidates_are_unknown_not_negative": True,
            "source_point_trace_patch_not_used_for_candidate_admission": True,
        },
    }
    selected_rows = [row for row in per_case_rows if row["alpha"] == selected["alpha"]]
    return summary, sweep, selected_rows


def fmt(value: Any) -> str:
    return "n/a" if value is None else f"{float(value):.6f}"


def render_markdown(summary: dict[str, Any]) -> str:
    lines = [
        "# Guideline Anchor Retrieval M5.63: Query Centroid Residual",
        "",
        f"**Status:** {summary['status']}",
        f"**Decision:** `{summary['decision']}`",
        "",
        "## Purpose",
        "",
        "M5.63 evaluates a closed-form query-side residual over frozen code embeddings. It estimates a positive-candidate centroid per track from inner_train and mixes that centroid into the guideline query embedding. This is a development-gated first-stage retrieval probe, not a frozen-test result.",
        "",
        "## Counts",
        "",
        "| Metric | Value |",
        "| --- | ---: |",
    ]
    for key, value in summary["counts"].items():
        lines.append(f"| {key} | {value} |")
    lines.extend(["", "## Alpha Sweep", "", "| Alpha | Split | R@30 | R@100 | R@500 | MRR | p50 rank |", "| ---: | --- | ---: | ---: | ---: | ---: | ---: |"])
    for item in summary["sweep"]:
        for split, metric in sorted(item["metrics"].items()):
            lines.append(
                f"| {item['alpha']} | {split} | {fmt(metric['R@30'])} | {fmt(metric['R@100'])} | "
                f"{fmt(metric['R@500'])} | {fmt(metric['MRR'])} | {fmt(metric['first_rank_p50'])} |"
            )
    lines.extend(
        [
            "",
            "## Gate",
            "",
            "```json",
            json.dumps(summary["gate"], ensure_ascii=False, indent=2, sort_keys=True),
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
    parser.add_argument("--split-manifest", type=Path, default=Path("/tmp/m5_62_inner_split_manifest_v1/split_manifest.jsonl"))
    parser.add_argument("--split-summary", type=Path, default=Path("/tmp/m5_62_inner_split_manifest_v1/summary.json"))
    parser.add_argument("--generic-pool", type=Path, default=Path("/data/lhq/workspace/route-hacker/output/phase1_guideline_retrieval/multitrack_merged_source_ready_v39/candidate_pool_v3/candidate_pool.jsonl"))
    parser.add_argument("--query-embeddings", type=Path, default=Path("/tmp/m5_56_strict_generic_fusion_v1/query_embeddings.json"))
    parser.add_argument("--embedding-cache-dir", type=Path, default=Path("/tmp/m5_54_strict_generic_embedding_v1/cache"))
    parser.add_argument("--output-dir", type=Path, default=Path("/tmp/m5_63_query_centroid_residual_v1"))
    parser.add_argument("--model-path", default=DEFAULT_MODEL_PATH)
    parser.add_argument("--text-field", default="text")
    parser.add_argument("--max-chars", type=int, default=4000)
    parser.add_argument("--alphas", default=",".join(str(alpha) for alpha in ALPHAS))
    args = parser.parse_args()
    alphas = tuple(float(item) for item in args.alphas.split(",") if item.strip())
    summary, sweep, selected_rows = evaluate(
        args.split_manifest,
        args.split_summary,
        args.generic_pool,
        args.query_embeddings,
        args.embedding_cache_dir,
        model_path=args.model_path,
        text_field=args.text_field,
        max_chars=args.max_chars,
        alphas=alphas,
    )
    write_json(args.output_dir / "summary.json", summary)
    write_jsonl(args.output_dir / "alpha_sweep.jsonl", sweep)
    write_jsonl(args.output_dir / "selected_case_ranks.jsonl", selected_rows)
    write_text(args.output_dir / "query_centroid_residual.md", render_markdown(summary))
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
