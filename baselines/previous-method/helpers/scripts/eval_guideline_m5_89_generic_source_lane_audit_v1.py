#!/usr/bin/env python3
"""Audit generic-only coverage and retrieval after M5.88 source-lane diagnosis."""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np

try:
    from scripts.eval_guideline_m5_54_strict_generic_embedding_v1 import DEFAULT_MODEL_PATH
    from scripts.eval_guideline_m5_56_strict_generic_fusion_v1 import bm25_score_array, rank_order, ranks_from_scores, zscore
    from scripts.eval_guideline_m5_65_residual_fusion_lane_v1 import load_needed_candidates, read_jsonl
    from scripts.eval_guideline_m5_86_expanded_split_bm25_embedding_v1 import add_method_result
    from scripts.eval_guideline_m5_88_fixed_bridge_learned_router_v1 import (
        BASE_METHODS,
        load_or_encode_queries,
        load_repo_embeddings,
        split_metrics,
        tokenize,
        write_json,
        write_jsonl,
        write_text,
    )
except ModuleNotFoundError:
    from eval_guideline_m5_54_strict_generic_embedding_v1 import DEFAULT_MODEL_PATH
    from eval_guideline_m5_56_strict_generic_fusion_v1 import bm25_score_array, rank_order, ranks_from_scores, zscore
    from eval_guideline_m5_65_residual_fusion_lane_v1 import load_needed_candidates, read_jsonl
    from eval_guideline_m5_86_expanded_split_bm25_embedding_v1 import add_method_result
    from eval_guideline_m5_88_fixed_bridge_learned_router_v1 import (
        BASE_METHODS,
        load_or_encode_queries,
        load_repo_embeddings,
        split_metrics,
        tokenize,
        write_json,
        write_jsonl,
        write_text,
    )


SCHEMA_VERSION = "1.0"
GENERIC_VIEW_TYPES = {"function", "sliding_window"}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def line_interval(row: dict[str, Any]) -> tuple[int | None, int | None]:
    try:
        start = int(row.get("start_line"))
        end = int(row.get("end_line"))
    except (TypeError, ValueError):
        return None, None
    if start <= 0 or end <= 0:
        return None, None
    if end < start:
        start, end = end, start
    return start, end


def overlaps(left: dict[str, Any], right: dict[str, Any]) -> bool:
    if str(left.get("file") or "") != str(right.get("file") or ""):
        return False
    left_start, left_end = line_interval(left)
    right_start, right_end = line_interval(right)
    if left_start is None or right_start is None:
        return False
    return left_start <= right_end and right_start <= left_end


def is_generic_candidate(row: dict[str, Any], generic_view_types: set[str]) -> bool:
    return str(row.get("view_type") or "") in generic_view_types


def map_positive_ids_to_generic(
    *,
    positive_ids: list[str],
    candidates: list[dict[str, Any]],
    by_id: dict[str, dict[str, Any]],
    generic_candidates: list[dict[str, Any]],
    generic_view_types: set[str],
) -> tuple[list[str], dict[str, Any]]:
    generic_ids: set[str] = set()
    direct_positive_ids: list[str] = []
    overlap_positive_ids: list[str] = []
    missing_positive_ids: list[str] = []
    unmapped_positive_ids: list[str] = []
    positive_view_types: Counter[str] = Counter()
    generic_by_file: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for candidate in generic_candidates:
        generic_by_file[str(candidate.get("file") or "")].append(candidate)

    for positive_id in positive_ids:
        positive = by_id.get(positive_id)
        if positive is None:
            missing_positive_ids.append(positive_id)
            continue
        positive_view_types[str(positive.get("view_type") or "")] += 1
        if is_generic_candidate(positive, generic_view_types):
            generic_ids.add(positive_id)
            direct_positive_ids.append(positive_id)
            continue
        mapped_for_positive: list[str] = []
        for candidate in generic_by_file.get(str(positive.get("file") or ""), []):
            if overlaps(positive, candidate):
                candidate_id = str(candidate.get("candidate_id") or "")
                if candidate_id:
                    generic_ids.add(candidate_id)
                    mapped_for_positive.append(candidate_id)
        if mapped_for_positive:
            overlap_positive_ids.append(positive_id)
        else:
            unmapped_positive_ids.append(positive_id)

    diagnostics = {
        "direct_positive_ids": sorted(direct_positive_ids),
        "overlap_positive_ids": sorted(overlap_positive_ids),
        "missing_positive_ids": sorted(missing_positive_ids),
        "unmapped_positive_ids": sorted(unmapped_positive_ids),
        "positive_view_type_counts": dict(sorted(positive_view_types.items())),
        "generic_positive_count": len(generic_ids),
    }
    return sorted(generic_ids), diagnostics


def evaluate_case(
    *,
    source_row: dict[str, Any],
    candidates: list[dict[str, Any]],
    generic_candidates: list[dict[str, Any]],
    repo_embeddings: np.ndarray,
    query_vectors: dict[str, np.ndarray],
    positive_ids: list[str],
    map_diagnostics: dict[str, Any],
) -> dict[str, Any]:
    generic_indices = [index for index, candidate in enumerate(candidates) if is_generic_candidate(candidate, GENERIC_VIEW_TYPES)]
    candidate_ids = [str(candidates[index].get("candidate_id") or "") for index in generic_indices]
    query = str(source_row["query_text"])
    bm25 = bm25_score_array(tokenize(query), generic_candidates)
    embedding = repo_embeddings[generic_indices] @ query_vectors[query]
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
    for method, scores in method_scores.items():
        add_method_result(row, method, rank_order(scores, candidate_ids), scores, candidate_ids, positive_set)
    return row


def source_family(candidate_id: str, view_type: str) -> str:
    if view_type in GENERIC_VIEW_TYPES:
        return f"generic:{view_type}"
    if "supplement" in candidate_id:
        return "supplement"
    return f"other:{view_type or 'unknown'}"


def summarize_mapping(rows: list[dict[str, Any]]) -> dict[str, Any]:
    by_split: dict[str, list[dict[str, Any]]] = defaultdict(list)
    by_track: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_split[str(row["inner_split"])].append(row)
        by_track[str(row["track_id"])].append(row)

    def one(part: list[dict[str, Any]]) -> dict[str, Any]:
        direct = sum(len(row["generic_mapping"]["direct_positive_ids"]) for row in part)
        overlap_count = sum(len(row["generic_mapping"]["overlap_positive_ids"]) for row in part)
        unmapped = sum(len(row["generic_mapping"]["unmapped_positive_ids"]) for row in part)
        missing = sum(len(row["generic_mapping"]["missing_positive_ids"]) for row in part)
        return {
            "cases": len(part),
            "covered_cases": sum(1 for row in part if row["positive_candidate_count"] > 0),
            "uncovered_cases": sum(1 for row in part if row["positive_candidate_count"] == 0),
            "source_positive_ids": sum(int(row["source_positive_candidate_count"]) for row in part),
            "generic_positive_ids": sum(int(row["positive_candidate_count"]) for row in part),
            "direct_source_positive_ids": direct,
            "overlap_mapped_source_positive_ids": overlap_count,
            "unmapped_source_positive_ids": unmapped,
            "missing_source_positive_ids": missing,
        }

    return {
        "all": one(rows),
        "by_split": {split: one(part) for split, part in sorted(by_split.items())},
        "by_track": {track: one(part) for track, part in sorted(by_track.items())},
    }


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
    generic_view_types: set[str],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    source_rows = read_jsonl(split_manifest)
    repos_needed = {str(row["repo_key"]) for row in source_rows}
    candidates_by_repo = load_needed_candidates(generic_pool, repos_needed)
    missing_repos = sorted(repos_needed - set(candidates_by_repo))
    if missing_repos:
        raise ValueError(f"candidate pool missing repos: {missing_repos[:10]}")

    query_texts = sorted({str(row["query_text"]) for row in source_rows})
    query_vectors = load_or_encode_queries(query_texts, model_path=model_path, device=device, max_seq_length=max_seq_length)
    repo_embeddings: dict[str, np.ndarray] = {}
    for repo_key, candidates in sorted(candidates_by_repo.items()):
        repo_embeddings[repo_key] = load_repo_embeddings(
            repo_key=repo_key,
            candidates=candidates,
            cache_dir=embedding_cache_dir,
            model_path=model_path,
            text_field=text_field,
            max_chars=max_chars,
        )

    rows: list[dict[str, Any]] = []
    source_family_counts: Counter[str] = Counter()
    generic_candidate_counts: Counter[str] = Counter()
    for source_row in source_rows:
        repo_key = str(source_row["repo_key"])
        candidates = candidates_by_repo[repo_key]
        by_id = {str(candidate.get("candidate_id") or ""): candidate for candidate in candidates}
        generic_candidates = [candidate for candidate in candidates if is_generic_candidate(candidate, generic_view_types)]
        for candidate in candidates:
            source_family_counts[source_family(str(candidate.get("candidate_id") or ""), str(candidate.get("view_type") or ""))] += 1
        for candidate in generic_candidates:
            generic_candidate_counts[str(candidate.get("view_type") or "")] += 1
        positive_ids, diagnostics = map_positive_ids_to_generic(
            positive_ids=[str(candidate_id) for candidate_id in source_row.get("positive_candidate_ids") or []],
            candidates=candidates,
            by_id=by_id,
            generic_candidates=generic_candidates,
            generic_view_types=generic_view_types,
        )
        rows.append(
            evaluate_case(
                source_row=source_row,
                candidates=candidates,
                generic_candidates=generic_candidates,
                repo_embeddings=repo_embeddings[repo_key],
                query_vectors=query_vectors,
                positive_ids=positive_ids,
                map_diagnostics=diagnostics,
            )
        )

    covered_rows = [row for row in rows if row["positive_candidate_count"] > 0]
    metrics = split_metrics(covered_rows, BASE_METHODS)
    # Keep comparison names explicit and small for this audit.
    by_split: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in covered_rows:
        by_split[str(row["inner_split"])].append(row)
    comparison_summary = {}
    for split, part in sorted(by_split.items()):
        comparison_summary[split] = {
            "embedding_vs_bm25_at_500": compare_methods(part, "bm25", "embedding", 500),
            "rrf_vs_bm25_at_500": compare_methods(part, "bm25", "rrf_bm25_embedding", 500),
            "zscore_vs_bm25_at_500": compare_methods(part, "bm25", "zscore_sum", 500),
        }

    summary = {
        "schema_version": SCHEMA_VERSION,
        "status": "completed",
        "created_at": utc_now(),
        "decision": "m5_89_generic_source_lane_audit_completed",
        "scope": {
            "split_manifest": str(split_manifest),
            "generic_pool": str(generic_pool),
            "embedding_cache_dir": str(embedding_cache_dir),
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
        },
        "candidate_source_family_counts": dict(sorted(source_family_counts.items())),
        "generic_candidate_view_type_counts": dict(sorted(generic_candidate_counts.items())),
        "mapping": summarize_mapping(rows),
        "metrics_on_generic_covered_cases": metrics,
        "comparisons_on_generic_covered_cases": comparison_summary,
        "method_boundary": {
            "development_only": True,
            "frozen_test_touched": False,
            "candidate_pool_mutated": False,
            "generic_only_evaluation": True,
            "positive_mapping": "same_repo_same_file_line_overlap_or_direct_generic_id",
            "source_lane_features_used": False,
            "updates_code_encoder": False,
            "uses_frozen_embedding_cache": True,
            "uncovered_cases_excluded_from_retrieval_metrics_but_reported_in_mapping": True,
        },
    }
    return summary, rows


def compare_methods(rows: list[dict[str, Any]], left: str, right: str, k: int) -> dict[str, Any]:
    rescues = []
    regressions = []
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


def metric_row(summary: dict[str, Any], split: str, method: str) -> dict[str, Any]:
    return summary.get("metrics_on_generic_covered_cases", {}).get(split, {}).get("all", {}).get(method, {})


def render_markdown(summary: dict[str, Any]) -> str:
    lines = [
        "# Guideline Anchor Retrieval M5.89: Generic Source-Lane Audit",
        "",
        f"**Status:** {summary['status']}",
        f"**Decision:** `{summary['decision']}`",
        "",
        "## Mapping Coverage",
        "",
        "```json",
        json.dumps(summary["mapping"]["all"], ensure_ascii=False, indent=2, sort_keys=True),
        "```",
        "",
        "## Inner-Val Generic-Only Metrics",
        "",
        "| Method | R@30 | R@100 | R@500 | MRR | p90 rank | p99 rank |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for method in BASE_METHODS:
        item = metric_row(summary, "inner_val", method)
        lines.append(
            "| {method} | {r30:.6f} | {r100:.6f} | {r500:.6f} | {mrr:.6f} | {p90:.6f} | {p99:.6f} |".format(
                method=method,
                r30=item.get("R@30") or 0.0,
                r100=item.get("R@100") or 0.0,
                r500=item.get("R@500") or 0.0,
                mrr=item.get("MRR") or 0.0,
                p90=item.get("first_rank_p90") or 0.0,
                p99=item.get("first_rank_p99") or 0.0,
            )
        )
    lines.extend(
        [
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
    parser.add_argument("--generic-pool", type=Path, default=Path("/tmp/m5_83_expanded_inner_split_manifest_v1/candidate_pool.v1.jsonl"))
    parser.add_argument("--embedding-cache-dir", type=Path, default=Path("/tmp/m5_86_expanded_split_bm25_embedding_v1/cache"))
    parser.add_argument("--output-dir", type=Path, default=Path("/tmp/m5_89_generic_source_lane_audit_v1"))
    parser.add_argument("--model-path", default=DEFAULT_MODEL_PATH)
    parser.add_argument("--device", default="cpu")
    parser.add_argument("--max-seq-length", type=int, default=512)
    parser.add_argument("--text-field", default="text")
    parser.add_argument("--max-chars", type=int, default=4000)
    args = parser.parse_args()
    summary, rows = evaluate(
        args.split_manifest,
        args.generic_pool,
        args.embedding_cache_dir,
        model_path=args.model_path,
        device=args.device,
        max_seq_length=args.max_seq_length,
        text_field=args.text_field,
        max_chars=args.max_chars,
        generic_view_types=GENERIC_VIEW_TYPES,
    )
    args.output_dir.mkdir(parents=True, exist_ok=True)
    write_json(args.output_dir / "summary.json", summary)
    write_jsonl(args.output_dir / "case_ranks.jsonl", rows)
    write_text(args.output_dir / "generic_source_lane_audit.md", render_markdown(summary))
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
