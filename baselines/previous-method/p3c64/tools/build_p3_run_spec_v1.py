#!/usr/bin/env python3
"""Freeze the finite P3 query-only hard-competition selection contract."""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "p3_hard_competition_query_adapter_run_spec_v1"
RUN_ID = "p3_hard_competition_query_adapter_v1"
MODEL_PATH = (
    "/data/lhq/.cache/huggingface/hub/models--Qwen--Qwen3-Embedding-0.6B/"
    "snapshots/97b0c614be4d77ee51c0cef4e5f07c00f9eb65b3"
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def now_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def write_json(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def manifest_entry(path: Path) -> dict[str, str]:
    return {"path": str(path), "sha256": sha256_file(path)}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--split-dir", type=Path, required=True)
    parser.add_argument("--m7-executor", type=Path, required=True)
    parser.add_argument("--locked-helper", type=Path, required=True)
    parser.add_argument("--p3-executor", type=Path, required=True)
    parser.add_argument("--output-path", type=Path, required=True)
    args = parser.parse_args()

    split_dir = args.split_dir.resolve()
    cases_path = split_dir / "p3_development_cases.v1.jsonl"
    pairs_path = split_dir / "p3_development_pairs.v1.jsonl"
    split_summary_path = split_dir / "summary.json"
    required = [
        cases_path,
        pairs_path,
        split_summary_path,
        args.m7_executor.resolve(),
        args.locked_helper.resolve(),
        args.p3_executor.resolve(),
    ]
    missing = [str(path) for path in required if not path.is_file()]
    if missing:
        raise FileNotFoundError(f"missing P3 preregistration input(s): {missing}")
    output_path = args.output_path.resolve()
    if output_path.exists():
        raise FileExistsError(f"refusing to overwrite P3 run spec: {output_path}")
    split_summary = read_json(split_summary_path)
    if split_summary.get("status") != "frozen_pre_training_pre_retrieval":
        raise ValueError("P3 split must be frozen before preregistration")
    counts = split_summary["counts"]
    if counts["case_count_by_split"] != {
        "p3_fitting": 112,
        "p3_selection": 43,
    } or counts["pair_count_by_split"] != {
        "p3_fitting": 217,
        "p3_selection": 78,
    }:
        raise ValueError(f"unexpected frozen P3 split counts: {counts}")
    all_track_ids = sorted(counts["selection_track_case_counts"])
    if (
        len(all_track_ids) != 10
        or set(counts["fitting_track_case_counts"]) != set(all_track_ids)
    ):
        raise ValueError("P3 split does not retain the same ten tracks on both sides")

    spec = {
        "schema_version": SCHEMA_VERSION,
        "run_id": RUN_ID,
        "status": "pre_registered_not_executed",
        "created_at": now_utc(),
        "method_hypothesis": (
            "M8 showed that adapting code vectors improved some long-budget tail "
            "measures but degraded early ranking. P3 retains the frozen audited "
            "code bank and adapts only a runtime-guideline query vector. Rather "
            "than sampling arbitrary background, P3 trains against deterministic "
            "same-repository candidates already competitive under frozen dense B0. "
            "This targets early review-budget ordering without asserting non-anchor "
            "candidates are safe or false."
        ),
        "inputs": {
            "p3_cases": manifest_entry(cases_path),
            "p3_pairs": manifest_entry(pairs_path),
            "p3_split_summary": manifest_entry(split_summary_path),
            "m7_executor": manifest_entry(args.m7_executor.resolve()),
            "locked_helper": manifest_entry(args.locked_helper.resolve()),
            "p3_executor": manifest_entry(args.p3_executor.resolve()),
            "model_path": MODEL_PATH,
            "candidate_pools": [
                {
                    "path": "/tmp/m5_83_expanded_inner_split_manifest_v1/"
                    "candidate_pool.v1.jsonl",
                    "sha256": (
                        "ddf58974d2dc05caac9afac31f4db1373e1bc1c1381cc99b08df67a6a81af92d"
                    ),
                },
                {
                    "path": "/tmp/m5_92_gap_generic_candidate_shard_v1/"
                    "gap_generic_candidate_shard.v1.jsonl",
                    "sha256": (
                        "065e01257d8faf855ad0a30600d7ee3fe9d65d9592fe7390005a308b1c9da454"
                    ),
                },
            ],
            "embedding_cache_dirs": [
                "/tmp/m5_86_expanded_split_bm25_embedding_v1/cache",
                "/tmp/m5_95_repaired_pool_embedding_cache_v1/cache",
            ],
        },
        "split_contract": {
            "source": "M7 inner_train pair-backed cases only",
            "unit": "normalized project family",
            "fitting_case_count": 112,
            "selection_case_count": 43,
            "fitting_pair_count": 217,
            "selection_pair_count": 78,
            "all_track_ids": all_track_ids,
            "selection_data_use": (
                "Selection may inspect only p3_selection aggregate metrics, rank "
                "ledgers, and paired rescues/regressions from this contract."
            ),
            "prohibited": (
                "M7 inner_val and every M8 query/candidate/vector/score/rank/result "
                "artifact are unavailable for P3 fitting or model selection."
            ),
        },
        "candidate_contract": {
            "admission": "frozen full-repository generic function + sliding_window",
            "text_field": "text",
            "max_chars": 4000,
            "max_sequence_length": 512,
            "embedding_dimension": 1024,
            "code_embedding_state": "frozen cached float32 L2-normalized Qwen vectors",
            "runtime_input": "fixed natural-language guideline text only",
        },
        "finite_variants": [
            {
                "variant_id": "B0",
                "training": False,
                "query_projection": False,
                "code_projection": False,
                "competition_count": None,
            },
            {
                "variant_id": "P3C16",
                "training": True,
                "query_projection": True,
                "code_projection": False,
                "competition_count": 16,
            },
            {
                "variant_id": "P3C64",
                "training": True,
                "query_projection": True,
                "code_projection": False,
                "competition_count": 64,
            },
        ],
        "training": {
            "backbone": "frozen Qwen3-Embedding-0.6B",
            "projection": {
                "type": "identity-initialized residual MLP",
                "hidden_dimension": 128,
                "residual_scale": 0.1,
                "initialization": "first layer xavier_uniform; output layer zeros",
            },
            "loss": {
                "positive_bag": "logmeanexp cosine over source-anchor-overlap candidates",
                "competition_bag": (
                    "logmeanexp cosine over deterministic B0 top same-repository "
                    "non-positive candidates"
                ),
                "ranking": "softplus(margin - positive_bag + competition_bag)",
                "margin": 0.05,
                "teacher_preservation": (
                    "MSE of frozen versus adapted scores on positive and competition "
                    "bags; it preserves ranking geometry locally without pushing "
                    "before/after or unlabeled code globally apart"
                ),
                "teacher_weight": 0.5,
                "competition_semantics": (
                    "Unlabeled ranking competitors only; never verified-safe, "
                    "hard-negative truth, or vulnerability absence evidence."
                ),
            },
            "optimizer": {
                "name": "AdamW",
                "learning_rate": 0.001,
                "weight_decay": 0.0,
                "batch_size": 16,
                "epochs": 12,
                "seed": 20260727,
            },
        },
        "required_outputs": {
            "zero_step_parity": True,
            "input_and_artifact_hashes": True,
            "per_case_rank_ledger": True,
            "per_variant_competition_ledger": True,
            "training_loss_logs": True,
            "recall_at": [1, 3, 5, 10, 20, 30, 50, 100, 200, 500],
            "first_hit_rank_percentiles": [
                "min",
                "p25",
                "p50",
                "p75",
                "p90",
                "p95",
                "p99",
                "max",
            ],
            "review_budget_coverage_targets": [0.25, 0.5, 0.75, 0.9],
            "paired_rescues_regressions_at": [10, 30, 100],
        },
        "selection_rule": {
            "required_non_degradation_against_B0": [
                "Recall@10",
                "MRR",
                "Recall@30",
                "Recall@100",
                "normalized first-hit p90",
            ],
            "required_early_budget_direction": "R@10 rescue_count > R@10 regression_count",
            "tie_break": [
                "higher Recall@10",
                "higher MRR",
                "higher Recall@30",
                "higher Recall@100",
                "lower normalized first-hit p90",
                "variant id ascending",
            ],
            "if_no_variant_passes": (
                "Record B0-only stop. Do not tune hyperparameters, expand the variant "
                "grid, or access M7 inner_val/M8 for rescue."
            ),
            "if_variant_passes": (
                "The result is a non-M8 development signal only. Refit/evaluation "
                "requires a separately frozen independent external expansion; M8 "
                "remains consumed and cannot be reused."
            ),
        },
        "hard_constraints": {
            "m8_read": False,
            "m8_used_for_training_or_selection": False,
            "m7_inner_val_used": False,
            "code_side_projection": False,
            "candidate_policy_changed": False,
            "uses_bm25": False,
            "uses_static_rules": False,
            "uses_patch_trace_source_point_or_advisory_at_runtime": False,
            "unknown_nonanchors_become_negative": False,
        },
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    write_json(output_path, spec)
    print(
        json.dumps(
            {
                "status": spec["status"],
                "run_id": spec["run_id"],
                "variants": [item["variant_id"] for item in spec["finite_variants"]],
                "split": spec["split_contract"],
                "selection_rule": spec["selection_rule"],
            },
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
