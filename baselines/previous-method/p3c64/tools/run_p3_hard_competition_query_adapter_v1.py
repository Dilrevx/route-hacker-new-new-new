#!/usr/bin/env python3
"""Run the preregistered P3 query-only hard-competition retriever.

P3 keeps the audited frozen Qwen code bank unchanged.  It adapts only the
runtime-guideline query vector with an identity-initialized residual MLP.
For each source-backed positive bag, its comparison set is the deterministic
top-scoring B0 same-repository non-positive candidates.  Those candidates are
unlabeled competition, not verified-safe or hard-negative truth.

The executor consumes the frozen P3 nested development split only.  It has no
M8 path or M8 read: M8 remains unavailable for method selection.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import math
import random
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import numpy as np
import torch
import torch.nn.functional as functional


DEFAULT_M7_EXECUTOR = Path("/tmp/run_m7_strict_runtime_residual_biencoder_v1.py")
DEFAULT_MODEL_PATH = (
    "/data/lhq/.cache/huggingface/hub/models--Qwen--Qwen3-Embedding-0.6B/"
    "snapshots/97b0c614be4d77ee51c0cef4e5f07c00f9eb65b3"
)
DEFAULT_LOCKED_HELPER = Path(
    "/tmp/route-hacker-m3-lock-20260725/scripts/"
    "eval_guideline_m5_94_generic_retrieval_with_shard_v1.py"
)


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


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


def load_m7_executor(path: Path) -> Any:
    if not path.is_file():
        raise FileNotFoundError(f"frozen M7 executor is unavailable: {path}")
    spec = importlib.util.spec_from_file_location("p3_frozen_m7_executor", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load M7 executor: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def require_spec_hash(
    spec: dict[str, Any], key: str, path: Path, *, label: str | None = None
) -> None:
    expected = str(spec["inputs"][key]["sha256"])
    actual = sha256_file(path)
    if actual != expected:
        raise ValueError(
            f"{label or key} hash does not match frozen P3 run spec: "
            f"expected={expected} actual={actual}"
        )


@dataclass
class TrainingExample:
    pair_id: str
    guideline_id: str
    guideline_text: str
    track_id: str
    repo_key: str
    positive_ids: list[str]
    competition_ids: list[str]
    positives: np.ndarray
    competition: np.ndarray


def build_hard_competition_examples(
    *,
    pairs: list[dict[str, Any]],
    fitting_pair_ids: set[str],
    banks: dict[str, Any],
    query_vectors: dict[str, np.ndarray],
    m7: Any,
    competition_count: int,
) -> tuple[list[TrainingExample], list[dict[str, Any]], dict[str, Any]]:
    examples: list[TrainingExample] = []
    competition_ledger: list[dict[str, Any]] = []
    skipped: Counter[str] = Counter()
    skipped_pair_ids: defaultdict[str, list[str]] = defaultdict(list)
    for pair in pairs:
        pair_id = str(pair.get("pair_id") or "")
        if pair_id not in fitting_pair_ids:
            continue
        repo_key = str(pair.get("repo_key") or "")
        bank = banks.get(repo_key)
        if bank is None:
            raise ValueError(f"fitting pair has no loaded repository bank: {pair_id}")
        positive_ids = sorted(
            {
                str(candidate_id)
                for candidate_id in pair.get("positive_candidate_ids") or []
                if str(candidate_id) in bank.generic_id_to_index
            }
        )
        if not positive_ids:
            skipped["no_generic_positive"] += 1
            skipped_pair_ids["no_generic_positive"].append(pair_id)
            continue
        guideline_id = str(pair["guideline_id"])
        query = query_vectors.get(guideline_id)
        if query is None:
            raise ValueError(f"missing B0 query vector for {guideline_id}")
        b0_scores = bank.generic_embeddings @ query
        b0_order = m7.rank_order(b0_scores, bank.generic_candidate_ids)
        competition_indices: list[int] = []
        competition_entries: list[dict[str, Any]] = []
        positive_set = set(positive_ids)
        for rank, candidate_index in enumerate(b0_order, start=1):
            candidate_id = bank.generic_candidate_ids[int(candidate_index)]
            if candidate_id in positive_set:
                continue
            competition_indices.append(int(candidate_index))
            competition_entries.append(
                {
                    "candidate_id": candidate_id,
                    "b0_rank": rank,
                    "b0_score": float(b0_scores[int(candidate_index)]),
                }
            )
            if len(competition_indices) == competition_count:
                break
        if not competition_indices:
            skipped["no_non_positive_competition"] += 1
            skipped_pair_ids["no_non_positive_competition"].append(pair_id)
            continue
        positive_indices = np.asarray(
            [bank.generic_id_to_index[candidate_id] for candidate_id in positive_ids],
            dtype=np.int64,
        )
        examples.append(
            TrainingExample(
                pair_id=pair_id,
                guideline_id=guideline_id,
                guideline_text=str(pair["guideline_text"]),
                track_id=str(pair["track_id"]),
                repo_key=repo_key,
                positive_ids=positive_ids,
                competition_ids=[
                    str(entry["candidate_id"]) for entry in competition_entries
                ],
                positives=bank.generic_embeddings[positive_indices],
                competition=bank.generic_embeddings[
                    np.asarray(competition_indices, dtype=np.int64)
                ],
            )
        )
        competition_ledger.append(
            {
                "pair_id": pair_id,
                "case_id": str(pair["case_id"]),
                "guideline_id": guideline_id,
                "track_id": str(pair["track_id"]),
                "repo_key": repo_key,
                "positive_candidate_ids": positive_ids,
                "competition_count_requested": competition_count,
                "competition_count_selected": len(competition_entries),
                "competition_selection": (
                    "Top frozen-B0 same-repository generic candidates after "
                    "excluding source-backed positive candidate IDs. Entries "
                    "remain unlabeled competition, not verified-safe negatives."
                ),
                "competition_entries": competition_entries,
            }
        )
    if len(examples) + sum(skipped.values()) != len(fitting_pair_ids):
        raise ValueError(
            "P3 fitting-pair materialization accounting mismatch: "
            f"expected={len(fitting_pair_ids)} examples={len(examples)} "
            f"skipped={dict(skipped)}"
        )
    return examples, competition_ledger, {
        "example_count": len(examples),
        "frozen_fitting_pair_count": len(fitting_pair_ids),
        "unique_guideline_count": len({example.guideline_id for example in examples}),
        "track_counts": dict(
            sorted(Counter(example.track_id for example in examples).items())
        ),
        "competition_count": competition_count,
        "skipped": dict(sorted(skipped.items())),
        "skipped_pair_ids": {
            reason: sorted(pair_ids)
            for reason, pair_ids in sorted(skipped_pair_ids.items())
        },
        "competition_semantics": (
            "Competition is deterministic frozen-B0 ranking pressure only. "
            "It is unlabeled background and is never asserted safe, non-vulnerable, "
            "or a hard-negative truth label."
        ),
    }


def train_query_only_variant(
    *,
    variant_id: str,
    variant: Any,
    examples: list[TrainingExample],
    query_vectors: dict[str, np.ndarray],
    training_config: dict[str, Any],
    device: torch.device,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    seed = int(training_config["optimizer"]["seed"])
    torch.manual_seed(seed)
    np.random.seed(seed)
    random.seed(seed)
    variant.to(device)
    variant.train()
    optimizer = torch.optim.AdamW(
        variant.parameters(),
        lr=float(training_config["optimizer"]["learning_rate"]),
        weight_decay=float(training_config["optimizer"]["weight_decay"]),
    )
    epoch_count = int(training_config["optimizer"]["epochs"])
    batch_size = int(training_config["optimizer"]["batch_size"])
    margin = float(training_config["loss"]["margin"])
    teacher_weight = float(training_config["loss"]["teacher_weight"])
    logs: list[dict[str, Any]] = []
    order = list(range(len(examples)))
    for epoch in range(1, epoch_count + 1):
        random.Random(seed + epoch).shuffle(order)
        total_loss = 0.0
        total_ranking_loss = 0.0
        total_teacher_loss = 0.0
        batch_count = 0
        for start in range(0, len(order), batch_size):
            batch = [examples[index] for index in order[start : start + batch_size]]
            queries = torch.as_tensor(
                np.stack([query_vectors[example.guideline_id] for example in batch]),
                dtype=torch.float32,
                device=device,
            )
            max_positive_count = max(len(example.positives) for example in batch)
            max_competition_count = max(len(example.competition) for example in batch)
            positives = torch.zeros(
                (len(batch), max_positive_count, queries.shape[-1]),
                dtype=torch.float32,
                device=device,
            )
            positive_mask = torch.zeros(
                (len(batch), max_positive_count), dtype=torch.bool, device=device
            )
            competition = torch.zeros(
                (len(batch), max_competition_count, queries.shape[-1]),
                dtype=torch.float32,
                device=device,
            )
            competition_mask = torch.zeros(
                (len(batch), max_competition_count), dtype=torch.bool, device=device
            )
            for index, example in enumerate(batch):
                positive = torch.as_tensor(
                    example.positives, dtype=torch.float32, device=device
                )
                competitors = torch.as_tensor(
                    example.competition, dtype=torch.float32, device=device
                )
                positives[index, : len(positive)] = positive
                positive_mask[index, : len(positive)] = True
                competition[index, : len(competitors)] = competitors
                competition_mask[index, : len(competitors)] = True
            adapted_query = variant.adapt_query(queries)
            positive_scores = torch.sum(adapted_query[:, None, :] * positives, dim=-1)
            competition_scores = torch.sum(
                adapted_query[:, None, :] * competition, dim=-1
            )
            positive_scores = positive_scores.masked_fill(~positive_mask, -torch.inf)
            competition_scores = competition_scores.masked_fill(
                ~competition_mask, -torch.inf
            )
            positive_bag = torch.logsumexp(positive_scores, dim=1) - torch.log(
                positive_mask.sum(dim=1).to(torch.float32)
            )
            competition_bag = torch.logsumexp(competition_scores, dim=1) - torch.log(
                competition_mask.sum(dim=1).to(torch.float32)
            )
            ranking_loss = functional.softplus(
                margin - positive_bag + competition_bag
            ).mean()
            with torch.no_grad():
                teacher_positive = torch.sum(queries[:, None, :] * positives, dim=-1)
                teacher_competition = torch.sum(
                    queries[:, None, :] * competition, dim=-1
                )
            teacher_loss = (
                (
                    positive_scores[positive_mask] - teacher_positive[positive_mask]
                ).square().mean()
                + (
                    competition_scores[competition_mask]
                    - teacher_competition[competition_mask]
                ).square().mean()
            )
            loss = ranking_loss + teacher_weight * teacher_loss
            optimizer.zero_grad(set_to_none=True)
            loss.backward()
            optimizer.step()
            total_loss += float(loss.detach().cpu())
            total_ranking_loss += float(ranking_loss.detach().cpu())
            total_teacher_loss += float(teacher_loss.detach().cpu())
            batch_count += 1
        logs.append(
            {
                "epoch": epoch,
                "loss": total_loss / max(batch_count, 1),
                "ranking_loss": total_ranking_loss / max(batch_count, 1),
                "teacher_loss": total_teacher_loss / max(batch_count, 1),
                "batch_count": batch_count,
            }
        )
    variant.eval()
    return {
        "variant_id": variant_id,
        "training": True,
        "epoch_count": epoch_count,
        "example_count": len(examples),
        "final_epoch": logs[-1] if logs else None,
    }, logs


def select_variant(
    *,
    metric_by_variant: dict[str, dict[str, Any]],
    comparisons_at_10: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    baseline = metric_by_variant["B0"]
    admissible: list[str] = []
    failures: dict[str, list[str]] = {}
    for variant_id in sorted(
        variant for variant in metric_by_variant if variant != "B0"
    ):
        metrics = metric_by_variant[variant_id]
        comparison = comparisons_at_10[variant_id]
        failed: list[str] = []
        if float(metrics["R@10"]) < float(baseline["R@10"]):
            failed.append("R@10 decreased")
        if float(metrics["MRR"]) < float(baseline["MRR"]):
            failed.append("MRR decreased")
        if float(metrics["R@30"]) < float(baseline["R@30"]):
            failed.append("R@30 decreased")
        if float(metrics["R@100"]) < float(baseline["R@100"]):
            failed.append("R@100 decreased")
        if int(comparison["rescue_count"]) <= int(comparison["regression_count"]):
            failed.append("R@10 rescues do not exceed regressions")
        if float(metrics["normalized_first_rank"]["p90"]) > float(
            baseline["normalized_first_rank"]["p90"]
        ):
            failed.append("normalized first-hit p90 increased")
        failures[variant_id] = failed
        if not failed:
            admissible.append(variant_id)
    ordered = sorted(
        admissible,
        key=lambda variant_id: (
            -float(metric_by_variant[variant_id]["R@10"]),
            -float(metric_by_variant[variant_id]["MRR"]),
            -float(metric_by_variant[variant_id]["R@30"]),
            -float(metric_by_variant[variant_id]["R@100"]),
            float(metric_by_variant[variant_id]["normalized_first_rank"]["p90"]),
            variant_id,
        ),
    )
    return {
        "selection_status": "learned_variant_selected" if ordered else "B0_only_stop",
        "selected_variant": ordered[0] if ordered else "B0",
        "admissible_learned_variants": ordered,
        "admissibility_failures": failures,
        "strict_validation_authorized": False,
        "external_refit_authorized": bool(ordered),
        "rule": {
            "all_required": [
                "R@10 non-decreasing",
                "MRR non-decreasing",
                "R@30 non-decreasing",
                "R@100 non-decreasing",
                "R@10 rescue_count > regression_count",
                "normalized first-hit p90 non-increasing",
            ],
            "tie_break": [
                "higher R@10",
                "higher MRR",
                "higher R@30",
                "higher R@100",
                "lower normalized first-hit p90",
                "variant id ascending",
            ],
        },
    }


def write_manifest(output_dir: Path) -> None:
    manifest = {"artifact": output_dir.name, "files": {}}
    for path in sorted(output_dir.iterdir()):
        if path.is_file() and path.name != "manifest.v1.json":
            manifest["files"][path.name] = {
                "sha256": sha256_file(path),
                "bytes": path.stat().st_size,
            }
    write_json(output_dir / "manifest.v1.json", manifest)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run preregistered P3 query-only hard-competition selection."
    )
    parser.add_argument("--run-spec", type=Path, required=True)
    parser.add_argument("--split-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--m7-executor", type=Path, default=DEFAULT_M7_EXECUTOR)
    parser.add_argument("--locked-helper", type=Path, default=DEFAULT_LOCKED_HELPER)
    parser.add_argument("--model-path", default=DEFAULT_MODEL_PATH)
    parser.add_argument("--pool", type=Path, action="append", dest="pools", default=[])
    parser.add_argument(
        "--embedding-cache-dir",
        type=Path,
        action="append",
        dest="embedding_cache_dirs",
        default=[],
    )
    parser.add_argument("--encoder-device", default="cuda:0")
    parser.add_argument("--training-device", default="cuda:0")
    parser.add_argument("--encoder-batch-size", type=int, default=32)
    parser.add_argument("--code-chunk-size", type=int, default=8192)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.output_dir.exists() and any(args.output_dir.iterdir()):
        raise SystemExit(f"refusing to overwrite non-empty output: {args.output_dir}")
    split_dir = args.split_dir.resolve()
    cases_path = split_dir / "p3_development_cases.v1.jsonl"
    pairs_path = split_dir / "p3_development_pairs.v1.jsonl"
    split_summary_path = split_dir / "summary.json"
    required_paths = [
        args.run_spec,
        cases_path,
        pairs_path,
        split_summary_path,
        args.m7_executor,
        args.locked_helper,
    ]
    missing = [str(path) for path in required_paths if not path.is_file()]
    if missing:
        raise FileNotFoundError(f"missing P3 input(s): {missing}")
    spec = read_json(args.run_spec)
    if spec.get("status") != "pre_registered_not_executed":
        raise ValueError("P3 run spec is not an unexecuted preregistration")
    if str(spec["inputs"]["model_path"]) != args.model_path:
        raise ValueError("model path does not match frozen P3 run spec")
    require_spec_hash(spec, "p3_cases", cases_path)
    require_spec_hash(spec, "p3_pairs", pairs_path)
    require_spec_hash(spec, "p3_split_summary", split_summary_path)
    require_spec_hash(spec, "m7_executor", args.m7_executor)
    require_spec_hash(spec, "locked_helper", args.locked_helper)
    if not torch.cuda.is_available() and args.training_device.startswith("cuda"):
        raise RuntimeError("P3 training device requests CUDA but CUDA is unavailable")

    m7 = load_m7_executor(args.m7_executor.resolve())
    split_summary = read_json(split_summary_path)
    if split_summary.get("status") != "frozen_pre_training_pre_retrieval":
        raise ValueError("P3 development split is not frozen pre-training")
    cases = read_jsonl(cases_path)
    pairs = read_jsonl(pairs_path)
    fitting_cases = [
        row for row in cases if str(row.get("p3_split") or "") == "p3_fitting"
    ]
    selection_cases = [
        row for row in cases if str(row.get("p3_split") or "") == "p3_selection"
    ]
    fitting_pair_ids = {
        str(pair["pair_id"])
        for pair in pairs
        if str(pair.get("p3_split") or "") == "p3_fitting"
    }
    if len(fitting_cases) != int(spec["split_contract"]["fitting_case_count"]):
        raise ValueError("P3 fitting case count differs from run spec")
    if len(selection_cases) != int(spec["split_contract"]["selection_case_count"]):
        raise ValueError("P3 selection case count differs from run spec")
    if len(fitting_pair_ids) != int(spec["split_contract"]["fitting_pair_count"]):
        raise ValueError("P3 fitting pair count differs from run spec")
    if not fitting_pair_ids:
        raise ValueError("P3 fitting pair set is empty")
    all_families_by_split = {
        split: {
            str(row["p3_project_family"])
            for row in cases
            if str(row.get("p3_split") or "") == split
        }
        for split in ("p3_fitting", "p3_selection")
    }
    if all_families_by_split["p3_fitting"] & all_families_by_split["p3_selection"]:
        raise ValueError("P3 project-family overlap is not allowed")
    if {
        str(row["track_id"]) for row in fitting_cases
    } != set(spec["split_contract"]["all_track_ids"]) or {
        str(row["track_id"]) for row in selection_cases
    } != set(spec["split_contract"]["all_track_ids"]):
        raise ValueError("P3 track coverage differs from frozen run spec")

    pools = args.pools or [
        Path("/tmp/m5_83_expanded_inner_split_manifest_v1/candidate_pool.v1.jsonl"),
        Path("/tmp/m5_92_gap_generic_candidate_shard_v1/gap_generic_candidate_shard.v1.jsonl"),
    ]
    cache_dirs = args.embedding_cache_dirs or [
        Path("/tmp/m5_86_expanded_split_bm25_embedding_v1/cache"),
        Path("/tmp/m5_95_repaired_pool_embedding_cache_v1/cache"),
    ]
    for path in [*pools, *cache_dirs]:
        if not path.exists():
            raise FileNotFoundError(path)
    expected_pools = spec["inputs"]["candidate_pools"]
    if len(pools) != len(expected_pools):
        raise ValueError("candidate-pool count does not match frozen P3 run spec")
    for actual_path, expected in zip(pools, expected_pools, strict=True):
        expected_path = Path(str(expected["path"])).resolve()
        if actual_path.resolve() != expected_path:
            raise ValueError(
                "candidate-pool path does not match frozen P3 run spec: "
                f"expected={expected_path} actual={actual_path.resolve()}"
            )
        actual_hash = sha256_file(actual_path)
        if actual_hash != str(expected["sha256"]):
            raise ValueError(
                "candidate-pool hash does not match frozen P3 run spec: "
                f"expected={expected['sha256']} actual={actual_hash}"
            )
    helper = m7.load_helper(args.locked_helper.resolve())
    repos_needed = {
        str(row["repo_key"]) for row in [*fitting_cases, *selection_cases]
    }
    banks, cache_audit = m7.load_repository_banks(
        helper=helper,
        pool_paths=pools,
        cache_dirs=cache_dirs,
        repos_needed=repos_needed,
        model_path=args.model_path,
        text_field=str(spec["candidate_contract"]["text_field"]),
        max_chars=int(spec["candidate_contract"]["max_chars"]),
    )
    selection_cases, evaluation_coverage = (
        m7.filter_rows_with_generic_retrieval_coverage(
            rows=selection_cases,
            banks=banks,
            helper=helper,
        )
    )
    if not selection_cases:
        raise ValueError("no generic-covered P3 selection cases")
    all_fitting_guideline_text = {
        str(pair["guideline_id"]): str(pair["guideline_text"])
        for pair in pairs
        if str(pair.get("p3_split") or "") == "p3_fitting"
    }
    encoder = m7.load_sentence_transformer(
        args.model_path,
        device=args.encoder_device,
        max_seq_length=int(spec["candidate_contract"]["max_sequence_length"]),
    )
    guideline_ids = sorted(all_fitting_guideline_text)
    encoded_queries = m7.encode_texts(
        encoder,
        [all_fitting_guideline_text[guideline_id] for guideline_id in guideline_ids],
        batch_size=args.encoder_batch_size,
    )
    query_vectors = {
        guideline_id: encoded_queries[index]
        for index, guideline_id in enumerate(guideline_ids)
    }
    dimension = int(spec["candidate_contract"]["embedding_dimension"])
    training_device = torch.device(args.training_device)
    variants: dict[str, Any | None] = {"B0": None}
    zero_variants: dict[str, Any | None] = {"B0": None}
    for definition in spec["finite_variants"]:
        variant_id = str(definition["variant_id"])
        if variant_id == "B0":
            continue
        if not bool(definition["query_projection"]) or bool(definition["code_projection"]):
            raise ValueError(f"P3 variant violates query-only frozen-code contract: {variant_id}")
        variant = m7.M6Variant(
            dimension=dimension,
            hidden_dimension=int(spec["training"]["projection"]["hidden_dimension"]),
            residual_scale=float(spec["training"]["projection"]["residual_scale"]),
            query_projection=True,
            code_projection=False,
        ).to(training_device).eval()
        variants[variant_id] = variant
        zero_variants[variant_id] = m7.M6Variant(
            dimension=dimension,
            hidden_dimension=int(spec["training"]["projection"]["hidden_dimension"]),
            residual_scale=float(spec["training"]["projection"]["residual_scale"]),
            query_projection=True,
            code_projection=False,
        ).to(training_device).eval()

    zero_rows, zero_parity = m7.evaluate_rows(
        rows=selection_cases,
        banks=banks,
        helper=helper,
        encoder=encoder,
        variants=zero_variants,
        supported_tracks=set(spec["split_contract"]["all_track_ids"]),
        device=training_device,
        encoder_batch_size=args.encoder_batch_size,
        code_chunk_size=args.code_chunk_size,
        include_zero_step=True,
    )
    del zero_rows
    if (
        zero_parity["zero_step_max_score_abs_diff"] != 0.0
        or zero_parity["zero_step_rank_mismatch_count"] != 0
    ):
        raise ValueError(f"P3 zero-step parity failed: {zero_parity}")

    args.output_dir.mkdir(parents=True, exist_ok=True)
    training_summaries: dict[str, Any] = {
        "B0": {"variant_id": "B0", "training": False}
    }
    training_logs: dict[str, list[dict[str, Any]]] = {"B0": []}
    training_example_summaries: dict[str, Any] = {}
    competition_ledger_by_variant: dict[str, list[dict[str, Any]]] = {}
    for definition in spec["finite_variants"]:
        variant_id = str(definition["variant_id"])
        if variant_id == "B0":
            continue
        examples, competition_ledger, example_summary = build_hard_competition_examples(
            pairs=pairs,
            fitting_pair_ids=fitting_pair_ids,
            banks=banks,
            query_vectors=query_vectors,
            m7=m7,
            competition_count=int(definition["competition_count"]),
        )
        if not examples:
            raise ValueError(f"no usable fitting examples for {variant_id}")
        summary, logs = train_query_only_variant(
            variant_id=variant_id,
            variant=variants[variant_id],
            examples=examples,
            query_vectors=query_vectors,
            training_config=spec["training"],
            device=training_device,
        )
        training_summaries[variant_id] = summary
        training_logs[variant_id] = logs
        training_example_summaries[variant_id] = example_summary
        competition_ledger_by_variant[variant_id] = competition_ledger
        torch.save(
            variants[variant_id].state_dict(),
            args.output_dir / f"{variant_id.lower()}_state.pt",
        )
        write_jsonl(
            args.output_dir / f"{variant_id.lower()}_competition_ledger.jsonl",
            competition_ledger,
        )
        write_jsonl(args.output_dir / f"{variant_id.lower()}_training_log.jsonl", logs)

    evaluated_rows, _ = m7.evaluate_rows(
        rows=selection_cases,
        banks=banks,
        helper=helper,
        encoder=encoder,
        variants=variants,
        supported_tracks=set(spec["split_contract"]["all_track_ids"]),
        device=training_device,
        encoder_batch_size=args.encoder_batch_size,
        code_chunk_size=args.code_chunk_size,
        include_zero_step=False,
    )
    variant_ids = list(variants)
    metric_by_variant = {
        variant_id: m7.metric_summary(evaluated_rows, method=variant_id)
        for variant_id in variant_ids
    }
    review_budget_by_variant = {
        variant_id: m7.review_budget_summary(evaluated_rows, method=variant_id)
        for variant_id in variant_ids
    }
    paired_by_variant_and_k = {
        variant_id: {
            f"at_{value}": m7.paired_comparison(
                evaluated_rows, left="B0", right=variant_id, k=value
            )
            for value in (10, 30, 100)
        }
        for variant_id in variant_ids
        if variant_id != "B0"
    }
    selection = select_variant(
        metric_by_variant=metric_by_variant,
        comparisons_at_10={
            variant_id: values["at_10"]
            for variant_id, values in paired_by_variant_and_k.items()
        },
    )
    write_jsonl(args.output_dir / "case_rank_ledger.jsonl", evaluated_rows)
    write_json(args.output_dir / "selection_decision.json", selection)
    summary = {
        "schema_version": "p3_hard_competition_query_adapter_result_v1",
        "run_id": spec["run_id"],
        "status": "completed",
        "created_at": utc_now(),
        "input_hashes": {
            "run_spec": sha256_file(args.run_spec),
            "p3_cases": sha256_file(cases_path),
            "p3_pairs": sha256_file(pairs_path),
            "p3_split_summary": sha256_file(split_summary_path),
            "m7_executor": sha256_file(args.m7_executor),
            "locked_helper": sha256_file(args.locked_helper),
            "candidate_pools": [sha256_file(path) for path in pools],
        },
        "method_boundary": {
            "runtime_input": "fixed natural-language guideline text only",
            "code_embeddings": "frozen audited Qwen candidate cache",
            "query_adapter": "identity-initialized residual MLP",
            "code_adapter": "none",
            "candidate_admission": "frozen generic function + sliding_window only",
            "training_positive": "source-anchor-overlap generic candidate bag",
            "competition": (
                "deterministic frozen-B0 top same-repository non-positive "
                "candidates; unlabeled competition, never safe-negative truth"
            ),
            "uses_bm25": False,
            "uses_static_rules": False,
            "uses_patch_or_trace_input": False,
            "m8_read": False,
            "m8_used_for_training_or_selection": False,
            "non_anchor_semantics": "unlabeled_background",
        },
        "split_audit": {
            "fitting_case_count": len(fitting_cases),
            "selection_case_count": len(selection_cases),
            "fitting_pair_count": len(fitting_pair_ids),
            "fitting_project_family_count": len(all_families_by_split["p3_fitting"]),
            "selection_project_family_count": len(
                all_families_by_split["p3_selection"]
            ),
            "project_family_overlap_count": len(
                all_families_by_split["p3_fitting"]
                & all_families_by_split["p3_selection"]
            ),
        },
        "cache_audit": cache_audit,
        "evaluation_coverage": evaluation_coverage,
        "zero_step_parity": zero_parity,
        "training": training_summaries,
        "training_examples": training_example_summaries,
        "metrics": metric_by_variant,
        "review_budget": review_budget_by_variant,
        "paired_comparisons": paired_by_variant_and_k,
        "selection": selection,
        "evaluation_scope": {
            "case_count": len(evaluated_rows),
            "repository_count": len({str(row["repo_key"]) for row in evaluated_rows}),
            "project_family_count": len(
                {str(row["project_family"]) for row in evaluated_rows}
            ),
            "track_counts": dict(
                sorted(Counter(str(row["track_id"]) for row in evaluated_rows).items())
            ),
        },
    }
    write_json(args.output_dir / "summary.json", summary)
    write_manifest(args.output_dir)
    print(
        json.dumps(
            {
                "status": summary["status"],
                "evaluation_case_count": summary["evaluation_scope"]["case_count"],
                "metrics": metric_by_variant,
                "selection": selection,
                "m8_read": False,
            },
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
