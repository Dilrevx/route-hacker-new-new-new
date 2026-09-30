#!/usr/bin/env python3
"""Run the frozen P4 external B0 versus P3C64 retrieval evaluation exactly once.

The evaluator is intentionally inference-only. It loads fixed guideline text
from a frozen one-shot spec, a frozen Qwen code cache, and the already selected
P3C64 query-adapter state. Offline mapped-positive IDs are used only after
ranking to measure retrieval hit position.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import numpy as np
import torch
import torch.nn.functional as functional
from torch import nn


SCHEMA_VERSION = "p4_external_b0_p3c64_one_shot_v1"
K_VALUES = (1, 3, 5, 10, 20, 30, 50, 100, 200, 500)
DEFAULT_MODEL_PATH = (
    "/data/lhq/.cache/huggingface/hub/models--Qwen--Qwen3-Embedding-0.6B/"
    "snapshots/97b0c614be4d77ee51c0cef4e5f07c00f9eb65b3"
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
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


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


def stable_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("_") or "repo"


def normalized_project_group(value: str) -> str:
    return re.sub(r"__[0-9a-f]{8,64}$", "", value, flags=re.IGNORECASE)


def percentile(values: list[float], fraction: float) -> float | None:
    if not values:
        return None
    return float(np.percentile(np.asarray(values, dtype="float64"), fraction * 100))


def rank_order(scores: np.ndarray, candidate_ids: list[str]) -> np.ndarray:
    return np.lexsort((np.asarray(candidate_ids), -scores))


def first_positive_rank(
    scores: np.ndarray,
    candidate_ids: list[str],
    positive_ids: set[str],
) -> int | None:
    for position, candidate_index in enumerate(rank_order(scores, candidate_ids), start=1):
        if candidate_ids[int(candidate_index)] in positive_ids:
            return position
    return None


def metric_summary(rows: list[dict[str, Any]], *, method: str) -> dict[str, Any]:
    ranks = [
        float(row[f"{method}_rank"])
        for row in rows
        if row.get(f"{method}_rank") is not None
    ]
    normalized_ranks = [
        float(row[f"{method}_normalized_rank"])
        for row in rows
        if row.get(f"{method}_normalized_rank") is not None
    ]
    output: dict[str, Any] = {
        "case_count": len(rows),
        "cases_with_hit": len(ranks),
        "MRR": sum(1.0 / rank for rank in ranks) / len(rows) if rows else None,
        "first_rank": {
            "min": min(ranks) if ranks else None,
            "p25": percentile(ranks, 0.25),
            "p50": percentile(ranks, 0.50),
            "p75": percentile(ranks, 0.75),
            "p90": percentile(ranks, 0.90),
            "p95": percentile(ranks, 0.95),
            "p99": percentile(ranks, 0.99),
            "max": max(ranks) if ranks else None,
        },
        "normalized_first_rank": {
            "min": min(normalized_ranks) if normalized_ranks else None,
            "p25": percentile(normalized_ranks, 0.25),
            "p50": percentile(normalized_ranks, 0.50),
            "p75": percentile(normalized_ranks, 0.75),
            "p90": percentile(normalized_ranks, 0.90),
            "p95": percentile(normalized_ranks, 0.95),
            "p99": percentile(normalized_ranks, 0.99),
            "max": max(normalized_ranks) if normalized_ranks else None,
        },
    }
    for value in K_VALUES:
        output[f"R@{value}"] = (
            sum(bool(row.get(f"{method}_hit_at_{value}")) for row in rows) / len(rows)
            if rows
            else None
        )
    return output


def review_budget_summary(rows: list[dict[str, Any]], *, method: str) -> dict[str, Any]:
    ranks = sorted(
        int(row[f"{method}_rank"])
        for row in rows
        if row.get(f"{method}_rank") is not None
    )
    output: dict[str, Any] = {}
    for target in (0.25, 0.50, 0.75, 0.90):
        needed = math.ceil(len(rows) * target)
        output[f"B@{int(target * 100)}"] = (
            ranks[needed - 1] if len(ranks) >= needed else None
        )
    return output


def paired_comparison(
    rows: list[dict[str, Any]],
    *,
    left: str,
    right: str,
    k: int,
) -> dict[str, Any]:
    rescues: list[dict[str, Any]] = []
    regressions: list[dict[str, Any]] = []
    for row in rows:
        item = {
            "case_id": row["case_id"],
            "cve_id": row.get("cve_id"),
            "track_id": row["track_id"],
            "repo_key": row["repo_key"],
            f"{left}_rank": row[f"{left}_rank"],
            f"{right}_rank": row[f"{right}_rank"],
        }
        if bool(row[f"{right}_hit_at_{k}"]) and not bool(row[f"{left}_hit_at_{k}"]):
            rescues.append(item)
        elif bool(row[f"{left}_hit_at_{k}"]) and not bool(row[f"{right}_hit_at_{k}"]):
            regressions.append(item)
    return {
        "left": left,
        "right": right,
        "k": k,
        "rescue_count": len(rescues),
        "regression_count": len(regressions),
        "rescue_rows": rescues,
        "regression_rows": regressions,
    }


class ResidualProjection(nn.Module):
    def __init__(self, dimension: int, hidden_dimension: int, scale: float) -> None:
        super().__init__()
        self.first = nn.Linear(dimension, hidden_dimension)
        self.output = nn.Linear(hidden_dimension, dimension)
        self.scale = float(scale)

    def forward(self, vectors: torch.Tensor) -> torch.Tensor:
        delta = self.output(functional.gelu(self.first(vectors)))
        return functional.normalize(vectors + self.scale * delta, p=2, dim=-1)


class QueryOnlyP3C64(nn.Module):
    def __init__(self) -> None:
        super().__init__()
        self.query_projection = ResidualProjection(
            dimension=1024,
            hidden_dimension=128,
            scale=0.1,
        )

    def adapt_query(self, vector: torch.Tensor) -> torch.Tensor:
        return self.query_projection(vector)


def load_query_encoder(model_path: str, *, device: str) -> Any:
    from sentence_transformers import SentenceTransformer

    model = SentenceTransformer(model_path, device=device)
    model.max_seq_length = 512
    return model


def encode_fixed_queries(
    model: Any,
    queries: list[str],
    *,
    batch_size: int,
) -> dict[str, np.ndarray]:
    vectors = model.encode(
        queries,
        batch_size=batch_size,
        normalize_embeddings=True,
        show_progress_bar=False,
        convert_to_numpy=True,
    ).astype("float32", copy=False)
    if vectors.shape != (len(queries), 1024):
        raise ValueError(f"unexpected frozen query embedding shape: {vectors.shape}")
    if not np.isfinite(vectors).all():
        raise ValueError("frozen query embedding has non-finite values")
    return {query: vectors[index] for index, query in enumerate(queries)}


def load_selected_candidate_ids(
    *,
    candidate_pool: Path,
    rows: list[dict[str, Any]],
) -> dict[str, list[str]]:
    target_repos = {str(row["repo_key"]) for row in rows}
    candidate_ids_by_repo: dict[str, list[str]] = {
        repo_key: [] for repo_key in target_repos
    }
    with candidate_pool.open(encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            candidate = json.loads(line)
            repo_key = str(candidate.get("repo_key") or "")
            if repo_key not in candidate_ids_by_repo:
                continue
            candidate_id = str(candidate.get("candidate_id") or "")
            view_type = str(candidate.get("view_type") or "")
            if not candidate_id or view_type not in {"function", "sliding_window"}:
                raise ValueError(f"invalid frozen P4 generic candidate for {repo_key}")
            candidate_ids_by_repo[repo_key].append(candidate_id)
    for row in rows:
        repo_key = str(row["repo_key"])
        candidate_ids = candidate_ids_by_repo[repo_key]
        expected = int(row["candidate_count"])
        if len(candidate_ids) != expected:
            raise ValueError(
                f"candidate count mismatch for {repo_key}: "
                f"spec={expected} pool={len(candidate_ids)}"
            )
        if len(set(candidate_ids)) != len(candidate_ids):
            raise ValueError(f"duplicate candidate IDs in frozen P4 repo: {repo_key}")
    return candidate_ids_by_repo


def load_cache_embeddings(
    cache_dir: Path,
    repo_key: str,
    *,
    expected_count: int,
) -> np.ndarray:
    cache_path = cache_dir / f"{stable_name(repo_key)}.npz"
    if not cache_path.is_file():
        raise FileNotFoundError(f"exact-ready P4 cache file disappeared: {cache_path}")
    with np.load(cache_path, allow_pickle=False) as archive:
        embeddings = archive["embeddings"].astype("float32", copy=False)
    if embeddings.shape != (expected_count, 1024):
        raise ValueError(
            f"cached embedding shape changed for {repo_key}: {embeddings.shape}"
        )
    if not np.isfinite(embeddings).all():
        raise ValueError(f"cached embedding has non-finite value for {repo_key}")
    norms = np.linalg.norm(embeddings, axis=1)
    if len(norms) and float(np.max(np.abs(norms - 1.0))) > 1e-4:
        raise ValueError(f"cached embedding normalization changed for {repo_key}")
    return embeddings


def validate_spec(args: argparse.Namespace) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    spec = read_json(args.one_shot_spec)
    if spec.get("status") != "frozen_unexecuted_one_shot_external_evaluation":
        raise ValueError("external one-shot spec is not an unexecuted frozen contract")
    if spec.get("run_id") != "p4_external_b0_vs_p3c64_v1":
        raise ValueError("unexpected P4 external run ID")
    boundary = spec.get("boundary") or {}
    required_boundary = {
        "runtime_candidate_admission": "P4 full-repository generic function + sliding_window only",
        "runtime_query": "fixed natural-language guideline text only",
        "source_anchor_role": "offline mapped-positive evaluation only",
        "non_anchor_role": "unknown unlabeled background; never safe-negative or hard-negative truth",
        "m8_read_or_used": False,
        "p4_training_or_refit": False,
        "p4_variant_selection": False,
        "uses_bm25": False,
        "uses_static_rules": False,
        "uses_patch_trace_source_point_or_advisory_at_runtime": False,
    }
    for key, expected in required_boundary.items():
        if boundary.get(key) != expected:
            raise ValueError(f"one-shot boundary mismatch for {key}")
    inputs = spec.get("inputs") or {}
    expected_paths = {
        "candidate_pool": args.candidate_pool.resolve(),
        "cache_audit": args.cache_audit.resolve(),
        "p3_state": args.p3_state.resolve(),
    }
    for key, path in expected_paths.items():
        expected = inputs.get(key) or {}
        if str(expected.get("path") or "") != str(path):
            raise ValueError(f"one-shot spec path mismatch for {key}")
        if str(expected.get("sha256") or "") != sha256_file(path):
            raise ValueError(f"one-shot spec hash mismatch for {key}")
    cache_contract = spec.get("cache_contract") or {}
    if str(cache_contract.get("cache_directory") or "") != str(args.cache_dir.resolve()):
        raise ValueError("one-shot spec cache path mismatch")
    if str(cache_contract.get("code_model_path") or "") != args.model_path:
        raise ValueError("one-shot spec model path mismatch")
    if (spec.get("methods") or {}).get("P3C64", {}).get("learned_state_sha256") != sha256_file(
        args.p3_state
    ):
        raise ValueError("one-shot spec P3C64 state hash mismatch")
    cache_audit = read_json(args.cache_audit)
    if cache_audit.get("status") != "ready_exact":
        raise ValueError("one-shot P4 cache audit is no longer exact-ready")
    if str((cache_audit.get("cache") or {}).get("path") or "") != str(args.cache_dir.resolve()):
        raise ValueError("P4 cache audit path mismatch")
    rows_path = args.one_shot_spec.parent / "external_evaluation_rows.v1.jsonl"
    expected_rows_hash = (
        spec.get("inputs", {})
        .get("selected_cases", {})
        .get("sha256")
    )
    if not rows_path.is_file():
        raise FileNotFoundError(f"one-shot external evaluation rows missing: {rows_path}")
    expected_rows_hash = str(
        (spec.get("runtime_row_ledger") or {}).get("sha256") or ""
    )
    if not expected_rows_hash:
        raise ValueError("one-shot spec is missing the runtime-row-ledger hash")
    if sha256_file(rows_path) != expected_rows_hash:
        raise ValueError("one-shot external evaluation rows hash mismatch")
    rows = read_jsonl(rows_path)
    if len(rows) != int((spec.get("external_scope") or {}).get("case_count") or 0):
        raise ValueError("one-shot external evaluation row count mismatch")
    if not rows:
        raise ValueError("one-shot external evaluation has no rows")
    return spec, rows


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--one-shot-spec", type=Path, required=True)
    parser.add_argument("--candidate-pool", type=Path, required=True)
    parser.add_argument("--cache-audit", type=Path, required=True)
    parser.add_argument("--cache-dir", type=Path, required=True)
    parser.add_argument("--p3-state", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--model-path", default=DEFAULT_MODEL_PATH)
    parser.add_argument("--encoder-device", default="cuda:0")
    parser.add_argument("--adapter-device", default="cuda:0")
    parser.add_argument("--encoder-batch-size", type=int, default=32)
    args = parser.parse_args()

    required = [
        args.one_shot_spec,
        args.candidate_pool,
        args.cache_audit,
        args.p3_state,
    ]
    missing = [str(path) for path in required if not path.is_file()]
    if not args.cache_dir.is_dir():
        missing.append(str(args.cache_dir))
    if not Path(args.model_path).is_dir():
        missing.append(args.model_path)
    if missing:
        raise FileNotFoundError(f"missing P4 one-shot evaluation input(s): {missing}")
    output_dir = args.output_dir.resolve()
    if output_dir.exists():
        raise FileExistsError(
            f"refusing to overwrite one-shot external evaluation output: {output_dir}"
        )
    if not torch.cuda.is_available() and (
        args.encoder_device.startswith("cuda") or args.adapter_device.startswith("cuda")
    ):
        raise RuntimeError("P4 one-shot evaluation requests CUDA but CUDA is unavailable")

    spec, rows = validate_spec(args)
    candidate_ids_by_repo = load_selected_candidate_ids(
        candidate_pool=args.candidate_pool.resolve(),
        rows=rows,
    )
    unique_queries = sorted({str(row["guideline_text"]) for row in rows})
    encoder = load_query_encoder(args.model_path, device=args.encoder_device)
    frozen_queries = encode_fixed_queries(
        encoder,
        unique_queries,
        batch_size=args.encoder_batch_size,
    )
    adapter_device = torch.device(args.adapter_device)
    adapter = QueryOnlyP3C64().to(adapter_device).eval()
    try:
        state = torch.load(args.p3_state, map_location=adapter_device, weights_only=True)
    except TypeError:
        state = torch.load(args.p3_state, map_location=adapter_device)
    adapter.load_state_dict(state, strict=True)
    with torch.no_grad():
        adapted_queries = {
            text: adapter.adapt_query(
                torch.as_tensor(vector, dtype=torch.float32, device=adapter_device)
            )
            .detach()
            .cpu()
            .numpy()
            .astype("float32", copy=False)
            for text, vector in frozen_queries.items()
        }
    for text, vector in adapted_queries.items():
        if vector.shape != (1024,) or not np.isfinite(vector).all():
            raise ValueError(f"invalid P3C64 adapted query vector for fixed guideline: {text!r}")
        if not np.isclose(np.linalg.norm(vector), 1.0, atol=1e-5):
            raise ValueError(f"P3C64 query normalization failed for fixed guideline: {text!r}")

    ledger: list[dict[str, Any]] = []
    for index, source in enumerate(rows, start=1):
        repo_key = str(source["repo_key"])
        candidate_ids = candidate_ids_by_repo[repo_key]
        positive_ids = {str(value) for value in source["positive_candidate_ids"]}
        if not positive_ids <= set(candidate_ids):
            raise ValueError(f"offline positive mapping no longer resolves for {source['case_id']}")
        embeddings = load_cache_embeddings(
            args.cache_dir.resolve(),
            repo_key,
            expected_count=int(source["candidate_count"]),
        )
        query_text = str(source["guideline_text"])
        scores_by_method = {
            "B0": embeddings @ frozen_queries[query_text],
            "P3C64": embeddings @ adapted_queries[query_text],
        }
        row: dict[str, Any] = {
            "case_id": str(source["case_id"]),
            "cve_id": source.get("cve_id"),
            "track_id": str(source["track_id"]),
            "repo_key": repo_key,
            "project_group": str(source.get("project_group") or normalized_project_group(repo_key)),
            "candidate_count": len(candidate_ids),
            "positive_candidate_ids": sorted(positive_ids),
            "positive_candidate_count": len(positive_ids),
            "positive_view_types": source.get("positive_view_types") or {},
            "runtime_query": query_text,
            "anchor_role": "offline_evaluation_mapping_only",
            "non_anchor_semantics": "unknown_unlabeled_background_not_safe_negative",
        }
        for method, scores in scores_by_method.items():
            rank = first_positive_rank(scores, candidate_ids, positive_ids)
            row[f"{method}_rank"] = rank
            row[f"{method}_normalized_rank"] = (
                (rank - 1) / max(len(candidate_ids) - 1, 1)
                if rank is not None
                else None
            )
            for value in K_VALUES:
                row[f"{method}_hit_at_{value}"] = bool(rank is not None and rank <= value)
        ledger.append(row)
        print(
            json.dumps(
                {
                    "event": "p4_external_case_scored",
                    "case_index": index,
                    "case_total": len(rows),
                    "case_id": row["case_id"],
                    "repo_key": repo_key,
                    "B0_rank": row["B0_rank"],
                    "P3C64_rank": row["P3C64_rank"],
                },
                ensure_ascii=False,
                sort_keys=True,
            ),
            flush=True,
        )

    methods = ("B0", "P3C64")
    metrics = {method: metric_summary(ledger, method=method) for method in methods}
    review_budget = {
        method: review_budget_summary(ledger, method=method) for method in methods
    }
    track_metrics: dict[str, dict[str, Any]] = {}
    for track_id in sorted({str(row["track_id"]) for row in ledger}):
        track_rows = [row for row in ledger if str(row["track_id"]) == track_id]
        track_metrics[track_id] = {
            method: metric_summary(track_rows, method=method) for method in methods
        }
    paired = {
        f"at_{value}": paired_comparison(
            ledger,
            left="B0",
            right="P3C64",
            k=value,
        )
        for value in (10, 30, 100)
    }
    output_dir.mkdir(parents=True, exist_ok=False)
    write_jsonl(output_dir / "case_rank_ledger.v1.jsonl", ledger)
    summary = {
        "schema_version": SCHEMA_VERSION,
        "run_id": spec["run_id"],
        "status": "completed_one_shot_external_evaluation",
        "created_at": utc_now(),
        "inputs": {
            "one_shot_spec": {
                "path": str(args.one_shot_spec.resolve()),
                "sha256": sha256_file(args.one_shot_spec),
            },
            "candidate_pool": {
                "path": str(args.candidate_pool.resolve()),
                "sha256": sha256_file(args.candidate_pool),
            },
            "cache_audit": {
                "path": str(args.cache_audit.resolve()),
                "sha256": sha256_file(args.cache_audit),
            },
            "p3_state": {
                "path": str(args.p3_state.resolve()),
                "sha256": sha256_file(args.p3_state),
            },
        },
        "method_boundary": spec["boundary"],
        "method_state": spec["methods"],
        "runtime": {
            "model_path": args.model_path,
            "encoder_device": args.encoder_device,
            "adapter_device": args.adapter_device,
            "encoded_unique_guideline_count": len(unique_queries),
            "training_performed": False,
            "p3_state_refit": False,
            "variant_selection_performed": False,
        },
        "evaluation_scope": {
            "case_count": len(ledger),
            "repository_count": len({row["repo_key"] for row in ledger}),
            "project_group_count": len({row["project_group"] for row in ledger}),
            "track_counts": dict(sorted(Counter(row["track_id"] for row in ledger).items())),
            "candidate_count_min": min(row["candidate_count"] for row in ledger),
            "candidate_count_max": max(row["candidate_count"] for row in ledger),
            "candidate_count_total": sum(row["candidate_count"] for row in ledger),
        },
        "metrics": metrics,
        "review_budget": review_budget,
        "track_metrics": track_metrics,
        "paired_comparisons": paired,
        "output_contract": {
            "case_rank_ledger": "case_rank_ledger.v1.jsonl",
            "offline_positive_semantics": "Source-derived generic overlap mapping for retrieval hit measurement only; not vulnerability proof.",
            "non_anchor_semantics": "unknown unlabeled background; never safe-negative or hard-negative truth.",
        },
        "stop_rule": spec["stop_rule"],
    }
    write_json(output_dir / "summary.json", summary)
    manifest = {"artifact": output_dir.name, "files": {}}
    for path in sorted(output_dir.iterdir()):
        if path.is_file():
            manifest["files"][path.name] = {
                "bytes": path.stat().st_size,
                "sha256": sha256_file(path),
            }
    write_json(output_dir / "manifest.v1.json", manifest)
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
