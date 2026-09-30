#!/usr/bin/env python3
"""Freeze the one-shot B0 versus P3C64 external-evaluation contract.

This gate runs only after the independent P4 code cache is exact-ready.  It
records immutable hashes and explicitly fixes the selected P3C64 state,
external cases, offline positive mappings, full-repository candidate universe,
and fixed per-track guideline texts.  It performs no retrieval itself.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import yaml


SCHEMA_VERSION = "p4_external_one_shot_spec_v1"
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


def sha256_jsonl_rows(rows: Iterable[dict[str, Any]]) -> str:
    digest = hashlib.sha256()
    for row in rows:
        digest.update(
            (
                json.dumps(row, ensure_ascii=False, sort_keys=True)
                + "\n"
            ).encode("utf-8")
        )
    return digest.hexdigest()


def yaml_tracks(path: Path) -> dict[str, str]:
    with path.open(encoding="utf-8") as handle:
        source = yaml.safe_load(handle)
    tracks = source.get("tracks") if isinstance(source, dict) else None
    if isinstance(tracks, dict):
        values = {
            str(track_id): str(row.get("guideline_text") or "")
            for track_id, row in tracks.items()
            if isinstance(row, dict)
        }
    elif isinstance(tracks, list):
        values = {
            str(row.get("track_id") or ""): str(row.get("guideline_text") or "")
            for row in tracks
            if isinstance(row, dict)
        }
    else:
        raise ValueError(
            "guideline track source must contain a tracks mapping or list"
        )
    if not all(values) or len(values) != len(set(values)):
        raise ValueError("guideline track source includes invalid or duplicate track IDs")
    if not all(values.values()):
        raise ValueError("guideline track source includes an empty guideline_text")
    return values


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--selected-cases", type=Path, required=True)
    parser.add_argument("--coverage", type=Path, required=True)
    parser.add_argument("--candidate-pool", type=Path, required=True)
    parser.add_argument("--pool-summary", type=Path, required=True)
    parser.add_argument("--cache-audit", type=Path, required=True)
    parser.add_argument("--cache-dir", type=Path, required=True)
    parser.add_argument("--guideline-tracks", type=Path, required=True)
    parser.add_argument("--p3-run-spec", type=Path, required=True)
    parser.add_argument("--p3-state", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--model-path", default=DEFAULT_MODEL_PATH)
    args = parser.parse_args()

    inputs = {
        "selected_cases": args.selected_cases.resolve(),
        "coverage": args.coverage.resolve(),
        "candidate_pool": args.candidate_pool.resolve(),
        "pool_summary": args.pool_summary.resolve(),
        "cache_audit": args.cache_audit.resolve(),
        "guideline_tracks": args.guideline_tracks.resolve(),
        "p3_run_spec": args.p3_run_spec.resolve(),
        "p3_state": args.p3_state.resolve(),
    }
    missing = [str(path) for path in inputs.values() if not path.is_file()]
    if not args.cache_dir.is_dir():
        missing.append(str(args.cache_dir))
    if not Path(args.model_path).is_dir():
        missing.append(args.model_path)
    if missing:
        raise FileNotFoundError(f"missing P4 one-shot-spec input(s): {missing}")
    output_dir = args.output_dir.resolve()
    if output_dir.exists():
        raise FileExistsError(f"refusing to overwrite P4 one-shot spec: {output_dir}")

    cache_audit = read_json(inputs["cache_audit"])
    if cache_audit.get("status") != "ready_exact":
        raise ValueError("P4 one-shot spec requires an exact-ready independent cache audit")
    audited_cache = str(
        (cache_audit.get("cache") or {}).get("path") or ""
    )
    if audited_cache != str(args.cache_dir.resolve()):
        raise ValueError("cache-audit directory does not match requested cache directory")

    p3_spec = read_json(inputs["p3_run_spec"])
    variants = {
        str(row.get("variant_id")): row for row in p3_spec.get("finite_variants") or []
    }
    p3c64 = variants.get("P3C64")
    if p3c64 != {
        "variant_id": "P3C64",
        "query_projection": True,
        "code_projection": False,
        "competition_count": 64,
        "training": True,
    }:
        raise ValueError("frozen P3 run spec does not define the expected P3C64 method")
    candidate_contract = p3_spec.get("candidate_contract") or {}
    if candidate_contract.get("code_embedding_state") != "frozen cached float32 L2-normalized Qwen vectors":
        raise ValueError("P3 run spec cache contract is unexpected")
    if candidate_contract.get("runtime_input") != "fixed natural-language guideline text only":
        raise ValueError("P3 run spec query contract is unexpected")
    if str((p3_spec.get("inputs") or {}).get("model_path") or "") != args.model_path:
        raise ValueError("P3 run spec model path differs from external cache model")

    cases = read_jsonl(inputs["selected_cases"])
    coverage_by_case = {
        str(row["case_id"]): row for row in read_jsonl(inputs["coverage"])
    }
    if not cases:
        raise ValueError("external selected-case ledger is empty")
    if len({str(row["repo_key"]) for row in cases}) != len(cases):
        raise ValueError("external selected-case ledger has non-unique repo keys")
    track_texts = yaml_tracks(inputs["guideline_tracks"])
    runtime_rows: list[dict[str, Any]] = []
    for case in sorted(cases, key=lambda row: str(row["case_id"])):
        case_id = str(case["case_id"])
        coverage = coverage_by_case.get(case_id)
        if coverage is None or not coverage.get("covered"):
            raise ValueError(f"external case lacks generic coverage: {case_id}")
        track_id = str(case["track_id"])
        guideline_text = track_texts.get(track_id)
        if not guideline_text:
            raise ValueError(f"external track lacks fixed guideline text: {track_id}")
        positive_ids = [str(value) for value in coverage.get("positive_candidate_ids") or []]
        if not positive_ids:
            raise ValueError(f"covered external case lacks mapped positives: {case_id}")
        runtime_rows.append(
            {
                "case_id": case_id,
                "cve_id": case.get("cve_id"),
                "repo_key": str(case["repo_key"]),
                "project_group": str(case.get("project_group") or ""),
                "track_id": track_id,
                "guideline_text": guideline_text,
                "candidate_count": int(coverage["candidate_count"]),
                "positive_candidate_ids": sorted(positive_ids),
                "positive_candidate_count": len(positive_ids),
                "positive_view_types": coverage.get("positive_view_types") or {},
                "anchor_role": "offline_evaluation_mapping_only",
                "non_anchor_semantics": "unknown_unlabeled_background_not_safe_negative",
            }
        )

    pool_summary = read_json(inputs["pool_summary"])
    expected_full_pool_count = int(pool_summary.get("summary", {}).get("candidate_count") or 0)
    expected_selected_count = sum(int(row["candidate_count"]) for row in runtime_rows)
    spec = {
        "schema_version": SCHEMA_VERSION,
        "status": "frozen_unexecuted_one_shot_external_evaluation",
        "created_at": utc_now(),
        "run_id": "p4_external_b0_vs_p3c64_v1",
        "inputs": {
            key: {"path": str(path), "sha256": sha256_file(path)}
            for key, path in inputs.items()
        },
        "cache_contract": {
            "cache_directory": str(args.cache_dir.resolve()),
            "audit_status": cache_audit["status"],
            "code_model_path": args.model_path,
            "embedding_dimension": 1024,
            "embedding_dtype": "float32",
            "normalization": "L2",
            "candidate_text_field": "text",
            "candidate_max_chars": 4000,
            "max_sequence_length": 512,
        },
        "methods": {
            "B0": {
                "description": "Frozen Qwen guideline embedding scored against frozen Qwen code vectors.",
                "learned_state": None,
            },
            "P3C64": {
                "description": "The fixed P3C64 query-only identity-initialized residual MLP; frozen code vectors remain unchanged.",
                "learned_state_path": str(inputs["p3_state"]),
                "learned_state_sha256": sha256_file(inputs["p3_state"]),
                "query_projection": True,
                "code_projection": False,
                "hidden_dimension": 128,
                "residual_scale": 0.1,
                "selection_origin": "P3 non-M8 inner development selection only",
            },
        },
        "external_scope": {
            "case_count": len(runtime_rows),
            "repository_count": len({row["repo_key"] for row in runtime_rows}),
            "project_group_count": len({row["project_group"] for row in runtime_rows}),
            "selected_candidate_count": expected_selected_count,
            "p4_full_pool_candidate_count_before_hold": expected_full_pool_count,
            "track_counts": dict(sorted(Counter(row["track_id"] for row in runtime_rows).items())),
        },
        "runtime_row_ledger": {
            "filename": "external_evaluation_rows.v1.jsonl",
            "sha256": sha256_jsonl_rows(runtime_rows),
            "semantic_role": (
                "Frozen runtime query text and offline mapped-positive evaluation "
                "ledger. Its anchors remain unavailable to the runtime scorer."
            ),
        },
        "metrics": {
            "recall_at": [1, 3, 5, 10, 20, 30, 50, 100, 200, 500],
            "first_hit_rank_percentiles": ["min", "p25", "p50", "p75", "p90", "p95", "p99", "max"],
            "normalized_first_hit_rank_percentiles": ["min", "p25", "p50", "p75", "p90", "p95", "p99", "max"],
            "review_budget_coverage_targets": [0.25, 0.5, 0.75, 0.9],
            "paired_comparisons_at": [10, 30, 100],
            "case_rank_ledger": True,
            "per_track_metrics": True,
        },
        "boundary": {
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
            "one_shot": "The evaluator must refuse an existing non-empty output directory.",
        },
        "stop_rule": (
            "This frozen one-shot external evaluation reports results only. "
            "It cannot trigger hyperparameter tuning, query rewriting, case "
            "replacement, cache regeneration, or method selection on P4."
        ),
    }
    output_dir.mkdir(parents=True, exist_ok=False)
    write_jsonl(output_dir / "external_evaluation_rows.v1.jsonl", runtime_rows)
    write_json(output_dir / "one_shot_spec.v1.json", spec)
    manifest = {"artifact": output_dir.name, "files": {}}
    for path in sorted(output_dir.iterdir()):
        if path.is_file():
            manifest["files"][path.name] = {
                "bytes": path.stat().st_size,
                "sha256": sha256_file(path),
            }
    write_json(output_dir / "manifest.v1.json", manifest)
    print(json.dumps(spec, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
