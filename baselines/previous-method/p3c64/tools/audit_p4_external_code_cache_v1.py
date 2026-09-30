#!/usr/bin/env python3
"""Audit the independent frozen code cache for the P4 external intake.

The audit recomputes exact cache metadata from the frozen generic candidate
pool and verifies that the cache has one valid float32, L2-normalized 1024d
matrix per selected external repository. It neither loads query text nor
labels/anchors and produces no retrieval result.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import numpy as np


SCHEMA_VERSION = "p4_external_code_cache_audit_v1"
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


def candidate_text(row: dict[str, Any], *, text_field: str, max_chars: int) -> str:
    text = str(row.get(text_field) or row.get("text") or "")
    return text[:max_chars] if max_chars > 0 else text


def fingerprint_docs(docs: list[str], candidate_ids: list[str]) -> str:
    digest = hashlib.sha256()
    for candidate_id, doc in zip(candidate_ids, docs, strict=True):
        digest.update(candidate_id.encode("utf-8", errors="replace"))
        digest.update(b"\0")
        data = doc.encode("utf-8", errors="replace")
        digest.update(str(len(data)).encode("ascii"))
        digest.update(b"\0")
        digest.update(data)
        digest.update(b"\0")
    return digest.hexdigest()


def expected_metadata(
    repo_key: str,
    candidate_ids: list[str],
    docs: list[str],
    *,
    model_path: str,
    text_field: str,
    max_chars: int,
) -> dict[str, Any]:
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


def validate_cache(
    cache_path: Path,
    *,
    expected: dict[str, Any],
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "cache_path": str(cache_path),
        "cache_exists": cache_path.is_file(),
        "status": "miss",
    }
    if not cache_path.is_file():
        return result
    try:
        with np.load(cache_path, allow_pickle=False) as archive:
            metadata = json.loads(str(archive["metadata"].item()))
            embeddings = archive["embeddings"]
    except Exception as error:
        result["status"] = "invalid_npz"
        result["error"] = f"{type(error).__name__}: {error}"
        return result

    result["observed_metadata"] = metadata
    result["embedding_shape"] = list(embeddings.shape)
    result["embedding_dtype"] = str(embeddings.dtype)
    if metadata != expected:
        result["status"] = "metadata_mismatch"
        return result
    if embeddings.dtype != np.dtype("float32"):
        result["status"] = "dtype_mismatch"
        return result
    expected_shape = (int(expected["doc_count"]), 1024)
    if embeddings.shape != expected_shape:
        result["status"] = "shape_mismatch"
        result["expected_shape"] = list(expected_shape)
        return result
    if not np.isfinite(embeddings).all():
        result["status"] = "nonfinite"
        return result
    norms = np.linalg.norm(embeddings, axis=1)
    result["embedding_norm_min"] = float(norms.min()) if len(norms) else None
    result["embedding_norm_max"] = float(norms.max()) if len(norms) else None
    result["embedding_norm_max_abs_error"] = (
        float(np.max(np.abs(norms - 1.0))) if len(norms) else 0.0
    )
    if result["embedding_norm_max_abs_error"] > 1e-4:
        result["status"] = "normalization_mismatch"
        return result
    result["status"] = "ready"
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cache-plan", type=Path, required=True)
    parser.add_argument("--selected-repositories", type=Path, required=True)
    parser.add_argument("--candidate-pool", type=Path, required=True)
    parser.add_argument("--pool-summary", type=Path, required=True)
    parser.add_argument("--cache-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--model-path", default=DEFAULT_MODEL_PATH)
    parser.add_argument("--text-field", default="text")
    parser.add_argument("--max-chars", type=int, default=4000)
    args = parser.parse_args()

    inputs = {
        "cache_plan": args.cache_plan.resolve(),
        "selected_repositories": args.selected_repositories.resolve(),
        "candidate_pool": args.candidate_pool.resolve(),
        "pool_summary": args.pool_summary.resolve(),
    }
    missing = [str(path) for path in inputs.values() if not path.is_file()]
    if not Path(args.model_path).is_dir():
        missing.append(args.model_path)
    if missing:
        raise FileNotFoundError(f"missing P4 cache-audit input(s): {missing}")
    if not args.cache_dir.is_dir():
        raise FileNotFoundError(f"cache directory is unavailable: {args.cache_dir}")
    output_dir = args.output_dir.resolve()
    if output_dir.exists():
        raise FileExistsError(f"refusing to overwrite P4 cache audit: {output_dir}")

    selected_rows = read_jsonl(inputs["selected_repositories"])
    selected_by_repo = {str(row["repo_key"]): row for row in selected_rows}
    if len(selected_by_repo) != len(selected_rows):
        raise ValueError("selected repository ledger has duplicate repo keys")
    plan = read_json(inputs["cache_plan"])
    planned_repos = {
        str(repo["repo_key"])
        for worker in plan.get("workers") or []
        for repo in worker.get("repos") or []
    }
    if planned_repos != set(selected_by_repo):
        raise ValueError("cache plan and selected repository ledger disagree")

    candidates_by_repo: dict[str, list[dict[str, Any]]] = {
        repo_key: [] for repo_key in selected_by_repo
    }
    for row in read_jsonl(inputs["candidate_pool"]):
        repo_key = str(row.get("repo_key") or "")
        if repo_key in candidates_by_repo:
            candidates_by_repo[repo_key].append(row)
    pool_summary = read_json(inputs["pool_summary"])
    expected_pool_count = int(pool_summary.get("summary", {}).get("candidate_count") or 0)
    if expected_pool_count <= 0:
        raise ValueError("P4 candidate pool summary has no candidates")

    rows: list[dict[str, Any]] = []
    for repo_key in sorted(selected_by_repo):
        candidates = candidates_by_repo[repo_key]
        expected_count = int(selected_by_repo[repo_key]["candidate_count"])
        candidate_ids = [str(row.get("candidate_id") or "") for row in candidates]
        if len(candidates) != expected_count:
            raise ValueError(
                f"candidate count mismatch for {repo_key}: "
                f"expected={expected_count} actual={len(candidates)}"
            )
        if not all(candidate_ids) or len(set(candidate_ids)) != len(candidate_ids):
            raise ValueError(f"invalid selected candidate IDs for {repo_key}")
        docs = [
            candidate_text(row, text_field=args.text_field, max_chars=args.max_chars)
            for row in candidates
        ]
        metadata = expected_metadata(
            repo_key,
            candidate_ids,
            docs,
            model_path=args.model_path,
            text_field=args.text_field,
            max_chars=args.max_chars,
        )
        audit = validate_cache(
            args.cache_dir / f"{stable_name(repo_key)}.npz",
            expected=metadata,
        )
        rows.append(
            {
                "repo_key": repo_key,
                "candidate_count": len(candidates),
                "expected_metadata": metadata,
                **audit,
            }
        )

    expected_files = {
        f"{stable_name(repo_key)}.npz" for repo_key in selected_by_repo
    }
    actual_files = {
        path.name for path in args.cache_dir.glob("*.npz") if path.is_file()
    }
    status_counts = Counter(str(row["status"]) for row in rows)
    ready = (
        status_counts == Counter({"ready": len(selected_by_repo)})
        and actual_files == expected_files
    )
    summary = {
        "schema_version": SCHEMA_VERSION,
        "status": "ready_exact" if ready else "not_ready",
        "created_at": utc_now(),
        "inputs": {
            key: {"path": str(path), "sha256": sha256_file(path)}
            for key, path in inputs.items()
        },
        "cache": {
            "path": str(args.cache_dir.resolve()),
            "storage_class": "runtime_cache_directory",
            "model_path": args.model_path,
            "text_field": args.text_field,
            "max_chars": args.max_chars,
            "expected_embedding_dtype": "float32",
            "expected_embedding_dimension": 1024,
            "expected_normalization": "L2",
        },
        "scope": {
            "selected_repository_count": len(selected_by_repo),
            "selected_candidate_count": sum(
                int(row["candidate_count"]) for row in selected_rows
            ),
            "p4_full_pool_candidate_count": expected_pool_count,
        },
        "status_counts": dict(sorted(status_counts.items())),
        "file_set": {
            "expected_count": len(expected_files),
            "actual_count": len(actual_files),
            "missing": sorted(expected_files - actual_files),
            "extra": sorted(actual_files - expected_files),
        },
        "boundary": (
            "This audit recomputes only code-cache identity from the frozen "
            "generic candidate pool. It encodes no guideline text, reads no "
            "offline labels or source anchors, and performs no ranking, "
            "training, checkpoint selection, or external evaluation."
        ),
    }
    output_dir.mkdir(parents=True, exist_ok=False)
    write_jsonl(output_dir / "cache_audit_rows.v1.jsonl", rows)
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
    return 0 if ready else 2


if __name__ == "__main__":
    raise SystemExit(main())
