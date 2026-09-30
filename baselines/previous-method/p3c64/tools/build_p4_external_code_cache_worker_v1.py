#!/usr/bin/env python3
"""Build one assigned shard of the frozen P4 external code-embedding cache.

Worker inputs are hash-checked against a frozen P4 cache plan.  The worker
loads only the exact assigned repositories from the generic candidate pool and
serializes vectors using the existing M5/M7 cache metadata contract.  It never
encodes guideline text or reads labels/anchors.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np


SCHEMA_VERSION = "p4_external_code_cache_worker_v1"
DEFAULT_MODEL_PATH = (
    "/data/lhq/.cache/huggingface/hub/models--Qwen--Qwen3-Embedding-0.6B/"
    "snapshots/97b0c614be4d77ee51c0cef4e5f07c00f9eb65b3"
)


def now_utc() -> str:
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


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
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


def normalize_vectors(vectors: np.ndarray) -> np.ndarray:
    vectors = vectors.astype("float32", copy=False)
    norms = np.linalg.norm(vectors, axis=1, keepdims=True)
    norms[norms == 0.0] = 1.0
    return vectors / norms


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


def read_cached_embeddings(path: Path, metadata: dict[str, Any]) -> tuple[np.ndarray | None, str]:
    if not path.exists():
        return None, "miss"
    try:
        with np.load(path, allow_pickle=False) as data:
            cached_metadata = json.loads(str(data["metadata"].item()))
            if cached_metadata != metadata:
                return None, "stale"
            embeddings = data["embeddings"].astype("float32", copy=False)
    except Exception:
        return None, "invalid"
    if embeddings.ndim != 2 or embeddings.shape[0] != metadata["doc_count"]:
        return None, "invalid_shape"
    if not np.isfinite(embeddings).all():
        return None, "invalid_nonfinite"
    return embeddings, "hit"


def write_cached_embeddings(path: Path, embeddings: np.ndarray, metadata: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("wb") as handle:
        np.savez(
            handle,
            embeddings=embeddings.astype("float32", copy=False),
            metadata=json.dumps(metadata, sort_keys=True),
        )
    temporary.replace(path)


def encode_documents(
    model: Any,
    docs: list[str],
    *,
    batch_size: int,
    chunk_size: int,
    repo_key: str,
) -> np.ndarray:
    chunks: list[np.ndarray] = []
    for start in range(0, len(docs), max(chunk_size, 1)):
        end = min(start + max(chunk_size, 1), len(docs))
        vectors = model.encode(
            docs[start:end],
            batch_size=batch_size,
            normalize_embeddings=True,
            show_progress_bar=False,
            convert_to_numpy=True,
        )
        chunks.append(vectors.astype("float32", copy=False))
        print(
            json.dumps(
                {
                    "event": "p4_repo_chunk_encoded",
                    "repo_key": repo_key,
                    "chunk_start": start,
                    "chunk_end": end,
                    "candidate_count": len(docs),
                },
                ensure_ascii=False,
                sort_keys=True,
            ),
            flush=True,
        )
    return normalize_vectors(np.vstack(chunks)) if chunks else np.empty((0, 0), dtype="float32")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cache-plan", type=Path, required=True)
    parser.add_argument("--selected-repositories", type=Path, required=True)
    parser.add_argument("--candidate-pool", type=Path, required=True)
    parser.add_argument("--worker-id", required=True)
    parser.add_argument("--output-cache-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--model-path", default=DEFAULT_MODEL_PATH)
    parser.add_argument("--device", required=True)
    parser.add_argument("--batch-size", type=int, default=64)
    parser.add_argument("--chunk-size", type=int, default=8192)
    parser.add_argument("--max-seq-length", type=int, default=512)
    parser.add_argument("--text-field", default="text")
    parser.add_argument("--max-chars", type=int, default=4000)
    args = parser.parse_args()

    paths = {
        "cache_plan": args.cache_plan.resolve(),
        "selected_repositories": args.selected_repositories.resolve(),
        "candidate_pool": args.candidate_pool.resolve(),
    }
    missing = [str(path) for path in paths.values() if not path.is_file()]
    if not Path(args.model_path).is_dir():
        missing.append(args.model_path)
    if missing:
        raise FileNotFoundError(f"missing P4 cache-worker input(s): {missing}")
    output_dir = args.output_dir.resolve()
    if output_dir.exists():
        raise FileExistsError(f"refusing to overwrite P4 cache worker output: {output_dir}")

    worker_plan = read_json(paths["cache_plan"])
    worker = next(
        (
            row
            for row in worker_plan.get("workers") or []
            if str(row.get("worker_id")) == args.worker_id
        ),
        None,
    )
    if worker is None:
        raise ValueError(f"worker ID absent from frozen plan: {args.worker_id}")
    assigned_repos = [str(row["repo_key"]) for row in worker.get("repos") or []]
    selected_repositories = {
        str(row["repo_key"]): row for row in read_jsonl(paths["selected_repositories"])
    }
    if not set(assigned_repos) <= set(selected_repositories):
        raise ValueError("cache worker assignment includes a non-selected repo")

    candidates_by_repo: dict[str, list[dict[str, Any]]] = {repo_key: [] for repo_key in assigned_repos}
    for row in read_jsonl(paths["candidate_pool"]):
        repo_key = str(row.get("repo_key") or "")
        if repo_key in candidates_by_repo:
            candidates_by_repo[repo_key].append(row)
    missing_repos = sorted(repo_key for repo_key, rows in candidates_by_repo.items() if not rows)
    if missing_repos:
        raise ValueError(f"assigned cache repos absent from candidate pool: {missing_repos}")
    for repo_key, rows in candidates_by_repo.items():
        expected_count = int(selected_repositories[repo_key]["candidate_count"])
        if len(rows) != expected_count:
            raise ValueError(
                f"candidate count changed for {repo_key}: expected={expected_count} actual={len(rows)}"
            )

    from sentence_transformers import SentenceTransformer

    model = SentenceTransformer(args.model_path, device=args.device)
    model.max_seq_length = args.max_seq_length
    output_cache_dir = args.output_cache_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=False)
    repo_rows: list[dict[str, Any]] = []
    status_counts: Counter[str] = Counter()
    for repo_index, repo_key in enumerate(sorted(assigned_repos), start=1):
        candidates = candidates_by_repo[repo_key]
        docs = [
            candidate_text(row, text_field=args.text_field, max_chars=args.max_chars)
            for row in candidates
        ]
        candidate_ids = [str(row.get("candidate_id") or "") for row in candidates]
        if not all(candidate_ids) or len(set(candidate_ids)) != len(candidate_ids):
            raise ValueError(f"invalid candidate IDs for cache repo: {repo_key}")
        metadata = expected_metadata(
            repo_key,
            candidate_ids,
            docs,
            model_path=args.model_path,
            text_field=args.text_field,
            max_chars=args.max_chars,
        )
        cache_path = output_cache_dir / f"{stable_name(repo_key)}.npz"
        embeddings, status = read_cached_embeddings(cache_path, metadata)
        if embeddings is None:
            embeddings = encode_documents(
                model,
                docs,
                batch_size=args.batch_size,
                chunk_size=args.chunk_size,
                repo_key=repo_key,
            )
            if embeddings.shape != (len(candidates), 1024):
                raise ValueError(
                    f"unexpected Qwen embedding shape for {repo_key}: {embeddings.shape}"
                )
            if not np.isfinite(embeddings).all():
                raise ValueError(f"non-finite Qwen embeddings for {repo_key}")
            embeddings = normalize_vectors(embeddings)
            write_cached_embeddings(cache_path, embeddings, metadata)
            status = f"cache_{status}"
        norms = np.linalg.norm(embeddings, axis=1)
        repo_rows.append(
            {
                "worker_id": args.worker_id,
                "repo_index": repo_index,
                "repo_key": repo_key,
                "candidate_count": len(candidates),
                "cache_path": str(cache_path),
                "cache_status": status,
                "embedding_shape": list(embeddings.shape),
                "embedding_norm_min": float(norms.min()) if len(norms) else None,
                "embedding_norm_max": float(norms.max()) if len(norms) else None,
                "embedding_metadata": metadata,
            }
        )
        status_counts.update([status])
        print(
            json.dumps(
                {
                    "event": "p4_repo_cache_ready",
                    "worker_id": args.worker_id,
                    "repo_index": repo_index,
                    "repo_total": len(assigned_repos),
                    "repo_key": repo_key,
                    "candidate_count": len(candidates),
                    "cache_status": status,
                },
                ensure_ascii=False,
                sort_keys=True,
            ),
            flush=True,
        )

    write_jsonl(output_dir / "repo_rows.v1.jsonl", repo_rows)
    summary = {
        "schema_version": SCHEMA_VERSION,
        "status": "completed_code_cache_no_query_or_retrieval",
        "created_at": now_utc(),
        "inputs": {
            key: {"path": str(path), "sha256": sha256_file(path)}
            for key, path in paths.items()
        },
        "worker": {
            "worker_id": args.worker_id,
            "device": args.device,
            "assigned_repo_count": len(assigned_repos),
            "assigned_candidate_count": sum(len(rows) for rows in candidates_by_repo.values()),
        },
        "model": {
            "model_path": args.model_path,
            "batch_size": args.batch_size,
            "chunk_size": args.chunk_size,
            "max_seq_length": args.max_seq_length,
            "text_field": args.text_field,
            "max_chars": args.max_chars,
            "embedding_dimension": 1024,
            "normalization": "L2",
            "serialization_contract": (
                "M5/M7 candidate_text=row[text_field or text][:max_chars]"
            ),
        },
        "cache_status_counts": dict(sorted(status_counts.items())),
        "boundary": (
            "This worker creates frozen code embeddings for its assigned P4 "
            "repositories only. It encodes no guideline text and performs no "
            "retrieval, ranking, model update, or external evaluation."
        ),
    }
    write_json(output_dir / "summary.json", summary)
    manifest = {"artifact": output_dir.name, "files": {}}
    for path in sorted(output_dir.iterdir()):
        if path.is_file():
            manifest["files"][path.name] = {
                "sha256": sha256_file(path),
                "bytes": path.stat().st_size,
            }
    write_json(output_dir / "manifest.v1.json", manifest)
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
