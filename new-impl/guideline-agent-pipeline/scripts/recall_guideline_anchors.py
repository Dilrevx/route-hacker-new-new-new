#!/usr/bin/env python3
"""Recall repository anchors from generic source slices with real embeddings."""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import math
import os
import re
import subprocess
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Iterable, Protocol

from run_hcvr_case_anchor_audits import (
    build_guideline,
    ensure_snapshot,
    load_selected_cases,
    safe_slug,
    sha256_file,
    write_jsonl,
)


DEFAULT_SUFFIXES = (
    ".java",
    ".c",
    ".cc",
    ".cpp",
    ".cxx",
    ".h",
    ".hh",
    ".hpp",
    ".hxx",
    ".go",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".py",
    ".rb",
    ".php",
    ".sh",
    ".xml",
    ".yaml",
    ".yml",
    ".properties",
    ".conf",
    ".cfg",
)
EXCLUDED_DIRS = {
    ".git",
    ".gradle",
    ".idea",
    ".mvn",
    "__pycache__",
    "build",
    "dist",
    "node_modules",
    "out",
    "target",
    "vendor",
}
SYMBOL_RE = re.compile(
    r"\b(?:class|interface|enum|def|function)\s+([A-Za-z_][A-Za-z0-9_]*)|"
    r"\b(?:public|private|protected|static|final|async|synchronized|\s)+"
    r"[A-Za-z0-9_<>\[\], ?]+\s+([A-Za-z_][A-Za-z0-9_]*)\s*\("
)


class Embedder(Protocol):
    @property
    def model_id(self) -> str: ...

    def embed_texts(self, texts: list[str]) -> list[list[float]]: ...


def read_jsonl(path: Path) -> Iterable[dict[str, Any]]:
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                yield json.loads(line)


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def l2_normalize(vector: Iterable[float]) -> list[float]:
    values = [float(value) for value in vector]
    norm = math.sqrt(sum(value * value for value in values))
    if norm == 0:
        return values
    return [value / norm for value in values]


def dot(a: list[float], b: list[float]) -> float:
    if len(a) != len(b):
        raise ValueError(f"embedding dimension mismatch: {len(a)} != {len(b)}")
    return float(sum(left * right for left, right in zip(a, b)))


class OpenAICompatibleEmbedder:
    def __init__(
        self,
        *,
        base_url: str,
        model: str,
        api_key: str | None,
        timeout: int,
        max_retries: int,
        retry_sleep: float,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._model = model
        self._api_key = api_key
        self._timeout = timeout
        self._max_retries = max(1, max_retries)
        self._retry_sleep = max(0.0, retry_sleep)

    @property
    def model_id(self) -> str:
        return self._model

    def embed_texts(self, texts: list[str]) -> list[list[float]]:
        if not texts:
            return []
        payload = json.dumps({"model": self._model, "input": texts}).encode("utf-8")
        last_error: Exception | None = None
        for attempt in range(1, self._max_retries + 1):
            request = urllib.request.Request(
                f"{self._base_url}/embeddings",
                data=payload,
                headers={"Content-Type": "application/json", "Connection": "close"},
                method="POST",
            )
            if self._api_key:
                request.add_header("Authorization", f"Bearer {self._api_key}")
            try:
                with urllib.request.urlopen(request, timeout=self._timeout) as response:
                    body = response.read().decode("utf-8")
                break
            except urllib.error.HTTPError as error:
                detail = error.read().decode("utf-8", errors="replace")
                last_error = RuntimeError(f"embedding service HTTP {error.code}: {detail[:1000]}")
                if error.code < 500 or attempt >= self._max_retries:
                    raise last_error from error
            except (TimeoutError, urllib.error.URLError) as error:
                last_error = error
                if attempt >= self._max_retries:
                    raise RuntimeError(f"embedding service request failed after {attempt} attempt(s): {error}") from error
            time.sleep(self._retry_sleep * attempt)
        else:
            raise RuntimeError(f"embedding service request failed: {last_error}")
        data = json.loads(body)
        items = sorted(data.get("data") or [], key=lambda item: int(item.get("index", 0)))
        if len(items) != len(texts):
            raise RuntimeError(f"embedding service returned {len(items)} vectors for {len(texts)} texts")
        return [l2_normalize(item["embedding"]) for item in items]


class SentenceTransformersEmbedder:
    def __init__(self, *, model: str, device: str, max_seq_length: int) -> None:
        from sentence_transformers import SentenceTransformer

        self._model_id = model
        self._model = SentenceTransformer(model, device=device)
        if max_seq_length > 0:
            self._model.max_seq_length = max_seq_length

    @property
    def model_id(self) -> str:
        return self._model_id

    def embed_texts(self, texts: list[str]) -> list[list[float]]:
        vectors = self._model.encode(
            texts,
            normalize_embeddings=True,
            show_progress_bar=False,
            convert_to_numpy=False,
        )
        return [l2_normalize(vector) for vector in vectors]


def make_embedder(args: argparse.Namespace) -> Embedder:
    if args.embedding_backend == "openai":
        api_key = os.environ.get(args.embedding_api_key_env) if args.embedding_api_key_env else None
        return OpenAICompatibleEmbedder(
            base_url=args.embedding_base_url,
            model=args.embedding_model,
            api_key=api_key,
            timeout=args.embedding_timeout,
            max_retries=args.embedding_max_retries,
            retry_sleep=args.embedding_retry_sleep,
        )
    return SentenceTransformersEmbedder(
        model=args.embedding_model,
        device=args.embedding_device,
        max_seq_length=args.max_seq_length,
    )


def line_overlap(a_start: int, a_end: int, b_start: int, b_end: int) -> bool:
    return max(a_start, b_start) <= min(a_end, b_end)


def anchor_hit(candidate: dict[str, Any], truth_anchors: list[dict[str, Any]]) -> bool:
    for truth in truth_anchors:
        if candidate.get("file") != truth.get("file"):
            continue
        if line_overlap(
            int(candidate.get("start_line") or 0),
            int(candidate.get("end_line") or 0),
            int(truth.get("start_line") or 0),
            int(truth.get("end_line") or 0),
        ):
            return True
    return False


def should_skip_path(path: Path) -> bool:
    return any(part in EXCLUDED_DIRS for part in path.parts)


def iter_source_files(snapshot: Path, suffixes: set[str], max_file_bytes: int, max_files: int) -> list[Path]:
    files: list[Path] = []
    for path in snapshot.rglob("*"):
        if len(files) >= max_files:
            break
        if not path.is_file() or should_skip_path(path.relative_to(snapshot)):
            continue
        if path.suffix.lower() not in suffixes:
            continue
        try:
            if path.stat().st_size > max_file_bytes:
                continue
        except OSError:
            continue
        files.append(path)
    return sorted(files, key=lambda item: str(item.relative_to(snapshot)))


def nearest_symbol(lines: list[str], start_index: int) -> str:
    lower = max(0, start_index - 40)
    for index in range(start_index, lower - 1, -1):
        match = SYMBOL_RE.search(lines[index])
        if match:
            return next(group for group in match.groups() if group) or ""
    return ""


def candidate_id(repo_key: str, revision: str, file: str, start_line: int, end_line: int) -> str:
    digest = hashlib.sha256(f"{repo_key}\0{revision}\0{file}\0{start_line}\0{end_line}".encode("utf-8")).hexdigest()
    return f"recalled_anchor::{digest[:24]}"


def candidate_text(candidate: dict[str, Any], max_chars: int) -> str:
    text = (
        f"FILE={candidate['file']}\n"
        f"LINES={candidate['start_line']}-{candidate['end_line']}\n"
        f"SYMBOL={candidate.get('symbol') or ''}\n"
        f"VIEW={candidate.get('span_kind') or 'sliding_window'}\n"
        f"{candidate.get('text') or ''}"
    )
    return text[:max_chars] if max_chars > 0 else text


def slice_snapshot(
    *,
    case: dict[str, Any],
    snapshot: Path,
    suffixes: set[str],
    window_lines: int,
    stride_lines: int,
    max_file_bytes: int,
    max_files: int,
    max_candidates: int,
) -> list[dict[str, Any]]:
    repo_key = case["repository"]["repo_key"]
    revision = case["revisions"]["checkout_revision"]
    candidates: list[dict[str, Any]] = []
    for path in iter_source_files(snapshot, suffixes, max_file_bytes, max_files):
        rel = str(path.relative_to(snapshot))
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except UnicodeDecodeError:
            continue
        if not lines:
            continue
        step = max(1, stride_lines)
        width = max(1, window_lines)
        for start in range(0, len(lines), step):
            end = min(len(lines), start + width)
            if start >= end:
                continue
            start_line = start + 1
            end_line = end
            candidates.append(
                {
                    "anchor_id": candidate_id(repo_key, revision, rel, start_line, end_line),
                    "file": rel,
                    "start_line": start_line,
                    "end_line": end_line,
                    "symbol": nearest_symbol(lines, start),
                    "span_kind": "sliding_window",
                    "text": "\n".join(lines[start:end]),
                }
            )
            if len(candidates) >= max_candidates:
                return candidates
            if end == len(lines):
                break
    return candidates


def batched(values: list[str], size: int) -> Iterable[list[str]]:
    for start in range(0, len(values), size):
        yield values[start : start + size]


def embed_documents(embedder: Embedder, texts: list[str], batch_size: int) -> list[list[float]]:
    vectors: list[list[float]] = []
    for batch in batched(texts, batch_size):
        vectors.extend(embedder.embed_texts(batch))
    return vectors


def rank_candidates(
    *,
    embedder: Embedder,
    query_text: str,
    candidates: list[dict[str, Any]],
    batch_size: int,
    text_max_chars: int,
    top_k: int,
) -> list[dict[str, Any]]:
    if not candidates:
        return []
    query_vector = embedder.embed_texts([query_text])[0]
    texts = [candidate_text(candidate, text_max_chars) for candidate in candidates]
    vectors = embed_documents(embedder, texts, batch_size)
    scored = []
    for candidate, vector in zip(candidates, vectors):
        row = {key: value for key, value in candidate.items() if key != "text"}
        row["score"] = dot(query_vector, vector)
        scored.append(row)
    scored.sort(key=lambda row: (-float(row["score"]), str(row["anchor_id"])))
    for rank, row in enumerate(scored[:top_k], start=1):
        row["rank"] = rank
    return scored[:top_k]


def recall_case(
    *,
    case: dict[str, Any],
    embedder: Embedder,
    repo_cache: Path,
    snapshot_root: Path,
    snapshot_lock: threading.Lock | None,
    clone_timeout: int,
    suffixes: set[str],
    window_lines: int,
    stride_lines: int,
    max_file_bytes: int,
    max_files: int,
    max_candidates: int,
    batch_size: int,
    text_max_chars: int,
    top_k: int,
) -> dict[str, Any]:
    started = time.time()
    if snapshot_lock is None:
        snapshot = ensure_snapshot(case, repo_cache, snapshot_root, clone_timeout)
    else:
        with snapshot_lock:
            snapshot = ensure_snapshot(case, repo_cache, snapshot_root, clone_timeout)
    candidates = slice_snapshot(
        case=case,
        snapshot=snapshot,
        suffixes=suffixes,
        window_lines=window_lines,
        stride_lines=stride_lines,
        max_file_bytes=max_file_bytes,
        max_files=max_files,
        max_candidates=max_candidates,
    )
    guideline = build_guideline(case)
    top = rank_candidates(
        embedder=embedder,
        query_text=guideline,
        candidates=candidates,
        batch_size=batch_size,
        text_max_chars=text_max_chars,
        top_k=top_k,
    )
    truth_anchors = list(case.get("recall_anchors") or [])
    for row in top:
        row["known_anchor_overlap"] = anchor_hit(row, truth_anchors)
        row["retrieval_source"] = "mechanical_slice_embedding_recall"
    best_hit_rank = next((int(row["rank"]) for row in top if row.get("known_anchor_overlap")), None)
    return {
        "identity_key": case["identity_key"],
        "case_id": case.get("new_unified_case_id"),
        "repo_key": case["repository"]["repo_key"],
        "repo_url": case["repository"]["repo_url"],
        "checkout_revision": case["revisions"]["checkout_revision"],
        "hcvr_type": (case.get("classification") or {}).get("primary_hcvr_type"),
        "cwe_ids": (case.get("classification") or {}).get("cwe_ids") or [],
        "snapshot": str(snapshot),
        "guideline": guideline,
        "candidate_count": len(candidates),
        "known_anchor_count": len(truth_anchors),
        "best_known_anchor_rank": best_hit_rank,
        "hit_at_top_k": best_hit_rank is not None,
        "duration_seconds": round(time.time() - started, 3),
        "top_anchors": top,
    }


def selected_anchor_row(case_result: dict[str, Any], rank: int) -> dict[str, Any] | None:
    for anchor in case_result.get("top_anchors") or []:
        if int(anchor.get("rank") or 0) == rank:
            return {
                "identity_key": case_result["identity_key"],
                "case_id": case_result.get("case_id"),
                "repo_url": case_result["repo_url"],
                "checkout_revision": case_result["checkout_revision"],
                "hcvr_type": case_result.get("hcvr_type"),
                "snapshot": case_result.get("snapshot"),
                **anchor,
            }
    return None


def summarize(results: list[dict[str, Any]], budgets: list[int]) -> dict[str, Any]:
    completed = [row for row in results if row.get("state", "completed") == "completed"]
    ranks = [int(row["best_known_anchor_rank"]) for row in completed if row.get("best_known_anchor_rank")]
    summary: dict[str, Any] = {
        "case_count": len(results),
        "completed_count": len(completed),
        "failed_count": len(results) - len(completed),
        "candidate_count": sum(int(row.get("candidate_count") or 0) for row in completed),
        "mean_candidates_per_completed_case": (
            sum(int(row.get("candidate_count") or 0) for row in completed) / len(completed)
            if completed
            else 0.0
        ),
        "hit_cases": len(ranks),
        "mrr": sum(1.0 / rank for rank in ranks) / len(results) if results else 0.0,
    }
    for budget in budgets:
        summary[f"known_anchor_hit_at_{budget}"] = (
            sum(1 for rank in ranks if rank <= budget) / len(results) if results else 0.0
        )
    return summary


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--qa", type=Path, required=True)
    parser.add_argument("--cases-file", type=Path)
    parser.add_argument("--identity-file", type=Path)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--repo-cache", type=Path, required=True)
    parser.add_argument("--snapshot-root", type=Path, required=True)
    parser.add_argument("--selection", choices=("added", "all"), default="all")
    parser.add_argument("--limit", type=int, default=20)
    parser.add_argument("--skip", type=int, default=0)
    parser.add_argument("--clone-timeout", type=int, default=600)
    parser.add_argument("--case-workers", type=int, default=4)
    parser.add_argument("--top-k", type=int, default=200)
    parser.add_argument("--audit-anchor-rank", type=int, default=1)
    parser.add_argument("--window-lines", type=int, default=80)
    parser.add_argument("--stride-lines", type=int, default=40)
    parser.add_argument("--include-ext", default=",".join(DEFAULT_SUFFIXES))
    parser.add_argument("--max-file-bytes", type=int, default=1_000_000)
    parser.add_argument("--max-files-per-repo", type=int, default=20_000)
    parser.add_argument("--max-candidates-per-case", type=int, default=50_000)
    parser.add_argument("--text-max-chars", type=int, default=4000)
    parser.add_argument("--embedding-backend", choices=("openai", "sentence-transformers"), default="openai")
    parser.add_argument("--embedding-base-url", default=os.environ.get("EMBEDDING_BASE_URL", "http://127.0.0.1:8001/v1"))
    parser.add_argument("--embedding-api-key-env", default="EMBEDDING_API_KEY")
    parser.add_argument("--embedding-model", default=os.environ.get("EMBEDDING_MODEL", "Qwen/Qwen3-Embedding-0.6B"))
    parser.add_argument("--embedding-device", default="cpu")
    parser.add_argument("--embedding-batch-size", type=int, default=64)
    parser.add_argument("--embedding-timeout", type=int, default=300)
    parser.add_argument("--embedding-max-retries", type=int, default=3)
    parser.add_argument("--embedding-retry-sleep", type=float, default=5.0)
    parser.add_argument("--max-seq-length", type=int, default=512)
    args = parser.parse_args()

    if args.limit < 1 or args.case_workers < 1 or args.top_k < 1 or args.audit_anchor_rank < 1:
        raise SystemExit("limit, case-workers, top-k, and audit-anchor-rank must be positive")
    if args.audit_anchor_rank > args.top_k:
        raise SystemExit("--audit-anchor-rank cannot exceed --top-k")

    output = args.output_dir.resolve()
    if output.exists():
        raise FileExistsError(f"refusing existing recall output: {output}")
    output.mkdir(parents=True)
    repo_cache = args.repo_cache.resolve()
    snapshot_root = args.snapshot_root.resolve()
    repo_cache.mkdir(parents=True, exist_ok=True)
    snapshot_root.mkdir(parents=True, exist_ok=True)
    cases = load_selected_cases(
        args.qa.resolve(),
        args.limit,
        args.skip,
        args.selection,
        args.cases_file.resolve() if args.cases_file else None,
        args.identity_file.resolve() if args.identity_file else None,
        None,
    )
    embedder = make_embedder(args)
    suffixes = {value.strip().lower() for value in args.include_ext.split(",") if value.strip()}
    started = time.time()
    results: list[dict[str, Any]] = []
    selected: list[dict[str, Any]] = []
    recall_path = output / "recall_results.jsonl"
    selected_path = output / "selected_cases.jsonl"
    recall_path.write_text("", encoding="utf-8")
    selected_path.write_text("", encoding="utf-8")
    repo_locks_guard = threading.Lock()
    repo_locks: dict[str, threading.Lock] = {}

    def repo_lock_for(case: dict[str, Any]) -> threading.Lock:
        repo_key = str(case["repository"]["repo_key"])
        with repo_locks_guard:
            lock = repo_locks.get(repo_key)
            if lock is None:
                lock = threading.Lock()
                repo_locks[repo_key] = lock
            return lock

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.case_workers) as pool:
        future_to_case = {
            pool.submit(
                recall_case,
                case=case,
                embedder=embedder,
                repo_cache=repo_cache,
                snapshot_root=snapshot_root,
                snapshot_lock=repo_lock_for(case),
                clone_timeout=args.clone_timeout,
                suffixes=suffixes,
                window_lines=args.window_lines,
                stride_lines=args.stride_lines,
                max_file_bytes=args.max_file_bytes,
                max_files=args.max_files_per_repo,
                max_candidates=args.max_candidates_per_case,
                batch_size=args.embedding_batch_size,
                text_max_chars=args.text_max_chars,
                top_k=args.top_k,
            ): case
            for case in cases
        }
        for future in concurrent.futures.as_completed(future_to_case):
            case = future_to_case[future]
            try:
                row = future.result()
                row["state"] = "completed"
            except (
                subprocess.CalledProcessError,
                subprocess.TimeoutExpired,
                OSError,
                RuntimeError,
                ValueError,
            ) as error:
                row = {
                    "identity_key": case["identity_key"],
                    "case_id": case.get("new_unified_case_id"),
                    "repo_key": case["repository"]["repo_key"],
                    "repo_url": case["repository"]["repo_url"],
                    "checkout_revision": case["revisions"]["checkout_revision"],
                    "state": "failed",
                    "error": f"{type(error).__name__}: {error}",
                    "candidate_count": 0,
                    "known_anchor_count": len(case.get("recall_anchors") or []),
                    "best_known_anchor_rank": None,
                    "top_anchors": [],
                }
            results.append(row)
            with recall_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
            chosen = selected_anchor_row(row, args.audit_anchor_rank)
            if chosen is not None:
                selected.append(chosen)
                with selected_path.open("a", encoding="utf-8") as handle:
                    handle.write(json.dumps(chosen, ensure_ascii=False, sort_keys=True) + "\n")
            print(json.dumps({"identity_key": row["identity_key"], "state": row["state"], "best_known_anchor_rank": row.get("best_known_anchor_rank"), "candidate_count": row.get("candidate_count")}, ensure_ascii=False, sort_keys=True), flush=True)

    order = {case["identity_key"]: index for index, case in enumerate(cases)}
    results.sort(key=lambda row: order.get(row["identity_key"], 10**9))
    selected.sort(key=lambda row: order.get(row["identity_key"], 10**9))
    write_jsonl(recall_path, results)
    write_jsonl(selected_path, selected)
    budgets = sorted({1, 3, 5, 10, 20, 30, 50, 100, args.top_k})
    summary = {
        "schema_version": "hcvr_guideline_anchor_recall_run.v1",
        "scope": "mechanical source slicing -> guideline embedding recall; known anchors used only for evaluation",
        "qa": str(args.qa.resolve()),
        "cases_file": str(args.cases_file.resolve()) if args.cases_file else None,
        "limit": args.limit,
        "skip": args.skip,
        "selection": args.selection,
        "top_k": args.top_k,
        "audit_anchor_rank": args.audit_anchor_rank,
        "embedding_backend": args.embedding_backend,
        "embedding_model": embedder.model_id,
        "embedding_base_url": args.embedding_base_url if args.embedding_backend == "openai" else None,
        "case_workers": args.case_workers,
        "embedding_batch_size": args.embedding_batch_size,
        "window_lines": args.window_lines,
        "stride_lines": args.stride_lines,
        "elapsed_seconds": round(time.time() - started, 3),
        "metrics": summarize(results, budgets),
        "artifacts": {
            "recall_results": str(recall_path),
            "selected_cases": str(selected_path),
        },
    }
    write_json(output / "summary.json", summary)
    (output / "README.md").write_text(
        "# Guideline Anchor Recall Run\n\n"
        "This run mechanically sliced source snapshots, embedded the guideline and candidate anchors, "
        "ranked anchors by embedding similarity, and used dataset anchors only to compute known-anchor hit metrics.\n\n"
        f"- Cases: {summary['metrics']['case_count']}\n"
        f"- Completed: {summary['metrics']['completed_count']}\n"
        f"- Hit@{args.top_k}: {summary['metrics'].get(f'known_anchor_hit_at_{args.top_k}', 0.0):.4f}\n"
        f"- Selected audit anchor rank: {args.audit_anchor_rank}\n",
        encoding="utf-8",
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True), flush=True)
    if summary["metrics"]["failed_count"]:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
