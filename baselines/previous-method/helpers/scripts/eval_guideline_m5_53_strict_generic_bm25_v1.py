#!/usr/bin/env python3
"""Evaluate BM25 on strict generic target bindings from M5.52."""

from __future__ import annotations

import argparse
import json
import math
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "1.0"
TOKEN_RE = re.compile(r"[A-Za-z0-9_]+")

FALLBACK_TRACK_QUERIES = {
    "toctou_check_use_race": "Find code that checks a mutable resource or state and later uses or updates the same or derived object without preserving identity, atomicity, or sufficient synchronization.",
    "authorization_bypass": "Find sensitive operations that execute without a correct authorization decision for the current principal and requested object, including missing object-level checks, wrong-principal checks, and permissions that are not propagated to the effect.",
    "authentication_session_token_validation": "Find authentication, session, or token-validation flows that accept an identity or credential without correctly validating its signature, binding, state, lifetime, nonce, issuer, audience, or invalidation requirements before the application trusts it.",
    "ssrf": "Find flows where an untrusted URL, host, or network locator can trigger a server-side request without robust destination validation, including parser differences, DNS/IP checks, redirects, and internal-network reachability.",
    "path_archive_traversal": "Find file or archive extraction paths where an untrusted path component can escape an intended base directory because canonicalization, normalization, containment, symlink, or archive-entry validation is incomplete.",
    "open_redirect": "Find redirect or navigation flows that use an untrusted destination without enforcing an appropriate origin, scheme, host, path, or allowlist policy after canonicalization.",
    "business_state_precondition": "Find state-changing business operations that proceed without validating the relevant ownership, balance, authorization, phase, uniqueness, or other precondition on the same logical resource.",
    "file_permission_temp_resource": "Find temporary-file, directory, or sensitive-resource creation and use that does not establish the intended ownership, access mode, creation boundary, or resource lifecycle protection.",
    "concurrent_object_lifecycle": "Find shared-object lifecycle operations where concurrent release, replacement, reference changes, or state mutation can invalidate an object another execution context still reads or uses without adequate synchronization or ownership transfer.",
    "template_expression_injection": "Find flows where untrusted content reaches a template, expression, macro, wiki-rendering, or evaluator context that can interpret it as code or privileged expression without the necessary isolation, escaping, or authorization boundary.",
    "cached_cve": "Find source-backed vulnerability review entries matching the case-specific security guideline.",
    "public_advisory": "Find source-backed vulnerability review entries matching the case-specific security guideline.",
    "selected_public_patch": "Find source-backed vulnerability review entries matching the case-specific security guideline.",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def tokenize(text: str) -> list[str]:
    return [token.lower() for token in TOKEN_RE.findall(text or "")]


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


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def load_track_queries(path: Path | None) -> dict[str, str]:
    queries = dict(FALLBACK_TRACK_QUERIES)
    if path is None or not path.exists():
        return queries
    current_track: str | None = None
    collecting = False
    buffer: list[str] = []
    with path.open(encoding="utf-8") as handle:
        for raw in handle:
            line = raw.rstrip("\n")
            stripped = line.strip()
            if stripped.startswith("- track_id:") or stripped.startswith("track_id:"):
                if current_track and buffer:
                    queries[current_track] = " ".join(part.strip() for part in buffer if part.strip())
                current_track = stripped.split(":", 1)[1].strip().strip('"')
                collecting = False
                buffer = []
                continue
            if current_track and stripped.startswith("guideline_text:"):
                collecting = True
                after = stripped.split(":", 1)[1].strip()
                if after and after not in {">-", ">", "|-", "|"}:
                    buffer.append(after.strip('"'))
                continue
            if collecting:
                if stripped and not stripped.startswith(("priority:", "guideline_ids:", "retrieval_intent:", "in_scope:", "out_of_scope:", "minimum_review_entry:", "sub_guidelines:", "- track_id:")):
                    buffer.append(stripped.strip('"'))
                else:
                    if current_track and buffer:
                        queries[current_track] = " ".join(part.strip() for part in buffer if part.strip())
                    collecting = False
                    buffer = []
                    if stripped.startswith("- track_id:"):
                        current_track = stripped.split(":", 1)[1].strip().strip('"')
    if current_track and buffer:
        queries[current_track] = " ".join(part.strip() for part in buffer if part.strip())
    return queries


def percentile(values: list[float], pct: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    pos = (len(ordered) - 1) * pct
    lo = math.floor(pos)
    hi = math.ceil(pos)
    if lo == hi:
        return ordered[lo]
    frac = pos - lo
    return ordered[lo] * (1 - frac) + ordered[hi] * frac


def bm25_scores(query_tokens: list[str], docs: list[dict[str, Any]], k1: float = 1.5, b: float = 0.75) -> list[tuple[float, dict[str, Any]]]:
    tokenized = [tokenize(str(doc.get("text") or "")) for doc in docs]
    lengths = [len(tokens) for tokens in tokenized]
    avgdl = sum(lengths) / len(lengths) if lengths else 0.0
    df: Counter[str] = Counter()
    for tokens in tokenized:
        df.update(set(tokens))
    n_docs = len(docs)
    query_counts = Counter(query_tokens)
    scores: list[tuple[float, dict[str, Any]]] = []
    for doc, tokens, doc_len in zip(docs, tokenized, lengths):
        tf = Counter(tokens)
        score = 0.0
        for token, qtf in query_counts.items():
            freq = tf.get(token, 0)
            if freq == 0:
                continue
            idf = math.log(1.0 + (n_docs - df[token] + 0.5) / (df[token] + 0.5))
            denom = freq + k1 * (1.0 - b + b * (doc_len / avgdl if avgdl else 0.0))
            score += qtf * idf * ((freq * (k1 + 1.0)) / denom)
        scores.append((score, doc))
    scores.sort(key=lambda item: (item[0], str(item[1].get("candidate_id") or "")), reverse=True)
    return scores


def build_case_targets(bindings: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    cases: dict[str, dict[str, Any]] = {}
    for row in bindings:
        for case_id in row.get("positive_case_ids") or []:
            case = cases.setdefault(
                case_id,
                {
                    "case_id": case_id,
                    "track_id": row.get("track_id"),
                    "repo_key": row.get("repo_key"),
                    "positive_candidate_ids": set(),
                    "source_target_count": 0,
                },
            )
            case["source_target_count"] += 1
            case["positive_candidate_ids"].update(row.get("generic_positive_candidate_ids") or [])
    return cases


def evaluate(binding_dir: Path, generic_pool: Path, track_queries_path: Path | None) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    binding_summary = read_json(binding_dir / "summary.json")
    bindings = read_jsonl(binding_dir / "generic_target_bindings.jsonl")
    cases = build_case_targets(bindings)
    repos_needed = {case["repo_key"] for case in cases.values()}
    candidates_by_repo: dict[str, list[dict[str, Any]]] = defaultdict(list)
    rows_scanned = 0
    with generic_pool.open(encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            rows_scanned += 1
            row = json.loads(line)
            repo_key = row.get("repo_key")
            if repo_key in repos_needed:
                candidates_by_repo[str(repo_key)].append(row)

    track_queries = load_track_queries(track_queries_path)
    k_values = [10, 30, 100, 200, 500]
    case_rows: list[dict[str, Any]] = []
    for case in cases.values():
        repo_key = str(case["repo_key"])
        docs = candidates_by_repo.get(repo_key, [])
        positive_ids = set(case["positive_candidate_ids"])
        query = track_queries.get(str(case["track_id"]) or "", FALLBACK_TRACK_QUERIES.get(str(case["track_id"]) or "", "Find security-relevant code matching the guideline."))
        ranked = bm25_scores(tokenize(query), docs)
        first_rank = None
        first_candidate_id = None
        for idx, (_score, doc) in enumerate(ranked, start=1):
            candidate_id = doc.get("candidate_id")
            if candidate_id in positive_ids:
                first_rank = idx
                first_candidate_id = candidate_id
                break
        row = {
            "case_id": case["case_id"],
            "track_id": case["track_id"],
            "repo_key": repo_key,
            "candidate_count": len(docs),
            "positive_candidate_count": len(positive_ids),
            "source_target_count": case["source_target_count"],
            "query": query,
            "first_positive_rank": first_rank,
            "first_positive_candidate_id": first_candidate_id,
            "mrr": 1.0 / first_rank if first_rank else 0.0,
        }
        for k in k_values:
            row[f"hit_at_{k}"] = bool(first_rank and first_rank <= k)
        case_rows.append(row)

    ranks = [row["first_positive_rank"] for row in case_rows if row["first_positive_rank"]]
    metrics = {
        "schema_version": SCHEMA_VERSION,
        "status": "completed",
        "created_at": utc_now(),
        "decision": "strict_generic_bm25_baseline_completed",
        "binding_decision": binding_summary.get("decision"),
        "binding_counts": binding_summary.get("counts"),
        "generic_pool": str(generic_pool),
        "rows_scanned": rows_scanned,
        "counts": {
            "eval_cases": len(case_rows),
            "repos": len(repos_needed),
            "cases_with_hit": len(ranks),
            "cases_without_hit": len(case_rows) - len(ranks),
            "candidate_rows_loaded": sum(len(v) for v in candidates_by_repo.values()),
        },
        "metrics": {
            **{f"B@{k}": sum(1 for row in case_rows if row[f"hit_at_{k}"]) / len(case_rows) if case_rows else None for k in k_values},
            "MRR": sum(row["mrr"] for row in case_rows) / len(case_rows) if case_rows else None,
            "first_rank_p50": percentile([float(v) for v in ranks], 0.50),
            "first_rank_p75": percentile([float(v) for v in ranks], 0.75),
            "first_rank_p90": percentile([float(v) for v in ranks], 0.90),
            "first_rank_p95": percentile([float(v) for v in ranks], 0.95),
            "first_rank_p99": percentile([float(v) for v in ranks], 0.99),
        },
        "track_metrics": {},
        "method_boundary": {
            "candidate_universe": "frozen v39 full-repository generic function/sliding_window pool",
            "target_binding": "M5.52 strict full-overlap generic target bindings",
            "uses_supplement_pool_for_ranking": False,
            "uses_bm25_keyword_baseline": True,
            "uses_embedding_or_training": False,
            "non_anchor_candidates_are_unknown_not_negative": True,
        },
    }
    by_track: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in case_rows:
        by_track[str(row["track_id"])].append(row)
    for track, rows in sorted(by_track.items()):
        metrics["track_metrics"][track] = {
            "case_count": len(rows),
            **{f"B@{k}": sum(1 for row in rows if row[f"hit_at_{k}"]) / len(rows) for k in k_values},
            "MRR": sum(row["mrr"] for row in rows) / len(rows),
        }
    return metrics, sorted(case_rows, key=lambda row: (str(row["track_id"]), str(row["case_id"])))


def render_markdown(summary: dict[str, Any]) -> str:
    lines = [
        "# Guideline Anchor Retrieval M5.53: Strict Generic BM25 Baseline",
        "",
        f"**Status:** {summary['status']}",
        f"**Decision:** `{summary['decision']}`",
        "",
        "## Purpose",
        "",
        "M5.53 runs a minimal BM25 baseline over the frozen v39 full-repository generic candidate pool using only M5.52 strict generic target bindings.",
        "It is a method sanity check after removing positive-only supplement-pool leakage.",
        "",
        "## Counts",
        "",
        "| Metric | Value |",
        "| --- | ---: |",
    ]
    for key, value in summary["counts"].items():
        lines.append(f"| {key} | {value} |")
    lines.extend(["", "## Metrics", "", "| Metric | Value |", "| --- | ---: |"])
    for key, value in summary["metrics"].items():
        rendered = "null" if value is None else f"{value:.6f}"
        lines.append(f"| {key} | {rendered} |")
    lines.extend(
        [
            "",
            "## Track Metrics",
            "",
            "```json",
            json.dumps(summary["track_metrics"], ensure_ascii=False, indent=2, sort_keys=True),
            "```",
            "",
            "## Method Boundary",
            "",
            "```json",
            json.dumps(summary["method_boundary"], ensure_ascii=False, indent=2, sort_keys=True),
            "```",
            "",
            "## Decision",
            "",
            "This is a keyword baseline over strict generic-pool bindings, not a learning-based method result. It is suitable as a leakage-clean baseline for the next embedding/reranker comparison.",
        ]
    )
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binding-dir", type=Path, default=Path("/tmp/m5_52_generic_target_binding_manifest_v1"))
    parser.add_argument("--generic-pool", type=Path, default=Path("/data/lhq/workspace/route-hacker/output/phase1_guideline_retrieval/multitrack_merged_source_ready_v39/candidate_pool_v3/candidate_pool.jsonl"))
    parser.add_argument("--track-queries", type=Path, default=Path("/data/lhq/workspace/route-hacker/assets/guideline_tracks_v1.yaml"))
    parser.add_argument("--output-dir", type=Path, default=Path("/tmp/m5_53_strict_generic_bm25_v1"))
    args = parser.parse_args()

    summary, rows = evaluate(args.binding_dir, args.generic_pool, args.track_queries)
    write_json(args.output_dir / "summary.json", summary)
    write_jsonl(args.output_dir / "case_ranks.jsonl", rows)
    (args.output_dir / "strict_generic_bm25_baseline.md").write_text(render_markdown(summary), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
