#!/usr/bin/env python3
"""Build a full-repository generic P4 candidate pool without anchor routing.

The candidate universe is constructed before any source-anchor mapping:

1. enumerate generic indexable files in deterministic repository/path order;
2. emit generic ``function`` and ``sliding_window`` views for every file;
3. only after enumeration, join source-derived anchors to mark evaluation
   overlap and coverage.

Anchors never affect file admission, enumeration order, view extraction,
candidate identity, candidate text, or candidate count.  They remain offline
evaluation mappings only.  This script creates no embedding, score, rank,
model fit, or retrieval result.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import yaml


SCHEMA_VERSION = "p4_external_generic_candidate_pool_v1"
INDEXABLE_FILE_POLICY_V3 = {
    "policy_id": "indexable_file_policy_v3",
    "description": (
        "Generic engineering boundary for source-like repository indexing. "
        "It includes source-like function and sliding-window suffixes and "
        "excludes dependency/build/cache directories and file-size outliers; "
        "it does not filter by guideline, API, source-point, trace, patch, "
        "anchor, or vulnerability keywords."
    ),
    "function_views": {
        "languages": ["java", "c", "cpp"],
        "suffixes": [
            ".java",
            ".c",
            ".cc",
            ".cpp",
            ".cxx",
            ".h",
            ".hh",
            ".hpp",
            ".hxx",
        ],
    },
    "sliding_window_views": {
        "suffixes": [
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
            ".in",
            ".init",
            ".sh",
            ".bash",
            ".php",
            ".py",
            ".pl",
            ".rb",
            ".txt",
            ".result",
            ".conf",
            ".cfg",
        ],
    },
    "excluded_directories": [
        ".git",
        ".gradle",
        ".idea",
        ".mvn",
        "build",
        "target",
        "out",
        "node_modules",
        "vendor",
    ],
}


def now_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


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


def normalize_text(value: Any) -> str:
    return str(value or "").strip()


def load_helper(path: Path) -> Any:
    if not path.is_file():
        raise FileNotFoundError(f"generic view helper is unavailable: {path}")
    spec = importlib.util.spec_from_file_location("p4_generic_view_helper", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load generic view helper: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def load_track_contract(path: Path) -> dict[str, str]:
    payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    tracks = payload.get("tracks") if isinstance(payload, dict) else None
    if not isinstance(tracks, list):
        raise ValueError(f"track contract has no tracks list: {path}")
    texts: dict[str, str] = {}
    for entry in tracks:
        if not isinstance(entry, dict):
            continue
        track_id = normalize_text(entry.get("track_id"))
        text = normalize_text(entry.get("guideline_text"))
        if not track_id or not text:
            raise ValueError(f"track contract has incomplete track: {entry}")
        if track_id in texts:
            raise ValueError(f"track contract duplicates track: {track_id}")
        texts[track_id] = text
    if not texts:
        raise ValueError(f"track contract contains no usable text: {path}")
    return texts


def source_overlap(
    *,
    helper: Any,
    candidate: dict[str, Any],
    case: dict[str, Any],
) -> bool:
    for anchor in case.get("positive_anchors") or []:
        anchor_file = normalize_text(anchor.get("file"))
        if anchor_file and not helper.anchor_file_matches(
            normalize_text(candidate.get("file")), anchor_file
        ):
            continue
        anchor_function = normalize_text(anchor.get("function"))
        if (
            normalize_text(candidate.get("view_type")) == "function"
            and anchor_function
            and helper.method_leaf(anchor_function)
            != helper.method_leaf(normalize_text(candidate.get("symbol")))
        ):
            continue
        if not helper.line_ranges_overlap(
            int(candidate.get("start_line") or 0),
            int(candidate.get("end_line") or 0),
            int(anchor.get("start_line") or 0),
            int(anchor.get("end_line") or 0),
        ):
            continue
        return True
    return False


def build_candidate(
    *,
    helper: Any,
    repo_key: str,
    repo_path: Path,
    source_path: Path,
    view: Any,
    view_index: int,
) -> dict[str, Any]:
    rel_file = helper.norm_path(str(source_path.relative_to(repo_path)))
    view.rel_file = rel_file
    view_type = (
        "sliding_window" if normalize_text(view.view_type) == "window" else view.view_type
    )
    candidate_id = "p4-generic::{}::{}::{}::{}".format(
        repo_key,
        view_type,
        helper.stable_id(rel_file, view_type, str(view.start_line), view.symbol),
        view_index,
    )
    text = helper.candidate_text(repo_key, view)
    if view_type == "sliding_window":
        text = text.replace("VIEW=window\n", "VIEW=sliding_window\n", 1)
    return {
        "candidate_id": candidate_id,
        "repo_key": repo_key,
        "repo_path": str(repo_path),
        "view_type": view_type,
        "file": rel_file,
        "symbol": view.symbol,
        "start_line": view.start_line,
        "end_line": view.end_line,
        "text": text,
        "text_symbol_masked": helper.mask_symbols(text),
        "text_api_shape_masked": helper.mask_api_shape(text),
        "is_positive": False,
        "positive_case_ids": [],
        "positive_cve_ids": [],
        "positive_source_advisory_ids": [],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cases", type=Path, required=True)
    parser.add_argument("--generic-view-helper", type=Path, required=True)
    parser.add_argument("--track-contract", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--max-file-bytes", type=int, default=512_000)
    parser.add_argument("--window-lines", type=int, default=80)
    parser.add_argument("--stride-lines", type=int, default=40)
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    paths = {
        "external_cases": args.cases.resolve(),
        "generic_view_helper": args.generic_view_helper.resolve(),
        "track_contract": args.track_contract.resolve(),
    }
    missing = [str(path) for path in paths.values() if not path.is_file()]
    if missing:
        raise FileNotFoundError(f"missing external generic-pool input(s): {missing}")
    output_dir = args.output_dir.resolve()
    if output_dir.exists():
        raise FileExistsError(f"refusing to overwrite P4 generic pool: {output_dir}")
    if args.max_file_bytes <= 0 or args.window_lines <= 0 or args.stride_lines <= 0:
        raise ValueError("file and window limits must be positive")

    helper = load_helper(paths["generic_view_helper"])
    track_texts = load_track_contract(paths["track_contract"])
    cases = read_jsonl(paths["external_cases"])
    if not cases:
        raise ValueError("external case manifest is empty")
    repo_keys = [normalize_text(case.get("repo_key")) for case in cases]
    if len(set(repo_keys)) != len(repo_keys):
        raise ValueError("external case manifest must contain one case per repo_key")

    output_dir.mkdir(parents=True, exist_ok=False)
    all_candidates: list[dict[str, Any]] = []
    repo_generation_rows: list[dict[str, Any]] = []
    candidates_by_repo: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
    view_counts: Counter[str] = Counter()

    for case in sorted(cases, key=lambda row: normalize_text(row.get("repo_key"))):
        case_id = normalize_text(case.get("case_id"))
        repo_key = normalize_text(case.get("repo_key"))
        repo_path = Path(normalize_text(case.get("repo_path"))).resolve()
        if not case_id or not repo_key or not repo_path.is_dir():
            raise ValueError(f"case has unusable external repository snapshot: {case_id}")
        source_files = list(
            helper.iter_source_files(repo_path, max_file_bytes=args.max_file_bytes)
        )
        repo_candidates: list[dict[str, Any]] = []
        extraction_failures = 0
        for source_path in source_files:
            try:
                source_text = source_path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                extraction_failures += 1
                continue
            views = helper.extract_functions_for_path(source_path, source_text)
            views.extend(
                helper.sliding_windows(
                    source_text,
                    window_lines=args.window_lines,
                    stride_lines=args.stride_lines,
                )
            )
            for view_index, view in enumerate(views):
                if not normalize_text(view.text):
                    continue
                candidate = build_candidate(
                    helper=helper,
                    repo_key=repo_key,
                    repo_path=repo_path,
                    source_path=source_path,
                    view=view,
                    view_index=view_index,
                )
                repo_candidates.append(candidate)
                view_counts.update([normalize_text(candidate["view_type"])])
        all_candidates.extend(repo_candidates)
        candidates_by_repo[repo_key].extend(repo_candidates)
        repo_generation_rows.append(
            {
                "case_id": case_id,
                "repo_key": repo_key,
                "repo_path": str(repo_path),
                "indexable_file_count": len(source_files),
                "source_read_failures": extraction_failures,
                "candidate_count_before_anchor_join": len(repo_candidates),
                "generation_order": "repository_key_then_relative_path",
            }
        )
        if args.verbose:
            print(
                json.dumps(repo_generation_rows[-1], ensure_ascii=False, sort_keys=True),
                flush=True,
            )

    coverage_rows: list[dict[str, Any]] = []
    for case in sorted(cases, key=lambda row: normalize_text(row.get("case_id"))):
        case_id = normalize_text(case.get("case_id"))
        repo_key = normalize_text(case.get("repo_key"))
        positive_ids: list[str] = []
        positive_view_types: Counter[str] = Counter()
        for candidate in candidates_by_repo[repo_key]:
            if not source_overlap(helper=helper, candidate=candidate, case=case):
                continue
            candidate["is_positive"] = True
            candidate["positive_case_ids"].append(case_id)
            candidate["positive_cve_ids"].append(normalize_text(case.get("cve_id")))
            candidate["positive_source_advisory_ids"].append(
                normalize_text(case.get("source_advisory_id") or case.get("cve_id"))
            )
            positive_ids.append(normalize_text(candidate.get("candidate_id")))
            positive_view_types.update([normalize_text(candidate.get("view_type"))])
        coverage_rows.append(
            {
                "case_id": case_id,
                "cve_id": case.get("cve_id"),
                "repo_key": repo_key,
                "repo_present": True,
                "candidate_count": len(candidates_by_repo[repo_key]),
                "positive_candidate_count": len(positive_ids),
                "positive_candidate_ids": sorted(positive_ids),
                "positive_view_types": dict(sorted(positive_view_types.items())),
                "covered": bool(positive_ids),
                "anchor_role": "post_enumeration_evaluation_overlap_only",
            }
        )

    for candidate in all_candidates:
        candidate["positive_case_ids"] = sorted(set(candidate["positive_case_ids"]))
        candidate["positive_cve_ids"] = sorted(set(candidate["positive_cve_ids"]))
        candidate["positive_source_advisory_ids"] = sorted(
            set(candidate["positive_source_advisory_ids"])
        )
    if len({candidate["candidate_id"] for candidate in all_candidates}) != len(
        all_candidates
    ):
        raise ValueError("generic candidate identifier collision")
    uncovered = [row["case_id"] for row in coverage_rows if not row["covered"]]

    query_rows: list[dict[str, Any]] = []
    for case in sorted(cases, key=lambda row: normalize_text(row.get("case_id"))):
        track_id = normalize_text(case.get("track_id"))
        query_text = track_texts.get(track_id)
        if not query_text:
            raise ValueError(f"unregistered external case track: {track_id}")
        query_rows.append(
            {
                "query_id": f"query::{case['case_id']}",
                "case_id": case.get("case_id"),
                "cve_id": case.get("cve_id"),
                "repo_key": case.get("repo_key"),
                "track_id": track_id,
                "text": query_text,
                "text_symbol_masked": helper.mask_query_symbols(query_text),
                "text_api_shape_masked": helper.mask_query_symbols(query_text),
            }
        )

    write_jsonl(output_dir / "candidate_pool.v1.jsonl", all_candidates)
    write_jsonl(output_dir / "case_coverage.v1.jsonl", coverage_rows)
    write_jsonl(output_dir / "queries.v1.jsonl", query_rows)
    write_jsonl(output_dir / "repo_generation_ledger.v1.jsonl", repo_generation_rows)
    summary = {
        "schema_version": SCHEMA_VERSION,
        "status": "completed_no_embedding_or_retrieval",
        "created_at": now_utc(),
        "inputs": {
            key: {"path": str(path), "sha256": sha256_file(path)}
            for key, path in paths.items()
        },
        "indexable_file_policy": INDEXABLE_FILE_POLICY_V3,
        "generation_config": {
            "max_file_bytes": args.max_file_bytes,
            "window_lines": args.window_lines,
            "stride_lines": args.stride_lines,
            "candidate_generation_order": (
                "repository_key_then_relative_path; no anchor, patch, trace, "
                "source-point, API, or guideline-dependent prioritization"
            ),
            "anchor_join_order": "after_full_repository_candidate_enumeration",
        },
        "summary": {
            "case_count": len(cases),
            "repo_count": len(candidates_by_repo),
            "candidate_count": len(all_candidates),
            "candidate_view_types": dict(sorted(view_counts.items())),
            "positive_candidate_count": sum(
                1 for candidate in all_candidates if candidate["is_positive"]
            ),
            "covered_case_count": sum(1 for row in coverage_rows if row["covered"]),
            "uncovered_case_ids": uncovered,
            "candidate_count_min": min(
                row["candidate_count"] for row in coverage_rows
            ),
            "candidate_count_max": max(
                row["candidate_count"] for row in coverage_rows
            ),
        },
        "boundary": (
            "The candidate universe is full-repository generic function and "
            "sliding_window views. Source anchors are joined only after candidate "
            "generation for offline evaluation coverage and never enter runtime "
            "query text or candidate admission. Non-anchor candidates remain "
            "unknown/unlabeled background, not safe or hard-negative truth."
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
