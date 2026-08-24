#!/usr/bin/env python3
"""Run official CodeQL CWE-tagged queries for a prepared case manifest."""

from __future__ import annotations

import argparse
import json
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import Counter
from pathlib import Path
from typing import Any


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--query-index", required=True, type=Path)
    parser.add_argument("--out-dir", required=True, type=Path)
    parser.add_argument("--codeql", required=True, type=Path)
    parser.add_argument("--max-workers", type=int, default=2)
    parser.add_argument("--threads", type=int, default=2)
    parser.add_argument("--ram", type=int, default=12000)
    parser.add_argument("--timeout-seconds", type=int, default=1800)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--limit", type=int)
    parser.add_argument("--keep-going", action="store_true", default=True)
    parser.add_argument(
        "--no-auto-finalize",
        action="store_true",
        help="Do not run codeql database finalize when analyze reports an unfinalized database.",
    )
    return parser.parse_args()


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def safe_id(identity_key: str) -> str:
    return (
        identity_key.replace("::", "__")
        .replace("/", "_")
        .replace("\\", "_")
        .replace(":", "_")
    )


def queries_for_case(case: dict[str, Any], query_by_lang_cwe: dict[tuple[str, str], list[dict[str, Any]]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    selected: list[dict[str, Any]] = []
    language = case.get("codeql_language") or ""
    for cwe in case.get("cwe_ids") or []:
        for query in query_by_lang_cwe.get((language, cwe), []):
            key = query["query_path"]
            if key not in seen:
                seen.add(key)
                selected.append(query)
    return selected


def classify_failed_analysis(
    completed: subprocess.CompletedProcess[str],
    finalize_completed: subprocess.CompletedProcess[str] | None,
) -> str:
    stderr = (completed.stderr or "") + "\n" + (
        finalize_completed.stderr if finalize_completed is not None else ""
    )
    if (
        finalize_completed is not None
        and finalize_completed.returncode != 0
        and "could not process any of it using the 'none' build mode" in stderr
    ):
        return "db_unfinalized_unusable"
    if (
        finalize_completed is not None
        and finalize_completed.returncode != 0
        and "needs to be finalized" in stderr
    ):
        return "db_finalize_failed"
    return "failed"


def run_one(
    case: dict[str, Any],
    queries: list[dict[str, Any]],
    codeql: Path,
    out_dir: Path,
    threads: int,
    ram: int,
    timeout_seconds: int,
    resume: bool,
    auto_finalize: bool,
) -> dict[str, Any]:
    identity = case["identity_key"]
    case_id = safe_id(identity)
    case_dir = out_dir / "cases" / case_id
    case_dir.mkdir(parents=True, exist_ok=True)
    sarif_path = case_dir / "results.sarif"
    log_path = case_dir / "codeql.log"
    query_manifest_path = case_dir / "queries.jsonl"
    write_jsonl(query_manifest_path, queries)

    base = {
        "identity_key": identity,
        "case_id": case_id,
        "db_dir": case.get("db_dir", ""),
        "codeql_language": case.get("codeql_language", ""),
        "cwe_ids": case.get("cwe_ids", []),
        "query_count": len(queries),
        "sarif_path": str(sarif_path),
        "log_path": str(log_path),
        "query_manifest_path": str(query_manifest_path),
    }
    if not case.get("codeql_db_usable") or not case.get("db_dir"):
        return {**base, "status": "missing_db", "returncode": None, "elapsed_seconds": 0.0}
    if not case.get("cwe_ids"):
        return {**base, "status": "missing_cwe", "returncode": None, "elapsed_seconds": 0.0}
    if not queries:
        return {**base, "status": "no_official_cwe_query", "returncode": None, "elapsed_seconds": 0.0}
    if resume and sarif_path.exists():
        return {**base, "status": "skipped_existing", "returncode": 0, "elapsed_seconds": 0.0}

    cmd = [
        str(codeql),
        "database",
        "analyze",
        str(case["db_dir"]),
        *[query["query_path"] for query in queries],
        "--format=sarifv2.1.0",
        f"--output={sarif_path}",
        f"--threads={threads}",
        f"--ram={ram}",
        "--rerun",
    ]
    started = time.time()
    finalize_cmd = [
        str(codeql),
        "database",
        "finalize",
        str(case["db_dir"]),
        f"--threads={threads}",
        f"--ram={ram}",
    ]

    def run_analyze() -> subprocess.CompletedProcess[str]:
        return subprocess.run(cmd, text=True, capture_output=True, timeout=timeout_seconds)

    try:
        completed = run_analyze()
        finalize_completed: subprocess.CompletedProcess[str] | None = None
        if (
            completed.returncode != 0
            and auto_finalize
            and "needs to be finalized" in (completed.stderr or "")
        ):
            finalize_completed = subprocess.run(
                finalize_cmd,
                text=True,
                capture_output=True,
                timeout=timeout_seconds,
            )
            if finalize_completed.returncode == 0:
                completed = run_analyze()
        elapsed = time.time() - started
        log_text = (
            "COMMAND\n" + json.dumps(cmd, ensure_ascii=False) + "\n\nSTDOUT\n"
            + completed.stdout + "\n\nSTDERR\n" + completed.stderr
        )
        if finalize_completed is not None:
            log_text += (
                "\n\nAUTO_FINALIZE_COMMAND\n"
                + json.dumps(finalize_cmd, ensure_ascii=False)
                + "\n\nAUTO_FINALIZE_STDOUT\n"
                + finalize_completed.stdout
                + "\n\nAUTO_FINALIZE_STDERR\n"
                + finalize_completed.stderr
            )
        log_path.write_text(log_text, encoding="utf-8")
        status = (
            "succeeded"
            if completed.returncode == 0
            else classify_failed_analysis(completed, finalize_completed)
        )
        return {
            **base,
            "status": status,
            "returncode": completed.returncode,
            "finalize_attempted": finalize_completed is not None,
            "finalize_returncode": finalize_completed.returncode if finalize_completed is not None else "",
            "elapsed_seconds": round(elapsed, 3),
        }
    except subprocess.TimeoutExpired as exc:
        elapsed = time.time() - started
        log_path.write_text(
            "COMMAND\n" + json.dumps(cmd, ensure_ascii=False) + "\n\nTIMEOUT\n"
            + f"timeout_seconds={timeout_seconds}\n"
            + "\nSTDOUT\n" + (exc.stdout or "")
            + "\n\nSTDERR\n" + (exc.stderr or ""),
            encoding="utf-8",
        )
        return {
            **base,
            "status": "timeout",
            "returncode": None,
            "elapsed_seconds": round(elapsed, 3),
        }


def main() -> None:
    args = parse_args()
    if args.max_workers < 1:
        raise SystemExit("--max-workers must be >= 1")
    args.out_dir.mkdir(parents=True, exist_ok=True)
    query_rows = read_jsonl(args.query_index)
    query_by_lang_cwe: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for query in query_rows:
        for cwe in query.get("cwe_ids") or []:
            query_by_lang_cwe.setdefault((query["language"], cwe), []).append(query)

    cases = read_jsonl(args.manifest)
    if args.limit:
        cases = cases[: args.limit]
    planned = []
    for case in cases:
        planned.append((case, queries_for_case(case, query_by_lang_cwe)))

    ledger_path = args.out_dir / "run_ledger.jsonl"
    completed: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=args.max_workers) as executor:
        futures = [
            executor.submit(
                run_one,
                case,
                queries,
                args.codeql,
                args.out_dir,
                args.threads,
                args.ram,
                args.timeout_seconds,
                args.resume,
                not args.no_auto_finalize,
            )
            for case, queries in planned
        ]
        with ledger_path.open("a", encoding="utf-8") as ledger:
            for future in as_completed(futures):
                row = future.result()
                completed.append(row)
                ledger.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
                ledger.flush()
                print(json.dumps({k: row.get(k) for k in ["identity_key", "status", "query_count", "elapsed_seconds"]}, ensure_ascii=False))
                if row["status"] in {"failed", "timeout"} and not args.keep_going:
                    raise SystemExit(f"case failed: {row['identity_key']}")

    summary = {
        "case_count": len(planned),
        "status_counts": dict(Counter(row["status"] for row in completed)),
        "query_count_total": sum(row["query_count"] for row in completed),
        "alarm_inputs": str(args.manifest),
        "query_index": str(args.query_index),
        "codeql": str(args.codeql),
        "out_dir": str(args.out_dir),
    }
    (args.out_dir / "run_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
