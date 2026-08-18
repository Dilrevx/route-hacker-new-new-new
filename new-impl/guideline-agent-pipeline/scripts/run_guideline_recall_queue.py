#!/usr/bin/env python3
"""Run guideline anchor recall as an isolated per-case queue.

This wrapper avoids a common failure mode of shell-level fan-out:
one slow or hung multi-case recall process leaves the outer shell in WAIT with
little visibility. Each case is executed in its own subprocess, repositories are
not materialized concurrently, and a wall timeout can fail one case without
blocking the whole queue indefinitely.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import signal
import subprocess
import sys
import threading
import time
from collections import deque
from pathlib import Path
from typing import Any

from recall_guideline_anchors import summarize, write_json
from run_hcvr_case_anchor_audits import load_selected_cases, safe_slug, write_jsonl


SCRIPT_DIR = Path(__file__).resolve().parent


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                rows.append(json.loads(line))
    return rows


class EventLogger:
    def __init__(self, path: Path) -> None:
        self._path = path
        self._lock = threading.Lock()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text("", encoding="utf-8")

    def emit(self, event: dict[str, Any]) -> None:
        event = {"ts": round(time.time(), 3), **event}
        line = json.dumps(event, ensure_ascii=False, sort_keys=True)
        with self._lock:
            with self._path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")
        print(line, flush=True)


def failed_row(case: dict[str, Any], error: str, duration: float) -> dict[str, Any]:
    return {
        "identity_key": case["identity_key"],
        "case_id": case.get("new_unified_case_id"),
        "repo_key": case["repository"]["repo_key"],
        "repo_url": case["repository"]["repo_url"],
        "checkout_revision": case["revisions"]["checkout_revision"],
        "state": "failed",
        "error": error,
        "candidate_count": 0,
        "known_anchor_count": len(case.get("recall_anchors") or []),
        "best_known_anchor_rank": None,
        "duration_seconds": round(duration, 3),
        "top_anchors": [],
    }


def run_one_case(
    *,
    args: argparse.Namespace,
    forward_args: list[str],
    case: dict[str, Any],
    output_root: Path,
    event_logger: EventLogger,
) -> dict[str, Any]:
    identity_key = case["identity_key"]
    slug = safe_slug(identity_key)
    identity_file = output_root / "identity_files" / f"{slug}.jsonl"
    case_output = output_root / "cases" / slug
    log_path = output_root / "logs" / f"{slug}.log"
    identity_file.parent.mkdir(parents=True, exist_ok=True)
    case_output.parent.mkdir(parents=True, exist_ok=True)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    identity_file.write_text(json.dumps({"identity_key": identity_key}, ensure_ascii=False) + "\n", encoding="utf-8")

    if args.resume and (case_output / "summary.json").exists():
        rows = read_jsonl(case_output / "recall_results.jsonl")
        if rows:
            event_logger.emit({"event": "case_skip_completed", "identity_key": identity_key})
            return rows[0]

    if case_output.exists():
        raise FileExistsError(f"refusing existing case output: {case_output}")

    cmd = [
        args.python,
        str(args.recall_script),
        "--qa",
        str(args.qa),
        "--output-dir",
        str(case_output),
        "--repo-cache",
        str(args.repo_cache),
        "--snapshot-root",
        str(args.snapshot_root),
        "--identity-file",
        str(identity_file),
        "--selection",
        "all",
        "--limit",
        "1",
        "--case-workers",
        "1",
    ]
    if args.cases_file:
        cmd.extend(["--cases-file", str(args.cases_file)])
    cmd.extend(forward_args)

    started = time.time()
    event_logger.emit(
        {
            "event": "case_start",
            "identity_key": identity_key,
            "repo_key": case["repository"]["repo_key"],
            "log": str(log_path),
        }
    )
    with log_path.open("w", encoding="utf-8") as log_handle:
        log_handle.write("$ " + " ".join(cmd) + "\n")
        log_handle.flush()
        process = subprocess.Popen(
            cmd,
            stdout=log_handle,
            stderr=subprocess.STDOUT,
            text=True,
            start_new_session=True,
        )
        try:
            process.wait(timeout=args.case_timeout)
            duration = time.time() - started
        except subprocess.TimeoutExpired:
            duration = time.time() - started
            try:
                os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                process.wait(timeout=10)
            except Exception:
                try:
                    os.killpg(os.getpgid(process.pid), signal.SIGKILL)
                except Exception:
                    pass
                pass
            event_logger.emit(
                {
                    "event": "case_timeout",
                    "identity_key": identity_key,
                    "duration_seconds": round(duration, 3),
                    "timeout_seconds": args.case_timeout,
                }
            )
            return failed_row(case, f"TimeoutExpired: exceeded {args.case_timeout}s", duration)

    rows = read_jsonl(case_output / "recall_results.jsonl")
    if rows:
        row = rows[0]
    else:
        row = failed_row(case, f"subprocess exited {process.returncode} without recall_results.jsonl", duration)
    if process.returncode != 0 and row.get("state", "completed") == "completed":
        row["state"] = "failed"
        row["error"] = f"subprocess exited {process.returncode}"
    row.setdefault("duration_seconds", round(duration, 3))
    event_logger.emit(
        {
            "event": "case_done",
            "identity_key": identity_key,
            "state": row.get("state", "completed"),
            "returncode": process.returncode,
            "duration_seconds": round(duration, 3),
            "candidate_count": row.get("candidate_count"),
            "best_known_anchor_rank": row.get("best_known_anchor_rank"),
        }
    )
    return row


def parse_args() -> tuple[argparse.Namespace, list[str]]:
    parser = argparse.ArgumentParser(
        description="Queue per-case guideline recall subprocesses and aggregate their outputs.",
        allow_abbrev=False,
    )
    parser.add_argument("--qa", type=Path, required=True)
    parser.add_argument("--cases-file", type=Path)
    parser.add_argument("--identity-file", type=Path)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--repo-cache", type=Path, required=True)
    parser.add_argument("--snapshot-root", type=Path, required=True)
    parser.add_argument("--selection", choices=("added", "all"), default="all")
    parser.add_argument("--limit", type=int, default=30)
    parser.add_argument("--skip", type=int, default=0)
    parser.add_argument("--concurrency", type=int, default=4)
    parser.add_argument("--case-timeout", type=int, default=1800)
    parser.add_argument("--heartbeat-interval", type=int, default=30)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--recall-script", type=Path, default=SCRIPT_DIR / "recall_guideline_anchors.py")
    args, forward_args = parser.parse_known_args()
    if args.limit < 1 or args.concurrency < 1 or args.case_timeout < 1 or args.heartbeat_interval < 1:
        raise SystemExit("limit, concurrency, case-timeout, and heartbeat-interval must be positive")
    return args, forward_args


def main() -> None:
    args, forward_args = parse_args()
    output = args.output_dir.resolve()
    if output.exists() and not args.resume:
        raise FileExistsError(f"refusing existing queue output: {output}")
    output.mkdir(parents=True, exist_ok=True)
    args.qa = args.qa.resolve()
    args.cases_file = args.cases_file.resolve() if args.cases_file else None
    args.identity_file = args.identity_file.resolve() if args.identity_file else None
    args.repo_cache = args.repo_cache.resolve()
    args.snapshot_root = args.snapshot_root.resolve()
    args.recall_script = args.recall_script.resolve()
    args.repo_cache.mkdir(parents=True, exist_ok=True)
    args.snapshot_root.mkdir(parents=True, exist_ok=True)

    cases = load_selected_cases(
        args.qa,
        args.limit,
        args.skip,
        args.selection,
        args.cases_file,
        args.identity_file,
        None,
    )
    event_logger = EventLogger(output / "events.jsonl")
    started = time.time()

    pending = deque(cases)
    running: dict[concurrent.futures.Future[dict[str, Any]], dict[str, Any]] = {}
    active_repos: set[str] = set()
    results_by_identity: dict[str, dict[str, Any]] = {}
    last_heartbeat = 0.0

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        while pending or running:
            launched = True
            while launched and len(running) < args.concurrency and pending:
                launched = False
                for _ in range(len(pending)):
                    case = pending.popleft()
                    repo_key = str(case["repository"]["repo_key"])
                    if repo_key in active_repos:
                        pending.append(case)
                        continue
                    active_repos.add(repo_key)
                    future = pool.submit(
                        run_one_case,
                        args=args,
                        forward_args=forward_args,
                        case=case,
                        output_root=output,
                        event_logger=event_logger,
                    )
                    running[future] = case
                    launched = True
                    break
                if not launched and len(running) == 0:
                    raise RuntimeError("scheduler deadlock: pending cases exist but no repository can run")
            if not running:
                continue
            done, _ = concurrent.futures.wait(running, timeout=5, return_when=concurrent.futures.FIRST_COMPLETED)
            if not done:
                now = time.time()
                if now - last_heartbeat >= args.heartbeat_interval:
                    last_heartbeat = now
                    event_logger.emit(
                        {
                            "event": "queue_wait",
                            "running": len(running),
                            "pending": len(pending),
                            "active_repos": sorted(active_repos),
                        }
                    )
                continue
            for future in done:
                case = running.pop(future)
                active_repos.discard(str(case["repository"]["repo_key"]))
                try:
                    row = future.result()
                except Exception as error:
                    row = failed_row(case, f"{type(error).__name__}: {error}", 0.0)
                    event_logger.emit(
                        {
                            "event": "case_exception",
                            "identity_key": case["identity_key"],
                            "error": row["error"],
                        }
                    )
                results_by_identity[case["identity_key"]] = row

    ordered_results = [results_by_identity.get(case["identity_key"], failed_row(case, "missing result", 0.0)) for case in cases]
    selected: list[dict[str, Any]] = []
    for case in cases:
        slug = safe_slug(case["identity_key"])
        selected.extend(read_jsonl(output / "cases" / slug / "selected_cases.jsonl"))
    recall_path = output / "recall_results.jsonl"
    selected_path = output / "selected_cases.jsonl"
    write_jsonl(recall_path, ordered_results)
    write_jsonl(selected_path, selected)
    budgets = sorted({1, 3, 5, 10, 20, 30, 50, 100, 200})
    summary = {
        "schema_version": "hcvr_guideline_anchor_recall_queue.v1",
        "scope": "per-case isolated mechanical source slicing -> guideline embedding recall",
        "qa": str(args.qa),
        "cases_file": str(args.cases_file) if args.cases_file else None,
        "limit": args.limit,
        "skip": args.skip,
        "selection": args.selection,
        "concurrency": args.concurrency,
        "case_timeout": args.case_timeout,
        "forward_args": forward_args,
        "elapsed_seconds": round(time.time() - started, 3),
        "metrics": summarize(ordered_results, budgets),
        "artifacts": {
            "events": str(output / "events.jsonl"),
            "recall_results": str(recall_path),
            "selected_cases": str(selected_path),
            "case_outputs": str(output / "cases"),
        },
    }
    write_json(output / "summary.json", summary)
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True), flush=True)
    if summary["metrics"]["failed_count"]:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
