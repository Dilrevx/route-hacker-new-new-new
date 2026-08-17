#!/usr/bin/env python3
"""Prepare and compare an immutable runtime-v2 review run."""

from __future__ import annotations

import argparse
import json
import sqlite3
from collections import Counter
from pathlib import Path
from typing import Any

from route_hacker.runtime_v2.queue import QueueStore


def read_rows(database: Path, query: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
    connection = sqlite3.connect(f"file:{database.resolve()}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        return [dict(row) for row in connection.execute(query, params).fetchall()]
    finally:
        connection.close()


def final_reason(final_path: str | None) -> dict[str, Any] | None:
    if not final_path:
        return None
    try:
        value = json.loads(Path(final_path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    reason = value.get("reason")
    return reason if isinstance(reason, dict) else None


def prepare_review(
    *,
    source_run: Path,
    review_run: Path,
    task_ids: set[str] | None,
    limit: int | None,
) -> dict[str, Any]:
    if review_run.exists() and any(review_run.iterdir()):
        raise ValueError(f"review run must be empty or absent: {review_run}")
    source_database = source_run / "queue.db"
    tasks = read_rows(
        source_database,
        """
        SELECT task_id, prompt, project_key, priority, status, attempt_index, final_json
        FROM tasks
        ORDER BY priority DESC, created_at, task_id
        """,
    )
    if task_ids is not None:
        tasks = [task for task in tasks if str(task["task_id"]) in task_ids]
    if limit is not None:
        tasks = tasks[:limit]
    if not tasks:
        raise ValueError("no source tasks selected")

    review_run.mkdir(parents=True, exist_ok=True)
    queue = QueueStore(review_run / "queue.db")
    manifest_rows = []
    for task in tasks:
        task_id = str(task["task_id"])
        old_task_dir = source_run / "tasks" / task_id
        reason = final_reason(task.get("final_json"))
        review_context = [
            "",
            "Previous runtime-v2 review context:",
            f"- Source run: {source_run}",
            f"- Source task directory: {old_task_dir}",
            f"- Previous terminal status: {task['status']}",
            f"- Previous final.json: {task.get('final_json')}",
            f"- Previous reason: {json.dumps(reason, ensure_ascii=False)}",
            "- The source run and source task directory are immutable review evidence.",
            "  Read and copy from them when useful, but never modify or delete their contents.",
            "Inspect and reuse valid source, images, compose files, scripts, logs, and",
            "diagnostic evidence from the previous task directory when useful. The new",
            "submission, mechanical verification, and AI audit must still pass independently.",
        ]
        queue.submit(
            task_id=task_id,
            prompt=str(task["prompt"]).rstrip() + "\n" + "\n".join(review_context),
            project_key=task.get("project_key"),
            priority=int(task.get("priority", 0)),
        )
        manifest_rows.append(
            {
                "task_id": task_id,
                "source_status": task["status"],
                "source_attempt_index": task["attempt_index"],
                "source_final_json": task.get("final_json"),
                "source_task_dir": str(old_task_dir),
                "source_reason": reason,
            }
        )

    manifest = {
        "schema": "runtime-v2-review-source.v1",
        "source_run": str(source_run.resolve()),
        "review_run": str(review_run.resolve()),
        "task_count": len(manifest_rows),
        "tasks": manifest_rows,
    }
    (review_run / "review-source-manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return manifest


def review_report(*, review_run: Path) -> dict[str, Any]:
    manifest = json.loads(
        (review_run / "review-source-manifest.json").read_text(encoding="utf-8")
    )
    review_rows = {
        str(row["task_id"]): row
        for row in read_rows(
            review_run / "queue.db",
            "SELECT task_id, status, final_json FROM tasks ORDER BY task_id",
        )
    }
    transitions: Counter[str] = Counter()
    reason_stages: Counter[str] = Counter()
    reason_codes: Counter[str] = Counter()
    rows = []
    for source in manifest["tasks"]:
        task_id = str(source["task_id"])
        review = review_rows.get(task_id, {})
        new_status = str(review.get("status") or "missing")
        transition = f"{source['source_status']} -> {new_status}"
        transitions[transition] += 1
        reason = final_reason(review.get("final_json"))
        if reason:
            reason_stages[str(reason.get("stage") or "unknown")] += 1
            reason_codes[str(reason.get("code") or "unknown")] += 1
        rows.append(
            {
                "task_id": task_id,
                "source_status": source["source_status"],
                "review_status": new_status,
                "transition": transition,
                "source_reason": source.get("source_reason"),
                "review_reason": reason,
                "review_final_json": review.get("final_json"),
            }
        )
    terminal = sum(
        count
        for transition, count in transitions.items()
        if transition.endswith("runtime_ready") or transition.endswith("failed")
    )
    report = {
        "schema": "runtime-v2-review-report.v1",
        "source_run": manifest["source_run"],
        "review_run": str(review_run.resolve()),
        "task_count": len(rows),
        "terminal_count": terminal,
        "transitions": dict(sorted(transitions.items())),
        "failure_reason_stages": dict(sorted(reason_stages.items())),
        "failure_reason_codes": dict(sorted(reason_codes.items())),
        "tasks": rows,
    }
    (review_run / "review-report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    markdown = [
        "# Runtime-v2 Review Report",
        "",
        f"- Source run: `{report['source_run']}`",
        f"- Review run: `{report['review_run']}`",
        f"- Terminal: {terminal}/{len(rows)}",
        "",
        "## Status transitions",
        "",
        "| Transition | Count |",
        "| --- | ---: |",
        *(f"| {transition} | {count} |" for transition, count in sorted(transitions.items())),
        "",
        "## Failure reason codes",
        "",
        "| Code | Count |",
        "| --- | ---: |",
        *(f"| {code} | {count} |" for code, count in sorted(reason_codes.items())),
        "",
    ]
    (review_run / "review-report.md").write_text("\n".join(markdown), encoding="utf-8")
    return report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    prepare = subparsers.add_parser("prepare")
    prepare.add_argument("--source-run", type=Path, required=True)
    prepare.add_argument("--review-run", type=Path, required=True)
    prepare.add_argument("--task-id", action="append")
    prepare.add_argument("--limit", type=int)
    report = subparsers.add_parser("report")
    report.add_argument("--review-run", type=Path, required=True)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.command == "prepare":
        value = prepare_review(
            source_run=args.source_run,
            review_run=args.review_run,
            task_ids=set(args.task_id) if args.task_id else None,
            limit=args.limit,
        )
    else:
        value = review_report(review_run=args.review_run)
    print(json.dumps(value, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
