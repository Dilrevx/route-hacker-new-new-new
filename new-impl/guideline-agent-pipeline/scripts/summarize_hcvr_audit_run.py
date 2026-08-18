#!/usr/bin/env python3
"""Summarize HCVR TraeX audit run progress, decisions, timing, and token usage."""

from __future__ import annotations

import argparse
import json
import time
from collections import Counter
from pathlib import Path
from typing import Any, Iterable


USAGE_KEYS = (
    "input_tokens",
    "cache_creation_input_tokens",
    "cached_input_tokens",
    "output_tokens",
    "reasoning_output_tokens",
)


def read_jsonl(path: Path) -> Iterable[dict[str, Any]]:
    if not path.is_file():
        return
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                yield json.loads(line)


def collect_usage(paths: Iterable[Path]) -> tuple[int, Counter[str]]:
    usage: Counter[str] = Counter()
    turn_count = 0
    seen: set[Path] = set()
    for path in paths:
        if path in seen or not path.is_file():
            continue
        seen.add(path)
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if event.get("type") != "turn.completed":
                continue
            event_usage = event.get("usage")
            if not isinstance(event_usage, dict):
                continue
            turn_count += 1
            for key in USAGE_KEYS:
                value = event_usage.get(key)
                if isinstance(value, int):
                    usage[key] += value
    return turn_count, usage


def event_paths(row: dict[str, Any]) -> list[Path]:
    paths: list[Path] = []
    if row.get("events"):
        paths.append(Path(row["events"]))
    for attempt in row.get("attempts") or []:
        events = attempt.get("events")
        if events:
            paths.append(Path(events))
    return paths


def enrich_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    enriched: list[dict[str, Any]] = []
    for row in rows:
        turn_count, usage = collect_usage(event_paths(row))
        item = dict(row)
        item["turn_completed_count"] = turn_count
        for key in USAGE_KEYS:
            item[key] = usage[key]
        item["billable_input_tokens_est"] = (
            item["input_tokens"] - item["cached_input_tokens"]
        )
        item["total_tokens_including_cached"] = (
            item["input_tokens"] + item["output_tokens"]
        )
        item["total_tokens_billable_est"] = (
            item["billable_input_tokens_est"] + item["output_tokens"]
        )
        enriched.append(item)
    return enriched


def sum_usage(rows: list[dict[str, Any]]) -> dict[str, int]:
    keys = (
        *USAGE_KEYS,
        "billable_input_tokens_est",
        "total_tokens_including_cached",
        "total_tokens_billable_est",
    )
    return {key: sum(row.get(key, 0) or 0 for row in rows) for key in keys}


def group(rows: list[dict[str, Any]], name: str) -> list[dict[str, Any]]:
    if name == "all":
        return rows
    if name == "completed":
        return [row for row in rows if row.get("state") == "completed"]
    if name == "timeout":
        return [row for row in rows if row.get("state") == "timeout"]
    if name == "risk":
        return [row for row in rows if row.get("decision") == "risk"]
    if name == "no-risk":
        return [row for row in rows if row.get("decision") == "no-risk"]
    raise ValueError(f"unsupported group: {name}")


def summarize(output: Path) -> dict[str, Any]:
    selected = list(read_jsonl(output / "selected_cases.jsonl"))
    rows = enrich_rows(list(read_jsonl(output / "audit_index.jsonl")))
    states = Counter(row.get("state") for row in rows)
    decisions = Counter(row.get("decision") for row in rows)
    mtimes = [
        path.stat().st_mtime
        for path in output.rglob("*")
        if path.exists()
    ]
    summary: dict[str, Any] = {
        "output_dir": str(output),
        "selected_count": len(selected),
        "audited_count": len(rows),
        "remaining_from_selected": max(0, len(selected) - len(rows)),
        "state_counts": dict(states),
        "decision_counts": {str(key): value for key, value in decisions.items()},
        "wall_elapsed_seconds": round(time.time() - output.stat().st_ctime, 3)
        if output.exists()
        else None,
        "artifact_mtime_span_seconds": round(max(mtimes) - min(mtimes), 3)
        if mtimes
        else None,
        "duration_seconds": {
            "all": round(sum(row.get("duration_seconds") or 0 for row in rows), 3),
            "completed": round(
                sum(
                    row.get("duration_seconds") or 0
                    for row in rows
                    if row.get("state") == "completed"
                ),
                3,
            ),
            "timeout": round(
                sum(
                    row.get("duration_seconds") or 0
                    for row in rows
                    if row.get("state") == "timeout"
                ),
                3,
            ),
        },
        "usage_by_group": {},
        "missing_usage_identities": [
            row["identity_key"]
            for row in rows
            if not row.get("turn_completed_count")
        ],
    }
    for name in ("all", "completed", "timeout", "risk", "no-risk"):
        group_rows = group(rows, name)
        summary["usage_by_group"][name] = {
            "count": len(group_rows),
            **sum_usage(group_rows),
        }
    return summary


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()
    summary = summarize(args.output_dir.resolve())
    if args.pretty:
        print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        print(json.dumps(summary, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
