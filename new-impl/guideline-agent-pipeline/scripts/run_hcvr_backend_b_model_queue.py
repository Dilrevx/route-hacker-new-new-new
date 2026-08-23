#!/usr/bin/env python3
"""Run Unified V2 backend-B model ablations with fixed Top-K grouped audits.

Backend-B varies only the bounded-audit model.  Recall, guideline prompts,
candidate budget, grouping, dataset, snapshots, and scorer must stay fixed.

Important terminology:

- ``top_k`` / ``anchor_budget`` is the number of recalled anchors consumed per
  case.
- ``m`` / ``anchor_group_size`` is the number of anchors in one audit group.

The current Backend-B probe setting is Top-160 with ``m=32``: each full case is
split into five grouped audit prompts.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Iterable


def read_jsonl(path: Path) -> Iterable[dict[str, Any]]:
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                yield json.loads(line)


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def append_jsonl(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(value, ensure_ascii=False, sort_keys=True) + "\n")
        handle.flush()


def selected_identities(allowlist: Path, start: int, end: int | None) -> list[str]:
    identities = [row["identity_key"] for row in read_jsonl(allowlist)]
    if start < 1:
        raise SystemExit("--case-start is 1-based and must be positive")
    stop = end if end is not None else len(identities)
    if stop < start:
        raise SystemExit("--case-end must be >= --case-start")
    return identities[start - 1 : stop]


def prepare_recall_projection(
    *,
    recall_results: Path,
    output_dir: Path,
    top_k: int,
    needed: set[str],
) -> Path:
    """Validate recall coverage and write a compact Top-K projection.

    A case can have fewer than ``top_k`` mechanical candidates when the source
    snapshot is small.  That is still a valid Top-K receipt: the audit consumes
    all available recalled anchors and records the short case in the manifest.
    """

    projection = output_dir / "input" / f"recall_results.top{top_k}.jsonl"
    manifest_path = output_dir / "input" / f"recall_results.top{top_k}.manifest.json"
    projection.parent.mkdir(parents=True, exist_ok=True)

    seen: set[str] = set()
    short: list[dict[str, Any]] = []
    empty: list[str] = []
    row_count = 0
    with recall_results.open(encoding="utf-8") as source, projection.open(
        "w",
        encoding="utf-8",
    ) as target:
        for line in source:
            if not line.strip():
                continue
            row_count += 1
            row = json.loads(line)
            identity = row.get("identity_key")
            anchors = list(row.get("top_anchors") or [])
            if identity in needed:
                if len(anchors) < top_k:
                    short.append(
                        {
                            "identity_key": identity,
                            "anchor_count": len(anchors),
                        }
                    )
                if not anchors:
                    empty.append(identity)
                seen.add(identity)
            compact = {
                key: row.get(key)
                for key in (
                    "identity_key",
                    "case_id",
                    "repo_key",
                    "repo_url",
                    "checkout_revision",
                    "hcvr_type",
                    "guideline",
                    "state",
                    "candidate_count",
                    "known_anchor_count",
                    "best_known_anchor_rank",
                    "hit_at_top_k",
                    "index",
                    "duration_seconds",
                    "snapshot",
                )
                if key in row
            }
            compact["top_anchors"] = anchors[:top_k]
            target.write(json.dumps(compact, ensure_ascii=False, sort_keys=True) + "\n")

    missing = sorted(needed - seen)
    if missing or empty:
        raise SystemExit(
            "recall input is not valid for backend-B Top-K run: "
            f"missing={missing[:10]} empty={empty[:10]}"
        )

    write_json(
        manifest_path,
        {
            "schema_version": "hcvr_backend_b_recall_projection.v1",
            "source_recall_results": str(recall_results.resolve()),
            "projection": str(projection.resolve()),
            "source_row_count": row_count,
            "top_k": top_k,
            "selected_case_count": len(needed),
            "short_case_count": len(short),
            "short_cases": short,
            "requirement": "Top-K is the per-case audit budget; m/group-size is separate. Cases with fewer available candidates consume all available anchors.",
        },
    )
    return projection


def case_completed(output_dir: Path) -> bool:
    result = output_dir / "full" / "case_results.jsonl"
    if not result.is_file():
        return False
    rows = [json.loads(line) for line in result.read_text(encoding="utf-8").splitlines() if line.strip()]
    return bool(rows and rows[-1].get("state") == "completed")


def main() -> None:
    repo_root = Path(__file__).resolve().parents[3]
    new_impl = repo_root / "new-impl"
    dataset_root = new_impl / "hcvr_new_unified_dataset_v2"
    parser = argparse.ArgumentParser()
    parser.add_argument("--recall-results", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--repo-cache", type=Path, required=True)
    parser.add_argument("--snapshot-root", type=Path, required=True)
    parser.add_argument("--temp-root", type=Path, required=True)
    parser.add_argument("--model", default="DeepSeek-V4-Flash")
    parser.add_argument("--model-reasoning-effort")
    parser.add_argument("--codex", default="traex")
    parser.add_argument("--codex-home", type=Path, default=Path.home() / ".trae")
    parser.add_argument("--case-start", type=int, default=1)
    parser.add_argument("--case-end", type=int)
    parser.add_argument("--top-k", type=int, default=160)
    parser.add_argument("--m", "--anchor-group-size", dest="group_size", type=int, default=32)
    parser.add_argument("--group-timeout", type=int, default=3600)
    parser.add_argument("--clone-timeout", type=int, default=600)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--qa", type=Path, default=dataset_root / "receipts/hcvr_new_unified_paper_eval_rebalance_qa.v2.json")
    parser.add_argument("--cases-file", type=Path, default=dataset_root / "dataset/new_unified_cases.v1.jsonl")
    parser.add_argument("--allowlist", type=Path, default=dataset_root / "receipts/hcvr_new_unified_fix_revision_paper_eval_review.v2.jsonl")
    parser.add_argument("--summary", type=Path, default=dataset_root / "dataset/summary.v1.json")
    args = parser.parse_args()

    if args.top_k < 1 or args.group_size < 1:
        raise SystemExit("--top-k and --m must be positive")
    if args.top_k < args.group_size:
        raise SystemExit("--top-k must be >= --m")

    args.output_dir = args.output_dir.resolve()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    args.repo_cache.mkdir(parents=True, exist_ok=True)
    args.snapshot_root.mkdir(parents=True, exist_ok=True)
    args.temp_root.mkdir(parents=True, exist_ok=True)

    identities = selected_identities(args.allowlist.resolve(), args.case_start, args.case_end)
    projection = prepare_recall_projection(
        recall_results=args.recall_results.resolve(),
        output_dir=args.output_dir,
        top_k=args.top_k,
        needed=set(identities),
    )
    write_json(
        args.output_dir / "backend_b_queue_config.json",
        {
            "schema_version": "hcvr_backend_b_model_queue.v1",
            "model": args.model,
            "model_reasoning_effort": args.model_reasoning_effort,
            "case_start": args.case_start,
            "case_end": args.case_end or (args.case_start + len(identities) - 1),
            "case_count": len(identities),
            "top_k": args.top_k,
            "m": args.group_size,
            "groups_per_full_case": (args.top_k + args.group_size - 1) // args.group_size,
            "recall_projection": str(projection.resolve()),
            "fixed_parts": [
                "Unified V2 fixed case allowlist",
                "same recall Top-K receipt",
                "same guideline prompts",
                "same anchor grouping budget",
                "same scorer",
            ],
        },
    )

    runner = new_impl / "guideline-agent-pipeline/scripts/run_hcvr_ablation_a.py"
    ledger = args.output_dir / "backend_b_queue_events.jsonl"
    for offset, identity in enumerate(identities, start=args.case_start):
        case_dir = args.output_dir / "per-case-runs" / f"case-{offset:03d}"
        if args.resume and case_completed(case_dir):
            append_jsonl(
                ledger,
                {
                    "event": "skip_completed",
                    "case_index": offset,
                    "identity_key": identity,
                    "output_dir": str(case_dir),
                    "time": time.time(),
                },
            )
            continue
        command = [
            sys.executable,
            str(runner),
            "--qa",
            str(args.qa.resolve()),
            "--cases-file",
            str(args.cases_file.resolve()),
            "--allowlist",
            str(args.allowlist.resolve()),
            "--summary",
            str(args.summary.resolve()),
            "--recall-results",
            str(projection),
            "--output-dir",
            str(case_dir),
            "--repo-cache",
            str(args.repo_cache.resolve()),
            "--snapshot-root",
            str(args.snapshot_root.resolve()),
            "--codex-home",
            str(args.codex_home.resolve()),
            "--temp-root",
            str((args.temp_root / f"case-{offset:03d}").resolve()),
            "--audit-runner",
            "codex",
            "--codex",
            args.codex,
            "--model",
            args.model,
            "--variants",
            "full",
            "--skip",
            str(offset - 1),
            "--limit",
            "1",
            "--anchor-budget",
            str(args.top_k),
            "--anchor-group-size",
            str(args.group_size),
            "--group-timeout",
            str(args.group_timeout),
            "--clone-timeout",
            str(args.clone_timeout),
            "--concurrency",
            "1",
            "--include-case-metadata",
        ]
        if args.model_reasoning_effort:
            command.extend(["--model-reasoning-effort", args.model_reasoning_effort])
        if args.allowlist.name != "hcvr_new_unified_fix_revision_paper_eval_review.v2.jsonl":
            command.append("--allow-subset-allowlist")
        if args.resume:
            command.extend(["--resume", "--retry-incomplete-groups"])
        append_jsonl(
            ledger,
            {
                "event": "start",
                "case_index": offset,
                "identity_key": identity,
                "output_dir": str(case_dir),
                "top_k": args.top_k,
                "m": args.group_size,
                "command": command,
                "time": time.time(),
            },
        )
        if args.dry_run:
            continue
        started = time.time()
        completed = subprocess.run(command, check=False)
        append_jsonl(
            ledger,
            {
                "event": "exit",
                "case_index": offset,
                "identity_key": identity,
                "output_dir": str(case_dir),
                "returncode": completed.returncode,
                "duration_seconds": round(time.time() - started, 3),
                "time": time.time(),
            },
        )


if __name__ == "__main__":
    main()
