#!/usr/bin/env python3
"""Compare two VulRAG evaluation summaries over the same ordered cases."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def model_label(summary: dict[str, Any], fallback: str) -> str:
    models = summary.get("models") or []
    if len(models) == 1:
        efforts = summary.get("reasoning_efforts") or []
        if len(efforts) == 1:
            return f"{models[0]} ({efforts[0]})"
        return models[0]
    return fallback


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", required=True, type=Path)
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--baseline-label", default="baseline")
    parser.add_argument("--candidate-label", default="candidate")
    parser.add_argument("--out-json", required=True, type=Path)
    parser.add_argument("--out-markdown", required=True, type=Path)
    args = parser.parse_args()

    baseline = read_json(args.baseline)
    candidate = read_json(args.candidate)
    baseline_cases = baseline["cases"]
    candidate_cases = candidate["cases"]
    baseline_identities = [row["identity_key"] for row in baseline_cases]
    candidate_identities = [row["identity_key"] for row in candidate_cases]
    if baseline_identities != candidate_identities:
        raise SystemExit("summary case identities or ordering differ")

    baseline_label = model_label(baseline, args.baseline_label)
    candidate_label = model_label(candidate, args.candidate_label)
    comparison_rows = []
    agreement_counts: Counter[str] = Counter()
    for baseline_row, candidate_row in zip(
        baseline_cases,
        candidate_cases,
    ):
        baseline_verdict = baseline_row.get("verdict")
        candidate_verdict = candidate_row.get("verdict")
        if (
            baseline_row["status"] == "completed"
            and candidate_row["status"] == "completed"
        ):
            agreement = (
                "same"
                if baseline_verdict == candidate_verdict
                else f"{baseline_verdict}_to_{candidate_verdict}"
            )
        elif baseline_row["status"] == candidate_row["status"]:
            agreement = f"same_status:{baseline_row['status']}"
        else:
            agreement = (
                f"status:{baseline_row['status']}_to_{candidate_row['status']}"
            )
        agreement_counts[agreement] += 1
        comparison_rows.append(
            {
                "identity_key": baseline_row["identity_key"],
                "baseline_status": baseline_row["status"],
                "candidate_status": candidate_row["status"],
                "baseline_verdict": baseline_verdict,
                "candidate_verdict": candidate_verdict,
                "agreement": agreement,
                "baseline_llm_call_count": baseline_row.get("llm_call_count"),
                "candidate_llm_call_count": candidate_row.get("llm_call_count"),
                "baseline_traex_reported_tokens": baseline_row.get(
                    "traex_reported_tokens"
                ),
                "candidate_traex_reported_tokens": candidate_row.get(
                    "traex_reported_tokens"
                ),
            }
        )

    both_completed = [
        row
        for row in comparison_rows
        if row["baseline_status"] == row["candidate_status"] == "completed"
    ]
    matching_verdicts = sum(row["agreement"] == "same" for row in both_completed)
    verdict_flips = [
        row
        for row in comparison_rows
        if row["baseline_status"] == row["candidate_status"] == "completed"
        and row["baseline_verdict"] != row["candidate_verdict"]
    ]
    result = {
        "schema_version": "vulrag_func_level_0817.model_comparison.v1",
        "denominator": len(comparison_rows),
        "baseline": {
            "label": baseline_label,
            "status_counts": baseline["status_counts"],
            "verdict_counts": baseline["verdict_counts"],
            "llm_call_count": baseline["llm_call_count"],
            "traex_reported_tokens": baseline["traex_reported_tokens"],
        },
        "candidate": {
            "label": candidate_label,
            "status_counts": candidate["status_counts"],
            "verdict_counts": candidate["verdict_counts"],
            "llm_call_count": candidate["llm_call_count"],
            "traex_reported_tokens": candidate["traex_reported_tokens"],
        },
        "both_completed": len(both_completed),
        "matching_verdicts": matching_verdicts,
        "verdict_agreement_rate": (
            matching_verdicts / len(both_completed) if both_completed else None
        ),
        "verdict_flip_count": len(verdict_flips),
        "agreement_counts": dict(sorted(agreement_counts.items())),
        "verdict_flips": verdict_flips,
        "cases": comparison_rows,
    }
    write_json(args.out_json, result)

    baseline_vulnerable = baseline["verdict_counts"].get("vulnerable", 0)
    candidate_vulnerable = candidate["verdict_counts"].get("vulnerable", 0)
    markdown = [
        "# VulRAG TraeX Model Comparison",
        "",
        "| Metric | " + baseline_label + " | " + candidate_label + " |",
        "| --- | ---: | ---: |",
        (
            f"| Completed | {baseline['status_counts'].get('completed', 0)} | "
            f"{candidate['status_counts'].get('completed', 0)} |"
        ),
        f"| Vulnerable verdicts | {baseline_vulnerable} | {candidate_vulnerable} |",
        (
            f"| LLM calls | {baseline['llm_call_count']} | "
            f"{candidate['llm_call_count']} |"
        ),
        (
            f"| TraeX-reported tokens | {baseline['traex_reported_tokens']} | "
            f"{candidate['traex_reported_tokens']} |"
        ),
        "",
        f"Common completed cases: {len(both_completed)}",
        "",
        f"Verdict agreement: {matching_verdicts}/{len(both_completed)} "
        f"({result['verdict_agreement_rate']:.2%})"
        if both_completed
        else "Verdict agreement: unavailable",
        "",
        f"Verdict flips: {len(verdict_flips)}",
        "",
        "| Case | Baseline | Candidate |",
        "| --- | --- | --- |",
    ]
    markdown.extend(
        (
            f"| `{row['identity_key']}` | {row['baseline_verdict']} | "
            f"{row['candidate_verdict']} |"
        )
        for row in verdict_flips
    )
    if not verdict_flips:
        markdown.append("| None | - | - |")
    args.out_markdown.parent.mkdir(parents=True, exist_ok=True)
    args.out_markdown.write_text("\n".join(markdown) + "\n", encoding="utf-8")

    print(
        json.dumps(
            {key: value for key, value in result.items() if key != "cases"},
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
