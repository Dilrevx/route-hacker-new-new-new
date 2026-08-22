#!/usr/bin/env python3
"""Build a cautious scorecard across guideline quality and embedding recall."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def pct(value: Any) -> str:
    if not isinstance(value, (int, float)):
        return "n/a"
    return f"{value * 100:.1f}%"


def fmt(value: Any, digits: int = 4) -> str:
    if value is None:
        return "n/a"
    if isinstance(value, float):
        return f"{value:.{digits}f}"
    return str(value)


def budget_metrics(recall_summary: dict[str, Any]) -> list[dict[str, Any]]:
    metrics = recall_summary.get("metrics_on_common_identities") or {}
    rows: list[dict[str, Any]] = []
    for key, value in sorted(metrics.items(), key=lambda item: metric_sort_key(item[0])):
        if not key.startswith("hit_at_") or not isinstance(value, dict):
            continue
        budget = int(key.removeprefix("hit_at_"))
        rows.append(
            {
                "budget": budget,
                "left_count": value.get("left_count"),
                "right_count": value.get("right_count"),
                "delta_count": value.get("delta_count"),
                "left_rate": value.get("left_rate"),
                "right_rate": value.get("right_rate"),
                "delta_rate": value.get("delta_rate"),
            }
        )
    return rows


def equivalence_evidence(recall_equivalence: dict[str, Any] | None) -> dict[str, Any]:
    if not recall_equivalence:
        return {
            "status": "missing",
            "recall_consumed_text_equivalent": None,
            "message": "No guideline sidecar equivalence report was provided.",
        }

    equivalent = bool(recall_equivalence.get("recall_consumed_text_equivalent"))
    status = "valid_consumed_text_equivalence" if equivalent else "invalid_consumed_text_difference"
    message = (
        "The released sidecar has the same recall-consumed identity keys and guideline text as the measured sidecar."
        if equivalent
        else "The released sidecar changes recall-consumed identity keys or guideline text; rerun recall before inheriting metrics."
    )
    return {
        "status": status,
        "recall_consumed_text_equivalent": equivalent,
        "same_key_set": bool(recall_equivalence.get("same_key_set")),
        "left_label": recall_equivalence.get("left_label"),
        "right_label": recall_equivalence.get("right_label"),
        "left_count": recall_equivalence.get("left_count"),
        "right_count": recall_equivalence.get("right_count"),
        "common_count": recall_equivalence.get("common_count"),
        "changed_text_count": recall_equivalence.get("changed_text_count"),
        "left_sha256": recall_equivalence.get("left_sha256"),
        "right_sha256": recall_equivalence.get("right_sha256"),
        "message": message,
    }


def metric_sort_key(name: str) -> tuple[int, str]:
    if name.startswith("hit_at_"):
        suffix = name.removeprefix("hit_at_")
        if suffix.isdigit():
            return int(suffix), name
    return 10**9, name


def recall_evidence(recall_summary: dict[str, Any] | None) -> dict[str, Any]:
    if not recall_summary:
        return {
            "status": "missing",
            "same_identity_set": None,
            "same_identity_order": None,
            "common_count": 0,
            "budgets": [],
            "message": "No recall A/B summary was provided; do not make embedding recall claims.",
        }

    same_identity_set = bool(recall_summary.get("same_identity_set"))
    same_identity_order = bool(recall_summary.get("same_identity_order"))
    status = "valid_same_identity" if same_identity_set else "invalid_identity_mismatch"
    message = (
        "Recall A/B evidence is valid for retrieval claims because both sides use the same identity set."
        if same_identity_set
        else "Recall A/B evidence is not valid for paper claims because identity sets differ."
    )
    return {
        "status": status,
        "same_identity_set": same_identity_set,
        "same_identity_order": same_identity_order,
        "common_count": recall_summary.get("common_count", 0),
        "left_label": recall_summary.get("left_label"),
        "right_label": recall_summary.get("right_label"),
        "primary_budget": recall_summary.get("primary_budget"),
        "budgets": budget_metrics(recall_summary),
        "mrr": (recall_summary.get("metrics_on_common_identities") or {}).get("mrr"),
        "message": message,
    }


def structural_evidence(group_summary: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": "advisory_structural_diagnostic",
        "guideline_count": group_summary.get("guideline_count"),
        "evaluated_group_count": group_summary.get("evaluated_group_count"),
        "source_only_group_count": group_summary.get("source_only_group_count"),
        "assigned_unique_case_count": group_summary.get("assigned_unique_case_count"),
        "total_case_count": group_summary.get("total_case_count"),
        "case_coverage_rate": group_summary.get("case_coverage_rate"),
        "weighted_primary_hcvr_purity": group_summary.get("weighted_primary_hcvr_purity"),
        "weighted_cwe_purity": group_summary.get("weighted_cwe_purity"),
        "mixed_hcvr_group_count": group_summary.get("mixed_hcvr_group_count"),
        "mixed_cwe_group_count": group_summary.get("mixed_cwe_group_count"),
        "pending_candidate_count": group_summary.get("pending_candidate_count"),
        "message": "Structural labels are triage signals for guideline grouping, not hard pass/fail gates.",
    }


def judge_evidence(judge_summary: dict[str, Any] | None) -> dict[str, Any]:
    if not judge_summary:
        return {
            "status": "missing",
            "judge_input_count": 0,
            "message": "No LLM judge summary was provided; semantic review evidence is missing.",
        }
    return {
        "status": "advisory_semantic_diagnostic",
        "judge_input_count": judge_summary.get("judge_input_count"),
        "parsed_count": judge_summary.get("parsed_count"),
        "missing_output_count": judge_summary.get("missing_output_count"),
        "invalid_output_count": judge_summary.get("invalid_output_count"),
        "accepted_count": judge_summary.get("accepted_count"),
        "decision_counts": judge_summary.get("decision_counts") or {},
        "low_score_count": judge_summary.get("low_score_count"),
        "average_scores": judge_summary.get("average_scores") or {},
        "message": "LLM-as-judge output is semantic review evidence; it must not become keyword routing or a hidden optimization target.",
    }


def claim_boundaries(
    *,
    structural: dict[str, Any],
    judge: dict[str, Any],
    recall: dict[str, Any],
    equivalence: dict[str, Any],
    desired_delta_rate: float,
) -> list[dict[str, Any]]:
    boundaries: list[dict[str, Any]] = [
        {
            "claim": "guideline_classification_quality",
            "status": "supported_as_advisory_diagnostic",
            "evidence": [
                "group structural summary",
                "source-only and pending-review accounting",
            ],
            "caveat": "Purity and flags are weak diagnostics; mechanism quality still needs semantic review.",
        },
        {
            "claim": "semantic_guideline_quality",
            "status": "supported_as_advisory_diagnostic" if judge["status"] != "missing" else "missing_evidence",
            "evidence": ["LLM-as-judge summary"] if judge["status"] != "missing" else [],
            "caveat": "Judge outputs rank review priority and cannot be converted into hardcoded routing.",
        },
    ]

    if recall["status"] not in {"valid_same_identity", "inherited_same_identity_by_sidecar_equivalence"}:
        boundaries.append(
            {
                "claim": "embedding_recall_improvement",
                "status": "missing_or_invalid_evidence",
                "evidence": [],
                "caveat": recall["message"],
            }
        )
        return boundaries

    qualifying = [
        row
        for row in recall["budgets"]
        if isinstance(row.get("delta_rate"), (int, float)) and row["delta_rate"] >= desired_delta_rate
    ]
    boundaries.append(
        {
            "claim": "embedding_recall_improvement",
            "status": "supported_for_reported_budgets" if qualifying else "not_supported_at_desired_delta",
            "evidence": [
                f"Hit@{row['budget']} delta {row['delta_count']} cases / {pct(row['delta_rate'])}"
                for row in qualifying
            ],
            "caveat": (
                "This claim is inherited by sidecar equivalence and still depends on the unchanged identity file, "
                "snapshots, candidate slicing, embedding backend, and ranking parameters."
                if equivalence["status"] == "valid_consumed_text_equivalence"
                else "This claim is about the evaluated embedding plus guideline/query configuration, not guideline taxonomy quality alone."
            ),
        }
    )
    return boundaries


def build_scorecard(
    *,
    release_summary: dict[str, Any],
    group_summary: dict[str, Any],
    judge_summary: dict[str, Any] | None,
    recall_summary: dict[str, Any] | None,
    recall_equivalence: dict[str, Any] | None = None,
    release_label: str,
    desired_delta_rate: float,
) -> dict[str, Any]:
    structural = structural_evidence(group_summary)
    judge = judge_evidence(judge_summary)
    recall = recall_evidence(recall_summary)
    equivalence = equivalence_evidence(recall_equivalence)
    if recall["status"] == "valid_same_identity" and equivalence["status"] == "valid_consumed_text_equivalence":
        recall = dict(recall)
        recall["status"] = "inherited_same_identity_by_sidecar_equivalence"
        recall["message"] = (
            "Recall metrics are inherited from an existing same-identity A/B because the release sidecar is "
            "equivalent under recall-consumed identity keys and guideline text. This is not a fresh recall run."
        )
        recall["equivalence_left_label"] = equivalence.get("left_label")
        recall["equivalence_right_label"] = equivalence.get("right_label")
    elif recall["status"] == "valid_same_identity" and equivalence["status"] == "invalid_consumed_text_difference":
        recall = dict(recall)
        recall["status"] = "invalid_sidecar_equivalence"
        recall["message"] = (
            "A recall comparison was provided, but the requested release sidecar changes recall-consumed "
            "identity keys or guideline text. Rerun recall for this release before making retrieval claims."
        )
    return {
        "schema_version": "hcvr_guideline_experiment_scorecard.v1",
        "release_label": release_label,
        "release": {
            "guideline_count": release_summary.get("guideline_count"),
            "work_item_count": release_summary.get("work_item_count"),
            "active_attribution_count": release_summary.get("active_attribution_count"),
            "pending_review_count": release_summary.get("pending_review_count"),
            "override_count": release_summary.get("override_count"),
            "pending_overrides_included": release_summary.get("pending_overrides_included"),
            "source_fingerprint": release_summary.get("source_fingerprint"),
        },
        "structural_evidence": structural,
        "judge_evidence": judge,
        "recall_evidence": recall,
        "recall_equivalence_evidence": equivalence,
        "claim_boundaries": claim_boundaries(
            structural=structural,
            judge=judge,
            recall=recall,
            equivalence=equivalence,
            desired_delta_rate=desired_delta_rate,
        ),
        "method_policy": [
            "Optimize guideline wording and grouping from source/sink/guard evidence, not from keyword checks.",
            "Use bad recall cases as regression and motivation data, not as per-case hardcoded fixes.",
            "Treat recall numbers as evidence for a specific embedding plus guideline/query configuration.",
            "Require same identity sets for paper-facing recall deltas.",
        ],
    }


def write_markdown(path: Path, scorecard: dict[str, Any], desired_delta_rate: float) -> None:
    release = scorecard["release"]
    structural = scorecard["structural_evidence"]
    judge = scorecard["judge_evidence"]
    recall = scorecard["recall_evidence"]
    equivalence = scorecard["recall_equivalence_evidence"]
    lines = [
        "# HCVR Guideline Experiment Scorecard",
        "",
        f"- Release: `{scorecard['release_label']}`",
        f"- Guidelines: {release['guideline_count']}",
        f"- Work items: {release['work_item_count']}",
        f"- Active attributions: {release['active_attribution_count']}",
        f"- Pending review: {release['pending_review_count']}",
        f"- Recall sidecar rows: {release['override_count']}",
        f"- Pending overrides included: {release['pending_overrides_included']}",
        "",
        "## Evidence Axes",
        "",
        "| Axis | Status | Main Evidence | Boundary |",
        "| --- | --- | --- | --- |",
        (
            f"| Guideline grouping | {structural['status']} | "
            f"{structural['evaluated_group_count']} evaluated groups, "
            f"weighted HCVR purity {fmt(structural['weighted_primary_hcvr_purity'])}, "
            f"weighted CWE purity {fmt(structural['weighted_cwe_purity'])} | "
            f"{structural['message']} |"
        ),
        (
            f"| LLM semantic judge | {judge['status']} | "
            f"parsed {judge.get('parsed_count', 0)}/{judge.get('judge_input_count', 0)}, "
            f"accepted {judge.get('accepted_count', 0)}, low-score {judge.get('low_score_count', 0)} | "
            f"{judge['message']} |"
        ),
        (
            f"| Embedding recall | {recall['status']} | "
            f"common identities {recall.get('common_count', 0)} | {recall['message']} |"
        ),
        (
            f"| Recall sidecar equivalence | {equivalence['status']} | "
            f"changed consumed texts {equivalence.get('changed_text_count', 'n/a')} | "
            f"{equivalence['message']} |"
        ),
        "",
    ]
    if recall["status"] in {"valid_same_identity", "inherited_same_identity_by_sidecar_equivalence"}:
        lines.extend(
            [
                "## Recall Budget Deltas",
                "",
                f"Left: `{recall.get('left_label')}`",
                f"Right: `{recall.get('right_label')}`",
                "",
                "| Budget | Left | Right | Delta Cases | Delta Rate |",
                "| ---: | ---: | ---: | ---: | ---: |",
            ]
        )
        for row in recall["budgets"]:
            lines.append(
                f"| Top-{row['budget']} | {row['left_count']} | {row['right_count']} | "
                f"{row['delta_count']} | {pct(row['delta_rate'])} |"
            )
        mrr = recall.get("mrr") or {}
        lines.append(f"| MRR | {fmt(mrr.get('left'), 6)} | {fmt(mrr.get('right'), 6)} | {fmt(mrr.get('delta'), 6)} | n/a |")
        lines.append("")

    if equivalence["status"] != "missing":
        lines.extend(
            [
                "## Sidecar Equivalence",
                "",
                f"- Compared sidecars: `{equivalence.get('left_label')}` vs `{equivalence.get('right_label')}`",
                f"- Same key set: {equivalence.get('same_key_set')}",
                f"- Changed consumed guideline texts: {equivalence.get('changed_text_count')}",
                f"- Recall-consumed text equivalent: {equivalence.get('recall_consumed_text_equivalent')}",
                "",
                "This evidence only covers the guideline text passed into retrieval. It does not cover changes to identities, source snapshots, slicing, embedding service, adapter weights, or ranking parameters.",
                "",
            ]
        )

    lines.extend(["## Claim Boundaries", ""])
    for item in scorecard["claim_boundaries"]:
        evidence = "; ".join(item["evidence"]) if item["evidence"] else "none"
        lines.append(f"- `{item['claim']}`: {item['status']}. Evidence: {evidence}. Caveat: {item['caveat']}")
    lines.extend(
        [
            "",
            "## Policy",
            "",
        ]
    )
    for item in scorecard["method_policy"]:
        lines.append(f"- {item}")
    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            f"A recall-improvement claim needs same-identity A/B evidence and should only name budgets whose delta is at least {pct(desired_delta_rate)} when using a percentage-point threshold.",
            "A guideline-classification claim can cite structural and LLM-judge diagnostics, but those diagnostics remain advisory and should drive source-evidence review rather than hardcoded keyword rules.",
            "",
        ]
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--release-summary", type=Path, required=True)
    parser.add_argument("--group-summary", type=Path, required=True)
    parser.add_argument("--judge-summary", type=Path)
    parser.add_argument("--recall-comparison", type=Path)
    parser.add_argument("--recall-equivalence", type=Path)
    parser.add_argument("--release-label", default="guideline-release")
    parser.add_argument("--desired-delta-rate", type=float, default=0.10)
    parser.add_argument("--output-json", type=Path, required=True)
    parser.add_argument("--output-md", type=Path, required=True)
    args = parser.parse_args()

    scorecard = build_scorecard(
        release_summary=read_json(args.release_summary),
        group_summary=read_json(args.group_summary),
        judge_summary=read_json(args.judge_summary) if args.judge_summary else None,
        recall_summary=read_json(args.recall_comparison) if args.recall_comparison else None,
        recall_equivalence=read_json(args.recall_equivalence) if args.recall_equivalence else None,
        release_label=args.release_label,
        desired_delta_rate=args.desired_delta_rate,
    )
    write_json(args.output_json, scorecard)
    write_markdown(args.output_md, scorecard, args.desired_delta_rate)
    print(json.dumps(scorecard["claim_boundaries"], ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
