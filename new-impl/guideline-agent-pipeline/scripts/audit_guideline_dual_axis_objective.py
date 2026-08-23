#!/usr/bin/env python3
"""Audit guideline generation against semantic-quality and recall-quality goals."""

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


def add_counts(target: dict[str, int], source: dict[str, Any]) -> None:
    for key, value in source.items():
        target[str(key)] = target.get(str(key), 0) + int(value or 0)


def aggregate_ledger_validations(summaries: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not summaries:
        return None
    decision_counts: dict[str, int] = {}
    result = {
        "schema_version": "hcvr_guideline_review_ledger_validation.aggregate.v1",
        "summary_count": len(summaries),
        "row_count": 0,
        "valid_count": 0,
        "invalid_count": 0,
        "promotable_count": 0,
        "decision_counts": decision_counts,
    }
    for summary in summaries:
        result["row_count"] += int(summary.get("row_count") or 0)
        result["valid_count"] += int(summary.get("valid_count") or 0)
        result["invalid_count"] += int(summary.get("invalid_count") or 0)
        result["promotable_count"] += int(summary.get("promotable_count") or 0)
        add_counts(decision_counts, summary.get("decision_counts") or {})
    result["decision_counts"] = dict(sorted(decision_counts.items()))
    return result


def aggregate_ledger_judges(summaries: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not summaries:
        return None
    decision_counts: dict[str, int] = {}
    score_sums: dict[str, float] = {}
    score_weights: dict[str, int] = {}
    result = {
        "schema_version": "hcvr_guideline_llm_judge_summary.aggregate.v1",
        "summary_count": len(summaries),
        "judge_input_count": 0,
        "parsed_count": 0,
        "missing_output_count": 0,
        "invalid_output_count": 0,
        "accepted_count": 0,
        "needs_revision_count": 0,
        "low_score_count": 0,
        "decision_counts": decision_counts,
        "average_scores": {},
    }
    for summary in summaries:
        parsed_count = int(summary.get("parsed_count") or 0)
        result["judge_input_count"] += int(summary.get("judge_input_count") or 0)
        result["parsed_count"] += parsed_count
        result["missing_output_count"] += int(summary.get("missing_output_count") or 0)
        result["invalid_output_count"] += int(summary.get("invalid_output_count") or 0)
        result["accepted_count"] += int(summary.get("accepted_count") or 0)
        result["needs_revision_count"] += int(summary.get("needs_revision_count") or 0)
        result["low_score_count"] += int(summary.get("low_score_count") or 0)
        add_counts(decision_counts, summary.get("decision_counts") or {})
        average_scores = summary.get("average_scores") if isinstance(summary.get("average_scores"), dict) else {}
        for field, value in average_scores.items():
            if value is None:
                continue
            score_sums[field] = score_sums.get(field, 0.0) + float(value) * parsed_count
            score_weights[field] = score_weights.get(field, 0) + parsed_count
    result["decision_counts"] = dict(sorted(decision_counts.items()))
    result["average_scores"] = {
        field: (score_sums[field] / score_weights[field] if score_weights.get(field) else None)
        for field in sorted(score_sums)
    }
    return result


def status_for_semantic_quality(scorecard: dict[str, Any], worklist: dict[str, Any]) -> str:
    judge = scorecard.get("judge_evidence") if isinstance(scorecard.get("judge_evidence"), dict) else {}
    decision_counts = judge.get("decision_counts") if isinstance(judge.get("decision_counts"), dict) else {}
    accepted = int(decision_counts.get("accept") or 0)
    parsed = int(judge.get("parsed_count") or 0)
    worklist_count = int(worklist.get("worklist_count") or 0)
    if parsed and accepted == parsed and worklist_count == 0:
        return "satisfied"
    if parsed and accepted > 0:
        return "partially_satisfied_needs_evidence"
    return "not_satisfied_needs_semantic_evidence"


def status_for_recall(scorecard: dict[str, Any], desired_delta_rate: float) -> str:
    recall = scorecard.get("recall_evidence") if isinstance(scorecard.get("recall_evidence"), dict) else {}
    status = str(recall.get("status") or "")
    budgets = recall.get("budgets") if isinstance(recall.get("budgets"), list) else []
    max_delta = max((float(row.get("delta_rate") or 0.0) for row in budgets), default=0.0)
    if status in {"valid_same_identity", "inherited_same_identity_by_sidecar_equivalence"}:
        if max_delta >= desired_delta_rate:
            return "satisfied_for_reported_same_identity_budget"
        return "compatible_but_improvement_below_target"
    if status:
        return f"not_satisfied_{status}"
    return "not_satisfied_missing_recall_evidence"


def source_reviewed_boundary_evidence(
    ledger_validation: dict[str, Any] | None,
    ledger_judge: dict[str, Any] | None,
) -> dict[str, Any]:
    if not ledger_validation and not ledger_judge:
        return {
            "status": "not_provided",
            "message": "No source-reviewed boundary ledger evidence was provided.",
        }

    valid_count = int((ledger_validation or {}).get("valid_count") or 0)
    invalid_count = int((ledger_validation or {}).get("invalid_count") or 0)
    promotable_count = int((ledger_validation or {}).get("promotable_count") or 0)
    parsed = int((ledger_judge or {}).get("parsed_count") or 0)
    accepted = int((ledger_judge or {}).get("accepted_count") or 0)
    low_score_count = int((ledger_judge or {}).get("low_score_count") or 0)
    if invalid_count:
        status = "not_satisfied_invalid_source_reviewed_ledger"
    elif valid_count and parsed and accepted == parsed:
        status = "satisfied_for_source_reviewed_boundaries"
    elif valid_count:
        status = "partially_satisfied_source_reviewed_boundaries_need_judge_or_revision"
    else:
        status = "not_satisfied_missing_source_reviewed_boundaries"
    return {
        "status": status,
        "valid_count": valid_count,
        "invalid_count": invalid_count,
        "promotable_count": promotable_count,
        "validation_decision_counts": (ledger_validation or {}).get("decision_counts") or {},
        "judge_parsed_count": parsed,
        "judge_accepted_count": accepted,
        "judge_low_score_count": low_score_count,
        "judge_decision_counts": (ledger_judge or {}).get("decision_counts") or {},
        "judge_average_scores": (ledger_judge or {}).get("average_scores") or {},
        "message": (
            "Source-reviewed boundary evidence is semantic QA only. It can justify a boundary as review-ready, "
            "but it does not prove embedding recall."
        ),
    }


def build_audit(
    *,
    scorecard: dict[str, Any],
    worklist: dict[str, Any],
    desired_delta_rate: float,
    recall_alignment: dict[str, Any] | None = None,
    recall_side_debug: dict[str, Any] | None = None,
    recall_side_miss_inspection: dict[str, Any] | None = None,
    boundary_recall_triage: dict[str, Any] | None = None,
    ledger_validation: dict[str, Any] | None = None,
    ledger_judge: dict[str, Any] | None = None,
) -> dict[str, Any]:
    recall = scorecard.get("recall_evidence") if isinstance(scorecard.get("recall_evidence"), dict) else {}
    judge = scorecard.get("judge_evidence") if isinstance(scorecard.get("judge_evidence"), dict) else {}
    structural = scorecard.get("structural_evidence") if isinstance(scorecard.get("structural_evidence"), dict) else {}
    recall_equivalence = (
        scorecard.get("recall_equivalence_evidence")
        if isinstance(scorecard.get("recall_equivalence_evidence"), dict)
        else {}
    )
    semantic_status = status_for_semantic_quality(scorecard, worklist)
    recall_status = status_for_recall(scorecard, desired_delta_rate)
    reviewed_boundary = source_reviewed_boundary_evidence(ledger_validation, ledger_judge)
    recall_alignment = recall_alignment or {}
    alignment_policy = (
        recall_alignment.get("cleanliness_policy")
        if isinstance(recall_alignment.get("cleanliness_policy"), dict)
        else {}
    )
    alignment_joined = recall_alignment.get("joined_recall_case_count")
    alignment_total = recall_alignment.get("recall_case_count")
    alignment_attention = (
        recall_alignment.get("attention_counts")
        if isinstance(recall_alignment.get("attention_counts"), dict)
        else {}
    )
    recall_side_debug = recall_side_debug or {}
    recall_side_miss_inspection = recall_side_miss_inspection or {}
    recall_side_miss_capability = (
        recall_side_miss_inspection.get("input_capability")
        if isinstance(recall_side_miss_inspection.get("input_capability"), dict)
        else {}
    )
    recall_side_miss_message = (
        "Case-level miss inspection includes exported Top-N candidate rows. It can separate candidate-generation "
        "absence from known anchors that are present but ranked below the primary budget; it still does not prove "
        "vulnerability precision or change guideline quality."
        if recall_side_miss_capability.get("full_ranked_candidate_lists")
        else (
            "Case-level miss inspection is rank-only when full candidate lists are unavailable. It narrows the "
            "next recall-side checks but does not prove candidate slicing failure or change guideline quality."
        )
    )
    boundary_recall_triage = boundary_recall_triage or {}
    boundary_next_actions = (
        boundary_recall_triage.get("next_action_counts")
        if isinstance(boundary_recall_triage.get("next_action_counts"), dict)
        else {}
    )
    aligned_boundary_count = int(
        boundary_next_actions.get("semantic_boundary_and_recall_examples_are_aligned_for_next_ablation")
        or 0
    )
    requirements = [
        {
            "requirement": "Design reusable guideline classification that generalizes across CVEs but remains audit-specific.",
            "evidence": [
                "mechanism guideline generator uses offline mechanism attribution, member evidence support, release-ready gating, and review queue quarantine",
                f"weighted_primary_hcvr_purity={structural.get('weighted_primary_hcvr_purity')}",
                f"weighted_cwe_purity={structural.get('weighted_cwe_purity')}",
                f"judge_decision_counts={judge.get('decision_counts')}",
                f"evidence_worklist_actions={worklist.get('action_counts')}",
                f"source_reviewed_boundary_status={reviewed_boundary.get('status')}",
                f"source_reviewed_boundary_validation_decisions={reviewed_boundary.get('validation_decision_counts')}",
                f"source_reviewed_boundary_judge_decisions={reviewed_boundary.get('judge_decision_counts')}",
            ],
            "status": semantic_status,
            "gap": "TraeX judge still finds many groups needing source/sink/guard evidence or split/revision work.",
        },
        {
            "requirement": "Keep guidelines compatible with the tuned embedding recall path.",
            "evidence": [
                f"recall_status={recall.get('status')}",
                f"same_identity_set={recall.get('same_identity_set')}",
                f"same_identity_order={recall.get('same_identity_order')}",
                f"recall_equivalence_status={recall_equivalence.get('status')}",
                f"primary_budget={recall.get('primary_budget')}",
                f"recall_alignment_joined={alignment_joined}/{alignment_total}",
                f"recall_alignment_attention_counts={alignment_attention}",
                f"recall_side_debug_group_count={recall_side_debug.get('debug_group_count')}",
                f"recall_side_debug_miss_state_totals={recall_side_debug.get('miss_state_totals')}",
                f"boundary_recall_triage_aligned_boundaries={aligned_boundary_count}",
                f"boundary_recall_triage_rank_tables={boundary_recall_triage.get('rank_table_labels')}",
            ],
            "status": recall_status,
            "gap": "The current r8 recall evidence is inherited by unchanged sidecar text; a fresh run is required after any consumed guideline text changes.",
        },
        {
            "requirement": "Use recall bad cases as motivation without turning them into answer keys.",
            "evidence": [
                "known anchors are used after ranking for metrics, not for query construction",
                "evidence worklist marks judge/bad-case material as review_only_not_release_not_recall_input",
                "README forbids runtime regex fallback, hidden label routing, and per-case fixes",
            ],
            "status": "satisfied_by_current_policy",
            "gap": "Must be rechecked whenever generator or recall query construction changes.",
        },
        {
            "requirement": "If semantic guideline quality is strong but recall remains weak, inspect recall method before weakening taxonomy.",
            "evidence": [
                "README separates semantic guideline quality from embedding recall compatibility",
                "revision backlog has actions for embedding/candidate/query mismatch",
                "scorecard separates structural, judge, recall, and sidecar-equivalence evidence",
                "source-reviewed boundaries can be marked semantically ready without being counted as recall-proven",
                f"label_mixture_is_blocking={alignment_policy.get('label_mixture_is_blocking')}",
                f"min_clean_purity_is_blocking={alignment_policy.get('min_clean_purity_is_blocking')}",
                "recall-side debug pack separates rank misses from rank-table coverage gaps",
                f"recall_side_miss_inspection_case_count={recall_side_miss_inspection.get('case_count')}",
                f"recall_side_miss_inspection_states={recall_side_miss_inspection.get('miss_state_counts')}",
            ],
            "status": "satisfied_as_evaluation_policy",
            "gap": "Need per-group semantic-vs-recall triage after the next changed-sidecar recall run.",
        },
        {
            "requirement": "Avoid hardcoding and be cautious with paper-facing engineering combinations.",
            "evidence": [
                "scorecard marks recall improvement claim as not_supported_at_desired_delta",
                "RRF/fusion is documented as a recall-compatible engineering path, not a guideline-quality claim",
                "TraeX judge output feeds backlog/worklist rather than released guidelines or ranking",
                "new embedders, fusion, or rerankers are allowed only as explicit same-identity A/B configurations",
            ],
            "status": "satisfied_by_current_policy",
            "gap": "Any future fusion or model substitution needs same-identity A/B and a separate claim boundary.",
        },
    ]
    missing = [
        row
        for row in requirements
        if not str(row["status"]).startswith("satisfied")
        and str(row["status"]) not in {"satisfied_as_evaluation_policy", "satisfied_by_current_policy"}
    ]
    next_gates = [
        {
            "gate": "semantic_evidence_gate",
            "run_when": "before changing released guideline text or lexicon entries",
            "pass_condition": "each promoted group has checked source, sink, missing guard, exploit precondition, and fix semantics for representative member cases",
            "current_state": "not passed; evidence worklist has outstanding rows",
        },
        {
            "gate": "same_identity_recall_gate",
            "run_when": "after recall-consumed guideline sidecar text changes",
            "pass_condition": "same_identity_set=true and same_identity_order=true against the frozen comparison baseline",
            "current_state": "not required for r8 equivalence; required for any next changed sidecar",
        },
        {
            "gate": "taxonomy_vs_embed_triage_gate",
            "run_when": "when a semantically clean group misses Top-K",
            "pass_condition": "record whether the miss is caused by guideline wording, candidate slicing, embedding backend, adapter weights, rank fusion, or audit budget",
            "current_state": (
                f"policy exists; {aligned_boundary_count} source-reviewed boundary/boundaries currently have "
                "same-identity recall examples aligned"
                if aligned_boundary_count
                else "policy exists; needs per-group run after next recall table"
            ),
        },
        {
            "gate": "recall_method_substitution_gate",
            "run_when": "when a source-reviewed guideline is coherent but the current embedding recall misses representative cases",
            "pass_condition": "compare any replacement embedder, reranker, or fusion method on the same identities, snapshots, candidates, and budgets without regex fallback or label routing",
            "current_state": "allowed by policy; no paper-facing method substitution claim until same-identity evidence exists",
        },
        {
            "gate": "paper_claim_boundary_gate",
            "run_when": "before writing results into the paper",
            "pass_condition": "semantic judge evidence, source-reviewed boundary evidence, structural diagnostics, sidecar equivalence, recall A/B deltas, and engineering fusion are reported as separate claims",
            "current_state": "satisfied by current scorecard format, but final paper table still needs fresh numbers if guideline text changes",
        },
    ]
    overall_status = "not_complete" if missing else "complete"
    return {
        "schema_version": "hcvr_guideline_dual_axis_objective_audit.v1",
        "desired_delta_rate": desired_delta_rate,
        "overall_status": overall_status,
        "requirements": requirements,
        "source_reviewed_boundary_evidence": reviewed_boundary,
        "recall_alignment_evidence": {
            "status": "provided" if recall_alignment else "not_provided",
            "recall_label": recall_alignment.get("recall_label"),
            "joined_recall_case_count": alignment_joined,
            "recall_case_count": alignment_total,
            "same_identity_baseline": recall_alignment.get("same_identity_baseline"),
            "attention_counts": alignment_attention,
            "cleanliness_policy": alignment_policy,
            "message": (
                "Recall alignment is diagnostic only. Limited joins or clean-group misses should guide recall-side "
                "inspection, not hidden routing or hardcoded guideline changes."
            ),
        },
        "recall_side_debug_evidence": {
            "status": "provided" if recall_side_debug else "not_provided",
            "recall_label": recall_side_debug.get("recall_label"),
            "debug_group_count": recall_side_debug.get("debug_group_count"),
            "miss_state_totals": recall_side_debug.get("miss_state_totals") or {},
            "recommended_check_counts": recall_side_debug.get("recommended_check_counts") or {},
            "message": (
                "Recall-side debug rows are not guideline changes. They queue query, slicing, embedder, adapter, "
                "and rank-table coverage checks for semantically clean groups that still miss Top-K."
            ),
        },
        "recall_side_miss_inspection_evidence": {
            "status": "provided" if recall_side_miss_inspection else "not_provided",
            "recall_label": recall_side_miss_inspection.get("recall_label"),
            "case_count": recall_side_miss_inspection.get("case_count"),
            "miss_state_counts": recall_side_miss_inspection.get("miss_state_counts") or {},
            "diagnosis_counts": recall_side_miss_inspection.get("diagnosis_counts") or {},
            "next_check_counts": recall_side_miss_inspection.get("next_check_counts") or {},
            "input_capability": recall_side_miss_capability,
            "message": recall_side_miss_message,
        },
        "missing_or_incomplete_requirements": missing,
        "next_gates": next_gates,
        "decision": (
            "Continue guideline-v2 work through evidence collection before rewriting released guidelines. "
            "Do not mark the objective complete until semantic evidence improves and any changed sidecar has a fresh same-identity recall evaluation."
        )
        if missing
        else "Objective is covered by current artifacts.",
    }


def write_readme(path: Path, audit: dict[str, Any]) -> None:
    recall_miss_capability = (
        audit.get("recall_side_miss_inspection_evidence", {}).get("input_capability")
        if isinstance(audit.get("recall_side_miss_inspection_evidence"), dict)
        else {}
    )
    recall_miss_note = (
        "This is the case-level expansion of the recall-side debug queue with exported Top-N candidate rows. "
        "It can show whether known-anchor-overlapping slices are present in the exported budget and whether "
        "they are simply ranked below the primary budget; it still does not prove vulnerability precision."
        if recall_miss_capability.get("full_ranked_candidate_lists")
        else (
            "This is the case-level expansion of the recall-side debug queue. With the current rank summary table "
            "it can distinguish coverage gaps from ranked-below-budget misses, but it cannot prove candidate-slicing "
            "quality without full ranked candidate exports."
        )
    )
    lines = [
        "# Guideline Dual-Axis Objective Audit",
        "",
        "This audit checks the current guideline-v2 state against two coupled goals:",
        "",
        "1. produce reusable, semantically accurate CVE-mechanism guidelines for audit;",
        "2. keep those guidelines compatible with the tuned embedding recall path.",
        "",
        "It is a completion audit, not a release file and not a recall input.",
        "",
        "## Overall Status",
        "",
        f"- Status: `{audit['overall_status']}`",
        f"- Desired recall delta rate: {audit['desired_delta_rate']:.4f}",
        f"- Decision: {audit['decision']}",
        "",
        "## Prompt-To-Artifact Checklist",
        "",
        "| Requirement | Status | Evidence | Gap |",
        "| --- | --- | --- | --- |",
    ]
    for row in audit["requirements"]:
        evidence = "<br>".join(str(item).replace("|", "\\|") for item in row["evidence"])
        gap = str(row.get("gap") or "").replace("|", "\\|")
        lines.append(f"| {row['requirement']} | `{row['status']}` | {evidence} | {gap} |")
    reviewed = audit.get("source_reviewed_boundary_evidence") or {}
    alignment = audit.get("recall_alignment_evidence") or {}
    recall_debug = audit.get("recall_side_debug_evidence") or {}
    recall_miss_inspection = audit.get("recall_side_miss_inspection_evidence") or {}
    lines.extend(
        [
            "",
            "## Source-Reviewed Boundary Evidence",
            "",
            f"- Status: `{reviewed.get('status')}`",
            f"- Ledger valid/invalid: {reviewed.get('valid_count')} / {reviewed.get('invalid_count')}",
            f"- Promotable boundaries: {reviewed.get('promotable_count')}",
            f"- Ledger decisions: {reviewed.get('validation_decision_counts')}",
            f"- Judge decisions: {reviewed.get('judge_decision_counts')}",
            f"- Judge average scores: {reviewed.get('judge_average_scores')}",
            "",
            "This section records source-reviewed guideline-boundary evidence. It can support a semantic boundary decision, but it does not prove recall. If one of these boundaries misses Top-K, the next action is recall-side diagnosis or a same-identity model/ranking A/B, not automatic taxonomy degradation.",
        ]
    )
    lines.extend(
        [
            "",
            "## Recall Alignment Diagnostics",
            "",
            f"- Status: `{alignment.get('status')}`",
            f"- Recall label: `{alignment.get('recall_label')}`",
            f"- Joined recall cases: {alignment.get('joined_recall_case_count')} / {alignment.get('recall_case_count')}",
            f"- Same identity baseline: {alignment.get('same_identity_baseline')}",
            f"- Attention counts: {alignment.get('attention_counts')}",
            f"- Cleanliness policy: {alignment.get('cleanliness_policy')}",
            "",
            "This diagnostic separates clean semantic boundaries from recall misses. Mixed HCVR/CWE labels remain review signals, but they are not hard gates because one reusable mechanism can cut across labels.",
        ]
    )
    lines.extend(
        [
            "",
            "## Recall-Side Debug Evidence",
            "",
            f"- Status: `{recall_debug.get('status')}`",
            f"- Recall label: `{recall_debug.get('recall_label')}`",
            f"- Debug groups: {recall_debug.get('debug_group_count')}",
            f"- Miss states: {recall_debug.get('miss_state_totals')}",
            f"- Recommended checks: {recall_debug.get('recommended_check_counts')}",
            "",
            "These rows are a work queue for recall-side diagnosis. They do not rewrite mechanism taxonomy and do not justify engineering combinations unless a same-identity A/B later supports that claim.",
        ]
    )
    lines.extend(
        [
            "",
            "## Recall-Side Case Inspection",
            "",
            f"- Status: `{recall_miss_inspection.get('status')}`",
            f"- Recall label: `{recall_miss_inspection.get('recall_label')}`",
            f"- Cases inspected: {recall_miss_inspection.get('case_count')}",
            f"- Miss states: {recall_miss_inspection.get('miss_state_counts')}",
            f"- Diagnosis counts: {recall_miss_inspection.get('diagnosis_counts')}",
            f"- Next checks: {recall_miss_inspection.get('next_check_counts')}",
            f"- Input capability: {recall_miss_inspection.get('input_capability')}",
            "",
            recall_miss_note,
        ]
    )
    lines.extend(
        [
            "",
            "## Required Gates For The Next Round",
            "",
            "| Gate | Run When | Pass Condition | Current State |",
            "| --- | --- | --- | --- |",
        ]
    )
    for row in audit["next_gates"]:
        lines.append(
            f"| `{row['gate']}` | {row['run_when']} | {row['pass_condition']} | {row['current_state']} |"
        )
    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "The current r8 line is methodologically cleaner than earlier iterations: unresolved groups are quarantined, "
            "TraeX judge output is advisory, and recall evidence is separated from semantic quality. The objective is "
            "still not complete because many reviewed groups need source/sink/guard evidence and the r8 recall evidence "
            "is inherited through sidecar equivalence rather than a fresh run after changed guideline text.",
            "",
            "The next concrete work is therefore evidence collection and mechanism-boundary repair, followed by a fresh "
            "same-identity P3C64 recall run only after the recall-consumed sidecar text changes.",
            "",
        ]
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scorecard", type=Path, required=True)
    parser.add_argument("--evidence-worklist-summary", type=Path, required=True)
    parser.add_argument("--recall-alignment-summary", type=Path)
    parser.add_argument("--recall-side-debug-summary", type=Path)
    parser.add_argument("--recall-side-miss-inspection-summary", type=Path)
    parser.add_argument("--boundary-recall-triage-summary", type=Path)
    parser.add_argument("--ledger-validation-summary", type=Path, action="append")
    parser.add_argument("--ledger-judge-summary", type=Path, action="append")
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--desired-delta-rate", type=float, default=0.10)
    args = parser.parse_args()
    if args.output_dir.exists() and any(args.output_dir.iterdir()):
        raise FileExistsError(f"refusing to overwrite non-empty output directory: {args.output_dir}")
    audit = build_audit(
        scorecard=read_json(args.scorecard),
        worklist=read_json(args.evidence_worklist_summary),
        desired_delta_rate=args.desired_delta_rate,
        recall_alignment=(
            read_json(args.recall_alignment_summary)
            if args.recall_alignment_summary
            else None
        ),
        recall_side_debug=(
            read_json(args.recall_side_debug_summary)
            if args.recall_side_debug_summary
            else None
        ),
        recall_side_miss_inspection=(
            read_json(args.recall_side_miss_inspection_summary)
            if args.recall_side_miss_inspection_summary
            else None
        ),
        boundary_recall_triage=(
            read_json(args.boundary_recall_triage_summary)
            if args.boundary_recall_triage_summary
            else None
        ),
        ledger_validation=aggregate_ledger_validations(
            [read_json(path) for path in (args.ledger_validation_summary or [])]
        ),
        ledger_judge=aggregate_ledger_judges(
            [read_json(path) for path in (args.ledger_judge_summary or [])]
        ),
    )
    args.output_dir.mkdir(parents=True, exist_ok=True)
    write_json(args.output_dir / "summary.json", audit)
    write_readme(args.output_dir / "README.md", audit)
    print(json.dumps({"overall_status": audit["overall_status"], "missing_count": len(audit["missing_or_incomplete_requirements"])}, sort_keys=True))


if __name__ == "__main__":
    main()
