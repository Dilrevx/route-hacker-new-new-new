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


def status_for_semantic_quality(
    scorecard: dict[str, Any],
    worklist: dict[str, Any],
    coverage: dict[str, Any] | None = None,
) -> str:
    coverage_status = str((coverage or {}).get("status") or "")
    if coverage_status in {"satisfied_semantic_coverage", "satisfied_semantic_coverage_pending_recall_followup"}:
        return "satisfied_by_source_review_coverage"
    if coverage_status.startswith("not_satisfied"):
        return coverage_status

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


def status_for_coverage_requirement(coverage: dict[str, Any], recall_status: str) -> str:
    coverage_status = str(coverage.get("status") or "")
    if (
        coverage_status == "satisfied_semantic_coverage_pending_recall_followup"
        and recall_status == "satisfied_for_reported_same_identity_budget"
    ):
        return "satisfied_semantic_coverage_with_recall_evidence"
    return coverage_status


def gap_for_coverage_requirement(coverage: dict[str, Any], coverage_requirement_status: str) -> str:
    if coverage_requirement_status == "satisfied_semantic_coverage_with_recall_evidence":
        return "Semantic coverage is satisfied and the changed sidecar has a valid same-identity recall A/B."
    if coverage_requirement_status == "satisfied_semantic_coverage":
        return "Semantic coverage is satisfied; same-identity recall is only required after recall-consumed text changes."
    if coverage.get("blocking_next_action_count"):
        return "Blocking source-review actions remain before the guideline taxonomy can be treated as semantically covered."
    return "After semantic coverage, recall-consumed text changes still need same-identity recall follow-up."


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


def aggregate_candidate_pair_judges(summaries: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not summaries:
        return None
    choice_outcome_counts: dict[str, int] = {}
    choice_counts: dict[str, int] = {}
    parsed_count = 0
    result = {
        "schema_version": "hcvr_recall_candidate_pair_judge_summary.aggregate.v1",
        "summary_count": len(summaries),
        "judge_input_count": 0,
        "parsed_count": 0,
        "missing_output_count": 0,
        "invalid_output_count": 0,
        "choice_outcome_counts": choice_outcome_counts,
        "choice_counts": choice_counts,
        "anchor_overlap_choice_rate": None,
        "top1_choice_rate": None,
    }
    for summary in summaries:
        current_parsed = int(summary.get("parsed_count") or 0)
        parsed_count += current_parsed
        result["judge_input_count"] += int(summary.get("judge_input_count") or 0)
        result["parsed_count"] += current_parsed
        result["missing_output_count"] += int(summary.get("missing_output_count") or 0)
        result["invalid_output_count"] += int(summary.get("invalid_output_count") or 0)
        add_counts(choice_outcome_counts, summary.get("choice_outcome_counts") or {})
        add_counts(choice_counts, summary.get("choice_counts") or {})
    result["choice_outcome_counts"] = dict(sorted(choice_outcome_counts.items()))
    result["choice_counts"] = dict(sorted(choice_counts.items()))
    if parsed_count:
        result["anchor_overlap_choice_rate"] = choice_outcome_counts.get("anchor_overlap_chosen", 0) / parsed_count
        result["top1_choice_rate"] = choice_outcome_counts.get("top1_chosen", 0) / parsed_count
    return result


def aggregate_candidate_list_judges(summaries: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not summaries:
        return None
    prompt_counts: dict[str, int] = {}
    hit_counts: dict[str, int] = {}
    result = {
        "schema_version": "hcvr_recall_candidate_list_judge_summary.aggregate.v1",
        "summary_count": len(summaries),
        "judge_input_count": 0,
        "parsed_prompt_count": 0,
        "missing_prompt_count": 0,
        "invalid_prompt_count": 0,
        "invalid_candidate_score_count": 0,
        "identity_count": 0,
        "identities_with_known_anchor_candidate": 0,
        "identities_with_scored_known_anchor_candidate": 0,
        "identity_coverage_gap_count": 0,
        "judge_rerank_hit_counts": hit_counts,
        "judge_rerank_hit_rates": {},
        "judge_rerank_hit_rate_denominator": 0,
        "prompt_counts": prompt_counts,
    }
    for summary in summaries:
        result["judge_input_count"] += int(summary.get("judge_input_count") or 0)
        result["parsed_prompt_count"] += int(summary.get("parsed_prompt_count") or 0)
        result["missing_prompt_count"] += int(summary.get("missing_prompt_count") or 0)
        result["invalid_prompt_count"] += int(summary.get("invalid_prompt_count") or 0)
        result["invalid_candidate_score_count"] += int(summary.get("invalid_candidate_score_count") or 0)
        result["identity_count"] += int(summary.get("identity_count") or 0)
        result["identities_with_known_anchor_candidate"] += int(summary.get("identities_with_known_anchor_candidate") or 0)
        result["identities_with_scored_known_anchor_candidate"] += int(
            summary.get("identities_with_scored_known_anchor_candidate") or 0
        )
        result["identity_coverage_gap_count"] += int(summary.get("identity_coverage_gap_count") or 0)
        result["judge_rerank_hit_rate_denominator"] += int(summary.get("judge_rerank_hit_rate_denominator") or 0)
        add_counts(prompt_counts, summary.get("prompt_counts") or {})
        add_counts(hit_counts, summary.get("judge_rerank_hit_counts") or {})
    result["prompt_counts"] = dict(sorted(prompt_counts.items()))
    result["judge_rerank_hit_counts"] = dict(sorted(hit_counts.items()))
    denominator = int(result["judge_rerank_hit_rate_denominator"] or 0)
    result["judge_rerank_hit_rates"] = {
        key: (count / denominator if denominator else None)
        for key, count in sorted(hit_counts.items())
    }
    return result


def recall_candidate_judge_evidence(
    pair_judge: dict[str, Any] | None,
    list_judge: dict[str, Any] | None,
) -> dict[str, Any]:
    if not pair_judge and not list_judge:
        return {
            "status": "not_provided",
            "message": "No recall-candidate judge diagnostics were provided.",
        }
    list_denominator = int((list_judge or {}).get("judge_rerank_hit_rate_denominator") or 0)
    if list_judge and list_denominator:
        list_status = "eligible_for_offline_rerank_diagnostic"
    elif list_judge:
        list_status = "coverage_gap_only_not_rerank_hit_evidence"
    else:
        list_status = "not_provided"
    return {
        "status": "provided",
        "pair_judge": pair_judge or {},
        "list_judge": list_judge or {},
        "list_judge_status": list_status,
        "message": (
            "Recall-candidate judge evidence is advisory for query/reranker design only. Pair prompts are "
            "oracle-shaped sanity checks, while list-wise prompts are closer to production reranking but only "
            "estimate Hit@K when the judged candidate set contains known-anchor-overlap candidates. These "
            "diagnostics are not recall evidence and do not update guidelines, sidecars, ranking, embedding "
            "weights, or paper recall metrics."
        ),
    }


def source_review_coverage_evidence(coverage_summary: dict[str, Any] | None) -> dict[str, Any]:
    if not coverage_summary:
        return {
            "status": "not_provided",
            "coverage_row_count": 0,
            "blocking_next_action_count": None,
            "message": "No source-review evidence coverage summary was provided.",
        }
    next_action_counts = (
        coverage_summary.get("next_action_counts")
        if isinstance(coverage_summary.get("next_action_counts"), dict)
        else {}
    )
    coverage_status_counts = (
        coverage_summary.get("coverage_status_counts")
        if isinstance(coverage_summary.get("coverage_status_counts"), dict)
        else {}
    )
    blocking_next_actions = {
        "fill_source_review_ledger",
        "fix_invalid_ledger_rows",
        "collect_missing_boundary_evidence",
        "run_ledger_judge_pack",
        "collect_or_assign_representative_cases",
    }
    blocking_count = sum(int(next_action_counts.get(action) or 0) for action in blocking_next_actions)
    recall_followup_count = int(next_action_counts.get("run_same_identity_recall_after_sidecar_change") or 0)
    optional_control_count = int(next_action_counts.get("optional_control_source_review") or 0)
    if blocking_count:
        status = "not_satisfied_source_review_coverage_incomplete"
    elif recall_followup_count:
        status = "satisfied_semantic_coverage_pending_recall_followup"
    else:
        status = "satisfied_semantic_coverage"
    return {
        "status": status,
        "worklist_count": coverage_summary.get("worklist_count"),
        "coverage_row_count": coverage_summary.get("coverage_row_count"),
        "coverage_status_counts": coverage_status_counts,
        "next_action_counts": next_action_counts,
        "blocking_next_action_count": blocking_count,
        "recall_followup_count": recall_followup_count,
        "optional_control_count": optional_control_count,
        "source_review_action_count": coverage_summary.get("source_review_action_count"),
        "source_review_judge_accepted_count": coverage_summary.get("source_review_judge_accepted_count"),
        "source_review_validation_only_count": coverage_summary.get("source_review_validation_only_count"),
        "promotable_valid_boundary_count": coverage_summary.get("promotable_valid_boundary_count"),
        "promotable_judge_accept_boundary_count": coverage_summary.get("promotable_judge_accept_boundary_count"),
        "message": (
            "Source-review coverage is a completion gate for semantic guideline work. It is diagnostic only "
            "and does not update released guidelines, sidecars, embeddings, rank tables, or audit prompts."
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
    recall_candidate_pair_judge: dict[str, Any] | None = None,
    recall_candidate_list_judge: dict[str, Any] | None = None,
    evidence_coverage: dict[str, Any] | None = None,
) -> dict[str, Any]:
    recall = scorecard.get("recall_evidence") if isinstance(scorecard.get("recall_evidence"), dict) else {}
    judge = scorecard.get("judge_evidence") if isinstance(scorecard.get("judge_evidence"), dict) else {}
    structural = scorecard.get("structural_evidence") if isinstance(scorecard.get("structural_evidence"), dict) else {}
    recall_equivalence = (
        scorecard.get("recall_equivalence_evidence")
        if isinstance(scorecard.get("recall_equivalence_evidence"), dict)
        else {}
    )
    reviewed_boundary = source_reviewed_boundary_evidence(ledger_validation, ledger_judge)
    coverage = source_review_coverage_evidence(evidence_coverage)
    recall_status = status_for_recall(scorecard, desired_delta_rate)
    semantic_status = status_for_semantic_quality(scorecard, worklist, coverage)
    coverage_requirement_status = status_for_coverage_requirement(coverage, recall_status)
    candidate_judge = recall_candidate_judge_evidence(
        recall_candidate_pair_judge,
        recall_candidate_list_judge,
    )
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
    if recall_status == "satisfied_for_reported_same_identity_budget":
        recall_gap = "The evaluated guideline/query plus embedding configuration has valid same-identity recall evidence at the reported budget."
    else:
        recall_gap = "A fresh same-identity recall run is required after any consumed guideline text changes."
    recall_claim_status = next(
        (
            claim.get("status")
            for claim in scorecard.get("claim_boundaries", [])
            if isinstance(claim, dict) and claim.get("claim") == "embedding_recall_improvement"
        ),
        None,
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
            "gap": (
                "Source-review coverage has no blocking evidence actions for this candidate; remaining semantic evidence caveats are tracked as advisory review signals."
                if semantic_status == "satisfied_by_source_review_coverage"
                else "LLM judge still finds many groups needing source/sink/guard evidence or split/revision work."
            ),
        },
        {
            "requirement": "Cover the semantic evidence worklist before treating guideline classification as complete.",
            "evidence": [
                f"evidence_coverage_status={coverage.get('status')}",
                f"coverage_rows={coverage.get('coverage_row_count')}/{coverage.get('worklist_count')}",
                f"coverage_status_counts={coverage.get('coverage_status_counts')}",
                f"coverage_next_action_counts={coverage.get('next_action_counts')}",
                f"coverage_blocking_next_action_count={coverage.get('blocking_next_action_count')}",
                f"coverage_recall_followup_count={coverage.get('recall_followup_count')}",
                f"source_review_judge_accepted={coverage.get('source_review_judge_accepted_count')}/{coverage.get('source_review_action_count')}",
            ],
            "status": coverage_requirement_status,
            "gap": gap_for_coverage_requirement(coverage, coverage_requirement_status),
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
            "gap": recall_gap,
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
                f"scorecard_recall_claim_status={recall_claim_status}",
                "RRF/fusion is documented as a recall-compatible engineering path, not a guideline-quality claim",
                "LLM judge output feeds backlog/worklist rather than released guidelines or ranking",
                "new embedders, fusion, or rerankers are allowed only as explicit same-identity A/B configurations",
                f"recall_candidate_pair_anchor_overlap_choice_rate={(candidate_judge.get('pair_judge') or {}).get('anchor_overlap_choice_rate')}",
                f"recall_candidate_list_status={candidate_judge.get('list_judge_status')}",
                f"recall_candidate_list_denominator={(candidate_judge.get('list_judge') or {}).get('judge_rerank_hit_rate_denominator')}",
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
            "current_state": (
                f"{coverage.get('status')}; blocking_next_actions={coverage.get('blocking_next_action_count')}; "
                f"next_actions={coverage.get('next_action_counts')}"
            ),
        },
        {
            "gate": "same_identity_recall_gate",
            "run_when": "after recall-consumed guideline sidecar text changes",
            "pass_condition": "same_identity_set=true and same_identity_order=true against the frozen comparison baseline",
            "current_state": (
                "satisfied for the current changed sidecar by fresh same-identity recall evidence"
                if recall_status == "satisfied_for_reported_same_identity_budget"
                else "required for the current changed sidecar before retrieval claims"
            ),
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
        "source_review_coverage_evidence": coverage,
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
        "recall_candidate_judge_evidence": candidate_judge,
        "missing_or_incomplete_requirements": missing,
        "next_gates": next_gates,
        "decision": (
            "Continue guideline-v2 work through evidence collection before rewriting released guidelines. "
            "Do not mark the objective complete until semantic evidence improves and any changed sidecar has a fresh same-identity recall evaluation."
        )
        if missing
        else (
            "Objective is covered by current artifacts for this scoped candidate: semantic coverage is source-reviewed, "
            "fresh same-identity recall supports the embedding path, and paper-facing claim boundaries remain separated."
        ),
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
    coverage = audit.get("source_review_coverage_evidence") or {}
    alignment = audit.get("recall_alignment_evidence") or {}
    recall_debug = audit.get("recall_side_debug_evidence") or {}
    recall_miss_inspection = audit.get("recall_side_miss_inspection_evidence") or {}
    candidate_judge = audit.get("recall_candidate_judge_evidence") or {}
    pair_judge = candidate_judge.get("pair_judge") if isinstance(candidate_judge.get("pair_judge"), dict) else {}
    list_judge = candidate_judge.get("list_judge") if isinstance(candidate_judge.get("list_judge"), dict) else {}
    lines.extend(
        [
            "",
            "## Source-Review Coverage Gate",
            "",
            f"- Status: `{coverage.get('status')}`",
            f"- Coverage rows: {coverage.get('coverage_row_count')} / {coverage.get('worklist_count')}",
            f"- Coverage statuses: {coverage.get('coverage_status_counts')}",
            f"- Next actions: {coverage.get('next_action_counts')}",
            f"- Blocking next actions: {coverage.get('blocking_next_action_count')}",
            f"- Recall follow-up rows: {coverage.get('recall_followup_count')}",
            f"- Source-review actions accepted by judge: {coverage.get('source_review_judge_accepted_count')} / {coverage.get('source_review_action_count')}",
            "",
            "This gate prevents a partially source-reviewed ledger set from being mistaken for full guideline readiness. It is still a planning artifact only: it does not mutate guideline text, recall sidecars, embedding inputs, ranking outputs, or audit prompts.",
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
            "## Recall-Candidate Judge Diagnostics",
            "",
            f"- Status: `{candidate_judge.get('status')}`",
            f"- Pair judge parsed/missing/invalid: {pair_judge.get('parsed_count')} / {pair_judge.get('missing_output_count')} / {pair_judge.get('invalid_output_count')}",
            f"- Pair judge outcome counts: {pair_judge.get('choice_outcome_counts')}",
            f"- Pair judge anchor-overlap choice rate: {pair_judge.get('anchor_overlap_choice_rate')}",
            f"- List judge status: `{candidate_judge.get('list_judge_status')}`",
            f"- List judge prompts parsed/missing/invalid: {list_judge.get('parsed_prompt_count')} / {list_judge.get('missing_prompt_count')} / {list_judge.get('invalid_prompt_count')}",
            f"- List judge identity coverage gaps: {list_judge.get('identity_coverage_gap_count')}",
            f"- List judge rerank denominator: {list_judge.get('judge_rerank_hit_rate_denominator')}",
            "",
            "Candidate judge outputs are useful for deciding whether to try a reranker, wider candidate budget, or query rewrite. They are not recall evidence and they do not change guideline text, sidecars, embeddings, ranking, or audit prompts.",
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
    if audit["overall_status"] == "complete":
        interpretation = [
            "The current scoped candidate satisfies the dual-axis gate recorded here: source-review coverage has no blocking evidence action, and the changed recall-consumed sidecar has fresh same-identity recall evidence over the evaluated identities.",
            "",
            "Paper text should still separate semantic guideline quality from retrieval performance. This audit supports the evaluated guideline/query plus embedding configuration, not an unconditional claim that the taxonomy is optimal for every future model or dataset split.",
        ]
    else:
        interpretation = [
            "The current r8 line is methodologically cleaner than earlier iterations: unresolved groups are quarantined, LLM judge output is advisory, and recall evidence is separated from semantic quality. The objective is still not complete because at least one semantic or recall gate remains incomplete.",
            "",
            "The next concrete work is therefore to close the listed missing requirements, then rerun same-identity recall only when the recall-consumed sidecar text changes.",
        ]
    lines.extend(["", "## Interpretation", "", *interpretation, ""])
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scorecard", type=Path, required=True)
    parser.add_argument("--evidence-worklist-summary", type=Path, required=True)
    parser.add_argument("--evidence-coverage-summary", type=Path)
    parser.add_argument("--recall-alignment-summary", type=Path)
    parser.add_argument("--recall-side-debug-summary", type=Path)
    parser.add_argument("--recall-side-miss-inspection-summary", type=Path)
    parser.add_argument("--boundary-recall-triage-summary", type=Path)
    parser.add_argument("--ledger-validation-summary", type=Path, action="append")
    parser.add_argument("--ledger-judge-summary", type=Path, action="append")
    parser.add_argument("--recall-candidate-pair-judge-summary", type=Path, action="append")
    parser.add_argument("--recall-candidate-list-judge-summary", type=Path, action="append")
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
        recall_candidate_pair_judge=aggregate_candidate_pair_judges(
            [read_json(path) for path in (args.recall_candidate_pair_judge_summary or [])]
        ),
        recall_candidate_list_judge=aggregate_candidate_list_judges(
            [read_json(path) for path in (args.recall_candidate_list_judge_summary or [])]
        ),
        evidence_coverage=(
            read_json(args.evidence_coverage_summary)
            if args.evidence_coverage_summary
            else None
        ),
    )
    args.output_dir.mkdir(parents=True, exist_ok=True)
    write_json(args.output_dir / "summary.json", audit)
    write_readme(args.output_dir / "README.md", audit)
    print(json.dumps({"overall_status": audit["overall_status"], "missing_count": len(audit["missing_or_incomplete_requirements"])}, sort_keys=True))


if __name__ == "__main__":
    main()
