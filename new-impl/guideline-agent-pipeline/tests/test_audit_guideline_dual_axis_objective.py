from __future__ import annotations

import importlib.util
import json
import math
import subprocess
import sys
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts" / "audit_guideline_dual_axis_objective.py"


def load_module():
    spec = importlib.util.spec_from_file_location("audit_guideline_dual_axis_objective", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def scorecard() -> dict:
    return {
        "judge_evidence": {
            "parsed_count": 2,
            "decision_counts": {"accept": 1, "needs_evidence": 1},
        },
        "structural_evidence": {
            "weighted_primary_hcvr_purity": 0.8,
            "weighted_cwe_purity": 0.9,
        },
        "recall_evidence": {
            "status": "valid_same_identity",
            "same_identity_set": True,
            "same_identity_order": True,
            "primary_budget": 100,
            "budgets": [{"budget": 100, "delta_rate": 0.12}],
        },
        "recall_equivalence_evidence": {"status": "not_needed"},
    }


def requirement(audit: dict, prefix: str) -> dict:
    for row in audit["requirements"]:
        if row["requirement"].startswith(prefix):
            return row
    raise AssertionError(f"missing requirement starting with {prefix!r}")


def test_audit_marks_semantic_gap_even_when_recall_passes():
    module = load_module()

    audit = module.build_audit(
        scorecard=scorecard(),
        worklist={"worklist_count": 1, "action_counts": {"collect_source_sink_guard_evidence": 1}},
        desired_delta_rate=0.10,
    )

    assert audit["overall_status"] == "not_complete"
    assert requirement(audit, "Design reusable guideline classification")["status"] == "partially_satisfied_needs_evidence"
    assert requirement(audit, "Keep guidelines compatible")["status"] == "satisfied_for_reported_same_identity_budget"
    assert audit["missing_or_incomplete_requirements"]


def test_audit_marks_recall_below_target():
    module = load_module()
    data = scorecard()
    data["judge_evidence"]["decision_counts"] = {"accept": 2}
    data["recall_evidence"]["budgets"] = [{"budget": 100, "delta_rate": 0.02}]

    audit = module.build_audit(
        scorecard=data,
        worklist={"worklist_count": 0, "action_counts": {}},
        desired_delta_rate=0.10,
    )

    assert audit["overall_status"] == "not_complete"
    assert requirement(audit, "Keep guidelines compatible")["status"] == "compatible_but_improvement_below_target"


def test_boundary_triage_is_recorded_without_completing_global_audit():
    module = load_module()

    audit = module.build_audit(
        scorecard=scorecard(),
        worklist={"worklist_count": 1, "action_counts": {"collect_source_sink_guard_evidence": 1}},
        desired_delta_rate=0.10,
        boundary_recall_triage={
            "rank_table_labels": ["p3c64-3case"],
            "next_action_counts": {
                "semantic_boundary_and_recall_examples_are_aligned_for_next_ablation": 1,
            },
        },
    )

    assert audit["overall_status"] == "not_complete"
    assert (
        "boundary_recall_triage_aligned_boundaries=1"
        in requirement(audit, "Keep guidelines compatible")["evidence"]
    )
    assert "1 source-reviewed boundary" in audit["next_gates"][2]["current_state"]


def test_recall_alignment_policy_is_diagnostic_not_completion_signal():
    module = load_module()

    audit = module.build_audit(
        scorecard=scorecard(),
        worklist={"worklist_count": 1, "action_counts": {"collect_source_sink_guard_evidence": 1}},
        desired_delta_rate=0.10,
        recall_alignment={
            "recall_label": "p3c64",
            "joined_recall_case_count": 28,
            "recall_case_count": 143,
            "same_identity_baseline": True,
            "attention_counts": {
                "label_mixed_structural_attention": 8,
                "embedding_or_candidate_recall_attention": 44,
            },
            "cleanliness_policy": {
                "label_mixture_is_blocking": False,
                "min_clean_purity_is_blocking": False,
            },
        },
    )

    assert audit["overall_status"] == "not_complete"
    alignment = audit["recall_alignment_evidence"]
    assert alignment["status"] == "provided"
    assert alignment["joined_recall_case_count"] == 28
    assert alignment["cleanliness_policy"]["label_mixture_is_blocking"] is False
    assert "label_mixture_is_blocking=False" in requirement(audit, "If semantic guideline quality")["evidence"]
    assert "recall_alignment_joined=28/143" in requirement(audit, "Keep guidelines compatible")["evidence"]


def test_recall_side_debug_pack_is_recorded_as_work_queue():
    module = load_module()

    audit = module.build_audit(
        scorecard=scorecard(),
        worklist={"worklist_count": 1, "action_counts": {"collect_source_sink_guard_evidence": 1}},
        desired_delta_rate=0.10,
        recall_side_debug={
            "recall_label": "p3c64",
            "debug_group_count": 6,
            "miss_state_totals": {
                "coverage_gap_not_in_rank_table": 9,
                "ranked_below_primary_budget": 6,
            },
            "recommended_check_counts": {
                "inspect_candidate_slicing_for_known_anchor_context": 6,
            },
        },
    )

    assert audit["overall_status"] == "not_complete"
    debug = audit["recall_side_debug_evidence"]
    assert debug["status"] == "provided"
    assert debug["debug_group_count"] == 6
    assert "recall_side_debug_group_count=6" in requirement(audit, "Keep guidelines compatible")["evidence"]
    assert "recall-side debug pack separates rank misses from rank-table coverage gaps" in requirement(audit, "If semantic guideline quality")["evidence"]


def test_recall_side_miss_inspection_is_rank_only_diagnostic_evidence():
    module = load_module()

    audit = module.build_audit(
        scorecard=scorecard(),
        worklist={"worklist_count": 1, "action_counts": {"collect_source_sink_guard_evidence": 1}},
        desired_delta_rate=0.10,
        recall_side_miss_inspection={
            "recall_label": "p3c64",
            "case_count": 15,
            "miss_state_counts": {
                "coverage_gap_not_in_rank_table": 9,
                "ranked_below_primary_budget": 6,
            },
            "diagnosis_counts": {
                "known_anchor_ranked_below_primary_budget": 6,
            },
            "next_check_counts": {
                "compare_embedding_backend_or_query_adapter_on_same_identity": 6,
            },
            "input_capability": {
                "full_ranked_candidate_lists": False,
            },
        },
    )

    assert audit["overall_status"] == "not_complete"
    inspection = audit["recall_side_miss_inspection_evidence"]
    assert inspection["status"] == "provided"
    assert inspection["case_count"] == 15
    assert inspection["input_capability"]["full_ranked_candidate_lists"] is False
    assert "recall_side_miss_inspection_case_count=15" in requirement(audit, "If semantic guideline quality")["evidence"]
    assert (
        "recall_side_miss_inspection_states={'coverage_gap_not_in_rank_table': 9, 'ranked_below_primary_budget': 6}"
        in requirement(audit, "If semantic guideline quality")["evidence"]
    )


def test_recall_side_miss_inspection_can_be_candidate_aware():
    module = load_module()

    audit = module.build_audit(
        scorecard=scorecard(),
        worklist={"worklist_count": 1, "action_counts": {"collect_source_sink_guard_evidence": 1}},
        desired_delta_rate=0.10,
        recall_side_miss_inspection={
            "recall_label": "p3c64",
            "case_count": 6,
            "miss_state_counts": {"ranked_below_primary_budget": 6},
            "diagnosis_counts": {
                "known_anchor_present_in_export_but_below_primary_budget": 6,
            },
            "next_check_counts": {
                "inspect_budget_or_reranker_need_on_same_identity": 3,
            },
            "input_capability": {
                "full_ranked_candidate_lists": True,
                "known_anchor_span_details": True,
            },
        },
    )

    inspection = audit["recall_side_miss_inspection_evidence"]
    assert inspection["input_capability"]["full_ranked_candidate_lists"] is True
    assert "exported Top-N candidate rows" in inspection["message"]
    assert "does not prove vulnerability precision" in inspection["message"]


def test_recall_candidate_judge_evidence_is_advisory_not_recall_completion():
    module = load_module()

    audit = module.build_audit(
        scorecard=scorecard(),
        worklist={"worklist_count": 1, "action_counts": {"collect_source_sink_guard_evidence": 1}},
        desired_delta_rate=0.10,
        recall_candidate_pair_judge={
            "judge_input_count": 6,
            "parsed_count": 6,
            "missing_output_count": 0,
            "invalid_output_count": 0,
            "choice_outcome_counts": {"anchor_overlap_chosen": 5, "neither": 1},
            "anchor_overlap_choice_rate": 5 / 6,
            "top1_choice_rate": 0.0,
        },
        recall_candidate_list_judge={
            "judge_input_count": 12,
            "parsed_prompt_count": 11,
            "missing_prompt_count": 0,
            "invalid_prompt_count": 2,
            "identity_count": 6,
            "identity_coverage_gap_count": 6,
            "judge_rerank_hit_rate_denominator": 0,
            "judge_rerank_hit_rates": {"top_1": None},
        },
    )

    assert audit["overall_status"] == "not_complete"
    judge = audit["recall_candidate_judge_evidence"]
    assert judge["status"] == "provided"
    assert judge["list_judge_status"] == "coverage_gap_only_not_rerank_hit_evidence"
    assert "not recall evidence" in judge["message"]
    assert (
        "recall_candidate_pair_anchor_overlap_choice_rate=0.8333333333333334"
        in requirement(audit, "Avoid hardcoding")["evidence"]
    )
    assert "recall_candidate_list_denominator=0" in requirement(audit, "Avoid hardcoding")["evidence"]


def test_aggregate_candidate_judge_summaries():
    module = load_module()

    pair = module.aggregate_candidate_pair_judges(
        [
            {
                "judge_input_count": 2,
                "parsed_count": 2,
                "missing_output_count": 0,
                "invalid_output_count": 0,
                "choice_outcome_counts": {"anchor_overlap_chosen": 1, "top1_chosen": 1},
                "choice_counts": {"A": 1, "B": 1},
            },
            {
                "judge_input_count": 1,
                "parsed_count": 1,
                "missing_output_count": 0,
                "invalid_output_count": 0,
                "choice_outcome_counts": {"anchor_overlap_chosen": 1},
                "choice_counts": {"B": 1},
            },
        ]
    )
    listwise = module.aggregate_candidate_list_judges(
        [
            {
                "judge_input_count": 2,
                "parsed_prompt_count": 2,
                "identity_count": 1,
                "identities_with_known_anchor_candidate": 1,
                "identities_with_scored_known_anchor_candidate": 1,
                "identity_coverage_gap_count": 0,
                "judge_rerank_hit_rate_denominator": 1,
                "judge_rerank_hit_counts": {"top_1": 0, "top_3": 1},
                "prompt_counts": {"parsed": 2},
            },
            {
                "judge_input_count": 1,
                "parsed_prompt_count": 1,
                "identity_count": 1,
                "identities_with_known_anchor_candidate": 0,
                "identities_with_scored_known_anchor_candidate": 0,
                "identity_coverage_gap_count": 1,
                "judge_rerank_hit_rate_denominator": 0,
                "judge_rerank_hit_counts": {"top_1": 0, "top_3": 0},
                "prompt_counts": {"parsed": 1},
            },
        ]
    )

    assert pair["parsed_count"] == 3
    assert pair["choice_outcome_counts"] == {"anchor_overlap_chosen": 2, "top1_chosen": 1}
    assert math.isclose(pair["anchor_overlap_choice_rate"], 2 / 3)
    assert listwise["identity_count"] == 2
    assert listwise["identity_coverage_gap_count"] == 1
    assert listwise["judge_rerank_hit_rate_denominator"] == 1
    assert listwise["judge_rerank_hit_rates"] == {"top_1": 0.0, "top_3": 1.0}


def test_source_reviewed_boundary_evidence_is_separate_from_recall_completion():
    module = load_module()

    audit = module.build_audit(
        scorecard=scorecard(),
        worklist={"worklist_count": 1, "action_counts": {"collect_source_sink_guard_evidence": 1}},
        desired_delta_rate=0.10,
        ledger_validation={
            "valid_count": 2,
            "invalid_count": 0,
            "promotable_count": 1,
            "decision_counts": {"promote_boundary": 1, "split_further": 1},
        },
        ledger_judge={
            "parsed_count": 2,
            "accepted_count": 2,
            "low_score_count": 1,
            "decision_counts": {"accept": 2},
            "average_scores": {"coherence_score": 0.925},
        },
    )

    assert audit["overall_status"] == "not_complete"
    reviewed = audit["source_reviewed_boundary_evidence"]
    assert reviewed["status"] == "satisfied_for_source_reviewed_boundaries"
    assert reviewed["promotable_count"] == 1
    assert "source_reviewed_boundary_status=satisfied_for_source_reviewed_boundaries" in requirement(audit, "Design reusable guideline classification")["evidence"]
    substitution_gate = next(
        gate for gate in audit["next_gates"] if gate["gate"] == "recall_method_substitution_gate"
    )
    assert "replacement embedder" in substitution_gate["pass_condition"]


def test_evidence_coverage_gate_prevents_partial_ledger_completion():
    module = load_module()

    data = scorecard()
    data["judge_evidence"]["decision_counts"] = {"accept": 2}
    audit = module.build_audit(
        scorecard=data,
        worklist={"worklist_count": 20, "action_counts": {"collect_source_sink_guard_evidence": 10}},
        desired_delta_rate=0.10,
        ledger_validation={
            "valid_count": 2,
            "invalid_count": 0,
            "promotable_count": 2,
            "decision_counts": {"promote_boundary": 2},
        },
        ledger_judge={
            "parsed_count": 2,
            "accepted_count": 2,
            "decision_counts": {"accept": 2},
        },
        evidence_coverage={
            "worklist_count": 20,
            "coverage_row_count": 20,
            "coverage_status_counts": {
                "not_source_reviewed": 16,
                "source_reviewed_and_judge_accepted": 3,
                "source_reviewed_validation_only": 1,
            },
            "next_action_counts": {
                "fill_source_review_ledger": 14,
                "optional_control_source_review": 2,
                "run_ledger_judge_pack": 1,
                "run_same_identity_recall_after_sidecar_change": 3,
            },
            "source_review_action_count": 18,
            "source_review_judge_accepted_count": 3,
        },
    )

    coverage = audit["source_review_coverage_evidence"]
    assert coverage["status"] == "not_satisfied_source_review_coverage_incomplete"
    assert coverage["blocking_next_action_count"] == 15
    assert audit["overall_status"] == "not_complete"
    coverage_requirement = requirement(audit, "Cover the semantic evidence worklist")
    assert coverage_requirement["status"] == "not_satisfied_source_review_coverage_incomplete"
    assert "coverage_blocking_next_action_count=15" in coverage_requirement["evidence"]
    semantic_gate = next(gate for gate in audit["next_gates"] if gate["gate"] == "semantic_evidence_gate")
    assert "blocking_next_actions=15" in semantic_gate["current_state"]


def test_evidence_coverage_can_be_semantic_ready_pending_recall_followup():
    module = load_module()

    coverage = module.source_review_coverage_evidence(
        {
            "worklist_count": 3,
            "coverage_row_count": 3,
            "coverage_status_counts": {"source_reviewed_and_judge_accepted": 3},
            "next_action_counts": {"run_same_identity_recall_after_sidecar_change": 3},
        }
    )

    assert coverage["status"] == "satisfied_semantic_coverage_pending_recall_followup"
    assert coverage["blocking_next_action_count"] == 0
    assert coverage["recall_followup_count"] == 3


def test_aggregate_multiple_source_reviewed_summaries():
    module = load_module()

    validation = module.aggregate_ledger_validations(
        [
            {
                "row_count": 2,
                "valid_count": 2,
                "invalid_count": 0,
                "promotable_count": 1,
                "decision_counts": {"promote_boundary": 1, "split_further": 1},
            },
            {
                "row_count": 4,
                "valid_count": 4,
                "invalid_count": 0,
                "promotable_count": 2,
                "decision_counts": {"promote_boundary": 2, "split_further": 1, "needs_more_evidence": 1},
            },
        ]
    )
    judge = module.aggregate_ledger_judges(
        [
            {
                "judge_input_count": 2,
                "parsed_count": 2,
                "accepted_count": 2,
                "needs_revision_count": 0,
                "low_score_count": 1,
                "decision_counts": {"accept": 2},
                "average_scores": {"coherence_score": 0.9},
            },
            {
                "judge_input_count": 3,
                "parsed_count": 3,
                "accepted_count": 2,
                "needs_revision_count": 1,
                "low_score_count": 1,
                "decision_counts": {"accept": 2, "needs_evidence": 1},
                "average_scores": {"coherence_score": 0.8},
            },
        ]
    )

    assert validation["summary_count"] == 2
    assert validation["row_count"] == 6
    assert validation["promotable_count"] == 3
    assert validation["decision_counts"] == {
        "needs_more_evidence": 1,
        "promote_boundary": 3,
        "split_further": 2,
    }
    assert judge["summary_count"] == 2
    assert judge["parsed_count"] == 5
    assert judge["accepted_count"] == 4
    assert judge["decision_counts"] == {"accept": 4, "needs_evidence": 1}
    assert math.isclose(judge["average_scores"]["coherence_score"], 0.84)


def test_cli_writes_dual_axis_audit(tmp_path: Path):
    scorecard_path = tmp_path / "scorecard.json"
    worklist_path = tmp_path / "worklist.json"
    coverage_path = tmp_path / "coverage.json"
    recall_alignment_path = tmp_path / "recall_alignment.json"
    recall_side_debug_path = tmp_path / "recall_side_debug.json"
    recall_side_miss_inspection_path = tmp_path / "recall_side_miss_inspection.json"
    pair_judge_path = tmp_path / "pair_judge.json"
    list_judge_path = tmp_path / "list_judge.json"
    ledger_validation_path = tmp_path / "ledger_validation.json"
    ledger_judge_path = tmp_path / "ledger_judge.json"
    output = tmp_path / "audit"
    scorecard_path.write_text(json.dumps(scorecard()), encoding="utf-8")
    worklist_path.write_text(
        json.dumps({"worklist_count": 1, "action_counts": {"collect_source_sink_guard_evidence": 1}}),
        encoding="utf-8",
    )
    coverage_path.write_text(
        json.dumps(
            {
                "worklist_count": 1,
                "coverage_row_count": 1,
                "coverage_status_counts": {"not_source_reviewed": 1},
                "next_action_counts": {"fill_source_review_ledger": 1},
            }
        ),
        encoding="utf-8",
    )
    recall_alignment_path.write_text(
        json.dumps(
            {
                "recall_label": "p3c64",
                "joined_recall_case_count": 28,
                "recall_case_count": 143,
                "same_identity_baseline": True,
                "attention_counts": {"label_mixed_structural_attention": 8},
                "cleanliness_policy": {"label_mixture_is_blocking": False},
            }
        ),
        encoding="utf-8",
    )
    recall_side_debug_path.write_text(
        json.dumps(
            {
                "recall_label": "p3c64",
                "debug_group_count": 6,
                "miss_state_totals": {"ranked_below_primary_budget": 6},
                "recommended_check_counts": {
                    "inspect_candidate_slicing_for_known_anchor_context": 6,
                },
            }
        ),
        encoding="utf-8",
    )
    recall_side_miss_inspection_path.write_text(
        json.dumps(
            {
                "recall_label": "p3c64",
                "case_count": 15,
                "miss_state_counts": {"ranked_below_primary_budget": 6},
            }
        ),
        encoding="utf-8",
    )
    ledger_validation_path.write_text(
        json.dumps({"valid_count": 1, "invalid_count": 0, "promotable_count": 1}),
        encoding="utf-8",
    )
    ledger_judge_path.write_text(
        json.dumps({"parsed_count": 1, "accepted_count": 1, "decision_counts": {"accept": 1}}),
        encoding="utf-8",
    )
    pair_judge_path.write_text(
        json.dumps(
            {
                "judge_input_count": 6,
                "parsed_count": 6,
                "choice_outcome_counts": {"anchor_overlap_chosen": 5, "neither": 1},
            }
        ),
        encoding="utf-8",
    )
    list_judge_path.write_text(
        json.dumps(
            {
                "judge_input_count": 12,
                "parsed_prompt_count": 11,
                "invalid_prompt_count": 2,
                "identity_count": 6,
                "identity_coverage_gap_count": 6,
                "judge_rerank_hit_rate_denominator": 0,
                "judge_rerank_hit_counts": {"top_1": 0},
            }
        ),
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--scorecard",
            str(scorecard_path),
            "--evidence-worklist-summary",
            str(worklist_path),
            "--evidence-coverage-summary",
            str(coverage_path),
            "--recall-alignment-summary",
            str(recall_alignment_path),
            "--recall-side-debug-summary",
            str(recall_side_debug_path),
            "--recall-side-miss-inspection-summary",
            str(recall_side_miss_inspection_path),
            "--ledger-validation-summary",
            str(ledger_validation_path),
            "--ledger-judge-summary",
            str(ledger_judge_path),
            "--recall-candidate-pair-judge-summary",
            str(pair_judge_path),
            "--recall-candidate-list-judge-summary",
            str(list_judge_path),
            "--output-dir",
            str(output),
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )

    assert result.returncode == 0
    summary = json.loads((output / "summary.json").read_text(encoding="utf-8"))
    assert summary["overall_status"] == "not_complete"
    readme = (output / "README.md").read_text(encoding="utf-8")
    assert "Guideline Dual-Axis Objective Audit" in readme
    assert "Source-Reviewed Boundary Evidence" in readme
    assert "Source-Review Coverage Gate" in readme
    assert "Recall Alignment Diagnostics" in readme
    assert "Recall-Side Debug Evidence" in readme
    assert "Recall-Side Case Inspection" in readme
    assert "Recall-Candidate Judge Diagnostics" in readme
    assert "coverage_gap_only_not_rerank_hit_evidence" in readme


def test_cli_accepts_repeated_source_reviewed_summaries(tmp_path: Path):
    scorecard_path = tmp_path / "scorecard.json"
    worklist_path = tmp_path / "worklist.json"
    validation_one = tmp_path / "ledger_validation_one.json"
    validation_two = tmp_path / "ledger_validation_two.json"
    judge_one = tmp_path / "ledger_judge_one.json"
    judge_two = tmp_path / "ledger_judge_two.json"
    output = tmp_path / "audit"
    scorecard_path.write_text(json.dumps(scorecard()), encoding="utf-8")
    worklist_path.write_text(
        json.dumps({"worklist_count": 1, "action_counts": {"collect_source_sink_guard_evidence": 1}}),
        encoding="utf-8",
    )
    validation_one.write_text(json.dumps({"row_count": 1, "valid_count": 1, "invalid_count": 0, "promotable_count": 1}), encoding="utf-8")
    validation_two.write_text(json.dumps({"row_count": 1, "valid_count": 1, "invalid_count": 0, "promotable_count": 1}), encoding="utf-8")
    judge_one.write_text(json.dumps({"judge_input_count": 1, "parsed_count": 1, "accepted_count": 1, "decision_counts": {"accept": 1}}), encoding="utf-8")
    judge_two.write_text(json.dumps({"judge_input_count": 1, "parsed_count": 1, "accepted_count": 1, "decision_counts": {"accept": 1}}), encoding="utf-8")

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--scorecard",
            str(scorecard_path),
            "--evidence-worklist-summary",
            str(worklist_path),
            "--ledger-validation-summary",
            str(validation_one),
            "--ledger-validation-summary",
            str(validation_two),
            "--ledger-judge-summary",
            str(judge_one),
            "--ledger-judge-summary",
            str(judge_two),
            "--output-dir",
            str(output),
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )

    assert result.returncode == 0
    reviewed = json.loads((output / "summary.json").read_text(encoding="utf-8"))["source_reviewed_boundary_evidence"]
    assert reviewed["valid_count"] == 2
    assert reviewed["promotable_count"] == 2
    assert reviewed["judge_accepted_count"] == 2
