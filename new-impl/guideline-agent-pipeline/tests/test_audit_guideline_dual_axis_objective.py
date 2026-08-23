from __future__ import annotations

import importlib.util
import json
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


def test_audit_marks_semantic_gap_even_when_recall_passes():
    module = load_module()

    audit = module.build_audit(
        scorecard=scorecard(),
        worklist={"worklist_count": 1, "action_counts": {"collect_source_sink_guard_evidence": 1}},
        desired_delta_rate=0.10,
    )

    assert audit["overall_status"] == "not_complete"
    assert audit["requirements"][0]["status"] == "partially_satisfied_needs_evidence"
    assert audit["requirements"][1]["status"] == "satisfied_for_reported_same_identity_budget"
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
    assert audit["requirements"][1]["status"] == "compatible_but_improvement_below_target"


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
        in audit["requirements"][1]["evidence"]
    )
    assert "1 source-reviewed boundary" in audit["next_gates"][2]["current_state"]


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
    assert "source_reviewed_boundary_status=satisfied_for_source_reviewed_boundaries" in audit["requirements"][0]["evidence"]
    substitution_gate = next(
        gate for gate in audit["next_gates"] if gate["gate"] == "recall_method_substitution_gate"
    )
    assert "replacement embedder" in substitution_gate["pass_condition"]


def test_cli_writes_dual_axis_audit(tmp_path: Path):
    scorecard_path = tmp_path / "scorecard.json"
    worklist_path = tmp_path / "worklist.json"
    ledger_validation_path = tmp_path / "ledger_validation.json"
    ledger_judge_path = tmp_path / "ledger_judge.json"
    output = tmp_path / "audit"
    scorecard_path.write_text(json.dumps(scorecard()), encoding="utf-8")
    worklist_path.write_text(
        json.dumps({"worklist_count": 1, "action_counts": {"collect_source_sink_guard_evidence": 1}}),
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

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--scorecard",
            str(scorecard_path),
            "--evidence-worklist-summary",
            str(worklist_path),
            "--ledger-validation-summary",
            str(ledger_validation_path),
            "--ledger-judge-summary",
            str(ledger_judge_path),
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
