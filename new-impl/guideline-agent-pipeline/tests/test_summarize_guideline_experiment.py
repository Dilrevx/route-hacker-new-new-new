from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts" / "summarize_guideline_experiment.py"


def load_module():
    spec = importlib.util.spec_from_file_location("summarize_guideline_experiment", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def release_summary() -> dict:
    return {
        "guideline_count": 3,
        "work_item_count": 5,
        "active_attribution_count": 4,
        "pending_review_count": 1,
        "override_count": 2,
        "pending_overrides_included": False,
        "source_fingerprint": "abc",
    }


def group_summary() -> dict:
    return {
        "guideline_count": 3,
        "evaluated_group_count": 2,
        "source_only_group_count": 1,
        "assigned_unique_case_count": 4,
        "total_case_count": 10,
        "case_coverage_rate": 0.4,
        "weighted_primary_hcvr_purity": 0.75,
        "weighted_cwe_purity": 0.8,
        "mixed_hcvr_group_count": 1,
        "mixed_cwe_group_count": 1,
        "pending_candidate_count": 1,
    }


def judge_summary() -> dict:
    return {
        "judge_input_count": 2,
        "parsed_count": 2,
        "missing_output_count": 0,
        "invalid_output_count": 0,
        "accepted_count": 1,
        "decision_counts": {"accept": 1, "revise": 1},
        "low_score_count": 1,
        "average_scores": {
            "coherence_score": 0.7,
            "coverage_score": 0.6,
            "actionability_score": 0.8,
            "retrieval_query_quality": 0.5,
        },
    }


def test_scorecard_marks_missing_recall_as_no_recall_claim():
    module = load_module()

    scorecard = module.build_scorecard(
        release_summary=release_summary(),
        group_summary=group_summary(),
        judge_summary=judge_summary(),
        recall_summary=None,
        release_label="r-test",
        desired_delta_rate=0.10,
    )

    recall_claim = next(item for item in scorecard["claim_boundaries"] if item["claim"] == "embedding_recall_improvement")
    assert scorecard["recall_evidence"]["status"] == "missing"
    assert recall_claim["status"] == "missing_or_invalid_evidence"
    assert "same identity" not in " ".join(recall_claim["evidence"]).lower()


def test_scorecard_accepts_same_identity_recall_budget_evidence():
    module = load_module()
    recall_summary = {
        "same_identity_set": True,
        "same_identity_order": True,
        "common_count": 10,
        "left_label": "new-guideline",
        "right_label": "baseline",
        "primary_budget": 100,
        "metrics_on_common_identities": {
            "hit_at_30": {
                "left_count": 4,
                "right_count": 3,
                "delta_count": 1,
                "left_rate": 0.4,
                "right_rate": 0.3,
                "delta_rate": 0.1,
            },
            "hit_at_100": {
                "left_count": 7,
                "right_count": 5,
                "delta_count": 2,
                "left_rate": 0.7,
                "right_rate": 0.5,
                "delta_rate": 0.2,
            },
            "mrr": {"left": 0.2, "right": 0.1, "delta": 0.1},
        },
    }

    scorecard = module.build_scorecard(
        release_summary=release_summary(),
        group_summary=group_summary(),
        judge_summary=None,
        recall_summary=recall_summary,
        release_label="r-test",
        desired_delta_rate=0.10,
    )

    recall_claim = next(item for item in scorecard["claim_boundaries"] if item["claim"] == "embedding_recall_improvement")
    assert scorecard["recall_evidence"]["status"] == "valid_same_identity"
    assert recall_claim["status"] == "supported_for_reported_budgets"
    assert any("Hit@100" in item for item in recall_claim["evidence"])
    assert scorecard["judge_evidence"]["status"] == "missing"


def test_scorecard_inherits_recall_when_sidecar_text_is_equivalent():
    module = load_module()
    recall_summary = {
        "same_identity_set": True,
        "same_identity_order": True,
        "common_count": 10,
        "left_label": "r7-measured",
        "right_label": "old-baseline",
        "primary_budget": 100,
        "metrics_on_common_identities": {
            "hit_at_100": {
                "left_count": 7,
                "right_count": 5,
                "delta_count": 2,
                "left_rate": 0.7,
                "right_rate": 0.5,
                "delta_rate": 0.2,
            }
        },
    }
    equivalence = {
        "recall_consumed_text_equivalent": True,
        "same_key_set": True,
        "left_label": "r7-sidecar",
        "right_label": "r8-sidecar",
        "left_count": 2,
        "right_count": 2,
        "common_count": 2,
        "changed_text_count": 0,
    }

    scorecard = module.build_scorecard(
        release_summary=release_summary(),
        group_summary=group_summary(),
        judge_summary=None,
        recall_summary=recall_summary,
        recall_equivalence=equivalence,
        release_label="r-test",
        desired_delta_rate=0.10,
    )

    recall_claim = next(item for item in scorecard["claim_boundaries"] if item["claim"] == "embedding_recall_improvement")
    assert scorecard["recall_evidence"]["status"] == "inherited_same_identity_by_sidecar_equivalence"
    assert scorecard["recall_equivalence_evidence"]["status"] == "valid_consumed_text_equivalence"
    assert recall_claim["status"] == "supported_for_reported_budgets"
    assert "inherited by sidecar equivalence" in recall_claim["caveat"]


def test_scorecard_does_not_inherit_recall_when_sidecar_text_differs():
    module = load_module()
    recall_summary = {
        "same_identity_set": True,
        "same_identity_order": True,
        "common_count": 10,
        "left_label": "r7-measured",
        "right_label": "old-baseline",
        "primary_budget": 100,
        "metrics_on_common_identities": {},
    }
    equivalence = {
        "recall_consumed_text_equivalent": False,
        "same_key_set": True,
        "changed_text_count": 1,
    }

    scorecard = module.build_scorecard(
        release_summary=release_summary(),
        group_summary=group_summary(),
        judge_summary=None,
        recall_summary=recall_summary,
        recall_equivalence=equivalence,
        release_label="r-test",
        desired_delta_rate=0.10,
    )

    assert scorecard["recall_evidence"]["status"] == "invalid_sidecar_equivalence"
    assert scorecard["recall_equivalence_evidence"]["status"] == "invalid_consumed_text_difference"


def test_cli_writes_json_and_markdown(tmp_path: Path):
    release_path = tmp_path / "release.json"
    group_path = tmp_path / "group.json"
    judge_path = tmp_path / "judge.json"
    recall_path = tmp_path / "recall.json"
    output_json = tmp_path / "scorecard.json"
    output_md = tmp_path / "README.md"
    equivalence_path = tmp_path / "equivalence.json"
    release_path.write_text(json.dumps(release_summary()), encoding="utf-8")
    group_path.write_text(json.dumps(group_summary()), encoding="utf-8")
    judge_path.write_text(json.dumps(judge_summary()), encoding="utf-8")
    recall_path.write_text(
        json.dumps(
            {
                "same_identity_set": False,
                "same_identity_order": False,
                "common_count": 1,
                "metrics_on_common_identities": {},
            }
        ),
        encoding="utf-8",
    )
    equivalence_path.write_text(
        json.dumps(
            {
                "recall_consumed_text_equivalent": True,
                "same_key_set": True,
                "changed_text_count": 0,
            }
        ),
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--release-summary",
            str(release_path),
            "--group-summary",
            str(group_path),
            "--judge-summary",
            str(judge_path),
            "--recall-comparison",
            str(recall_path),
            "--recall-equivalence",
            str(equivalence_path),
            "--release-label",
            "fixture-release",
            "--output-json",
            str(output_json),
            "--output-md",
            str(output_md),
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )

    assert result.returncode == 0
    scorecard = json.loads(output_json.read_text(encoding="utf-8"))
    assert scorecard["release_label"] == "fixture-release"
    assert scorecard["recall_evidence"]["status"] == "invalid_identity_mismatch"
    assert scorecard["recall_equivalence_evidence"]["status"] == "valid_consumed_text_equivalence"
    markdown = output_md.read_text(encoding="utf-8")
    assert "HCVR Guideline Experiment Scorecard" in markdown
    assert "invalid_identity_mismatch" in markdown
    assert "Sidecar Equivalence" in markdown
