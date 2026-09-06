from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts" / "run_hcvr_ablation_a.py"


def load_module():
    spec = importlib.util.spec_from_file_location("hcvr_ablation_a", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def sample_case() -> dict:
    return {
        "identity_key": "owner__repo::CVE-2099-0001",
        "new_unified_case_id": "case::1",
        "repository": {"repo_url": "https://example.invalid/owner/repo.git"},
        "revisions": {"checkout_revision": "a" * 40},
        "classification": {
            "primary_hcvr_type": "sql_like_pattern_misuse",
            "cwe_ids": ["CWE-20"],
        },
        "vulnerability": {"id": "CVE-2099-0001"},
        "vulnerability_trace": {
            "nodes": [
                {
                    "trace_node_id": "trace::one",
                    "file": "src/App.java",
                    "start_line": 10,
                    "end_line": 20,
                    "symbol": "App.first",
                    "span_kind": "method",
                },
                {
                    "trace_node_id": "trace::two",
                    "file": "src/App.java",
                    "start_line": 30,
                    "end_line": 40,
                    "symbol": "App.second",
                    "span_kind": "method",
                },
            ]
        },
    }


def anchors(count: int) -> list[dict]:
    return [
        {
            "anchor_id": f"anchor::{index}",
            "file": "src/App.java",
            "start_line": index,
            "end_line": index,
            "symbol": f"App.m{index}",
            "span_kind": "method",
            "rank": index,
        }
        for index in range(1, count + 1)
    ]


def test_directory_groups_cover_all_top_k_once_and_keep_nearby_files(tmp_path: Path):
    module = load_module()
    grouped = module.group_anchors_by_directory(
        [
            {**anchor, "file": f"src/near/{index}.java"} if index <= 10
            else {**anchor, "file": f"src/far/{index}.java"}
            for index, anchor in enumerate(anchors(12), start=1)
        ],
        10,
    )
    assert [anchor["rank"] for group in grouped for anchor in group] == list(range(1, 13))
    assert len(grouped) == 2
    assert all(anchor["file"].startswith("src/near/") for anchor in grouped[0])


def test_group_prompt_is_bounded_and_allows_local_agentic_exploration(tmp_path: Path):
    module = load_module()
    prompt = module.build_group_prompt(
        case=sample_case(),
        snapshot=tmp_path,
        variant="full",
        anchors=anchors(10),
        group_index=1,
        group_count=20,
        model_budget_note="test",
    )
    assert "Candidate group 1/20 (10 anchors" in prompt
    assert "rank=10 id=anchor::10" in prompt
    assert "agentic repository exploration" in prompt
    assert "repository-wide generic vulnerability search" in prompt
    assert "Finish this group promptly" in prompt
    assert "candidate_dispositions" in prompt
    assert "one structured finding for every distinct" in prompt
    assert "Emit at most one primary finding" not in prompt
    assert "CVE-2099-0001" not in prompt


def test_minus_rank_keeps_identical_candidates_but_hides_rank(tmp_path: Path):
    module = load_module()
    ranked = anchors(10)
    unranked = module.remove_rank_order(ranked)
    assert {anchor["anchor_id"] for anchor in unranked} == {anchor["anchor_id"] for anchor in ranked}
    prompt = module.build_group_prompt(
        case=sample_case(),
        snapshot=tmp_path,
        variant="minus_rank",
        anchors=unranked,
        group_index=1,
        group_count=1,
        model_budget_note="test",
    )
    assert "deliberately unsorted" in prompt
    assert "rank=" not in prompt
    assert module.group_anchors_by_directory(ranked, 4) == module.group_anchors_by_directory(unranked, 4)


def test_minus_guideline_hides_hcvr_family_and_case_identity(tmp_path: Path):
    module = load_module()
    prompt = module.build_group_prompt(
        case=sample_case(),
        snapshot=tmp_path,
        variant="minus_guideline",
        anchors=anchors(10),
        group_index=1,
        group_count=1,
        model_budget_note="test",
    )
    assert "HCVR vulnerability family" not in prompt
    assert "sql_like_pattern_misuse" not in prompt
    assert "CVE-2099-0001" not in prompt


def test_candidate_disposition_validation_requires_exact_one_to_one_match():
    module = load_module()
    selected = anchors(2)
    valid, error = module.validate_candidate_dispositions(
        [
            {"anchor_id": "anchor::1", "status": "dismissed"},
            {"anchor_id": "anchor::2", "status": "risk"},
        ],
        selected,
    )
    assert valid is True
    assert error == ""
    valid, error = module.validate_candidate_dispositions(
        [
            {"anchor_id": "anchor::1", "status": "dismissed"},
            {"anchor_id": "anchor::1", "status": "risk"},
        ],
        selected,
    )
    assert valid is False
    assert "mismatch" in error


def test_formal_gate_rejects_completed_case_with_bad_group_dispositions():
    module = load_module()
    row = {
        "state": "completed",
        "groups": [
            {
                "group_index": 1,
                "state": "completed",
                "anchors": anchors(2),
                "candidate_dispositions": [
                    {"anchor_id": "anchor::1", "status": "dismissed"},
                    {"anchor_id": "anchor::1", "status": "risk"},
                ],
            }
        ],
    }
    complete, error = module.case_receipt_is_complete(row)
    assert complete is False
    assert "group_1" in error


def test_type_guideline_override_replaces_only_matching_type():
    module = load_module()
    override = {"sql_like_pattern_misuse": "Audit SQL LIKE pattern construction only."}
    rendered = module.build_type_guideline(sample_case(), override)
    assert "Audit SQL LIKE pattern construction only." in rendered
    assert "CVE-2099-0001" not in rendered


def test_normalize_findings_preserves_all_valid_findings():
    module = load_module()
    findings = module.normalize_findings(
        {
            "findings": [
                {"file": "src/App.java", "start_line": 10, "end_line": 20},
                {"file": "src/App.java", "start_line": 30, "end_line": 40},
            ]
        },
        "",
    )
    assert len(findings) == 2


def test_score_variant_counts_multiple_findings_and_distinct_truth_methods(tmp_path: Path):
    module = load_module()
    variant_dir = tmp_path / "full"
    variant_dir.mkdir()
    row = {
        "identity_key": "owner__repo::CVE-2099-0001",
        "state": "completed",
        "findings": [
            {"file": "src/App.java", "start_line": 12, "end_line": 15, "symbol": "App.first"},
            {"file": "src/App.java", "start_line": 32, "end_line": 35, "symbol": "App.second"},
            {"file": "src/Other.java", "start_line": 1, "end_line": 1, "symbol": "Other.nope"},
        ],
    }
    (variant_dir / "case_results.jsonl").write_text(json.dumps(row) + "\n", encoding="utf-8")
    score = module.score_variant(
        variant_dir,
        {"owner__repo::CVE-2099-0001": sample_case()},
        denominator=1,
    )
    assert score["tp"] == 1
    assert score["fp"] == 2
    assert score["fn"] == 0
    assert score["alarms"] == 3
    assert score["recall"] == 1.0
    assert score["precision"] == 1 / 3
    assert score["alarms"] == score["tp"] + score["fp"]
