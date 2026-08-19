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


def test_prompt_keeps_all_top_k_and_allows_agentic_exploration(tmp_path: Path):
    module = load_module()
    prompt = module.build_case_prompt(
        case=sample_case(),
        snapshot=tmp_path,
        variant="full",
        anchors=anchors(65),
        anchor_batch_size=30,
        model_budget_note="test",
    )
    assert "Candidate batch 1/3" in prompt
    assert "Candidate batch 3/3" in prompt
    assert "65. id=anchor::65" in prompt
    assert "agentic repository exploration" in prompt
    assert "one structured finding for every distinct" in prompt
    assert "Emit at most one primary finding" not in prompt
    assert "CVE-2099-0001" not in prompt


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
    assert score["fp"] == 1
    assert score["fn"] == 0
    assert score["alarms"] == 3
    assert score["recall"] == 1.0
    assert score["precision"] == 1 / 3
