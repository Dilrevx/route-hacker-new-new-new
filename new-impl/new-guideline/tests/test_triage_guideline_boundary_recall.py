from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts" / "triage_guideline_boundary_recall.py"


def load_module():
    spec = importlib.util.spec_from_file_location("triage_guideline_boundary_recall", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def promotable_row() -> dict:
    return {
        "guideline_id": "gl_a",
        "mechanism_id": "mech_a",
        "boundary_label": "candidate_boundary_01",
        "boundary_decision": "promote_boundary",
        "representative_cases": ["repo::CVE-1", "repo::CVE-2"],
        "source_shape": "source",
        "sink_or_sensitive_effect": "sink",
        "missing_guard": "guard",
        "exploit_precondition": "precondition",
        "safe_fix_semantics": "fix",
    }


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


def test_promotable_boundary_with_missing_rank_rows_is_coverage_gap():
    module = load_module()

    summary, rows = module.build_triage(
        ledger_rows=[promotable_row()],
        rank_tables={"p3c64": [{"identity_key": "repo::CVE-1", "best_known_anchor_rank": 20}]},
        budgets=[30, 100],
        primary_budget=100,
    )

    assert summary["semantic_status_counts"] == {"source_reviewed_promotable": 1}
    assert rows[0]["recall"]["p3c64"]["status"] == "recall_coverage_gap"
    assert rows[0]["recall"]["p3c64"]["missing_identities"] == ["repo::CVE-2"]
    assert rows[0]["next_action"] == "run_same_identity_recall_for_this_boundary_before_claiming_embedding_effect"


def test_promotable_boundary_with_all_hits_is_aligned_for_ablation():
    module = load_module()

    _, rows = module.build_triage(
        ledger_rows=[promotable_row()],
        rank_tables={
            "p3c64": [
                {"identity_key": "repo::CVE-1", "best_known_anchor_rank": 20},
                {"identity_key": "repo::CVE-2", "rank": 99},
            ]
        },
        budgets=[30, 100],
        primary_budget=100,
    )

    assert rows[0]["recall"]["p3c64"]["status"] == "recall_supported_for_boundary_examples"
    assert rows[0]["recall"]["p3c64"]["budget_hits"]["hit_at_100"]["hit_count"] == 2
    assert rows[0]["next_action"] == "semantic_boundary_and_recall_examples_are_aligned_for_next_ablation"


def test_incomplete_semantic_boundary_blocks_recall_interpretation():
    module = load_module()
    row = promotable_row()
    row["source_shape"] = ""

    _, rows = module.build_triage(
        ledger_rows=[row],
        rank_tables={
            "p3c64": [
                {"identity_key": "repo::CVE-1", "best_known_anchor_rank": 20},
                {"identity_key": "repo::CVE-2", "best_known_anchor_rank": 25},
            ]
        },
        budgets=[30, 100],
        primary_budget=100,
    )

    assert rows[0]["semantic_status"] == "promotion_incomplete"
    assert rows[0]["semantic_missing_fields"] == ["source_shape"]
    assert rows[0]["next_action"] == "collect_source_sink_guard_fix_evidence_before_recall_interpretation"


def test_cli_writes_triage_report(tmp_path: Path):
    ledger = tmp_path / "ledger.jsonl"
    ranks = tmp_path / "ranks.jsonl"
    output = tmp_path / "triage"
    write_jsonl(ledger, [promotable_row()])
    write_jsonl(
        ranks,
        [
            {"identity_key": "repo::CVE-1", "best_known_anchor_rank": 10},
            {"identity_key": "repo::CVE-2", "best_known_anchor_rank": 300},
        ],
    )

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--ledger",
            str(ledger),
            "--rank-table",
            f"p3c64={ranks}",
            "--output-dir",
            str(output),
            "--budgets",
            "30,100",
            "--primary-budget",
            "100",
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )

    assert result.returncode == 0
    summary = json.loads((output / "summary.json").read_text(encoding="utf-8"))
    assert summary["boundary_count"] == 1
    assert "Guideline Boundary Recall Triage" in (output / "README.md").read_text(encoding="utf-8")
