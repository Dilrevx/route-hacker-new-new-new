from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts" / "diagnose_guideline_recall_alignment.py"


def load_module():
    spec = importlib.util.spec_from_file_location("diagnose_guideline_recall_alignment", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


def clean_group() -> dict:
    return {
        "guideline_id": "gl_clean",
        "guideline_group_key": "cluster_a__mech_clean",
        "mechanism_id": "mech_clean",
        "mechanism_name": "clean mechanism",
        "mechanism_family": "authz",
        "flags": [],
        "primary_hcvr_purity": 1.0,
        "cwe_purity": 1.0,
    }


def pending_group() -> dict:
    return {
        "guideline_id": "gl_pending",
        "guideline_group_key": "cluster_b__pending",
        "mechanism_id": "pending_mech_b",
        "mechanism_name": "pending",
        "mechanism_family": "pending_review",
        "flags": ["pending_review"],
        "primary_hcvr_purity": 1.0,
        "cwe_purity": 1.0,
    }


def mixed_label_group() -> dict:
    return {
        "guideline_id": "gl_mixed",
        "guideline_group_key": "cluster_c__mech_cross_label",
        "mechanism_id": "mech_cross_label",
        "mechanism_name": "cross-label mechanism",
        "mechanism_family": "ssrf",
        "flags": ["mixed_hcvr", "mixed_cwe"],
        "primary_hcvr_purity": 0.5,
        "cwe_purity": 0.5,
    }


def test_clean_group_with_misses_points_to_embedding_or_candidate_recall():
    module = load_module()
    summary, group_rows, case_rows = module.diagnose(
        group_rows=[clean_group(), pending_group()],
        assignments={
            "gl_clean": [
                {"identity_key": "case-a", "primary_hcvr_type": "authz"},
                {"identity_key": "case-b", "primary_hcvr_type": "authz"},
            ],
            "gl_pending": [{"identity_key": "case-c", "primary_hcvr_type": "ssrf"}],
        },
        recall_rows=[
            {"identity_key": "case-a", "rank": 500},
            {"identity_key": "case-b", "rank": None},
            {"identity_key": "case-c", "rank": 3},
        ],
        recall_label="candidate",
        baseline_rows=None,
        baseline_label=None,
        budgets=[100],
        primary_budget=100,
        min_purity=0.67,
    )

    by_guideline = {row["guideline_id"]: row for row in group_rows}
    assert summary["joined_recall_case_count"] == 3
    assert "embedding_or_candidate_recall_attention" in by_guideline["gl_clean"]["attention"]
    assert "guideline_quality_attention" not in by_guideline["gl_clean"]["attention"]
    assert "guideline_pending_review" in by_guideline["gl_pending"]["attention"]
    assert len(case_rows) == 3


def test_mixed_labels_are_structural_attention_not_cleanliness_blocker():
    module = load_module()
    summary, group_rows, _ = module.diagnose(
        group_rows=[mixed_label_group()],
        assignments={
            "gl_mixed": [
                {"identity_key": "case-a", "primary_hcvr_type": "ssrf"},
                {"identity_key": "case-b", "primary_hcvr_type": "jndi"},
            ]
        },
        recall_rows=[
            {"identity_key": "case-a", "rank": None},
            {"identity_key": "case-b", "rank": 500},
        ],
        recall_label="candidate",
        baseline_rows=None,
        baseline_label=None,
        budgets=[100],
        primary_budget=100,
        min_purity=0.67,
    )

    row = group_rows[0]
    assert row["guideline_clean_enough"] is True
    assert "label_mixed_structural_attention" in row["attention"]
    assert "guideline_quality_attention" not in row["attention"]
    assert "embedding_or_candidate_recall_attention" in row["attention"]
    assert summary["attention_counts"]["label_mixed_structural_attention"] == 1
    assert summary["cleanliness_policy"]["label_mixture_is_blocking"] is False
    assert "mixed_hcvr" in summary["cleanliness_policy"]["label_mixed_flags"]
    assert "mixed_hcvr" not in summary["cleanliness_policy"]["blocking_flags"]


def test_baseline_identity_mismatch_is_debug_only():
    module = load_module()
    summary, _, _ = module.diagnose(
        group_rows=[clean_group()],
        assignments={"gl_clean": [{"identity_key": "case-a"}]},
        recall_rows=[{"identity_key": "case-a", "rank": 10}],
        recall_label="candidate",
        baseline_rows=[{"identity_key": "case-b", "rank": 10}],
        baseline_label="baseline",
        budgets=[100],
        primary_budget=100,
        min_purity=0.67,
    )

    assert summary["same_identity_baseline"] is False


def test_cli_writes_alignment_outputs(tmp_path: Path):
    group_report = tmp_path / "group_report.jsonl"
    assignments = tmp_path / "case_assignments.jsonl"
    recall = tmp_path / "recall.jsonl"
    output = tmp_path / "alignment"
    write_jsonl(group_report, [clean_group()])
    write_jsonl(assignments, [{"guideline_id": "gl_clean", "identity_key": "case-a"}])
    write_jsonl(recall, [{"identity_key": "case-a", "rank": 7}])

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--group-report",
            str(group_report),
            "--case-assignments",
            str(assignments),
            "--recall-results",
            str(recall),
            "--recall-label",
            "fixture-recall",
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
    assert summary["recall_label"] == "fixture-recall"
    assert summary["cleanliness_policy"]["min_clean_purity_is_blocking"] is False
    assert (output / "group_recall_alignment.tsv").is_file()
    assert "Guideline Recall Alignment" in (output / "README.md").read_text(encoding="utf-8")
