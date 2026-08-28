from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts" / "compare_recall_rank_tables.py"


def load_module():
    spec = importlib.util.spec_from_file_location("compare_recall_rank_tables", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


def test_compare_tables_requires_same_identity_set_for_strict_ab():
    module = load_module()
    summary = module.compare_tables(
        left_rows=[
            {"identity_key": "case-a", "best_known_anchor_rank": 10, "candidate_count": 100},
            {"identity_key": "case-b", "best_known_anchor_rank": 300, "candidate_count": 100},
        ],
        right_rows=[
            {"identity_key": "case-a", "rank": 20, "candidate_count": 100},
            {"identity_key": "case-c", "rank": 30, "candidate_count": 100},
        ],
        left_label="left",
        right_label="right",
        budgets=[30, 200],
        primary_budget=200,
    )

    assert not summary["same_identity_set"]
    assert summary["common_count"] == 1
    assert summary["left_only_count"] == 1
    assert summary["right_only_count"] == 1
    assert summary["metrics_on_common_identities"]["hit_at_30"]["delta_count"] == 0


def test_compare_tables_extracts_known_overlap_rank_from_recall_results():
    module = load_module()
    summary = module.compare_tables(
        left_rows=[
            {
                "identity_key": "case-a",
                "candidate_count": 50,
                "top_anchors": [
                    {"rank": 1, "known_anchor_overlap": False},
                    {"rank": 9, "known_anchor_overlap": True},
                ],
            }
        ],
        right_rows=[
            {"identity_key": "case-a", "rank": 250, "candidate_count": 50},
        ],
        left_label="left",
        right_label="right",
        budgets=[10, 200],
        primary_budget=200,
    )

    assert summary["same_identity_set"]
    assert summary["metrics_on_common_identities"]["hit_at_10"]["left_count"] == 1
    assert summary["metrics_on_common_identities"]["hit_at_10"]["right_count"] == 0
    assert summary["primary_budget_crossing"]["left_only_hit_count"] == 1


def test_compare_tables_does_not_treat_penalized_rank_as_hit_rank():
    module = load_module()
    summary = module.compare_tables(
        left_rows=[{"identity_key": "case-a", "rank": 10, "candidate_count": 20}],
        right_rows=[
            {
                "identity_key": "case-a",
                "rank": None,
                "penalized_rank": 21,
                "candidate_count": 20,
            }
        ],
        left_label="left",
        right_label="right",
        budgets=[30],
        primary_budget=30,
    )

    assert summary["metrics_on_common_identities"]["hit_at_30"]["left_count"] == 1
    assert summary["metrics_on_common_identities"]["hit_at_30"]["right_count"] == 0
    assert summary["primary_budget_crossing"]["left_only_hit_count"] == 1


def test_cli_fails_on_identity_mismatch_without_explicit_allowance(tmp_path: Path):
    left = tmp_path / "left.jsonl"
    right = tmp_path / "right.jsonl"
    write_jsonl(left, [{"identity_key": "case-a", "rank": 1}])
    write_jsonl(right, [{"identity_key": "case-b", "rank": 1}])

    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--left", str(left), "--right", str(right)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )

    assert result.returncode != 0
    assert "identity sets differ" in result.stderr


def test_cli_allows_mismatch_for_intersection_diagnostics(tmp_path: Path):
    left = tmp_path / "left.jsonl"
    right = tmp_path / "right.jsonl"
    output = tmp_path / "summary.json"
    write_jsonl(
        left,
        [
            {"identity_key": "case-a", "rank": 10, "candidate_count": 20},
            {"identity_key": "case-b", "rank": 10, "candidate_count": 30},
        ],
    )
    write_jsonl(
        right,
        [
            {"identity_key": "case-a", "rank": 300, "candidate_count": 20},
            {"identity_key": "case-c", "rank": 10, "candidate_count": 30},
        ],
    )

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--left",
            str(left),
            "--right",
            str(right),
            "--allow-mismatch",
            "--output-json",
            str(output),
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )

    assert result.returncode == 0
    summary = json.loads(output.read_text(encoding="utf-8"))
    assert summary["common_count"] == 1
    assert summary["primary_budget_crossing"]["left_only_hit_count"] == 1
