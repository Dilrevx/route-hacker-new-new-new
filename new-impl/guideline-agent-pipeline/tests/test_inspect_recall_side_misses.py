from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts" / "inspect_recall_side_misses.py"


def load_module():
    spec = importlib.util.spec_from_file_location("inspect_recall_side_misses", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


def debug_summary() -> dict:
    return {
        "recall_label": "p3c64",
        "primary_budget": 100,
        "debug_group_count": 1,
    }


def group_rows() -> list[dict]:
    return [
        {
            "guideline_id": "gl_clean",
            "guideline_group_key": "cluster_clean",
            "mechanism_id": "mech_clean",
            "mechanism_name": "clean mechanism",
            "mechanism_family": "authz",
            "attention": ["embedding_or_candidate_recall_attention"],
            "flags": [],
        }
    ]


def test_inspection_splits_ranked_miss_from_coverage_gap():
    module = load_module()

    summary, rows = module.build_inspection(
        debug_summary=debug_summary(),
        group_rows=group_rows(),
        case_rows=[
            {
                "guideline_id": "gl_clean",
                "guideline_group_key": "cluster_clean",
                "identity_key": "repo-a::CVE-1",
                "rank": 150,
                "present_in_recall_table": True,
                "hit_at_primary_budget": False,
            },
            {
                "guideline_id": "gl_clean",
                "guideline_group_key": "cluster_clean",
                "identity_key": "repo-b::CVE-2",
                "rank": None,
                "present_in_recall_table": False,
                "hit_at_primary_budget": False,
            },
        ],
        rank_rows=[
            {
                "identity_key": "repo-a::CVE-1",
                "case_id": "case-a",
                "repo_key": "repo-a",
                "best_known_anchor_rank": 150,
                "candidate_count": 6000,
                "known_anchor_count": 3,
                "top1_file": "src/A.java",
                "top1_start_line": 1,
                "top1_end_line": 80,
                "top1_known_anchor_overlap": False,
                "state": "completed",
            }
        ],
        exported_candidate_rows=None,
    )

    assert summary["case_count"] == 2
    assert summary["miss_state_counts"] == {
        "coverage_gap_not_in_rank_table": 1,
        "ranked_below_primary_budget": 1,
    }
    ranked = rows[0]
    assert ranked["identity_key"] == "repo-a::CVE-1"
    assert ranked["rank_distance_from_primary_budget"] == 50
    assert ranked["candidate_count_bucket"] == "5k_to_20k"
    assert "top1_candidate_does_not_overlap_known_anchor" in ranked["diagnosis"]
    assert "large_candidate_pool_budget_pressure" in ranked["diagnosis"]
    assert ranked["evidence_available"]["full_ranked_candidate_list"] is False
    assert ranked["policy"] == "rank_only_recall_diagnosis_no_guideline_or_ranking_change"

    gap = rows[1]
    assert gap["miss_state"] == "coverage_gap_not_in_rank_table"
    assert gap["diagnosis"] == ["identity_absent_from_rank_table"]


def test_inspection_uses_only_embedding_attention_groups():
    module = load_module()

    summary, rows = module.build_inspection(
        debug_summary=debug_summary(),
        group_rows=[
            {"guideline_id": "gl_quality", "attention": ["guideline_quality_attention"]},
            {"guideline_id": "gl_clean", "attention": ["embedding_or_candidate_recall_attention"]},
        ],
        case_rows=[
            {
                "guideline_id": "gl_quality",
                "identity_key": "repo-a::CVE-1",
                "present_in_recall_table": True,
                "rank": 150,
                "hit_at_primary_budget": False,
            },
            {
                "guideline_id": "gl_clean",
                "identity_key": "repo-b::CVE-2",
                "present_in_recall_table": True,
                "rank": None,
                "hit_at_primary_budget": False,
            },
        ],
        rank_rows=[
            {
                "identity_key": "repo-b::CVE-2",
                "candidate_count": 10,
                "known_anchor_count": 2,
                "state": "completed",
            }
        ],
        exported_candidate_rows=None,
    )

    assert summary["case_count"] == 1
    assert rows[0]["identity_key"] == "repo-b::CVE-2"
    assert rows[0]["miss_state"] == "ranked_without_known_anchor_overlap"
    assert rows[0]["next_checks"] == ["inspect_known_anchor_span_matching_and_candidate_overlap"]


def test_inspection_uses_exported_candidate_overlap_summary():
    module = load_module()

    summary, rows = module.build_inspection(
        debug_summary=debug_summary(),
        group_rows=group_rows(),
        case_rows=[
            {
                "guideline_id": "gl_clean",
                "identity_key": "repo-a::CVE-1",
                "present_in_recall_table": True,
                "rank": 150,
                "hit_at_primary_budget": False,
            }
        ],
        rank_rows=[
            {
                "identity_key": "repo-a::CVE-1",
                "candidate_count": 10,
                "known_anchor_count": 2,
                "state": "completed",
            }
        ],
        exported_candidate_rows=[
            {
                "identity_key": "repo-a::CVE-1",
                "rank": 1,
                "file": "Top.java",
                "known_anchor_overlap": False,
            },
            {
                "identity_key": "repo-a::CVE-1",
                "rank": 150,
                "file": "Anchor.java",
                "known_anchor_overlap": True,
            },
        ],
    )

    assert summary["input_capability"]["full_ranked_candidate_lists"] is True
    assert rows[0]["exported_candidate_summary"] == {
        "provided": True,
        "exported_count": 2,
        "known_anchor_overlap_count": 1,
        "best_exported_overlap_rank": 150,
        "overlap_within_primary_budget": False,
        "top_files": ["Top.java", "Anchor.java"],
    }
    assert "known_anchor_present_in_export_but_below_primary_budget" in rows[0]["diagnosis"]


def test_cli_writes_case_level_inspection(tmp_path: Path):
    summary_path = tmp_path / "debug_summary.json"
    group_path = tmp_path / "groups.jsonl"
    case_path = tmp_path / "cases.jsonl"
    rank_path = tmp_path / "ranks.jsonl"
    output = tmp_path / "out"
    summary_path.write_text(json.dumps(debug_summary()), encoding="utf-8")
    write_jsonl(group_path, group_rows())
    write_jsonl(
        case_path,
        [
            {
                "guideline_id": "gl_clean",
                "identity_key": "repo-a::CVE-1",
                "present_in_recall_table": True,
                "rank": 150,
                "hit_at_primary_budget": False,
            }
        ],
    )
    write_jsonl(
        rank_path,
        [
            {
                "identity_key": "repo-a::CVE-1",
                "candidate_count": 100,
                "known_anchor_count": 1,
                "state": "completed",
            }
        ],
    )

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--recall-side-debug-summary",
            str(summary_path),
            "--group-alignment",
            str(group_path),
            "--case-alignment",
            str(case_path),
            "--recall-rank-table",
            str(rank_path),
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
    assert summary["case_count"] == 1
    assert (output / "case_miss_inspection.tsv").is_file()
    assert "rank-only" in (output / "README.md").read_text(encoding="utf-8")
