from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts" / "build_recall_side_debug_pack.py"


def load_module():
    spec = importlib.util.spec_from_file_location("build_recall_side_debug_pack", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


def alignment_summary() -> dict:
    return {
        "recall_label": "p3c64",
        "primary_budget": 100,
        "joined_recall_case_count": 2,
        "recall_case_count": 3,
        "attention_counts": {"embedding_or_candidate_recall_attention": 1},
        "cleanliness_policy": {
            "label_mixture_is_blocking": False,
            "blocking_flags": ["pending_review"],
        },
    }


def test_pack_splits_coverage_gap_from_joined_topk_miss():
    module = load_module()

    summary, rows = module.build_pack(
        alignment_summary=alignment_summary(),
        group_rows=[
            {
                "guideline_id": "gl_clean",
                "mechanism_id": "mech_clean",
                "mechanism_name": "clean",
                "attention": ["embedding_or_candidate_recall_attention", "missing_recall_rows"],
                "assigned_case_count": 3,
                "recall_joined_case_count": 2,
                "missing_recall_count": 1,
                "primary_hit_count": 0,
            }
        ],
        case_rows=[
            {
                "guideline_id": "gl_clean",
                "identity_key": "case-a",
                "present_in_recall_table": True,
                "rank": 150,
                "hit_at_primary_budget": False,
            },
            {
                "guideline_id": "gl_clean",
                "identity_key": "case-b",
                "present_in_recall_table": True,
                "rank": None,
                "hit_at_primary_budget": False,
            },
            {
                "guideline_id": "gl_clean",
                "identity_key": "case-c",
                "present_in_recall_table": False,
                "rank": None,
                "hit_at_primary_budget": False,
            },
        ],
        max_cases_per_group=5,
    )

    assert summary["debug_group_count"] == 1
    assert summary["miss_state_totals"] == {
        "coverage_gap_not_in_rank_table": 1,
        "ranked_below_primary_budget": 1,
        "ranked_without_known_anchor_overlap": 1,
    }
    assert rows[0]["recommended_checks"] == [
        "verify_identity_filter_dataset_split_and_rank_table_coverage",
        "inspect_guideline_query_wording_against_source_evidence",
        "inspect_candidate_slicing_for_known_anchor_context",
        "compare_embedding_backend_or_query_adapter_on_same_identity",
        "inspect_known_anchor_span_matching_and_candidate_overlap",
    ]
    assert rows[0]["policy"] == "debug_only_no_guideline_or_ranking_change"


def test_pack_ignores_groups_without_embedding_attention():
    module = load_module()

    summary, rows = module.build_pack(
        alignment_summary=alignment_summary(),
        group_rows=[{"guideline_id": "gl_quality", "attention": ["guideline_quality_attention"]}],
        case_rows=[{"guideline_id": "gl_quality", "identity_key": "case-a", "hit_at_primary_budget": False}],
        max_cases_per_group=5,
    )

    assert summary["debug_group_count"] == 0
    assert rows == []


def test_cli_writes_recall_side_debug_pack(tmp_path: Path):
    summary_path = tmp_path / "summary.json"
    group_path = tmp_path / "group.jsonl"
    case_path = tmp_path / "case.jsonl"
    output = tmp_path / "debug"
    summary_path.write_text(json.dumps(alignment_summary()), encoding="utf-8")
    write_jsonl(
        group_path,
        [
            {
                "guideline_id": "gl_clean",
                "mechanism_id": "mech_clean",
                "attention": ["embedding_or_candidate_recall_attention"],
                "assigned_case_count": 1,
                "recall_joined_case_count": 1,
                "missing_recall_count": 0,
                "primary_hit_count": 0,
            }
        ],
    )
    write_jsonl(
        case_path,
        [
            {
                "guideline_id": "gl_clean",
                "identity_key": "case-a",
                "present_in_recall_table": True,
                "rank": 150,
                "hit_at_primary_budget": False,
            }
        ],
    )

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--alignment-summary",
            str(summary_path),
            "--group-alignment",
            str(group_path),
            "--case-alignment",
            str(case_path),
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
    assert summary["debug_group_count"] == 1
    assert (output / "recall_side_debug_pack.tsv").is_file()
    assert "Recall-Side Debug Pack" in (output / "README.md").read_text(encoding="utf-8")
