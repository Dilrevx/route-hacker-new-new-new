from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts" / "build_guideline_revision_backlog.py"


def load_module():
    spec = importlib.util.spec_from_file_location("build_guideline_revision_backlog", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


def test_backlog_keeps_judge_suggestion_as_review_candidate():
    module = load_module()

    summary, rows = module.build_backlog(
        judge_summary={"judge_input_count": 1, "parsed_count": 1, "accepted_count": 0},
        judge_rows=[
            {
                "guideline_id": "gl_a",
                "mechanism_id": "mech_a",
                "decision": "revise",
                "min_score": 0.2,
                "main_issue": "wrong source-to-sink mechanism",
                "suggested_guideline": "Trace the corrected mechanism.",
            }
        ],
        alignment_summary=None,
        alignment_rows=[],
        max_items=None,
    )

    assert summary["backlog_count"] == 1
    assert rows[0]["recommended_action"] == "revise_mechanism_text_from_evidence"
    assert rows[0]["candidate_guideline_status"] == "review_candidate_not_release"


def test_clean_group_with_recall_miss_points_to_embedding_candidate_or_query():
    module = load_module()

    _, rows = module.build_backlog(
        judge_summary=None,
        judge_rows=[],
        alignment_summary={"recall_label": "candidate", "same_identity_baseline": True},
        alignment_rows=[
            {
                "guideline_id": "gl_clean",
                "mechanism_id": "mech_clean",
                "guideline_clean_enough": True,
                "attention": ["embedding_or_candidate_recall_attention"],
                "assigned_case_count": 2,
                "primary_hit_count": 0,
            }
        ],
        max_items=None,
    )

    assert rows[0]["recommended_action"] == "inspect_embedding_candidate_or_query_mismatch"
    assert rows[0]["candidate_guideline_status"] == "none"


def test_cli_writes_revision_backlog(tmp_path: Path):
    judge_summary = tmp_path / "judge_summary.json"
    judge_report = tmp_path / "judge_report.jsonl"
    alignment_summary = tmp_path / "alignment_summary.json"
    alignment_report = tmp_path / "alignment.jsonl"
    output = tmp_path / "backlog"
    judge_summary.write_text(json.dumps({"judge_input_count": 1, "parsed_count": 1, "accepted_count": 0}), encoding="utf-8")
    write_jsonl(judge_report, [{"guideline_id": "gl_a", "decision": "split", "min_score": 0.1}])
    alignment_summary.write_text(json.dumps({"recall_label": "candidate", "same_identity_baseline": True}), encoding="utf-8")
    write_jsonl(alignment_report, [{"guideline_id": "gl_a", "attention": ["guideline_quality_attention"]}])

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--judge-summary",
            str(judge_summary),
            "--judge-report",
            str(judge_report),
            "--alignment-summary",
            str(alignment_summary),
            "--alignment-report",
            str(alignment_report),
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
    assert summary["backlog_count"] == 1
    assert (output / "revision_backlog.tsv").is_file()
    assert "Guideline Revision Backlog" in (output / "README.md").read_text(encoding="utf-8")
