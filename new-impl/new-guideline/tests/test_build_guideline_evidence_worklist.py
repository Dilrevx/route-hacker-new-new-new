from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts" / "build_guideline_evidence_worklist.py"


def load_module():
    spec = importlib.util.spec_from_file_location("build_guideline_evidence_worklist", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


def test_worklist_marks_review_only_and_extracts_evidence_gaps():
    module = load_module()

    summary, rows = module.build_worklist(
        backlog_rows=[
            {
                "guideline_id": "gl_a",
                "mechanism_id": "mech_a",
                "decision": "split",
                "recommended_action": "split_mechanism_boundary",
                "main_issue": "mixed mechanism",
                "split_suggestions": ["bucket one", "bucket two"],
            }
        ],
        group_rows=[
            {
                "guideline_id": "gl_a",
                "flags": ["mixed_hcvr"],
                "assigned_case_count": 2,
                "judge_case_examples": [
                    {
                        "case_id": "case-a",
                        "identity_key": "repo::CVE-1",
                        "trace_evidence": ["review-entry retrieval ground truth, not proof of exploitability"],
                        "anchor_examples": [{"file": "A.java", "start_line": 1, "end_line": 10}],
                    }
                ],
            }
        ],
        max_cases_per_item=3,
    )

    assert summary["worklist_count"] == 1
    assert summary["action_counts"]["split_mechanism_boundary"] == 1
    assert rows[0]["policy"] == "review_only_not_release_not_recall_input"
    assert "source_level_trace_evidence" in rows[0]["evidence_gaps"]
    assert "mixed_membership_boundary" in rows[0]["evidence_gaps"]
    assert "candidate_split_validation" in rows[0]["evidence_gaps"]
    assert rows[0]["example_cases"][0]["evidence_state"] == "review_entry_only"


def test_worklist_keeps_accept_as_control_group():
    module = load_module()

    _, rows = module.build_worklist(
        backlog_rows=[
            {
                "guideline_id": "gl_control",
                "mechanism_id": "mech_control",
                "decision": "accept",
                "recommended_action": "keep_as_control_group",
            }
        ],
        group_rows=[
            {
                "guideline_id": "gl_control",
                "judge_case_examples": [
                    {
                        "case_id": "case-control",
                        "identity_key": "repo::CVE-2",
                        "trace_evidence": ["old-side source reaches sink without the owner check"],
                    }
                ],
            }
        ],
        max_cases_per_item=2,
    )

    assert rows[0]["recommended_action"] == "keep_as_control_group"
    assert rows[0]["evidence_gaps"] == ["control_case_invariant"]
    assert rows[0]["example_cases"][0]["evidence_state"] == "source_trace_present"


def test_cli_writes_evidence_worklist(tmp_path: Path):
    backlog = tmp_path / "revision_backlog.jsonl"
    group_report = tmp_path / "group_report.jsonl"
    output = tmp_path / "worklist"
    write_jsonl(
        backlog,
        [
            {
                "guideline_id": "gl_a",
                "mechanism_id": "mech_a",
                "decision": "needs_evidence",
                "recommended_action": "collect_source_sink_guard_evidence",
                "main_issue": "needs source evidence",
            }
        ],
    )
    write_jsonl(
        group_report,
        [
            {
                "guideline_id": "gl_a",
                "assigned_case_count": 1,
                "judge_case_examples": [{"case_id": "case-a", "identity_key": "repo::CVE-1"}],
            }
        ],
    )

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--revision-backlog",
            str(backlog),
            "--group-report",
            str(group_report),
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
    assert summary["worklist_count"] == 1
    assert (output / "evidence_worklist.tsv").is_file()
    assert "Guideline Evidence Collection Worklist" in (output / "README.md").read_text(encoding="utf-8")
