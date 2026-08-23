from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts" / "summarize_guideline_evidence_coverage.py"


def load_module():
    spec = importlib.util.spec_from_file_location("summarize_guideline_evidence_coverage", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


def test_coverage_separates_source_review_from_recall_completion():
    module = load_module()

    assert module.boundary_from_prompt("prompts/gl_done.candidate_boundary_01.md") == "candidate_boundary_01"

    summary, rows, queue = module.build_coverage(
        worklist_rows=[
            {
                "priority": 1,
                "guideline_id": "gl_done",
                "mechanism_id": "mech_done",
                "recommended_action": "split_mechanism_boundary",
                "evidence_gaps": ["mechanism_boundary"],
            },
            {
                "priority": 2,
                "guideline_id": "gl_validation_only",
                "mechanism_id": "mech_validation_only",
                "recommended_action": "revise_mechanism_text_from_evidence",
            },
            {
                "priority": 3,
                "guideline_id": "gl_missing",
                "mechanism_id": "mech_missing",
                "recommended_action": "collect_source_sink_guard_evidence",
            },
        ],
        ledger_rows=[
            {
                "guideline_id": "gl_done",
                "boundary_label": "candidate_boundary_01",
                "boundary_decision": "promote_boundary",
                "representative_cases": ["repo::CVE-1"],
            },
            {
                "guideline_id": "gl_validation_only",
                "boundary_label": "candidate_revision",
                "boundary_decision": "promote_boundary",
                "representative_cases": ["repo::CVE-2"],
            },
        ],
        validation_rows=[
            {
                "guideline_id": "gl_done",
                "boundary_label": "candidate_boundary_01",
                "boundary_decision": "promote_boundary",
                "valid": True,
            },
            {
                "guideline_id": "gl_validation_only",
                "boundary_label": "candidate_revision",
                "boundary_decision": "promote_boundary",
                "valid": True,
            },
        ],
        judge_rows=[
            {
                "guideline_id": "gl_done",
                "prompt_file": "prompts/gl_done.candidate_boundary_01.md",
                "decision": "accept",
                "min_score": 0.8,
            }
        ],
    )

    by_id = {row["guideline_id"]: row for row in rows}
    assert by_id["gl_done"]["coverage_status"] == "source_reviewed_and_judge_accepted"
    assert by_id["gl_done"]["next_action"] == "run_same_identity_recall_after_sidecar_change"
    assert by_id["gl_validation_only"]["coverage_status"] == "source_reviewed_validation_only"
    assert by_id["gl_validation_only"]["next_action"] == "run_ledger_judge_pack"
    assert by_id["gl_missing"]["coverage_status"] == "not_source_reviewed"
    assert by_id["gl_missing"]["next_action"] == "fill_source_review_ledger"
    assert summary["source_review_action_count"] == 3
    assert summary["source_review_judge_accepted_count"] == 1
    assert [row["guideline_id"] for row in queue] == ["gl_missing", "gl_validation_only"]


def test_nonaccept_judge_keeps_boundary_in_evidence_queue():
    module = load_module()

    summary, rows, queue = module.build_coverage(
        worklist_rows=[
            {
                "priority": 1,
                "guideline_id": "gl_needs",
                "mechanism_id": "mech_needs",
                "recommended_action": "split_mechanism_boundary",
            }
        ],
        ledger_rows=[
            {
                "guideline_id": "gl_needs",
                "boundary_label": "candidate_boundary_02",
                "boundary_decision": "needs_more_evidence",
            }
        ],
        validation_rows=[
            {
                "guideline_id": "gl_needs",
                "boundary_label": "candidate_boundary_02",
                "boundary_decision": "needs_more_evidence",
                "valid": True,
            }
        ],
        judge_rows=[
            {
                "guideline_id": "gl_needs",
                "prompt_file": "prompts/gl_needs.candidate_boundary_02.md",
                "decision": "needs_evidence",
                "min_score": 0.2,
            }
        ],
    )

    assert rows[0]["coverage_status"] == "source_reviewed_needs_more_evidence"
    assert rows[0]["next_action"] == "collect_missing_boundary_evidence"
    assert summary["coverage_status_counts"] == {"source_reviewed_needs_more_evidence": 1}
    assert queue[0]["guideline_id"] == "gl_needs"


def test_cli_writes_evidence_coverage(tmp_path: Path):
    worklist = tmp_path / "worklist.jsonl"
    ledger = tmp_path / "ledger.jsonl"
    validation = tmp_path / "validation.json"
    judge_report = tmp_path / "judge_report.jsonl"
    output = tmp_path / "coverage"
    write_jsonl(
        worklist,
        [
            {
                "priority": 1,
                "guideline_id": "gl_a",
                "mechanism_id": "mech_a",
                "recommended_action": "revise_mechanism_text_from_evidence",
                "evidence_gaps": ["source_level_trace_evidence"],
            }
        ],
    )
    write_jsonl(
        ledger,
        [
            {
                "guideline_id": "gl_a",
                "boundary_label": "candidate_revision",
                "boundary_decision": "promote_boundary",
                "representative_cases": ["repo::CVE-1"],
            }
        ],
    )
    validation.write_text(
        json.dumps(
            [
                {
                    "guideline_id": "gl_a",
                    "boundary_label": "candidate_revision",
                    "boundary_decision": "promote_boundary",
                    "valid": True,
                }
            ]
        ),
        encoding="utf-8",
    )
    write_jsonl(
        judge_report,
        [
            {
                "guideline_id": "gl_a",
                "prompt_file": "prompts/gl_a.candidate_revision.md",
                "decision": "accept",
                "min_score": 0.75,
            }
        ],
    )

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--evidence-worklist",
            str(worklist),
            "--ledger",
            str(ledger),
            "--validation-rows",
            str(validation),
            "--judge-report",
            str(judge_report),
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
    assert summary["coverage_status_counts"] == {"source_reviewed_and_judge_accepted": 1}
    assert (output / "guideline_evidence_coverage.tsv").is_file()
    assert (output / "next_review_queue.jsonl").is_file()
    assert "Guideline Evidence Coverage Summary" in (output / "README.md").read_text(encoding="utf-8")
