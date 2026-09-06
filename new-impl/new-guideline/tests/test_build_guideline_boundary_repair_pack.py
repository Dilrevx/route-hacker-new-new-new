from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts" / "build_guideline_boundary_repair_pack.py"


def load_module():
    spec = importlib.util.spec_from_file_location("build_guideline_boundary_repair_pack", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


def test_pack_keeps_only_split_and_revise_rows():
    module = load_module()

    summary, rows = module.build_pack(
        worklist_rows=[
            {
                "priority": 1,
                "guideline_id": "gl_split",
                "mechanism_id": "mech_split",
                "recommended_action": "split_mechanism_boundary",
                "split_suggestions": ["A specific mechanism", "Another mechanism"],
                "example_cases": [
                    {
                        "identity_key": "repo::CVE-1",
                        "evidence_state": "source_trace_present",
                        "first_trace_evidence": "source reaches sink",
                    },
                    {
                        "identity_key": "repo::CVE-2",
                        "evidence_state": "review_entry_only",
                        "first_trace_evidence": "review-entry only",
                    },
                ],
            },
            {
                "priority": 2,
                "guideline_id": "gl_collect",
                "mechanism_id": "mech_collect",
                "recommended_action": "collect_source_sink_guard_evidence",
            },
        ],
        max_examples_per_state=2,
        max_items=None,
    )

    assert summary["pack_count"] == 1
    assert summary["repair_kind_counts"] == {"split_mechanism_boundary": 1}
    assert rows[0]["release_policy"] == "review_only_not_release_not_recall_input"
    assert len(rows[0]["proposed_boundaries"]) == 2
    assert rows[0]["source_trace_examples"][0]["identity_key"] == "repo::CVE-1"
    assert rows[0]["review_entry_only_examples"][0]["identity_key"] == "repo::CVE-2"


def test_pack_builds_revision_boundary_from_candidate_text():
    module = load_module()

    _, rows = module.build_pack(
        worklist_rows=[
            {
                "priority": 1,
                "guideline_id": "gl_revise",
                "mechanism_id": "mech_revise",
                "recommended_action": "revise_mechanism_text_from_evidence",
                "candidate_guideline_text": "Trace URL input into outbound requests with destination checks.",
            }
        ],
        max_examples_per_state=2,
        max_items=None,
    )

    assert rows[0]["repair_kind"] == "revise_mechanism_text_from_evidence"
    assert rows[0]["proposed_boundaries"] == [
        {
            "boundary_label": "candidate_revision",
            "description": "Trace URL input into outbound requests with destination checks.",
            "status": "needs_source_validation_before_release",
        }
    ]


def test_cli_writes_boundary_repair_pack(tmp_path: Path):
    worklist = tmp_path / "evidence_worklist.jsonl"
    output = tmp_path / "repair_pack"
    write_jsonl(
        worklist,
        [
            {
                "priority": 1,
                "guideline_id": "gl_a",
                "mechanism_id": "mech_a",
                "recommended_action": "revise_mechanism_text_from_evidence",
                "candidate_guideline_text": "Trace path input into file writes.",
            }
        ],
    )

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--evidence-worklist",
            str(worklist),
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
    assert summary["pack_count"] == 1
    assert (output / "boundary_repair_pack.tsv").is_file()
    assert "Guideline Boundary Repair Pack" in (output / "README.md").read_text(encoding="utf-8")
