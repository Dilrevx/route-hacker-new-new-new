from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts" / "verify_guideline_review_ledger.py"


def load_module():
    spec = importlib.util.spec_from_file_location("verify_guideline_review_ledger", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


def test_promote_boundary_requires_source_sink_guard_fix_fields():
    module = load_module()

    summary, rows = module.validate_ledger(
        [
            {
                "guideline_id": "gl_a",
                "boundary_label": "candidate_boundary_01",
                "boundary_decision": "promote_boundary",
                "representative_cases": ["repo::CVE-1"],
                "source_shape": "request URL",
                "sink_or_sensitive_effect": "HTTP request",
                "missing_guard": "no private-address check",
                "exploit_precondition": "attacker controls URL",
                "safe_fix_semantics": "validate resolved destination",
                "recall_follow_up": "rerun same-identity recall",
            },
            {
                "guideline_id": "gl_b",
                "boundary_label": "candidate_boundary_01",
                "boundary_decision": "promote_boundary",
                "representative_cases": [],
                "source_shape": "",
            },
        ]
    )

    assert summary["row_count"] == 2
    assert summary["promotable_count"] == 1
    assert summary["invalid_count"] == 1
    assert "missing_source_shape" in rows[1]["errors"]
    assert "missing_representative_cases" in rows[1]["errors"]


def test_needs_more_evidence_requires_rationale():
    module = load_module()

    summary, rows = module.validate_ledger(
        [
            {
                "guideline_id": "gl_a",
                "boundary_label": "candidate_boundary_01",
                "boundary_decision": "needs_more_evidence",
            }
        ]
    )

    assert summary["invalid_count"] == 1
    assert rows[0]["errors"] == ["missing_rationale"]


def test_cli_writes_validation_report(tmp_path: Path):
    ledger = tmp_path / "ledger.jsonl"
    output = tmp_path / "validation"
    write_jsonl(
        ledger,
        [
            {
                "guideline_id": "gl_a",
                "boundary_label": "candidate_boundary_01",
                "boundary_decision": "mark_out_of_scope",
                "rationale": "not the same mechanism",
            }
        ],
    )

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--ledger",
            str(ledger),
            "--output-dir",
            str(output),
            "--fail-on-invalid",
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )

    assert result.returncode == 0
    summary = json.loads((output / "summary.json").read_text(encoding="utf-8"))
    assert summary["valid_count"] == 1
    assert "Guideline Review Ledger Validation" in (output / "README.md").read_text(encoding="utf-8")
