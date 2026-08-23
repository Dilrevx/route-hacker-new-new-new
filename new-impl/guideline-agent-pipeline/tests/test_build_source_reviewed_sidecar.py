from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts" / "build_source_reviewed_sidecar.py"


def load_module():
    spec = importlib.util.spec_from_file_location("build_source_reviewed_sidecar", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text(
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows),
        encoding="utf-8",
    )


def promotable_row(**overrides):
    row = {
        "schema_version": "hcvr_guideline_review_ledger.v1",
        "guideline_id": "gl_test",
        "mechanism_id": "mech_test_boundary",
        "mechanism_name": "test missing guard mechanism",
        "boundary_label": "candidate_boundary_01",
        "boundary_text": "Trace attacker-controlled resource names into sensitive reads before final containment is proven.",
        "boundary_decision": "promote_boundary",
        "representative_cases": ["owner__repo::CVE-2099-0001"],
        "source_shape": "request resource name",
        "sink_or_sensitive_effect": "sensitive file read",
        "missing_guard": "final normalized containment is not checked",
        "exploit_precondition": "attacker chooses a resource name",
        "safe_fix_semantics": "normalize the final path and enforce containment",
        "evidence_refs": [
            {
                "identity_key": "owner__repo::CVE-2099-0001",
                "source_evidence": "src/App.java:123 proves the source trace.",
            }
        ],
        "recall_follow_up": "rerun same-identity recall",
    }
    row.update(overrides)
    return row


def test_accepts_only_valid_judge_accepted_promoted_boundaries():
    module = load_module()
    ledger_rows = [
        promotable_row(boundary_label="candidate_boundary_01"),
        promotable_row(boundary_label="candidate_boundary_02"),
        promotable_row(
            boundary_label="candidate_boundary_03",
            boundary_decision="needs_more_evidence",
            rationale="needs evidence",
        ),
    ]
    validation = module.index_validation_rows(
        [
            {"guideline_id": "gl_test", "boundary_label": "candidate_boundary_01", "valid": True},
            {"guideline_id": "gl_test", "boundary_label": "candidate_boundary_02", "valid": False},
            {"guideline_id": "gl_test", "boundary_label": "candidate_boundary_03", "valid": True},
        ]
    )
    judge = module.index_judge_rows(
        [
            {
                "guideline_id": "gl_test",
                "prompt_file": "prompts/gl_test.candidate_boundary_01.md",
                "decision": "accept",
            },
            {
                "guideline_id": "gl_test",
                "prompt_file": "prompts/gl_test.candidate_boundary_02.md",
                "decision": "accept",
            },
            {
                "guideline_id": "gl_test",
                "prompt_file": "prompts/gl_test.candidate_boundary_03.md",
                "decision": "accept",
            },
        ]
    )

    accepted = module.accepted_promoted_boundaries(
        ledger_rows=ledger_rows,
        validation_by_boundary=validation,
        judge_by_boundary=judge,
    )

    assert [row["boundary_label"] for row in accepted] == ["candidate_boundary_01"]


def test_cli_writes_review_only_sidecar_without_evidence_leakage(tmp_path: Path):
    ledger = tmp_path / "ledger.jsonl"
    validation = tmp_path / "validation.json"
    judge = tmp_path / "judge.jsonl"
    cases = tmp_path / "cases.jsonl"
    output = tmp_path / "sidecar"
    write_jsonl(
        ledger,
        [
            promotable_row(),
            promotable_row(
                guideline_id="gl_source_only",
                mechanism_id="mech_source_only",
                mechanism_name="source only boundary",
                boundary_label="candidate_boundary_01",
                representative_cases=["missing__repo::CVE-2099-0002"],
            ),
        ],
    )
    write_json(
        validation,
        [
            {"guideline_id": "gl_test", "boundary_label": "candidate_boundary_01", "valid": True},
            {"guideline_id": "gl_source_only", "boundary_label": "candidate_boundary_01", "valid": True},
        ],
    )
    write_jsonl(
        judge,
        [
            {
                "guideline_id": "gl_test",
                "prompt_file": "prompts/gl_test.candidate_boundary_01.md",
                "decision": "accept",
            },
            {
                "guideline_id": "gl_source_only",
                "prompt_file": "prompts/gl_source_only.candidate_boundary_01.md",
                "decision": "accept",
            },
        ],
    )
    write_jsonl(
        cases,
        [
            {
                "identity_key": "owner__repo::CVE-2099-0001",
                "new_unified_case_id": "case::1",
            }
        ],
    )

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--ledger",
            str(ledger),
            "--validation-rows",
            str(validation),
            "--judge-report",
            str(judge),
            "--cases-file",
            str(cases),
            "--output-dir",
            str(output),
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    summary = json.loads((output / "summary.json").read_text(encoding="utf-8"))
    assert summary["accepted_promotable_boundary_count"] == 2
    assert summary["sidecar_identity_count"] == 1
    assert summary["unmatched_representative_case_count"] == 1
    sidecar = [
        json.loads(line)
        for line in (output / "guideline_overrides.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert sidecar[0]["identity_key"] == "owner__repo::CVE-2099-0001"
    assert sidecar[0]["case_id"] == "case::1"
    guideline = sidecar[0]["retrieval_guideline"]
    assert "test missing guard mechanism" in guideline
    assert "final normalized containment" in guideline
    assert "CVE-2099-0001" not in guideline
    assert "src/App.java" not in guideline
    assert "source_evidence" not in guideline


def test_generated_query_rejects_cve_ids_or_file_line_shapes():
    module = load_module()

    assert module.validate_retrieval_guideline_text("Audit CVE-2099-0001 in generic code") == [
        "contains_cve_id"
    ]
    assert module.validate_retrieval_guideline_text("Check src/App.java:123 before use") == [
        "contains_file_line_shape"
    ]
