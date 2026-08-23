from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts" / "build_propagated_boundary_sidecar.py"


def load_module():
    spec = importlib.util.spec_from_file_location("build_propagated_boundary_sidecar", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text("".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows), encoding="utf-8")


def propagation_row(**overrides):
    row = {
        "guideline_id": "gl_test",
        "boundary_label": "candidate_boundary_01",
        "boundary_mechanism_id": "mech_test",
        "boundary_mechanism_name": "test source-reviewed mechanism",
        "release_assigned_case_count": 2,
        "propagation_status": "group_ablation_ready",
    }
    row.update(overrides)
    return row


def boundary_override(**overrides):
    row = {
        "guideline_id": "gl_test",
        "boundary_label": "candidate_boundary_01",
        "mechanism_id": "mech_test",
        "mechanism_name": "test source-reviewed mechanism",
        "retrieval_guideline": "Audit the source-reviewed mechanism without case-specific anchors.",
    }
    row.update(overrides)
    return row


def assignment(identity: str, guideline_id: str = "gl_test") -> dict:
    return {
        "identity_key": identity,
        "case_id": f"case::{identity[-4:]}",
        "cve_ids": ["CVE-2099-0001"],
        "guideline_id": guideline_id,
        "mechanism_id": "mech_test",
        "mechanism_name": "test source-reviewed mechanism",
    }


def case(identity: str) -> dict:
    return {
        "identity_key": identity,
        "new_unified_case_id": f"case::{identity[-4:]}",
    }


def test_default_selects_only_group_ablation_ready_boundaries():
    module = load_module()

    summary, sidecar, selected = module.build_sidecar(
        propagation_rows=[
            propagation_row(),
            propagation_row(
                guideline_id="gl_skip",
                boundary_label="candidate_boundary_02",
                propagation_status="requires_release_regeneration",
            ),
        ],
        boundary_overrides=[
            boundary_override(),
            boundary_override(
                guideline_id="gl_skip",
                boundary_label="candidate_boundary_02",
                retrieval_guideline="Do not consume yet.",
            ),
        ],
        case_assignments=[
            assignment("owner__repo::CVE-2099-0001"),
            assignment("owner__repo::CVE-2099-0002"),
            assignment("other__repo::CVE-2099-9999", guideline_id="gl_skip"),
        ],
        cases=[
            case("owner__repo::CVE-2099-0001"),
            case("owner__repo::CVE-2099-0002"),
            case("other__repo::CVE-2099-9999"),
        ],
        allowed_statuses={"group_ablation_ready"},
    )

    assert summary["selected_boundary_count"] == 1
    assert summary["sidecar_identity_count"] == 2
    assert [row["guideline_id"] for row in selected] == ["gl_test"]
    assert [row["identity_key"] for row in sidecar] == [
        "owner__repo::CVE-2099-0001",
        "owner__repo::CVE-2099-0002",
    ]
    assert all(row["guideline_ids"] == ["gl_test"] for row in sidecar)


def test_can_explicitly_allow_outside_fixed_set_status():
    module = load_module()

    summary, sidecar, selected = module.build_sidecar(
        propagation_rows=[
            propagation_row(
                guideline_id="gl_xxe",
                propagation_status="group_ablation_candidate_outside_fixed_set",
            )
        ],
        boundary_overrides=[
            boundary_override(
                guideline_id="gl_xxe",
                retrieval_guideline="Audit unsafe XML parser external resource resolution.",
            )
        ],
        case_assignments=[assignment("xml__repo::CVE-2099-0003", guideline_id="gl_xxe")],
        cases=[case("xml__repo::CVE-2099-0003")],
        allowed_statuses={"group_ablation_candidate_outside_fixed_set"},
    )

    assert summary["selected_boundary_count"] == 1
    assert selected[0]["guideline_id"] == "gl_xxe"
    assert sidecar[0]["retrieval_guideline"] == "Audit unsafe XML parser external resource resolution."


def test_cli_writes_release_group_sidecar(tmp_path: Path):
    propagation = tmp_path / "propagation.jsonl"
    boundary = tmp_path / "boundary.jsonl"
    assignments = tmp_path / "assignments.jsonl"
    cases = tmp_path / "cases.jsonl"
    output = tmp_path / "out"
    write_jsonl(propagation, [propagation_row()])
    write_jsonl(boundary, [boundary_override()])
    write_jsonl(assignments, [assignment("owner__repo::CVE-2099-0001")])
    write_jsonl(cases, [case("owner__repo::CVE-2099-0001")])

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--propagation",
            str(propagation),
            "--boundary-overrides",
            str(boundary),
            "--case-assignments",
            str(assignments),
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
    assert summary["policy"] == [
        "release_group_sidecar_candidate",
        "source_reviewed_boundaries_only",
        "no_bad_case_answer_key",
        "no_regex_fallback",
        "requires_same_identity_recall_before_claim",
    ]
    assert (output / "guideline_overrides.jsonl").is_file()
    assert (output / "selected_boundaries.jsonl").is_file()
