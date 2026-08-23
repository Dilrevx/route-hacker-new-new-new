from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts" / "audit_source_reviewed_boundary_propagation.py"


def load_module():
    spec = importlib.util.spec_from_file_location("audit_source_reviewed_boundary_propagation", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text(
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows),
        encoding="utf-8",
    )


def boundary_row(**overrides):
    row = {
        "guideline_id": "gl_test",
        "boundary_label": "candidate_boundary_01",
        "mechanism_id": "mech_test",
        "mechanism_name": "test mechanism",
        "representative_cases": ["owner__repo::CVE-2099-0001", "owner__repo::CVE-2099-0002"],
    }
    row.update(overrides)
    return row


def group_row(**overrides):
    row = {
        "guideline_id": "gl_test",
        "guideline_group_key": "cluster_0001__mech_test",
        "mechanism_id": "mech_test",
        "mechanism_name": "test mechanism",
        "assigned_case_count": 3,
        "flags": [],
    }
    row.update(overrides)
    return row


def assignment(identity: str, guideline_id: str = "gl_test", mechanism_id: str = "mech_test") -> dict:
    return {
        "identity_key": identity,
        "case_id": f"case::{identity[-4:]}",
        "guideline_id": guideline_id,
        "guideline_group_key": f"cluster__{mechanism_id}",
        "mechanism_id": mechanism_id,
        "mechanism_name": mechanism_id,
    }


def test_group_ablation_ready_with_fixed_overlap():
    module = load_module()

    summary, boundaries, groups, fixed_rows = module.audit_propagation(
        boundary_rows=[boundary_row()],
        group_rows=[group_row()],
        assignment_rows=[
            assignment("owner__repo::CVE-2099-0001"),
            assignment("owner__repo::CVE-2099-0002"),
            assignment("owner__repo::CVE-2099-0003"),
        ],
        fixed_identities={"owner__repo::CVE-2099-0001", "owner__repo::CVE-2099-0003"},
        min_group_representatives=2,
    )

    assert summary["status_counts"] == {"group_ablation_ready": 1}
    assert boundaries[0]["propagation_status"] == "group_ablation_ready"
    assert boundaries[0]["same_guideline_representative_count"] == 2
    assert boundaries[0]["fixed_group_overlap_count"] == 2
    assert groups[0]["status_counts"] == {"group_ablation_ready": 1}
    assert [row["identity_key"] for row in fixed_rows] == [
        "owner__repo::CVE-2099-0001",
        "owner__repo::CVE-2099-0003",
    ]


def test_assignment_conflict_blocks_group_propagation():
    module = load_module()

    summary, boundaries, _, _ = module.audit_propagation(
        boundary_rows=[boundary_row()],
        group_rows=[group_row()],
        assignment_rows=[
            assignment("owner__repo::CVE-2099-0001", guideline_id="gl_other", mechanism_id="mech_other"),
            assignment("owner__repo::CVE-2099-0002"),
        ],
        fixed_identities=None,
        min_group_representatives=2,
    )

    assert summary["status_counts"] == {"blocked_by_assignment_conflict": 1}
    assert boundaries[0]["assigned_elsewhere_count"] == 1
    assert boundaries[0]["propagation_status"] == "blocked_by_assignment_conflict"


def test_release_mechanism_mismatch_requires_regeneration():
    module = load_module()

    summary, boundaries, _, _ = module.audit_propagation(
        boundary_rows=[boundary_row(mechanism_id="mech_refined")],
        group_rows=[group_row(mechanism_id="mech_old_release")],
        assignment_rows=[
            assignment("owner__repo::CVE-2099-0001", mechanism_id="mech_old_release"),
            assignment("owner__repo::CVE-2099-0002", mechanism_id="mech_old_release"),
        ],
        fixed_identities={"owner__repo::CVE-2099-0001"},
        min_group_representatives=2,
    )

    assert summary["status_counts"] == {"requires_release_regeneration": 1}
    assert boundaries[0]["propagation_status"] == "requires_release_regeneration"


def test_low_support_and_outside_fixed_set_are_separate():
    module = load_module()

    low_summary, low_boundaries, _, _ = module.audit_propagation(
        boundary_rows=[boundary_row(representative_cases=["owner__repo::CVE-2099-0001"])],
        group_rows=[group_row()],
        assignment_rows=[assignment("owner__repo::CVE-2099-0001")],
        fixed_identities={"owner__repo::CVE-2099-0001"},
        min_group_representatives=2,
    )
    assert low_summary["status_counts"] == {"group_ablation_candidate_low_support": 1}
    assert low_boundaries[0]["propagation_status"] == "group_ablation_candidate_low_support"

    outside_summary, outside_boundaries, _, _ = module.audit_propagation(
        boundary_rows=[boundary_row()],
        group_rows=[group_row()],
        assignment_rows=[
            assignment("owner__repo::CVE-2099-0001"),
            assignment("owner__repo::CVE-2099-0002"),
        ],
        fixed_identities={"other__repo::CVE-2099-9999"},
        min_group_representatives=2,
    )
    assert outside_summary["status_counts"] == {"group_ablation_candidate_outside_fixed_set": 1}
    assert outside_boundaries[0]["propagation_status"] == "group_ablation_candidate_outside_fixed_set"


def test_cli_writes_diagnostic_artifact(tmp_path: Path):
    boundaries = tmp_path / "boundaries.jsonl"
    groups = tmp_path / "groups.jsonl"
    assignments = tmp_path / "assignments.jsonl"
    identities = tmp_path / "ids.jsonl"
    output = tmp_path / "out"
    write_jsonl(boundaries, [boundary_row()])
    write_jsonl(groups, [group_row()])
    write_jsonl(
        assignments,
        [
            assignment("owner__repo::CVE-2099-0001"),
            assignment("owner__repo::CVE-2099-0002"),
        ],
    )
    write_jsonl(identities, [{"identity_key": "owner__repo::CVE-2099-0001"}])

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--boundary-overrides",
            str(boundaries),
            "--group-report",
            str(groups),
            "--case-assignments",
            str(assignments),
            "--fixed-identity-file",
            str(identities),
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
        "diagnostic_only",
        "no_bad_case_answer_key",
        "no_regex_fallback",
        "no_release_or_sidecar_mutation",
        "same_identity_recall_required_for_paper_claims",
    ]
    assert (output / "boundary_propagation.jsonl").is_file()
    assert (output / "group_propagation.jsonl").is_file()
    assert (output / "fixed_identity_candidates.jsonl").is_file()
