from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts" / "build_source_reviewed_release_candidate.py"


def load_module():
    spec = importlib.util.spec_from_file_location("build_source_reviewed_release_candidate", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text("".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows), encoding="utf-8")


def boundary(label: str, representatives: list[str]) -> dict:
    return {
        "guideline_id": "gl_old",
        "boundary_label": label,
        "mechanism_id": f"mech_{label}",
        "mechanism_name": f"mechanism {label}",
        "representative_cases": representatives,
        "retrieval_guideline": f"Audit mechanism {label} without using anchor answers.",
    }


def case(identity: str, cve: str = "CVE-2099-0001") -> dict:
    return {
        "identity_key": identity,
        "new_unified_case_id": f"case::{identity[-4:]}",
        "vulnerability": {"id": cve, "aliases": []},
        "classification": {"primary_hcvr_type": "test_type", "cwe_ids": ["CWE-999"]},
    }


def test_default_keeps_singleton_out_of_recall_sidecar():
    module = load_module()

    summary, guidelines, overrides, assignments, unresolved = module.build_release(
        boundaries=[
            boundary("two_case", ["owner__repo::CVE-2099-0001", "owner__repo::CVE-2099-0002"]),
            boundary("single_case", ["owner__repo::CVE-2099-0003"]),
        ],
        cases_by_identity={
            "owner__repo::CVE-2099-0001": case("owner__repo::CVE-2099-0001"),
            "owner__repo::CVE-2099-0002": case("owner__repo::CVE-2099-0002", "CVE-2099-0002"),
            "owner__repo::CVE-2099-0003": case("owner__repo::CVE-2099-0003", "CVE-2099-0003"),
        },
        include_singleton_overrides=False,
    )

    assert summary["guideline_count"] == 2
    assert summary["release_ready_guideline_count"] == 1
    assert summary["review_only_guideline_count"] == 1
    assert summary["override_count"] == 2
    assert len(assignments) == 3
    assert unresolved == []
    assert [row["boundary_label"] for row in guidelines] == ["single_case", "two_case"]
    assert all("source-reviewed mechanism boundary" in row["guideline_text"] for row in guidelines)
    assert [row["identity_key"] for row in overrides] == [
        "owner__repo::CVE-2099-0001",
        "owner__repo::CVE-2099-0002",
    ]


def test_include_singleton_overrides_adds_singletons_to_sidecar():
    module = load_module()

    summary, _, overrides, _, _ = module.build_release(
        boundaries=[boundary("single_case", ["owner__repo::CVE-2099-0003"])],
        cases_by_identity={"owner__repo::CVE-2099-0003": case("owner__repo::CVE-2099-0003")},
        include_singleton_overrides=True,
    )

    assert summary["release_ready_guideline_count"] == 1
    assert summary["override_count"] == 1
    assert overrides[0]["identity_key"] == "owner__repo::CVE-2099-0003"


def test_missing_representatives_are_reported():
    module = load_module()

    summary, _, overrides, assignments, unresolved = module.build_release(
        boundaries=[boundary("missing_case", ["missing__repo::CVE-2099-9999"])],
        cases_by_identity={},
        include_singleton_overrides=True,
    )

    assert summary["review_only_guideline_count"] == 1
    assert summary["unresolved_representative_count"] == 1
    assert overrides == []
    assert assignments == []
    assert unresolved[0]["reason"] == "representative_case_missing_from_cases_file"


def test_cli_writes_release_candidate(tmp_path: Path):
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    write_jsonl(
        source_dir / "boundary_overrides.jsonl",
        [boundary("two_case", ["owner__repo::CVE-2099-0001", "owner__repo::CVE-2099-0002"])],
    )
    cases = tmp_path / "cases.jsonl"
    write_jsonl(cases, [case("owner__repo::CVE-2099-0001"), case("owner__repo::CVE-2099-0002")])
    output = tmp_path / "out"

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--source-reviewed-sidecar-dir",
            str(source_dir),
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
        "source_reviewed_release_candidate",
        "accepted_boundaries_only",
        "no_regex_fallback",
        "no_bad_case_answer_key",
        "requires_same_identity_recall_before_claim",
    ]
    assert (output / "index.json").is_file()
    assert (output / "guidelines" / "sr_mech_0001.json").is_file()
    assert (output / "guideline_overrides.jsonl").is_file()
