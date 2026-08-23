import runpy
from pathlib import Path


def test_full_admission_requires_only_official_metadata_and_exact_source(tmp_path):
    module = runpy.run_path(
        str(
            Path(__file__).resolve().parents[1]
            / "scripts"
            / "build_full_iris_strict_admission.py"
        )
    )
    package_names = tmp_path / "package-names"
    package_names.mkdir()
    (package_names / "owner__repo_CVE-2023-0001_1.0.0.txt").write_text("org.example\n")
    source = tmp_path / "source"
    source.mkdir()
    case = {
        "case_id": "v8:owner__repo_CVE-2023-0001_1.0.0",
        "identity_key": "owner__repo_CVE-2023-0001_1.0.0",
        "project_slug": "owner__repo_CVE-2023-0001_1.0.0",
        "iris_query": "cwe-079wLLM",
        "full213_matrix_evidence": {"case_index": 7},
    }
    receipt = {
        "case_id": case["case_id"],
        "project_slug": case["project_slug"],
        "status": "source_materialized_exact_archive_snapshot",
        "declared_buggy_commit": "abc123",
        "resolved_buggy_commit": "abc123",
        "source_dir": str(source),
        "archive_result": {"archive_sha256": "archive"},
    }
    rows, rejections = module["build_rows"](
        frozen_cases=[case],
        source_receipts=[receipt],
        project_rows=[
            {
                "project_slug": case["project_slug"],
                "cve_id": "CVE-2023-0001",
                "cwe_id": "CWE-079",
                "buggy_commit_id": "abc123",
            }
        ],
        fix_rows=[
            {
                "project_slug": case["project_slug"],
                "cve_id": "CVE-2023-0001",
            }
        ],
        source_sink_rows=[],
        package_names_dir=package_names,
        supported_query_names={"cwe-079wLLM"},
        clean_commit="clean123",
    )

    assert rejections == {}
    assert len(rows) == 1
    row = rows[0]
    assert row["official_iris_admission"] == {
        "exact_source_receipt": True,
        "fix_info_present": True,
        "native_query_supported": True,
        "package_names_present": True,
        "project_info_present": True,
    }
    assert row["revisions"]["declared_buggy_commit"] == "abc123"
    assert row["official_table_evidence"]["frozen_full213_case_index"] == 7


def test_full_admission_rejects_unsupported_query_without_emitting_a_row(tmp_path):
    module = runpy.run_path(
        str(
            Path(__file__).resolve().parents[1]
            / "scripts"
            / "build_full_iris_strict_admission.py"
        )
    )
    package_names = tmp_path / "package-names"
    package_names.mkdir()
    source = tmp_path / "source"
    source.mkdir()
    case = {
        "case_id": "v8:owner__repo_CVE-2023-0001_1.0.0",
        "project_slug": "owner__repo_CVE-2023-0001_1.0.0",
        "iris_query": "cwe-999wLLM",
    }
    receipt = {
        "case_id": case["case_id"],
        "project_slug": case["project_slug"],
        "status": "source_materialized_exact_archive_snapshot",
        "declared_buggy_commit": "abc123",
        "resolved_buggy_commit": "abc123",
        "source_dir": str(source),
    }
    rows, rejections = module["build_rows"](
        frozen_cases=[case],
        source_receipts=[receipt],
        project_rows=[
            {
                "project_slug": case["project_slug"],
                "cve_id": "CVE-2023-0001",
                "cwe_id": "CWE-999",
                "buggy_commit_id": "abc123",
            }
        ],
        fix_rows=[{"project_slug": case["project_slug"], "cve_id": "CVE-2023-0001"}],
        source_sink_rows=[],
        package_names_dir=package_names,
        supported_query_names=set(),
        clean_commit="clean123",
    )

    assert rows == []
    assert rejections == {
        "native_query_supported;package_names_present": 1,
    }
