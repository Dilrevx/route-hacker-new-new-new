import json
import runpy
from pathlib import Path


def test_repaired_db_manifest_requires_verified_evidence_and_complete_layout(tmp_path):
    module = runpy.run_path(
        str(
            Path(__file__).resolve().parents[1]
            / "scripts"
            / "build_repaired_db_native_iris_manifest.py"
        )
    )
    source = tmp_path / "source"
    source.mkdir()
    packages = tmp_path / "packages.txt"
    packages.write_text("io.jstach\n")
    database = tmp_path / "database"
    (database / "db-java" / "default").mkdir(parents=True)
    (database / "codeql-database.yml").write_text("primaryLanguage: java\n")
    (database / "db-java" / "default" / "exprs.rel").write_text("")

    admission = {
        "case_id": "iris213::case",
        "project_slug": "owner__repo_CVE-2023-0001_1.0.0",
        "cve_id": "CVE-2023-0001",
        "cwe_id": "CWE-079",
        "iris_query": "cwe-079wLLM",
        "input_paths": {"source": str(source), "package_names": str(packages)},
        "revisions": {
            "declared_buggy_commit": "abc123",
            "official_buggy_commit_id": "abc123",
        },
        "official_iris_admission": {
            "exact_source_receipt": True,
            "fix_info_present": True,
            "native_query_supported": True,
            "package_names_present": True,
            "project_info_present": True,
        },
        "source_provenance": {"status": "source_materialized_exact_archive_snapshot"},
    }
    source_receipt = {
        "case_id": "iris213::case",
        "project_slug": admission["project_slug"],
        "status": "source_materialized_exact_archive_snapshot",
    }
    repair_receipt = {
        "case_id": "iris213::case",
        "status": "codeql_db_repaired",
        "source_revision_evidence": {"verified": True},
        "validated_decision": {"decision_sha256": "decision"},
        "repair_attempt": {
            "database_valid": True,
            "database_dir": str(database),
            "source_integrity_evidence": {"verified": True, "changed_path_count": 0},
        },
    }
    ledger = tmp_path / "repair.jsonl"
    ledger.write_text(json.dumps(repair_receipt) + "\n")

    row, binding = module["build_manifest_row"](
        admission,
        source_receipt,
        repair_receipt,
        ledger,
    )

    assert row["input_paths"]["codeql_db"] == str(database.resolve())
    assert row["input_status"]["codeql_db_status"] == "codeql_db_created_by_compile_builder_v2"
    assert row["revisions"]["v2_checkout_revision"] == "abc123"
    assert binding["relation_file_count"] == 1

    repair_receipt["repair_attempt"]["source_integrity_evidence"] = {"verified": False}
    try:
        module["build_manifest_row"](admission, source_receipt, repair_receipt, ledger)
    except ValueError as exc:
        assert "source-integrity" in str(exc)
    else:
        raise AssertionError("unverified source integrity must block manifest admission")
