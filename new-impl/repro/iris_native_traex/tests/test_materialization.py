from pathlib import Path
import runpy


def test_scripts_are_present():
    root = Path(__file__).resolve().parents[1] / "scripts"
    assert (root / "serve_traex_openai.py").is_file()
    assert (root / "materialize_iris_case.py").is_file()
    assert (root / "run_native_iris_case.py").is_file()
    assert (root / "run_native_iris_batch.py").is_file()
    assert (root / "summarize_native_iris_metrics.py").is_file()


def test_batch_attempt_id_is_namespaced():
    module = runpy.run_path(str(Path(__file__).resolve().parents[1] / "scripts" / "run_native_iris_batch.py"))
    assert module["safe_name"]("flash-a1") == "flash-a1"
    assert module["safe_name"]("v8:case") == "v8_case"


def test_manifest_input_path_validation_reports_missing_paths(tmp_path):
    module = runpy.run_path(str(Path(__file__).resolve().parents[1] / "scripts" / "run_native_iris_batch.py"))
    row = {
        "input_paths": {
            "source": str(tmp_path / "source"),
            "codeql_db": str(tmp_path / "db"),
            "package_names": str(tmp_path / "packages.txt"),
        }
    }
    errors = module["input_path_errors"](row)
    assert len(errors) == 3
    assert "source" in errors[0]


def test_manifest_materialization_path_validation_requires_revision(tmp_path):
    module = runpy.run_path(str(Path(__file__).resolve().parents[1] / "scripts" / "materialize_iris_case.py"))
    row = {
        "identity_key": "repo::CVE-1",
        "project_slug": "repo_CVE-1",
        "iris_query": "cwe-022wLLM",
        "input_paths": {"source": "a", "codeql_db": "b", "package_names": "c"},
    }
    try:
        module["validate_manifest_row"](row)
    except ValueError as exc:
        assert "v2_checkout_revision" in str(exc)
    else:
        raise AssertionError("missing revision must be rejected")


def test_batch_manifest_accepts_v2_checkout_revision(tmp_path):
    module = runpy.run_path(str(Path(__file__).resolve().parents[1] / "scripts" / "run_native_iris_batch.py"))
    row = {
        "identity_key": "repo::CVE-1",
        "project_slug": "repo_CVE-1",
        "iris_query": "cwe-022wLLM",
        "input_paths": {
            "source": str(tmp_path / "source"),
            "codeql_db": str(tmp_path / "db"),
            "package_names": str(tmp_path / "packages.txt"),
        },
        "revisions": {"v2_checkout_revision": "abc123"},
        "source_provenance": [{"source_family": "test"}],
        "input_status": {"codeql_db_status": "codeql_db_created"},
    }
    validated = module["validate_iris_manifest"]([row], [row], expected_count=1)
    assert validated == [row]


def test_batch_summary_counts_verified_statistics(tmp_path):
    module = runpy.run_path(str(Path(__file__).resolve().parents[1] / "scripts" / "run_native_iris_batch.py"))
    ledger = tmp_path / "receipts.jsonl"
    ledger.write_text(
        '{"status":"completed_verified","elapsed_seconds":3,"iris_statistics":{"candidate_apis":5,"vanilla_paths":2}}\n'
        '{"status":"failed_or_incomplete","elapsed_seconds":9,"iris_statistics":{"candidate_apis":99}}\n'
    )
    summary = module["summarize_receipts"](ledger)
    assert summary["completed_verified_count"] == 1
    assert summary["verified_totals"]["elapsed_seconds"] == 3
    assert summary["verified_totals"]["candidate_apis"] == 5
    assert summary["verified_totals"]["vanilla_paths"] == 2
