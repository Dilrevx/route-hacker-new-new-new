from pathlib import Path
import runpy
from unittest.mock import patch


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


def test_batch_rejects_overcommitted_llm_concurrency(tmp_path):
    module = runpy.run_path(str(Path(__file__).resolve().parents[1] / "scripts" / "run_native_iris_batch.py"))
    manifest = tmp_path / "manifest.jsonl"
    allowlist = tmp_path / "allowlist.jsonl"
    row = {
        "identity_key": "repo::CVE-1",
        "project_slug": "repo_CVE-1",
        "iris_query": "cwe-022wLLM",
        "input_paths": {"source": "source", "codeql_db": "db", "package_names": "packages.txt"},
        "revisions": {"v2_checkout_revision": "abc123"},
        "source_provenance": [{"source_family": "test"}],
        "input_status": {"codeql_db_status": "codeql_db_created"},
    }
    manifest.write_text(__import__("json").dumps(row) + "\n")
    allowlist.write_text(__import__("json").dumps(row) + "\n")
    with patch(
        "sys.argv",
        [
            "run_native_iris_batch.py",
            "--iris-manifest", str(manifest),
            "--allowlist", str(allowlist),
            "--expected-manifest-count", "1",
            "--workspace-root", str(tmp_path / "workspaces"),
            "--clean-iris-root", str(tmp_path),
            "--codeql-dir", str(tmp_path),
            "--bridge-url", "http://127.0.0.1:18888",
            "--output-dir", str(tmp_path / "output"),
            "--materializer", str(tmp_path / "materialize.py"),
            "--single-case-runner", str(tmp_path / "runner.py"),
            "--max-workers", "8",
            "--num-threads", "8",
            "--bridge-max-concurrency", "8",
        ],
    ):
        try:
            module["main"]()
        except SystemExit as exc:
            assert "exceeds bridge capacity" in str(exc)
        else:
            raise AssertionError("overcommitted dispatch must be rejected")


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


def test_batch_rejects_partial_codeql_database(tmp_path):
    module = runpy.run_path(str(Path(__file__).resolve().parents[1] / "scripts" / "run_native_iris_batch.py"))
    database = tmp_path / "db"
    database.mkdir()
    (database / "codeql-database.yml").write_text("primaryLanguage: java\n")
    errors = module["codeql_database_errors"]({"input_paths": {"codeql_db": str(database)}})
    assert len(errors) == 1
    assert "db-java" in errors[0]
    (database / "db-java").mkdir()
    assert module["codeql_database_errors"]({"input_paths": {"codeql_db": str(database)}}) == []


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


def test_traex_alias_injection_preserves_valid_python(tmp_path):
    module = runpy.run_path(str(Path(__file__).resolve().parents[1] / "scripts" / "materialize_iris_case.py"))
    gpt = tmp_path / "gpt.py"
    gpt.write_text(
        'import os\n'
        'from openai import OpenAI\n'
        '_model_name_map = {\n'
        '    "gpt-4": "gpt-4-preview"\n'
        '}\n'
        '_OPENAI_DEFAULT_PARAMS = {}\n'
        'class GPTModel:\n'
        '    def __init__(self, api_key):\n'
        '        self.client = OpenAI(api_key=api_key)\n'
        '    def _predict(self, main_prompt, expect_json=False):\n'
        '        return self.client.chat.completions.create(model="gpt-4", messages=main_prompt)\n'
    )
    module["add_traex_model_aliases"](gpt)
    source = gpt.read_text()
    assert '"gpt-4": "gpt-4-preview",' in source
    assert '"gpt-traex-pro": "DeepSeek-V4-Pro",' in source
    assert "def _create_completion_with_retry" in source
    assert "IRIS_LLM_MAX_ATTEMPTS" in source
    compile(source, str(gpt), "exec")


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
