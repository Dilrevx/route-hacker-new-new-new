from pathlib import Path
import runpy
import sys
import types
from unittest.mock import patch


def test_scripts_are_present():
    root = Path(__file__).resolve().parents[1] / "scripts"
    assert (root / "serve_traex_openai.py").is_file()
    assert (root / "materialize_iris_case.py").is_file()
    assert (root / "run_native_iris_case.py").is_file()
    assert (root / "run_native_iris_batch.py").is_file()
    assert (root / "summarize_native_iris_metrics.py").is_file()


def test_bridge_json_mode_preserves_the_callers_requested_json_shape():
    module = runpy.run_path(str(Path(__file__).resolve().parents[1] / "scripts" / "serve_traex_openai.py"))
    prompt = module["render_prompt"](
        [
            {"role": "system", "content": "Classify APIs."},
            {"role": "user", "content": "Return one JSON list, such as []."},
        ],
        require_json=True,
    )
    assert "one valid JSON value" in prompt
    assert "exactly the JSON shape requested" in prompt
    assert "valid JSON object" not in prompt


def test_batch_attempt_id_is_namespaced():
    module = runpy.run_path(str(Path(__file__).resolve().parents[1] / "scripts" / "run_native_iris_batch.py"))
    assert module["safe_name"]("flash-a1") == "flash-a1"
    assert module["safe_name"]("v8:case") == "v8_case"


def test_batch_single_case_command_forwards_label_batch_sizes(tmp_path):
    module = runpy.run_path(str(Path(__file__).resolve().parents[1] / "scripts" / "run_native_iris_batch.py"))
    command = module["single_case_command"](
        python="python3",
        runner=tmp_path / "runner.py",
        workspace=tmp_path / "workspace",
        run_id="qa-a8-case",
        bridge_url="http://127.0.0.1:18889",
        llm="gpt-traex-pro",
        num_threads=1,
        label_api_batch_size=30,
        label_func_param_batch_size=20,
        timeout_seconds=7200,
        output_dir=tmp_path / "output",
    )
    assert command[command.index("--label-api-batch-size") + 1] == "30"
    assert command[command.index("--label-func-param-batch-size") + 1] == "20"


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


def test_batch_quarantines_interrupted_workspace_before_resume(tmp_path):
    module = runpy.run_path(str(Path(__file__).resolve().parents[1] / "scripts" / "run_native_iris_batch.py"))
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "partial.txt").write_text("interrupted")

    quarantined = module["quarantine_workspace"](workspace)

    assert not workspace.exists()
    assert quarantined.is_dir()
    assert (quarantined / "partial.txt").read_text() == "interrupted"
    assert module["workspace_lock_path"](workspace) == tmp_path / ".workspace.lock"


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
        '        response = self.client.chat.completions.create(model="gpt-4", messages=main_prompt)\n'
        '        response=response.choices[0].message.content\n'
        '        return response\n'
    )
    module["add_traex_model_aliases"](gpt)
    source = gpt.read_text()
    assert '"gpt-4": "gpt-4-preview",' in source
    assert '"gpt-traex-pro": "DeepSeek-V4-Pro",' in source
    assert "def _create_completion_with_retry" in source
    assert "IRIS_LLM_MAX_ATTEMPTS" in source
    assert "def _retry_json_list_format" in source
    assert "IRIS_JSON_LIST_FORMAT_ATTEMPTS" in source
    compile(source, str(gpt), "exec")


def test_traex_alias_injection_retries_invalid_json_list_with_original_prompt(tmp_path, monkeypatch):
    module = runpy.run_path(str(Path(__file__).resolve().parents[1] / "scripts" / "materialize_iris_case.py"))
    gpt = tmp_path / "gpt.py"
    gpt.write_text(
        'import os\n'
        'from tqdm.contrib.concurrent import thread_map\n'
        'from openai import OpenAI\n'
        'import src.models.config as config\n'
        'from src.utils.mylogger import MyLogger\n'
        'from src.models.llm import LLM\n'
        '_model_name_map = {\n'
        '    "gpt-4": "gpt-4-preview"\n'
        '}\n'
        '_OPENAI_DEFAULT_PARAMS = {}\n'
        'class GPTModel(LLM):\n'
        '    def __init__(self, model_name, logger, **kwargs):\n'
        '        super().__init__(model_name, logger, _model_name_map, **kwargs)\n'
        '        api_key = "test"\n'
        '        self.client = OpenAI(api_key=api_key)\n'
        '        self.logprobs = None\n'
        '    def _predict(self, main_prompt, expect_json=False):\n'
        '        prompt = main_prompt\n'
        '        response = self.client.chat.completions.create(model=self.model_id, messages=prompt)\n'
        '        if response.choices[0].logprobs != None:\n'
        '            self.logprobs = response.choices[0].logprobs.content\n'
        '        else:\n'
        '            self.logprobs = None\n'
        '        response = response.choices[0].message.content\n'
        '        return response\n'
    )
    module["add_traex_model_aliases"](gpt)

    calls = []

    class DummyCompletion:
        def __init__(self, text):
            self.choices = [
                types.SimpleNamespace(
                    logprobs=None,
                    message=types.SimpleNamespace(content=text),
                )
            ]

    class DummyClient:
        def __init__(self):
            self.chat = types.SimpleNamespace(
                completions=types.SimpleNamespace(create=self.create)
            )

        def create(self, **kwargs):
            calls.append(kwargs)
            return DummyCompletion("explanation before JSON" if len(calls) == 1 else "[]")

    class DummyOpenAI:
        def __init__(self, **kwargs):
            self._client = DummyClient()

        @property
        def chat(self):
            return self._client.chat

    class DummyLLM:
        def __init__(self, model_name, logger, model_name_map, **kwargs):
            self.model_id = model_name_map[model_name]
            self.kwargs = kwargs

    openai_module = types.ModuleType("openai")
    openai_module.OpenAI = DummyOpenAI
    src_module = types.ModuleType("src")
    models_module = types.ModuleType("src.models")
    config_module = types.ModuleType("src.models.config")
    llm_module = types.ModuleType("src.models.llm")
    llm_module.LLM = DummyLLM
    utils_module = types.ModuleType("src.utils")
    logger_module = types.ModuleType("src.utils.mylogger")
    logger_module.MyLogger = object
    tqdm_module = types.ModuleType("tqdm")
    tqdm_contrib_module = types.ModuleType("tqdm.contrib")
    tqdm_concurrent_module = types.ModuleType("tqdm.contrib.concurrent")
    tqdm_concurrent_module.thread_map = lambda function, values, **kwargs: [function(value) for value in values]
    with patch.dict(
        sys.modules,
        {
            "openai": openai_module,
            "src": src_module,
            "src.models": models_module,
            "src.models.config": config_module,
            "src.models.llm": llm_module,
            "src.utils": utils_module,
            "src.utils.mylogger": logger_module,
            "tqdm": tqdm_module,
            "tqdm.contrib": tqdm_contrib_module,
            "tqdm.contrib.concurrent": tqdm_concurrent_module,
        },
    ):
        namespace = runpy.run_path(str(gpt))
        model = namespace["GPTModel"]("gpt-traex-pro", None)
        prompt = [
            {"role": "system", "content": "Return the result as a json list."},
            {"role": "user", "content": "Classify the APIs."},
        ]
        assert model._predict(prompt) == "[]"

    assert len(calls) == 2
    assert calls[0]["messages"] == prompt
    assert calls[1]["messages"][:2] == prompt
    assert calls[1]["messages"][2]["role"] == "user"
    assert "valid JSON array" in calls[1]["messages"][2]["content"]


def test_traex_alias_injection_accepts_complete_fenced_json_list_without_retry(tmp_path):
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
        '    def __init__(self):\n'
        '        api_key = "test"\n'
        '        self.client = OpenAI(api_key=api_key)\n'
        '    def _predict(self, main_prompt, expect_json=False):\n'
        '        response = self.client.chat.completions.create(model="gpt-4", messages=main_prompt)\n'
        '        response=response.choices[0].message.content\n'
        '        return response\n'
    )
    module["add_traex_model_aliases"](gpt)
    source = gpt.read_text()
    namespace = {"json": __import__("json")}
    class_start = source.index("    @staticmethod\n    def _is_json_list_response")
    class_end = source.index("    def _retry_json_list_format", class_start)
    method_source = source[class_start:class_end]
    exec("class ValidationOnly:\n" + method_source, namespace)
    assert namespace["ValidationOnly"]._is_json_list_response("```json\n[]\n```")


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
