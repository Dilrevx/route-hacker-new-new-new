from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import sys
import time
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from route_hacker.runtime.codeql_repair import RepairValidationError, stable_json_sha256
from scripts.run_codeql_llm_repair_dispatch import (
    build_repair_prompt,
    command_for_claude,
    extract_structured_output,
    invoke_openai_bridge_model,
    normalize_openai_base_url,
    repair_json_schema,
    validate_prior_completion_binding,
)


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "run_codeql_llm_repair_dispatch.py"
LAUNCHER = ROOT / "scripts" / "launch_deepseek_claude.sh"


def source_receipt(source: Path, case_id: str, revision: str) -> dict:
    archive = source.parent / "source.tar.gz"
    archive.write_bytes(b"exact-source")
    return {
        "case_id": case_id,
        "source_dir": str(source),
        "resolved_buggy_commit": revision,
        "status": "source_materialized_exact_archive_snapshot",
        "contract": {"exact_declared_buggy_commit_only": True},
        "archive_result": {
            "archive_path": str(archive),
            "archive_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
            "archive_url": f"https://codeload.example.test/org/repo/tar.gz/{revision}",
        },
    }


def failed_receipt(source: Path, case_id: str, revision: str) -> dict:
    log = source.parent / "failed.log"
    log.write_text("BUILD FAILURE\npassword=do-not-leak\n", encoding="utf-8")
    return {
        "case_id": case_id,
        "project_slug": "example",
        "resolved_buggy_commit": revision,
        "status": "codeql_db_failed",
        "source_dir": str(source),
        "planned_codeql_database_command": [
            "codeql",
            "database",
            "create",
            str(source.parent / "old-db"),
            "--language=java",
            f"--source-root={source}",
            "--overwrite",
            "--command",
            "mvn -DskipTests package",
        ],
        "codeql_database_create_result": {"log_path": str(log)},
    }


def deterministic_completion(failed: dict, source: dict) -> dict:
    return {
        "schema_version": "route_hacker_codeql_repair_dispatch.v1:case_completion",
        "case_id": failed["case_id"],
        "status": "no_safe_deterministic_repair",
        "failed_receipt_sha256": stable_json_sha256(failed),
        "source_receipt_sha256": stable_json_sha256(source),
    }


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )


def repair_packet() -> dict:
    return {
        "allowed_action_schema": {
            "maximum_actions": 4,
            "approved_java_homes": ["/opt/java-17"],
            "approved_maven_homes": ["/opt/maven-3.9"],
            "safe_build_args": ["-Denforcer.skip=true"],
            "safe_maven_heap_options": ["-Xmx4g"],
        }
    }


def test_llm_prompt_is_redacted_and_command_has_tools_disabled(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    prompt = build_repair_prompt(
        {
            "allowed_action_schema": {"kinds": ["no_safe_action"]},
            "failed_attempt": {"log": {"excerpt": "password=[REDACTED]"}},
        }
    )

    assert "do-not-leak" not in prompt
    assert "retry_same_command is a standalone action" in prompt
    command = command_for_claude("/opt/claude", repair_packet())
    assert "--tools" in command
    assert command[command.index("--tools") + 1] == ""


def test_repair_json_schema_encodes_per_packet_action_values() -> None:
    schema = json.loads(repair_json_schema(repair_packet()))
    actions = schema["properties"]["actions"]["oneOf"]
    retry_sequence, no_safe_sequence, executable_sequence = actions

    assert retry_sequence["maxItems"] == 1
    assert retry_sequence["items"]["properties"]["kind"] == {"const": "retry_same_command"}
    assert no_safe_sequence["maxItems"] == 1
    assert no_safe_sequence["items"]["properties"]["kind"] == {"const": "no_safe_action"}
    choices = executable_sequence["items"]["oneOf"]
    java_choice = next(
        choice for choice in choices if choice["properties"]["kind"] == {"const": "set_java_home"}
    )
    maven_choice = next(
        choice for choice in choices if choice["properties"]["kind"] == {"const": "set_maven_home"}
    )
    args_choice = next(
        choice for choice in choices if choice["properties"]["kind"] == {"const": "append_build_args"}
    )
    assert java_choice["properties"]["java_home"]["enum"] == ["/opt/java-17"]
    assert maven_choice["properties"]["maven_home"]["enum"] == ["/opt/maven-3.9"]
    assert args_choice["properties"]["args"]["minItems"] == 1
    assert args_choice["properties"]["args"]["items"]["enum"] == ["-Denforcer.skip=true"]


def test_launcher_suppresses_profile_settings_mutation() -> None:
    source = LAUNCHER.read_text(encoding="utf-8")

    assert "settings mutation suppressed for worker" in source
    assert 'COMPILE_BUILDER_CLAUDE_BIN:-/data/lhq/.local/bin/claude' in source
    assert 'exec "$@"' in source


def test_extract_structured_output_uses_terminal_result_only() -> None:
    stream = "\n".join(
        [
            '{"type":"assistant","message":{"content":[{"type":"text","text":"ignore"}]}}',
            json.dumps(
                {
                    "type": "result",
                    "structured_output": {
                        "actions": [{"kind": "no_safe_action"}],
                        "rationale": "No listed action applies.",
                    },
                }
            ),
        ]
    )
    assert extract_structured_output(stream)["actions"] == [{"kind": "no_safe_action"}]


def test_openai_bridge_transport_wraps_validated_structured_output(tmp_path: Path) -> None:
    class BridgeHandler(BaseHTTPRequestHandler):
        request_payload: dict | None = None
        request_path: str | None = None

        def log_message(self, _format: str, *args: object) -> None:
            return

        def do_POST(self) -> None:
            BridgeHandler.request_path = self.path
            BridgeHandler.request_payload = json.loads(
                self.rfile.read(int(self.headers["Content-Length"])).decode("utf-8")
            )
            payload = {
                "choices": [
                    {
                        "message": {
                            "content": json.dumps(
                                {
                                    "actions": [{"kind": "no_safe_action"}],
                                    "rationale": "No approved action is justified.",
                                }
                            )
                        }
                    }
                ],
                "usage": {"total_tokens": 7},
            }
            body = json.dumps(payload).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), BridgeHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        result = invoke_openai_bridge_model(
            bridge_url=f"http://127.0.0.1:{server.server_port}",
            model="DeepSeek-V4-Pro",
            prompt="Return strict JSON.",
            output_path=tmp_path / "model-output.txt",
            timeout_seconds=5,
            case_id="case::bridge",
        )
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()

    assert result["bounded_process"]["returncode"] == 0
    assert result["bridge"]["model"] == "DeepSeek-V4-Pro"
    assert BridgeHandler.request_path == "/v1/chat/completions"
    assert BridgeHandler.request_payload is not None
    assert BridgeHandler.request_payload["response_format"] == {"type": "json_object"}
    assert extract_structured_output(result["raw_text"]) == {
        "actions": [{"kind": "no_safe_action"}],
        "rationale": "No approved action is justified.",
    }


@pytest.mark.parametrize(
    ("bridge_url", "expected"),
    [
        ("http://127.0.0.1:18889", "http://127.0.0.1:18889/v1"),
        ("http://127.0.0.1:18889/", "http://127.0.0.1:18889/v1"),
        ("http://127.0.0.1:18889/v1", "http://127.0.0.1:18889/v1"),
        ("http://127.0.0.1:18889/v1/", "http://127.0.0.1:18889/v1"),
    ],
)
def test_normalize_openai_base_url(bridge_url: str, expected: str) -> None:
    assert normalize_openai_base_url(bridge_url) == expected


def test_normalize_openai_base_url_rejects_blank_value() -> None:
    with pytest.raises(ValueError, match="must not be empty"):
        normalize_openai_base_url("   ")


def test_prior_completion_binding_rejects_receipt_mismatch(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    receipt = source_receipt(source, "v8:example", "abc123")
    failed = failed_receipt(source, "v8:example", "abc123")
    completion = deterministic_completion(failed, receipt)
    completion["source_receipt_sha256"] = "wrong"

    with pytest.raises(RepairValidationError, match="source receipt hash mismatch"):
        validate_prior_completion_binding(
            failed_receipt=failed,
            source_receipt=receipt,
            completion=completion,
        )


def test_dry_run_only_accepts_deterministic_unresolved_rows(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    case_id = "v8:example"
    source_row = source_receipt(source, case_id, "abc123")
    failed = failed_receipt(source, case_id, "abc123")
    prior = deterministic_completion(failed, source_row)
    failed_path = tmp_path / "failed.jsonl"
    source_path = tmp_path / "source.jsonl"
    prior_path = tmp_path / "prior.jsonl"
    output = tmp_path / "output"
    write_jsonl(failed_path, [failed])
    write_jsonl(source_path, [source_row])
    write_jsonl(prior_path, [prior])

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--failed-receipts",
            str(failed_path),
            "--source-receipts",
            str(source_path),
            "--prior-ledger",
            str(prior_path),
            "--output-dir",
            str(output),
            "--expected-eligible-case-count",
            "1",
            "--dry-run",
        ],
        cwd=ROOT,
        env={"PYTHONPATH": str(ROOT / "src")},
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    summary = json.loads((output / "summary.json").read_text(encoding="utf-8"))
    row = json.loads((output / "w1_llm_repair_receipts.jsonl").read_text(encoding="utf-8"))
    assert summary["status"] == "dry_run_completed"
    assert summary["counts"]["eligible_deterministic_unresolved_case_count"] == 1
    assert row["status"] == "llm_repair_dry_run"
    assert row["contract"]["model_actions_validated_locally"] is True
    assert row["source_revision_evidence"]["verified"] is True


def test_controller_uses_its_adjacent_runtime_without_pythonpath(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    case_id = "v8:isolated-runtime"
    source_row = source_receipt(source, case_id, "abc123")
    failed = failed_receipt(source, case_id, "abc123")
    prior = deterministic_completion(failed, source_row)
    failed_path = tmp_path / "failed.jsonl"
    source_path = tmp_path / "source.jsonl"
    prior_path = tmp_path / "prior.jsonl"
    output = tmp_path / "output"
    model = tmp_path / "fake-claude"
    model.write_text(
        "#!" + sys.executable + "\n"
        "import json\n"
        "import sys\n"
        "sys.stdin.read()\n"
        "print(json.dumps({'type':'result','structured_output':"
        "{'actions':[{'kind':'no_safe_action'}],'rationale':'no action'}}))\n",
        encoding="utf-8",
    )
    model.chmod(model.stat().st_mode | stat.S_IXUSR)
    write_jsonl(failed_path, [failed])
    write_jsonl(source_path, [source_row])
    write_jsonl(prior_path, [prior])

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--failed-receipts",
            str(failed_path),
            "--source-receipts",
            str(source_path),
            "--prior-ledger",
            str(prior_path),
            "--output-dir",
            str(output),
            "--expected-eligible-case-count",
            "1",
            "--claude-command",
            str(model),
            "--model-timeout-seconds",
            "10",
        ],
        cwd=ROOT,
        env={"PATH": os.environ["PATH"]},
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    row = json.loads((output / "w1_llm_repair_receipts.jsonl").read_text(encoding="utf-8"))
    assert row["status"] == "no_safe_llm_repair"


def test_controller_has_distinct_worker_failure_status() -> None:
    source = SCRIPT.read_text(encoding="utf-8")

    assert '"llm_repair_worker_failed"' in source
    assert '"status": "llm_repair_worker_failed"' in source


def test_controller_keeps_progress_bounded_across_repair_queue_turnover(
    tmp_path: Path,
) -> None:
    case_ids = [f"v8:bounded-{index}" for index in range(5)]
    failed_rows: list[dict] = []
    source_rows: list[dict] = []
    prior_rows: list[dict] = []
    for index, case_id in enumerate(case_ids):
        source = tmp_path / f"source-{index}"
        source.mkdir()
        source_row = source_receipt(source, case_id, f"revision-{index}")
        failed = failed_receipt(source, case_id, f"revision-{index}")
        failed_rows.append(failed)
        source_rows.append(source_row)
        prior_rows.append(deterministic_completion(failed, source_row))

    failed_path = tmp_path / "failed.jsonl"
    source_path = tmp_path / "source.jsonl"
    prior_path = tmp_path / "prior.jsonl"
    write_jsonl(failed_path, failed_rows)
    write_jsonl(source_path, source_rows)
    write_jsonl(prior_path, prior_rows)
    output = tmp_path / "output"
    model = tmp_path / "slow-fake-claude"
    model.write_text(
        "#!" + sys.executable + "\n"
        "import json\n"
        "import sys\n"
        "import time\n"
        "sys.stdin.read()\n"
        "time.sleep(0.25)\n"
        "print(json.dumps({'type':'result','structured_output':"
        "{'actions':[{'kind':'no_safe_action'}],'rationale':'no action'}}))\n",
        encoding="utf-8",
    )
    model.chmod(model.stat().st_mode | stat.S_IXUSR)

    process = subprocess.Popen(
        [
            sys.executable,
            str(SCRIPT),
            "--failed-receipts",
            str(failed_path),
            "--source-receipts",
            str(source_path),
            "--prior-ledger",
            str(prior_path),
            "--output-dir",
            str(output),
            "--expected-eligible-case-count",
            str(len(case_ids)),
            "--claude-command",
            str(model),
            "--model-timeout-seconds",
            "10",
            "--max-workers",
            "2",
            "--heartbeat-seconds",
            "1",
        ],
        cwd=ROOT,
        env={"PATH": os.environ["PATH"]},
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    summary_path = output / "summary.json"
    observed_progress: list[dict] = []
    deadline = time.monotonic() + 15
    last_payload = ""
    while process.poll() is None and time.monotonic() < deadline:
        if summary_path.is_file():
            payload = summary_path.read_text(encoding="utf-8")
            if payload != last_payload:
                last_payload = payload
                progress = json.loads(payload)
                if progress["status"] == "running":
                    observed_progress.append(progress)
        time.sleep(0.02)

    stdout, stderr = process.communicate(timeout=15)
    assert process.returncode == 0, f"stdout={stdout}\nstderr={stderr}"
    assert observed_progress
    assert any(
        progress["counts"]["completed_this_invocation"] >= 1
        for progress in observed_progress
    )
    for progress in observed_progress:
        counts = progress["counts"]
        assert counts["active_case_count"] <= 2
        assert (
            counts["queued_not_started_count"]
            + counts["active_case_count"]
            + counts["completed_this_invocation"]
            == counts["selected_case_count"]
        )
        assert len(progress["active_cases"]) == counts["active_case_count"]

    rows = [
        json.loads(line)
        for line in (output / "w1_llm_repair_receipts.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
        if line.strip()
    ]
    assert len(rows) == len(case_ids)
    assert {row["status"] for row in rows} == {"no_safe_llm_repair"}
