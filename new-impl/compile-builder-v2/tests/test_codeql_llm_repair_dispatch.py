from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import sys
import tarfile
import time
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from route_hacker.runtime.codeql_repair import RepairValidationError, stable_json_sha256
import scripts.run_codeql_llm_repair_dispatch as dispatcher
from scripts.run_codeql_llm_repair_dispatch import (
    build_repair_prompt,
    command_for_claude,
    extract_structured_output,
    invoke_openai_bridge_model,
    materialize_isolated_attempt_receipts,
    normalize_openai_base_url,
    repair_json_schema,
    validate_prior_completion_binding,
)


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "run_codeql_llm_repair_dispatch.py"
LAUNCHER = ROOT / "scripts" / "launch_deepseek_claude.sh"


def source_receipt(source: Path, case_id: str, revision: str) -> dict:
    receipt_name = case_id.replace(":", "_")
    archive = source.parent / f"{receipt_name}.tar.gz"
    archive_input = source.parent / f"{receipt_name}-archive-input"
    archive_root = archive_input / "repo-revision"
    archive_root.mkdir(parents=True)
    (archive_root / "README.md").write_text("exact-source\n", encoding="utf-8")
    with tarfile.open(archive, "w:gz") as handle:
        handle.add(archive_root, arcname=archive_root.name)
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
            "removable_existing_build_args": ["-Dmaven.test.skip=true"],
            "safe_maven_heap_options": ["-Xmx4g"],
            "allow_prepend_maven_clean": False,
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
    assert "Unless you select set_java_home, execution inherits only the approved" in prompt
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
    removal_choice = next(
        choice
        for choice in choices
        if choice["properties"]["kind"] == {"const": "remove_existing_build_args"}
    )
    assert java_choice["properties"]["value"]["enum"] == ["/opt/java-17"]
    assert maven_choice["properties"]["value"]["enum"] == ["/opt/maven-3.9"]
    assert args_choice["properties"]["args"]["minItems"] == 1
    assert args_choice["properties"]["args"]["items"]["enum"] == ["-Denforcer.skip=true"]
    assert removal_choice["properties"]["args"]["items"]["enum"] == [
        "-Dmaven.test.skip=true"
    ]


def test_repair_json_schema_offers_clean_only_for_direct_maven_build() -> None:
    packet = repair_packet()
    packet["failed_attempt"] = {
        "planned_codeql_database_command": [
            "codeql",
            "database",
            "create",
            "/tmp/db",
            "--source-root=/tmp/source",
            "--command",
            "mvn -DskipTests package",
        ]
    }
    packet["allowed_action_schema"]["allow_prepend_maven_clean"] = True

    schema = json.loads(repair_json_schema(packet))
    choices = schema["properties"]["actions"]["oneOf"][2]["items"]["oneOf"]

    assert any(choice["properties"]["kind"] == {"const": "prepend_maven_clean"} for choice in choices)


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


def test_openai_bridge_connection_reset_becomes_a_failed_model_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def connection_reset(*_args: object, **_kwargs: object) -> object:
        raise ConnectionResetError(104, "Connection reset by peer")

    monkeypatch.setattr(dispatcher.urllib.request, "urlopen", connection_reset)

    result = invoke_openai_bridge_model(
        bridge_url="http://127.0.0.1:18889",
        model="DeepSeek-V4-Pro",
        prompt="Return strict JSON.",
        output_path=tmp_path / "model-output.txt",
        timeout_seconds=5,
        case_id="case::connection-reset",
    )

    assert result["bounded_process"]["returncode"] == 1
    assert result["bounded_process"]["timed_out"] is False
    assert result["bounded_process"]["transport_error"].startswith(
        "ConnectionResetError:"
    )
    assert "ConnectionResetError" in result["raw_text"]


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


def test_materialize_isolated_attempt_receipts_uses_archive_and_rewrites_source_root(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    case_id = "v8:isolated-source"
    receipt = source_receipt(source, case_id, "abc123")
    failed = failed_receipt(source, case_id, "abc123")
    destination = tmp_path / "attempt-source"

    execution_failed, execution_source, evidence = materialize_isolated_attempt_receipts(
        failed_receipt=failed,
        source_receipt=receipt,
        destination=destination,
    )

    assert (destination / "README.md").read_text(encoding="utf-8") == "exact-source\n"
    assert execution_failed["source_dir"] == str(destination.resolve())
    assert execution_source["source_dir"] == str(destination.resolve())
    command = execution_failed["planned_codeql_database_command"]
    assert f"--source-root={destination.resolve()}" in command
    assert evidence["mode"] == "archive_verified_isolated_copy"


def test_materialize_isolated_attempt_receipts_rejects_archive_link_escape(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    case_id = "v8:unsafe-archive-link"
    receipt = source_receipt(source, case_id, "abc123")
    archive = Path(receipt["archive_result"]["archive_path"])
    archive_input = tmp_path / "unsafe-archive-input"
    archive_root = archive_input / "repo-revision"
    archive_root.mkdir(parents=True)
    (archive_root / "inside.txt").write_text("safe\n", encoding="utf-8")
    (archive_root / "escape").symlink_to("../../outside")
    with tarfile.open(archive, "w:gz") as handle:
        handle.add(archive_root, arcname=archive_root.name, recursive=True)
    receipt["archive_result"]["archive_sha256"] = hashlib.sha256(archive.read_bytes()).hexdigest()
    failed = failed_receipt(source, case_id, "abc123")

    with pytest.raises(RepairValidationError, match="unsafe link target"):
        materialize_isolated_attempt_receipts(
            failed_receipt=failed,
            source_receipt=receipt,
            destination=tmp_path / "attempt-source",
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


def test_controller_corrects_one_locally_rejected_model_proposal(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    case_id = "v8:proposal-correction"
    source_row = source_receipt(source, case_id, "abc123")
    failed = failed_receipt(source, case_id, "abc123")
    prior = deterministic_completion(failed, source_row)
    failed_path = tmp_path / "failed.jsonl"
    source_path = tmp_path / "source.jsonl"
    prior_path = tmp_path / "prior.jsonl"
    output = tmp_path / "output"
    counter = tmp_path / "model-call-count.txt"
    model = tmp_path / "correcting-fake-claude"
    model.write_text(
        "#!" + sys.executable + "\n"
        "import json\n"
        "import pathlib\n"
        "import sys\n"
        "sys.stdin.read()\n"
        f"counter = pathlib.Path({str(counter)!r})\n"
        "call_count = int(counter.read_text()) + 1 if counter.exists() else 1\n"
        "counter.write_text(str(call_count))\n"
        "actions = ([{'kind':'append_build_args','value':'-Dunapproved=true'}]\n"
        "           if call_count == 1 else [{'kind':'no_safe_action'}])\n"
        "print(json.dumps({'type':'result','structured_output':"
        "{'actions':actions,'rationale':'bounded correction'}}))\n",
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
    assert counter.read_text() == "2"
    assert row["status"] == "no_safe_llm_repair"
    assert len(row["model_invocations"]) == 2
    assert row["proposal_validation_errors"] == [
        "append_build_args contains an unapproved argument"
    ]


def test_controller_replans_once_from_fresh_failed_build_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    case_id = "v8:build-feedback"
    source_row = source_receipt(source, case_id, "abc123")
    failed = failed_receipt(source, case_id, "abc123")
    prior = deterministic_completion(failed, source_row)
    prompts: list[str] = []
    executed_decisions: list[dict] = []
    execution_kwargs: list[dict[str, object]] = []

    def fake_invoke_model(**kwargs: object) -> dict:
        prompts.append(str(kwargs["prompt"]))
        decision = (
            {
                "actions": [{"kind": "append_build_args", "args": ["-Dcheckstyle.skip=true"]}],
                "rationale": "Skip the failed quality gate.",
            }
            if len(prompts) == 1
            else {
                "actions": [{"kind": "append_build_args", "args": ["-Denforcer.skip=true"]}],
                "rationale": "Use a distinct bounded retry action.",
            }
        )
        return {
            "command": ["fake-model"],
            "bounded_process": {"returncode": 0, "timed_out": False},
            "output_path": str(kwargs["output_path"]),
            "raw_text": json.dumps({"type": "result", "structured_output": decision}),
        }

    def fake_execute_repair_attempt(
        receipt: dict,
        decision: dict,
        **kwargs: object,
    ) -> dict:
        executed_decisions.append(decision)
        execution_kwargs.append(kwargs)
        packet = dispatcher.build_repair_packet(
            receipt,
            approved_java_homes=[],
            approved_maven_homes=[],
            source_receipt=source_row,
        )
        packet["failed_attempt"] = {
            **packet["failed_attempt"],
            "failure_category": "maven_quality_gate",
            "log": {
                "path": "fresh-codeql-repair.log",
                "sha256": "fresh-log",
                "available": True,
                "excerpt": "BUILD FAILURE: fresh checkstyle network failure",
            },
        }
        packet["packet_sha256"] = stable_json_sha256(
            {key: value for key, value in packet.items() if key != "packet_sha256"}
        )
        return {
            "status": (
                "repair_attempt_failed"
                if len(executed_decisions) == 1
                else "codeql_db_repaired"
            ),
            "packet": packet,
            "database_valid": len(executed_decisions) == 2,
        }

    monkeypatch.setattr(dispatcher, "invoke_model", fake_invoke_model)
    monkeypatch.setattr(dispatcher, "execute_repair_attempt", fake_execute_repair_attempt)

    result = dispatcher.run_case(
        failed_receipt=failed,
        source_receipt=source_row,
        prior_completion=prior,
        output_dir=tmp_path / "output",
        attempt_number=1,
        claude_command="fake-model",
        openai_bridge_url=None,
        openai_model="fake-model",
        model_timeout_seconds=10,
        codeql_timeout_seconds=10,
        codeql_inactivity_timeout_seconds=None,
        approved_java_homes=[],
        approved_maven_homes=[],
        dry_run=False,
    )

    assert result["status"] == "codeql_db_repaired"
    assert result["build_feedback_replan_count"] == 1
    assert len(result["model_invocations"]) == 2
    assert len(result["repair_attempts"]) == 2
    assert len(executed_decisions) == 2
    assert all(kwargs["isolate_build_home"] is True for kwargs in execution_kwargs)
    assert all(
        kwargs["historical_toolchain_receipt"] is failed for kwargs in execution_kwargs
    )
    assert executed_decisions[0] != executed_decisions[1]
    assert "fresh checkstyle network failure" in prompts[1]
    assert "Select a different action set" in prompts[1]


def test_controller_retries_one_transport_failure_before_validating_decision(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    case_id = "v8:transport-retry"
    source_row = source_receipt(source, case_id, "abc123")
    failed = failed_receipt(source, case_id, "abc123")
    prior = deterministic_completion(failed, source_row)
    invocation_count = 0

    def fake_invoke_model(**_kwargs: object) -> dict:
        nonlocal invocation_count
        invocation_count += 1
        if invocation_count == 1:
            return {
                "command": ["fake-model"],
                "bounded_process": {
                    "returncode": 1,
                    "timed_out": False,
                    "transport_error": "ConnectionResetError: reset",
                },
                "raw_text": '{"type":"result","is_error":true}',
            }
        return {
            "command": ["fake-model"],
            "bounded_process": {
                "returncode": 0,
                "timed_out": False,
                "transport_error": None,
            },
            "raw_text": json.dumps(
                {
                    "type": "result",
                    "structured_output": {
                        "actions": [{"kind": "no_safe_action"}],
                        "rationale": "No approved action is justified.",
                    },
                }
            ),
        }

    monkeypatch.setattr(dispatcher, "invoke_model", fake_invoke_model)
    result = dispatcher.run_case(
        failed_receipt=failed,
        source_receipt=source_row,
        prior_completion=prior,
        output_dir=tmp_path / "output",
        attempt_number=1,
        claude_command="fake-model",
        openai_bridge_url=None,
        openai_model="fake-model",
        model_timeout_seconds=10,
        codeql_timeout_seconds=10,
        codeql_inactivity_timeout_seconds=None,
        approved_java_homes=[],
        approved_maven_homes=[],
        dry_run=False,
    )

    assert result["status"] == "no_safe_llm_repair"
    assert invocation_count == 2
    assert len(result["model_invocations"]) == 2
    assert result["model_invocations"][0]["bounded_process"]["transport_error"].startswith(
        "ConnectionResetError:"
    )


def test_controller_does_not_reexecute_a_repeated_build_feedback_decision(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    case_id = "v8:repeated-build-feedback"
    source_row = source_receipt(source, case_id, "abc123")
    failed = failed_receipt(source, case_id, "abc123")
    prior = deterministic_completion(failed, source_row)
    executed_decisions: list[dict] = []

    def fake_invoke_model(**kwargs: object) -> dict:
        decision = {
            "actions": [{"kind": "retry_same_command"}],
            "rationale": "Repeat the same bounded retry.",
        }
        return {
            "command": ["fake-model"],
            "bounded_process": {"returncode": 0, "timed_out": False},
            "output_path": str(kwargs["output_path"]),
            "raw_text": json.dumps({"type": "result", "structured_output": decision}),
        }

    def fake_execute_repair_attempt(
        receipt: dict,
        decision: dict,
        **kwargs: object,
    ) -> dict:
        executed_decisions.append(decision)
        packet = dispatcher.build_repair_packet(
            receipt,
            approved_java_homes=[],
            approved_maven_homes=[],
            source_receipt=source_row,
        )
        return {"status": "repair_attempt_failed", "packet": packet}

    monkeypatch.setattr(dispatcher, "invoke_model", fake_invoke_model)
    monkeypatch.setattr(dispatcher, "execute_repair_attempt", fake_execute_repair_attempt)

    result = dispatcher.run_case(
        failed_receipt=failed,
        source_receipt=source_row,
        prior_completion=prior,
        output_dir=tmp_path / "output",
        attempt_number=1,
        claude_command="fake-model",
        openai_bridge_url=None,
        openai_model="fake-model",
        model_timeout_seconds=10,
        codeql_timeout_seconds=10,
        codeql_inactivity_timeout_seconds=None,
        approved_java_homes=[],
        approved_maven_homes=[],
        dry_run=False,
    )

    assert result["status"] == "no_safe_llm_repair"
    assert result["reason"] == "repeated_validated_decision_after_build_failure"
    assert len(result["model_invocations"]) == 2
    assert len(executed_decisions) == 1
    assert len(result["decision_rounds"]) == 1


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
