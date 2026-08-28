import json
from pathlib import Path

from gca.poc_agent.runner import (
    PocAgentRunConfig,
    PocVerifierRunConfig,
    run_poc_agent,
    run_poc_verifier,
)


def _fake_agent(tmp_path: Path, *, usage: int = 150, cached_tokens: int = 20) -> Path:
    executable = tmp_path / "fake-agent"
    executable.write_text(
        f"""#!/bin/sh
final=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--output-last-message" ]; then
    shift
    final="$1"
  fi
  shift
done
prompt="$(cat)"
printf '%s' "$prompt" > "$FAKE_PROMPT_CAPTURE"
printf '%s\n' '{{"type":"thread.started","thread_id":"session-test-123"}}'
printf '%s\n' '{{"type":"item.completed","item":{{"type":"agent_message","text":"CONFIRMED"}}}}'
printf '%s\n' '{{"type":"turn.completed","usage":{{"input_tokens":{usage - 10},"cached_input_tokens":{cached_tokens},"output_tokens":10,"reasoning_output_tokens":3}}}}'
printf '%s' 'CONFIRMED' > "$final"
""",
        encoding="utf-8",
    )
    executable.chmod(0o755)
    return executable


def _config(
    tmp_path: Path,
    fake_agent: Path,
    *,
    token_limit: int = 1_000,
) -> PocAgentRunConfig:
    audit = tmp_path / "audit.md"
    audit.write_text("Risk at FileWebService.java:123", encoding="utf-8")
    return PocAgentRunConfig(
        audit_report=audit,
        output_dir=tmp_path / "run",
        poc_workspace="/remote/poc-output",
        agent_cwd=tmp_path,
        agent_command=(str(fake_agent),),
        token_limit=token_limit,
        timeout_seconds=10,
        environment={"FAKE_PROMPT_CAPTURE": str(tmp_path / "captured-prompt.txt")},
    )


def test_run_poc_agent_preserves_session_prompt_usage_and_artifacts(tmp_path: Path) -> None:
    result = run_poc_agent(_config(tmp_path, _fake_agent(tmp_path)))

    assert result.succeeded
    assert result.status == "completed"
    assert result.session_id == "session-test-123"
    assert result.token_usage["total_tokens"] == 150
    assert result.token_usage["budget_tokens"] == 130
    assert "--ephemeral" not in result.command

    prompt = (tmp_path / "captured-prompt.txt").read_text(encoding="utf-8")
    assert "Risk at FileWebService.java:123" in prompt
    assert "/remote/poc-output" in prompt
    assert "write a PoC, execute" in prompt
    assert "budget of 1000 uncached input plus output" in prompt

    run = json.loads((tmp_path / "run" / "run.json").read_text(encoding="utf-8"))
    assert run["session_id"] == "session-test-123"
    assert run["status"] == "completed"
    assert Path(run["events_path"]).is_file()
    assert Path(run["final_message_path"]).read_text(encoding="utf-8") == "CONFIRMED"


def test_run_poc_agent_records_token_limit_failure(tmp_path: Path) -> None:
    result = run_poc_agent(
        _config(tmp_path, _fake_agent(tmp_path, usage=250, cached_tokens=20), token_limit=200)
    )

    assert not result.succeeded
    assert result.status == "token_limit_exceeded"
    assert result.token_usage["total_tokens"] == 250
    assert result.token_usage["budget_tokens"] == 230
    assert result.error is not None
    assert "used 230 budget tokens" in result.error

    run = json.loads((tmp_path / "run" / "run.json").read_text(encoding="utf-8"))
    assert run["status"] == "token_limit_exceeded"


def test_cached_context_does_not_count_against_budget(tmp_path: Path) -> None:
    result = run_poc_agent(
        _config(
            tmp_path,
            _fake_agent(tmp_path, usage=1_000, cached_tokens=850),
            token_limit=200,
        )
    )

    assert result.succeeded
    assert result.token_usage["total_tokens"] == 1_000
    assert result.token_usage["budget_tokens"] == 150


def test_run_poc_verifier_uses_independent_verifier_prompt(tmp_path: Path) -> None:
    audit = tmp_path / "audit.md"
    audit.write_text("Verify FileWebService private-room leak", encoding="utf-8")
    fake_agent = _fake_agent(tmp_path)

    result = run_poc_verifier(
        PocVerifierRunConfig(
            audit_report=audit,
            output_dir=tmp_path / "verify",
            poc_artifact="/remote/poc/FileWebServicePrivateRoomNegativeParentPoCTest.java",
            reproduce_command="ssh gpu-host /remote/poc/run_poc.sh",
            verifier_workspace="/remote/verifier-receipts/case-1",
            agent_cwd=tmp_path,
            agent_command=(str(fake_agent),),
            timeout_seconds=10,
            environment={"FAKE_PROMPT_CAPTURE": str(tmp_path / "verifier-prompt.txt")},
        )
    )

    assert result.succeeded
    assert result.session_id == "session-test-123"
    assert Path(result.prompt_path).name == "verifier.prompt.txt"
    assert Path(result.events_path).name == "verifier.events.jsonl"
    assert Path(result.run_path).name == "verifier.run.json"

    prompt = (tmp_path / "verifier-prompt.txt").read_text(encoding="utf-8")
    assert "independent AI PoC Verifier" in prompt
    assert "Do not look for or rely on the" in prompt
    assert "PoC Development Agent transcript" in prompt
    assert "/remote/poc/FileWebServicePrivateRoomNegativeParentPoCTest.java" in prompt
    assert "ssh gpu-host /remote/poc/run_poc.sh" in prompt
    assert "/remote/verifier-receipts/case-1" in prompt
    assert "Do not modify the PoC request semantics" in prompt
    assert "Verify FileWebService private-room leak" in prompt
