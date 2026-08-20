"""Thin launcher for an autonomous TraeX PoC-development session."""

from __future__ import annotations

import json
import hashlib
import os
import signal
import subprocess
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence


DEVELOPER_VERDICTS = {"CONFIRMED", "NOT_VULNERABLE", "INCONCLUSIVE", "BLOCKED"}
VERIFIER_VERDICTS = {"CONFIRMED", "REJECTED", "INVALID_POC", "BLOCKED", "INCONCLUSIVE"}
LINEAGE_FIELDS = (
    "identity_key",
    "case_id",
    "finding_id",
    "finding_sha256",
    "checkout_revision",
)


@dataclass(frozen=True)
class PocAgentRunConfig:
    audit_report: Path
    output_dir: Path
    poc_workspace: str
    agent_cwd: Path
    traex_command: Sequence[str] = ("traex",)
    model: str | None = None
    token_limit: int = 800_000
    timeout_seconds: int = 7_200
    environment: Mapping[str, str] | None = None
    confirmation_request: Path | None = None


@dataclass(frozen=True)
class PocVerifierRunConfig:
    audit_report: Path
    output_dir: Path
    poc_artifact: str
    reproduce_command: str
    verifier_workspace: str
    agent_cwd: Path
    traex_command: Sequence[str] = ("traex",)
    model: str | None = None
    timeout_seconds: int = 3_600
    environment: Mapping[str, str] | None = None
    confirmation_request: Path | None = None
    developer_receipt: Path | None = None


@dataclass(frozen=True)
class PocAgentRunResult:
    status: str
    returncode: int | None
    session_id: str | None
    elapsed_seconds: float
    token_usage: dict[str, int]
    prompt_path: str
    events_path: str
    stderr_path: str
    final_message_path: str
    run_path: str
    command: list[str]
    error: str | None = None
    receipt_path: str | None = None
    verdict: str | None = None

    @property
    def succeeded(self) -> bool:
        return self.status == "completed" and self.returncode == 0 and self.verdict is not None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


PocVerifierRunResult = PocAgentRunResult


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _read_json_object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is not a readable JSON object: {type(exc).__name__}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value


def _load_confirmation_request(path: Path | None) -> dict[str, str] | None:
    if path is None:
        return None
    resolved = path.expanduser().resolve()
    if not resolved.is_file():
        raise FileNotFoundError(f"confirmation request does not exist: {resolved}")
    value = _read_json_object(resolved, "confirmation request")
    missing = [field for field in LINEAGE_FIELDS if not isinstance(value.get(field), str) or not value[field].strip()]
    if missing:
        raise ValueError(f"confirmation request is missing lineage fields: {missing}")
    return {field: value[field].strip() for field in LINEAGE_FIELDS}


def _validated_receipt(
    *,
    output_dir: Path,
    role: str,
    expected_lineage: dict[str, str] | None,
    developer_receipt_sha256: str | None = None,
    receipt_path: Path | None = None,
) -> tuple[Path, dict[str, Any]]:
    receipt_path = receipt_path or output_dir / f"{role}-receipt.json"
    if not receipt_path.is_file():
        raise ValueError(f"{role} agent exited successfully but did not write {receipt_path.name}")
    receipt = _read_json_object(receipt_path, f"{role} receipt")
    allowed = DEVELOPER_VERDICTS if role == "developer" else VERIFIER_VERDICTS
    if receipt.get("verdict") not in allowed:
        raise ValueError(f"{role} receipt verdict must be one of {sorted(allowed)}")
    if expected_lineage:
        for field, expected in expected_lineage.items():
            if receipt.get(field) != expected:
                raise ValueError(f"{role} receipt lineage mismatch for {field}")
    if developer_receipt_sha256 is not None and receipt.get("developer_receipt_sha256") != developer_receipt_sha256:
        raise ValueError("verifier receipt does not bind the exact developer receipt SHA-256")
    if receipt["verdict"] == "CONFIRMED":
        artifact = receipt.get("artifact_path")
        evidence = receipt.get("evidence_paths")
        reproduce = receipt.get("reproduce_command")
        if not isinstance(artifact, str) or not Path(artifact).expanduser().is_file():
            raise ValueError(f"{role} CONFIRMED receipt must reference an existing artifact_path")
        if not isinstance(evidence, list) or not evidence or any(not isinstance(item, str) or not Path(item).expanduser().is_file() for item in evidence):
            raise ValueError(f"{role} CONFIRMED receipt must reference existing non-empty evidence_paths")
        if not isinstance(reproduce, str) or not reproduce.strip():
            raise ValueError(f"{role} CONFIRMED receipt must contain reproduce_command")
    return receipt_path, receipt


def _budget_tokens(usage: Mapping[str, int]) -> int:
    uncached_input = max(
        int(usage.get("input_tokens", 0)) - int(usage.get("cached_input_tokens", 0)),
        0,
    )
    return uncached_input + int(usage.get("output_tokens", 0))


def build_poc_agent_prompt(
    *,
    audit_report: str,
    poc_workspace: str,
    token_limit: int,
    receipt_path: str,
    lineage: Mapping[str, str] | None = None,
) -> str:
    """Build an open-ended PoC-development brief from an audit report."""
    return f"""You are the independent PoC Development Agent.

Your only objective is to verify whether the audit report below describes a real,
reproducible vulnerability in the specified target revision/runtime. Work
autonomously: inspect the source and runtime, write a PoC or negative test,
execute it, read the real feedback, and revise it until you can support a concrete
verdict. Do not stop at a plan, static source argument, or an untested PoC.

You have unrestricted access to the available source and environment. Choose the
PoC language, files, commands, and execution strategy yourself. The PoC artifact
format is intentionally unconstrained. You may add test or harness code, but do not
change product behavior merely to manufacture the reported vulnerability.

Keep the final reproducible PoC and its evidence under:
{poc_workspace}

The run has an aggregate budget of {token_limit} uncached input plus output
tokens. Cached context may be reported separately by the runtime, but still
converge before the active budget is exhausted.

Before finishing:
1. Execute the final PoC against the target or its faithful test/runtime harness.
2. Preserve the PoC plus enough output to distinguish success from a normal safe
   response.
3. Write a machine-readable JSON receipt to {receipt_path}. It must include:
   verdict, identity_key, case_id, finding_id, finding_sha256, checkout_revision,
   artifact_path, evidence_paths, and reproduce_command. For CONFIRMED, all named
   artifact/evidence paths must exist.
4. In your final response, state the exact artifact paths and reproduction command,
   summarize iterations and observed feedback, and label the result with exactly
   one of CONFIRMED, NOT_VULNERABLE, INCONCLUSIVE, or BLOCKED.

Use CONFIRMED only when the observed effect matches the audit report. Use
NOT_VULNERABLE when you have exercised the relevant code path and the runtime
behavior contradicts the reported vulnerability. Use INCONCLUSIVE when evidence is
insufficient after meaningful execution. Use BLOCKED only with concrete command
output and a precise external blocker.

Audit report:
--- BEGIN AUDIT REPORT ---
{audit_report.rstrip()}
--- END AUDIT REPORT ---
""" + (f"\nImmutable finding lineage (copy verbatim into the receipt):\n{json.dumps(dict(lineage), ensure_ascii=False, sort_keys=True)}\n" if lineage else "")


def build_poc_verifier_prompt(
    *,
    audit_report: str,
    poc_artifact: str,
    reproduce_command: str,
    verifier_workspace: str,
    receipt_path: str,
    lineage: Mapping[str, str] | None = None,
    developer_receipt_sha256: str | None = None,
) -> str:
    """Build an independent verification brief for a completed PoC artifact."""
    return f"""You are the independent AI PoC Verifier.

Your objective is to verify a completed PoC artifact against the original audit
report. You must use a fresh, independent session. Do not look for or rely on the
PoC Development Agent transcript, reasoning, failed attempts, or private notes.

Inputs:
- Audit report: embedded below.
- PoC artifact: {poc_artifact}
- Reproduction command: {reproduce_command}
- Verifier workspace for receipts and logs: {verifier_workspace}

Rules:
1. Rebuild or rerun the target environment as needed, preferably from clean state.
2. You may adapt environment-only settings such as host, port, container name,
   network name, mount path, credential injection path, or local dependency path.
3. Do not modify the PoC request semantics, payload, assertions, success condition,
   or exploit logic.
4. Do not modify the instrumentation or target bundle. If the PoC only works after
   changing its security semantics, label the result INVALID_POC.
5. Write a machine-readable verifier receipt to {receipt_path}. It must include
   verdict, identity_key, case_id, finding_id, finding_sha256, checkout_revision,
   developer_receipt_sha256, artifact_path, evidence_paths, and reproduce_command.
   For CONFIRMED, all named artifact/evidence paths must exist.

Final verdict must be one of:
- CONFIRMED
- REJECTED
- INVALID_POC
- BLOCKED
- INCONCLUSIVE

Use CONFIRMED only when the PoC can be rerun and the observed effect matches the
audit report. Use BLOCKED only for concrete environment failures with command
output. Use INCONCLUSIVE when evidence is insufficient but not clearly blocked.

Audit report:
--- BEGIN AUDIT REPORT ---
{audit_report.rstrip()}
--- END AUDIT REPORT ---
""" + (f"\nImmutable finding lineage (copy verbatim into the receipt):\n{json.dumps(dict(lineage), ensure_ascii=False, sort_keys=True)}\nDeveloper receipt SHA-256 (copy verbatim): {developer_receipt_sha256}\n" if lineage else "")


def _token_usage(event: dict[str, Any]) -> dict[str, int] | None:
    if event.get("type") != "turn.completed":
        return None
    raw = event.get("usage")
    if not isinstance(raw, dict):
        return None
    fields = (
        "input_tokens",
        "cache_creation_input_tokens",
        "cached_input_tokens",
        "output_tokens",
        "reasoning_output_tokens",
    )
    usage = {field: int(raw.get(field, 0) or 0) for field in fields}
    usage["total_tokens"] = usage["input_tokens"] + usage["output_tokens"]
    usage["budget_tokens"] = _budget_tokens(usage)
    return usage


def _terminate_process_group(process: subprocess.Popen[str]) -> None:
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()


def run_poc_agent(config: PocAgentRunConfig) -> PocAgentRunResult:
    """Launch one persistent TraeX session and retain its complete run evidence."""
    if config.token_limit <= 0:
        raise ValueError("token_limit must be positive")
    if config.timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive")

    audit_path = config.audit_report.expanduser().resolve()
    if not audit_path.is_file():
        raise FileNotFoundError(f"audit report does not exist: {audit_path}")
    agent_cwd = config.agent_cwd.expanduser().resolve()
    if not agent_cwd.is_dir():
        raise NotADirectoryError(f"agent cwd does not exist: {agent_cwd}")

    output_dir = config.output_dir.expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    lineage = _load_confirmation_request(config.confirmation_request)
    prompt_path = output_dir / "prompt.txt"
    events_path = output_dir / "agent.events.jsonl"
    stderr_path = output_dir / "agent.stderr.log"
    final_message_path = output_dir / "agent.final.txt"
    run_path = output_dir / "run.json"

    audit_report = audit_path.read_text(encoding="utf-8")
    prompt = build_poc_agent_prompt(
        audit_report=audit_report,
        poc_workspace=config.poc_workspace,
        token_limit=config.token_limit,
        receipt_path=str(output_dir / "developer-receipt.json"),
        lineage=lineage,
    )
    prompt_path.write_text(prompt, encoding="utf-8")

    command = [
        *[str(part) for part in config.traex_command],
        "exec",
        "--json",
        "--dangerously-bypass-approvals-and-sandbox",
        "--skip-git-repo-check",
        "--output-last-message",
        str(final_message_path),
        "-C",
        str(agent_cwd),
    ]
    if config.model:
        command.extend(["--model", config.model])
    command.append("-")

    environment = os.environ.copy()
    environment.update(dict(config.environment or {}))
    started = time.monotonic()
    session_id: str | None = None
    usage = {
        "input_tokens": 0,
        "cache_creation_input_tokens": 0,
        "cached_input_tokens": 0,
        "output_tokens": 0,
        "reasoning_output_tokens": 0,
        "total_tokens": 0,
        "budget_tokens": 0,
    }
    status = "failed"
    error: str | None = None
    returncode: int | None = None
    process: subprocess.Popen[str] | None = None
    deadline_reached = threading.Event()

    try:
        with events_path.open("w", encoding="utf-8") as events, stderr_path.open(
            "w", encoding="utf-8"
        ) as stderr:
            process = subprocess.Popen(
                command,
                cwd=agent_cwd,
                env=environment,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=stderr,
                text=True,
                bufsize=1,
                start_new_session=True,
            )
            assert process.stdin is not None
            assert process.stdout is not None
            process.stdin.write(prompt)
            process.stdin.close()

            def _timeout_guard() -> None:
                if not deadline_reached.wait(config.timeout_seconds):
                    deadline_reached.set()
                    _terminate_process_group(process)

            guard = threading.Thread(target=_timeout_guard, daemon=True)
            guard.start()

            token_limit_exceeded = False
            for line in process.stdout:
                events.write(line)
                events.flush()
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if event.get("type") == "thread.started":
                    raw_session_id = event.get("thread_id")
                    if isinstance(raw_session_id, str):
                        session_id = raw_session_id
                event_usage = _token_usage(event)
                if event_usage:
                    for key, value in event_usage.items():
                        usage[key] += value
                    if usage["budget_tokens"] > config.token_limit:
                        token_limit_exceeded = True
                        _terminate_process_group(process)
                        break

            returncode = process.wait()
            if token_limit_exceeded:
                status = "token_limit_exceeded"
                error = (
                    f"PoC Agent used {usage['budget_tokens']} budget tokens, exceeding "
                    f"the limit of {config.token_limit}"
                )
            elif deadline_reached.is_set():
                status = "timed_out"
                error = f"PoC Agent timed out after {config.timeout_seconds} seconds"
            elif returncode == 0:
                try:
                    _, receipt = _validated_receipt(
                        output_dir=output_dir,
                        role="developer",
                        expected_lineage=lineage,
                    )
                    status = "completed"
                    verdict = str(receipt["verdict"])
                except ValueError as exc:
                    error = str(exc)
            else:
                error = f"TraeX exited with status {returncode}"
    except OSError as exc:
        error = f"{type(exc).__name__}: {exc}"
        if process is not None and process.poll() is None:
            _terminate_process_group(process)
            returncode = process.returncode
    finally:
        deadline_reached.set()

    receipt_path = output_dir / "developer-receipt.json"
    result = PocAgentRunResult(
        status=status,
        returncode=returncode,
        session_id=session_id,
        elapsed_seconds=round(time.monotonic() - started, 3),
        token_usage=usage,
        prompt_path=str(prompt_path),
        events_path=str(events_path),
        stderr_path=str(stderr_path),
        final_message_path=str(final_message_path),
        run_path=str(run_path),
        command=command,
        error=error,
        receipt_path=str(receipt_path) if receipt_path.is_file() else None,
        verdict=locals().get("verdict"),
    )
    run_path.write_text(
        json.dumps(result.to_dict(), indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return result


def run_poc_verifier(config: PocVerifierRunConfig) -> PocVerifierRunResult:
    """Launch one fresh TraeX session to independently verify a PoC artifact."""
    if config.timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive")

    audit_path = config.audit_report.expanduser().resolve()
    if not audit_path.is_file():
        raise FileNotFoundError(f"audit report does not exist: {audit_path}")
    agent_cwd = config.agent_cwd.expanduser().resolve()
    if not agent_cwd.is_dir():
        raise NotADirectoryError(f"agent cwd does not exist: {agent_cwd}")

    output_dir = config.output_dir.expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    lineage = _load_confirmation_request(config.confirmation_request)
    developer_receipt_sha256: str | None = None
    if lineage is not None and config.developer_receipt is None:
        raise ValueError(
            "formal confirmation verification requires --developer-receipt to bind the exact developer receipt"
        )
    if config.developer_receipt is not None:
        developer_path = config.developer_receipt.expanduser().resolve()
        if not developer_path.is_file():
            raise FileNotFoundError(f"developer receipt does not exist: {developer_path}")
        _validated_receipt(
            output_dir=developer_path.parent,
            role="developer",
            expected_lineage=lineage,
            receipt_path=developer_path,
        )
        developer_receipt_sha256 = _sha256_file(developer_path)
    prompt_path = output_dir / "verifier.prompt.txt"
    events_path = output_dir / "verifier.events.jsonl"
    stderr_path = output_dir / "verifier.stderr.log"
    final_message_path = output_dir / "verifier.final.txt"
    run_path = output_dir / "verifier.run.json"

    audit_report = audit_path.read_text(encoding="utf-8")
    prompt = build_poc_verifier_prompt(
        audit_report=audit_report,
        poc_artifact=config.poc_artifact,
        reproduce_command=config.reproduce_command,
        verifier_workspace=config.verifier_workspace,
        receipt_path=str(output_dir / "verifier-receipt.json"),
        lineage=lineage,
        developer_receipt_sha256=developer_receipt_sha256,
    )
    prompt_path.write_text(prompt, encoding="utf-8")

    command = [
        *[str(part) for part in config.traex_command],
        "exec",
        "--json",
        "--dangerously-bypass-approvals-and-sandbox",
        "--skip-git-repo-check",
        "--output-last-message",
        str(final_message_path),
        "-C",
        str(agent_cwd),
    ]
    if config.model:
        command.extend(["--model", config.model])
    command.append("-")

    environment = os.environ.copy()
    environment.update(dict(config.environment or {}))
    started = time.monotonic()
    session_id: str | None = None
    usage = {
        "input_tokens": 0,
        "cache_creation_input_tokens": 0,
        "cached_input_tokens": 0,
        "output_tokens": 0,
        "reasoning_output_tokens": 0,
        "total_tokens": 0,
        "budget_tokens": 0,
    }
    status = "failed"
    error: str | None = None
    returncode: int | None = None
    process: subprocess.Popen[str] | None = None
    deadline_reached = threading.Event()

    try:
        with events_path.open("w", encoding="utf-8") as events, stderr_path.open(
            "w", encoding="utf-8"
        ) as stderr:
            process = subprocess.Popen(
                command,
                cwd=agent_cwd,
                env=environment,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=stderr,
                text=True,
                bufsize=1,
                start_new_session=True,
            )
            assert process.stdin is not None
            assert process.stdout is not None
            process.stdin.write(prompt)
            process.stdin.close()

            def _timeout_guard() -> None:
                if not deadline_reached.wait(config.timeout_seconds):
                    deadline_reached.set()
                    _terminate_process_group(process)

            guard = threading.Thread(target=_timeout_guard, daemon=True)
            guard.start()

            for line in process.stdout:
                events.write(line)
                events.flush()
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if event.get("type") == "thread.started":
                    raw_session_id = event.get("thread_id")
                    if isinstance(raw_session_id, str):
                        session_id = raw_session_id
                event_usage = _token_usage(event)
                if event_usage:
                    for key, value in event_usage.items():
                        usage[key] += value

            returncode = process.wait()
            if deadline_reached.is_set():
                status = "timed_out"
                error = f"Verifier timed out after {config.timeout_seconds} seconds"
            elif returncode == 0:
                try:
                    _, receipt = _validated_receipt(
                        output_dir=output_dir,
                        role="verifier",
                        expected_lineage=lineage,
                        developer_receipt_sha256=developer_receipt_sha256,
                    )
                    status = "completed"
                    verdict = str(receipt["verdict"])
                except ValueError as exc:
                    error = str(exc)
            else:
                error = f"TraeX exited with status {returncode}"
    except OSError as exc:
        error = f"{type(exc).__name__}: {exc}"
        if process is not None and process.poll() is None:
            _terminate_process_group(process)
            returncode = process.returncode
    finally:
        deadline_reached.set()

    receipt_path = output_dir / "verifier-receipt.json"
    result = PocVerifierRunResult(
        status=status,
        returncode=returncode,
        session_id=session_id,
        elapsed_seconds=round(time.monotonic() - started, 3),
        token_usage=usage,
        prompt_path=str(prompt_path),
        events_path=str(events_path),
        stderr_path=str(stderr_path),
        final_message_path=str(final_message_path),
        run_path=str(run_path),
        command=command,
        error=error,
        receipt_path=str(receipt_path) if receipt_path.is_file() else None,
        verdict=locals().get("verdict"),
    )
    run_path.write_text(
        json.dumps(result.to_dict(), indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return result
