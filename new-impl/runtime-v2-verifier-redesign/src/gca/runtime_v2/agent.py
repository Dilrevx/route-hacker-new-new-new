"""Agent backend adapters for autonomous runtime construction."""

from __future__ import annotations

import os
import signal
import subprocess
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Mapping, Protocol, Sequence

from .models import AttemptKind, RuntimeTask
from .workspace import attempt_resource_name


@dataclass(frozen=True)
class AgentRunResult:
    command: list[str]
    returncode: int | None
    timed_out: bool
    elapsed_seconds: float
    stdout_path: str
    stderr_path: str
    final_message_path: str
    error: str | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


class AgentBackend(Protocol):
    def run(
        self,
        *,
        task: RuntimeTask,
        attempt_kind: AttemptKind,
        attempt_dir: Path,
        prompt: str,
        timeout_seconds: int,
    ) -> AgentRunResult: ...


def build_agent_prompt(
    *,
    task: RuntimeTask,
    attempt_kind: AttemptKind,
    attempt_dir: Path,
    submit_command: Sequence[str],
    history_paths: Sequence[Path] = (),
) -> str:
    candidate_path = attempt_dir / "candidate-result.json"
    command_text = " ".join(submit_command)
    compose_project = attempt_resource_name(attempt_dir)
    lines = [
        "Build a runnable application environment for the vulnerability task below.",
        "",
        "You have full autonomy. Inspect or clone source code, choose revisions, use or",
        "ignore any supplied compile image or Dockerfile, install tools, resolve dependency",
        "conflicts, pull supporting service images, and create a Docker image, Compose",
        "topology, or start/stop scripts. Keep debugging until the environment works.",
        "Do not run destructive shared-host cleanup commands such as docker system prune,",
        "docker builder prune, docker image prune, docker container prune, or Docker daemon restarts.",
        "Only remove containers, images, volumes, or temporary files that you created for this attempt.",
        "",
        f"Task ID: {task.task_id}",
        f"Attempt: {attempt_kind}",
        f"Working directory: {attempt_dir / 'workspace'}",
        f"Candidate result file: {candidate_path}",
        f"Required submission command: {command_text}",
        f"Compose self-test project name: {compose_project}",
        "",
        "When you have a candidate, write candidate-result.json with:",
        '- "primary_image": the main application image name;',
        '- "launch": an object whose type is image, compose, or script;',
        '- "probes": a list of HTTP, TCP, command, exec, log, or liveness probes.',
        "",
        "Use one of these launch shapes. For a single image, use",
        '`{"type":"image","image":"name:tag","ports":["127.0.0.1:18080:8080"]}`.',
        "For Compose, write a compose YAML file under the attempt workspace and use",
        '`{"type":"compose","file":"docker-compose.yml"}`.',
        f"Run every Compose self-test with `docker compose -p {compose_project} ...`.",
        "Always pass that exact project name; never use the default inferred Compose project name",
        "because this is a shared host. Only inspect, restart, or remove that named project.",
        "For a script runtime, use",
        '`{"type":"script","start":"start.sh","stop":"stop.sh"}`.',
        "HTTP probes should use a full URL, for example",
        '`{"type":"http","url":"http://127.0.0.1:18080/health","timeout_seconds":30}`.',
        "TCP probes should use host and port; command probes should use command as",
        "an argv list.",
        "",
        "Run the required submission command before ending the attempt. It validates",
        "metadata and records the submission. If it returns accepted=false, read the",
        "structured reason, repair the metadata or artifacts, and run the command again",
        "within this same attempt. Do not stop until accepted=true or no repair is possible.",
        "",
        "The platform will independently restart the accepted environment and execute the",
        "declared probes. Do not stop merely because the first build command fails.",
        "After an accepted submission, keep the declared image, compose file, scripts, and",
        "configuration available for the verifier. Do not delete volumes or files required",
        "to start the declared runtime from a clean verifier invocation.",
    ]
    if history_paths:
        lines.extend(
            [
                "",
                "This is a warm retry. Continue from the existing workspace and inspect",
                "these prior records before choosing the next repair:",
                *(f"- {path}" for path in history_paths),
            ]
        )
    lines.extend(["", "Vulnerability task:", task.prompt.strip(), ""])
    return "\n".join(lines)


class LocalAgentBackend:
    def __init__(
        self,
        *,
        command: Sequence[str] = ("codex",),
        extra_args: Sequence[str] = (),
        environment: Mapping[str, str] | None = None,
    ):
        self.command = [str(part) for part in command]
        self.extra_args = [str(part) for part in extra_args]
        self.environment = dict(environment or {})

    def run(
        self,
        *,
        task: RuntimeTask,
        attempt_kind: AttemptKind,
        attempt_dir: Path,
        prompt: str,
        timeout_seconds: int,
    ) -> AgentRunResult:
        logs_dir = attempt_dir / "logs"
        logs_dir.mkdir(parents=True, exist_ok=True)
        stdout_path = logs_dir / "agent.stdout.jsonl"
        stderr_path = logs_dir / "agent.stderr.log"
        final_message_path = logs_dir / "agent.final.txt"
        executable = Path(self.command[0]).name
        command = [
            *self.command,
            "exec",
            "--json",
            "--ephemeral",
            "--dangerously-bypass-approvals-and-sandbox",
            "--skip-git-repo-check",
            "--output-last-message",
            str(final_message_path),
            *self.extra_args,
        ]
        if executable == "codex":
            command.append("-")
        environment = os.environ.copy()
        environment.update(self.environment)
        environment["RUNTIME_V2_TASK_ID"] = task.task_id
        environment["RUNTIME_V2_ATTEMPT"] = attempt_kind
        environment["RUNTIME_V2_RESULT_PATH"] = str(attempt_dir / "result.json")
        environment["RUNTIME_V2_CANDIDATE_PATH"] = str(
            attempt_dir / "candidate-result.json"
        )
        environment["RUNTIME_V2_WORKSPACE"] = str(attempt_dir / "workspace")
        package_root = str(Path(__file__).resolve().parents[2])
        existing_pythonpath = environment.get("PYTHONPATH")
        environment["PYTHONPATH"] = (
            os.pathsep.join([package_root, existing_pythonpath])
            if existing_pythonpath
            else package_root
        )
        started = time.monotonic()
        error: str | None = None
        returncode: int | None = None
        timed_out = False
        with stdout_path.open("w", encoding="utf-8") as stdout, stderr_path.open(
            "w", encoding="utf-8"
        ) as stderr:
            try:
                process = subprocess.Popen(
                    command,
                    cwd=attempt_dir / "workspace",
                    env=environment,
                    stdin=subprocess.PIPE,
                    text=True,
                    stdout=stdout,
                    stderr=stderr,
                    start_new_session=True,
                )
                try:
                    process.communicate(input=prompt, timeout=timeout_seconds)
                    returncode = process.returncode
                except subprocess.TimeoutExpired:
                    timed_out = True
                    error = f"agent timed out after {timeout_seconds} seconds"
                    try:
                        os.killpg(process.pid, signal.SIGTERM)
                    except ProcessLookupError:
                        pass
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        try:
                            os.killpg(process.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        process.wait()
                    returncode = 124
            except OSError as exc:
                error = f"{type(exc).__name__}: {exc}"
        return AgentRunResult(
            command=command,
            returncode=returncode,
            timed_out=timed_out,
            elapsed_seconds=round(time.monotonic() - started, 3),
            stdout_path=str(stdout_path),
            stderr_path=str(stderr_path),
            final_message_path=str(final_message_path),
            error=error,
        )


class DiagnosticAgent:
    def __init__(self, backend: AgentBackend):
        self.backend = backend

    def run(
        self,
        *,
        task: RuntimeTask,
        task_dir: Path,
        timeout_seconds: int,
    ) -> AgentRunResult:
        diagnosis_dir = task_dir / "diagnosis"
        (diagnosis_dir / "workspace").mkdir(parents=True, exist_ok=True)
        (diagnosis_dir / "logs").mkdir(parents=True, exist_ok=True)
        records = sorted((task_dir / "attempts").glob("*/logs/*"))
        results = sorted((task_dir / "attempts").glob("*/result.json"))
        report_json = diagnosis_dir / "report.json"
        report_markdown = diagnosis_dir / "report.md"
        prompt = "\n".join(
            [
                "Analyze why all autonomous runtime construction attempts failed.",
                "Do not build, modify Docker state, or start services.",
                f"Write a concise diagnosis to {report_markdown} and structured findings",
                f"to {report_json}. Include verified facts, likely root causes,",
                "useful work from prior attempts, and the next recommended action.",
                "",
                "Original task:",
                task.prompt,
                "",
                "Attempt records:",
                *(f"- {path}" for path in [*records, *results]),
            ]
        )
        return self.backend.run(
            task=task,
            attempt_kind="clean",
            attempt_dir=diagnosis_dir,
            prompt=prompt,
            timeout_seconds=timeout_seconds,
        )
