"""Autonomous PoC-development agent commands."""

from __future__ import annotations

import json
import shlex
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from gca.poc_agent import (
    PocAgentRunConfig,
    PocVerifierRunConfig,
    run_poc_agent,
    run_poc_verifier,
)


poc_app = typer.Typer(
    help="Launch an autonomous Agent that writes, executes, and revises a PoC",
    no_args_is_help=True,
)
console = Console()


@poc_app.command("run")
def run(
    audit_report: Path = typer.Argument(
        ...,
        help="Audit report supplied to the PoC Agent",
        exists=True,
        dir_okay=False,
        readable=True,
    ),
    output_dir: Path = typer.Option(
        ...,
        "--output-dir",
        "-o",
        help="Local directory for prompt, Agent event stream, and run metadata",
    ),
    poc_workspace: str = typer.Option(
        ...,
        "--poc-workspace",
        help="Artifact workspace visible to the Agent; may be local or remote",
    ),
    agent_cwd: Path = typer.Option(
        Path.cwd(),
        "--agent-cwd",
        help="Local Agent CLI working root",
        exists=True,
        file_okay=False,
    ),
    agent: str = typer.Option(
        "codex",
        "--agent",
        help="Agent CLI command, optionally including fixed wrapper arguments",
    ),
    model: Optional[str] = typer.Option(None, "--model", help="Optional Agent CLI model override"),
    token_limit: int = typer.Option(
        800_000,
        "--token-limit",
        min=1,
        help="Maximum observed aggregate input and output tokens for the PoC Agent",
    ),
    timeout: int = typer.Option(
        7_200,
        "--timeout",
        min=1,
        help="Wall-clock timeout in seconds",
    ),
) -> None:
    """Run one independent Agent session until PoC completion or a resource limit."""
    command = shlex.split(agent)
    if not command:
        raise typer.BadParameter("--agent must contain an executable")
    result = run_poc_agent(
        PocAgentRunConfig(
            audit_report=audit_report,
            output_dir=output_dir,
            poc_workspace=poc_workspace,
            agent_cwd=agent_cwd,
            agent_command=command,
            model=model,
            token_limit=token_limit,
            timeout_seconds=timeout,
        )
    )
    console.print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
    if not result.succeeded:
        raise typer.Exit(1)


@poc_app.command("verify")
def verify(
    audit_report: Path = typer.Argument(
        ...,
        help="Original audit report supplied to the verifier",
        exists=True,
        dir_okay=False,
        readable=True,
    ),
    poc_artifact: str = typer.Option(
        ...,
        "--poc-artifact",
        help="Path or URI of the final PoC artifact to verify",
    ),
    reproduce_command: str = typer.Option(
        ...,
        "--reproduce-command",
        help="Command the verifier should use as the primary reproduction entrypoint",
    ),
    verifier_workspace: str = typer.Option(
        ...,
        "--verifier-workspace",
        help="Workspace where verifier receipts and logs should be written",
    ),
    output_dir: Path = typer.Option(
        ...,
        "--output-dir",
        "-o",
        help="Local directory for verifier prompt, event stream, and run metadata",
    ),
    agent_cwd: Path = typer.Option(
        Path.cwd(),
        "--agent-cwd",
        help="Local Agent CLI working root",
        exists=True,
        file_okay=False,
    ),
    agent: str = typer.Option(
        "codex",
        "--agent",
        help="Agent CLI command, optionally including fixed wrapper arguments",
    ),
    model: Optional[str] = typer.Option(None, "--model", help="Optional Agent CLI model override"),
    timeout: int = typer.Option(
        3_600,
        "--timeout",
        min=1,
        help="Wall-clock timeout in seconds",
    ),
) -> None:
    """Run one independent verifier Agent session against a completed PoC."""
    command = shlex.split(agent)
    if not command:
        raise typer.BadParameter("--agent must contain an executable")
    result = run_poc_verifier(
        PocVerifierRunConfig(
            audit_report=audit_report,
            output_dir=output_dir,
            poc_artifact=poc_artifact,
            reproduce_command=reproduce_command,
            verifier_workspace=verifier_workspace,
            agent_cwd=agent_cwd,
            agent_command=command,
            model=model,
            timeout_seconds=timeout,
        )
    )
    console.print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
    if not result.succeeded:
        raise typer.Exit(1)
