from __future__ import annotations

from pathlib import Path

from gca.runtime_v2.agent import build_agent_prompt
from gca.runtime_v2.models import RuntimeTask


def _prompt(attempt_dir: Path) -> str:
    return build_agent_prompt(
        task=RuntimeTask(task_id="case-1", prompt="Build the main application"),
        attempt_kind="initial",
        attempt_dir=attempt_dir,
        submit_command=["runtime-v2", "submit-result"],
    )


def test_build_agent_prompt_requires_attempt_unique_compose_project(
    tmp_path: Path,
) -> None:
    first_prompt = _prompt(tmp_path / "attempt-1")
    second_prompt = _prompt(tmp_path / "attempt-2")

    first_project_line = next(
        line
        for line in first_prompt.splitlines()
        if line.startswith("Compose self-test project name: ")
    )
    second_project_line = next(
        line
        for line in second_prompt.splitlines()
        if line.startswith("Compose self-test project name: ")
    )

    assert first_project_line != second_project_line
    assert "docker compose -p" in first_prompt
    assert "never use the default inferred Compose project name" in first_prompt
