"""Per-task and per-attempt filesystem layout."""

from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path
from typing import Any

from .models import AttemptKind, RuntimeTask


def attempt_resource_name(attempt_dir: Path) -> str:
    digest = hashlib.sha256(str(attempt_dir.resolve()).encode()).hexdigest()[:12]
    return f"runtime-v2-{digest}"


class WorkspaceManager:
    def __init__(self, run_dir: Path):
        self.run_dir = run_dir.resolve()
        self.tasks_dir = self.run_dir / "tasks"
        self.tasks_dir.mkdir(parents=True, exist_ok=True)

    def task_dir(self, task_id: str) -> Path:
        return self.tasks_dir / task_id

    def initialize_task(self, task: RuntimeTask) -> Path:
        task_dir = self.task_dir(task.task_id)
        task_dir.mkdir(parents=True, exist_ok=True)
        (task_dir / "task.txt").write_text(task.prompt + "\n", encoding="utf-8")
        return task_dir

    def prepare_attempt(
        self,
        *,
        task: RuntimeTask,
        attempt_index: int,
        kind: AttemptKind,
    ) -> Path:
        task_dir = self.initialize_task(task)
        attempt_dir = task_dir / "attempts" / f"{attempt_index:02d}-{kind}"
        if attempt_dir.exists():
            return attempt_dir
        if kind == "warm":
            initial = task_dir / "attempts" / "01-initial"
            attempt_dir.mkdir(parents=True)
            initial_workspace = initial / "workspace"
            if initial_workspace.exists():
                try:
                    shutil.copytree(
                        initial_workspace,
                        attempt_dir / "workspace",
                        dirs_exist_ok=True,
                        ignore_dangling_symlinks=True,
                    )
                except shutil.Error:
                    pass
        else:
            attempt_dir.mkdir(parents=True)
        for name in ("workspace", "logs"):
            (attempt_dir / name).mkdir(parents=True, exist_ok=True)
        return attempt_dir

    def write_json(self, path: Path, value: dict[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(path.suffix + ".tmp")
        temporary.write_text(
            json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True)
            + "\n",
            encoding="utf-8",
        )
        temporary.replace(path)
