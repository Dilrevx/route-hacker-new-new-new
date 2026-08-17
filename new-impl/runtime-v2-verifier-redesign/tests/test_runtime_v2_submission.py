import json
import sqlite3
from pathlib import Path

from route_hacker.runtime_v2.models import RuntimeTask
from route_hacker.runtime_v2.queue import QueueStore
from route_hacker.runtime_v2.submission import ResultSubmissionService
from route_hacker.runtime_v2.workspace import WorkspaceManager


def _running_attempt(tmp_path: Path) -> tuple[QueueStore, Path, int]:
    run_dir = tmp_path / "run"
    queue = QueueStore(run_dir / "queue.db")
    task = queue.submit(task_id="case-1", prompt="Build a runtime")
    claimed = queue.claim(owner="test", lease_seconds=60)
    assert claimed is not None
    attempt_dir = WorkspaceManager(run_dir).prepare_attempt(
        task=RuntimeTask(
            task_id=task.task_id,
            prompt=task.prompt,
            status="running",
        ),
        attempt_index=1,
        kind="initial",
    )
    attempt_id = queue.start_attempt(
        task_id=task.task_id,
        attempt_index=1,
        kind="initial",
        workspace=attempt_dir,
    )
    return queue, attempt_dir, attempt_id


def test_submit_rejects_then_accepts_and_persists_both_checks(tmp_path: Path) -> None:
    queue, attempt_dir, attempt_id = _running_attempt(tmp_path)
    workspace = attempt_dir / "workspace"
    candidate = attempt_dir / "candidate-result.json"
    candidate.write_text(
        json.dumps(
            {
                "primary_image": "example:latest",
                "launch": {"type": "compose", "file": "missing.yaml"},
                "probes": [{"type": "tcp", "host": "127.0.0.1", "port": 8080}],
            }
        ),
        encoding="utf-8",
    )
    service = ResultSubmissionService(queue)

    rejected = service.submit(
        task_id="case-1",
        attempt_id=attempt_id,
        candidate_path=candidate,
    )

    assert rejected.accepted is False
    assert rejected.reason is not None
    assert rejected.reason.code == "compose_file_missing"
    assert not (attempt_dir / "result.json").exists()

    (workspace / "missing.yaml").write_text("services: {}\n", encoding="utf-8")
    accepted = service.submit(
        task_id="case-1",
        attempt_id=attempt_id,
        candidate_path=candidate,
    )

    assert accepted.accepted is True
    assert accepted.submission_index == 2
    assert json.loads((attempt_dir / "result.json").read_text(encoding="utf-8"))[
        "launch"
    ]["file"] == "missing.yaml"
    submissions = queue.submissions_for(attempt_id)
    assert [item["status"] for item in submissions] == ["rejected", "accepted"]
    assert queue.accepted_submission(attempt_id)["id"] == accepted.submission_id


def test_submit_rejects_path_outside_attempt(tmp_path: Path) -> None:
    queue, _, attempt_id = _running_attempt(tmp_path)
    outside = tmp_path / "outside.json"
    outside.write_text("{}", encoding="utf-8")

    try:
        ResultSubmissionService(queue).submit(
            task_id="case-1",
            attempt_id=attempt_id,
            candidate_path=outside,
        )
    except ValueError as exc:
        assert "inside the attempt directory" in str(exc)
    else:
        raise AssertionError("outside submission was accepted")


def test_queue_migrates_existing_attempt_table(tmp_path: Path) -> None:
    database = tmp_path / "queue.db"
    with sqlite3.connect(database) as connection:
        connection.executescript(
            """
            CREATE TABLE tasks (
                task_id TEXT PRIMARY KEY,
                prompt TEXT NOT NULL,
                project_key TEXT,
                priority INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'queued',
                attempt_index INTEGER NOT NULL DEFAULT 0,
                lease_owner TEXT,
                lease_expires_at TEXT,
                cancel_requested INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                final_json TEXT
            );
            CREATE TABLE attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id TEXT NOT NULL,
                attempt_index INTEGER NOT NULL,
                kind TEXT NOT NULL,
                status TEXT NOT NULL,
                workspace TEXT NOT NULL,
                started_at TEXT NOT NULL,
                completed_at TEXT,
                error TEXT,
                agent_returncode INTEGER,
                agent_timed_out INTEGER NOT NULL DEFAULT 0,
                result_path TEXT,
                verification_path TEXT,
                UNIQUE(task_id, attempt_index)
            );
            CREATE TABLE events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id TEXT NOT NULL,
                attempt_id INTEGER,
                event TEXT NOT NULL,
                detail TEXT,
                created_at TEXT NOT NULL
            );
            """
        )

    queue = QueueStore(database)

    with queue.connect() as connection:
        columns = {
            row["name"] for row in connection.execute("PRAGMA table_info(attempts)")
        }
        submission_table = connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='submission_checks'"
        ).fetchone()
    assert {"accepted_submission_id", "audit_path", "reason_json"} <= columns
    assert submission_table is not None
