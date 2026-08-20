"""SQLite-backed task queue for autonomous runtime construction."""

from __future__ import annotations

import json
import re
import sqlite3
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Iterator

from .models import AttemptKind, FailureReason, RuntimeTask


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


class QueueStore:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA busy_timeout=30000")
        return connection

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        connection = self.connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self.connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS tasks (
                    task_id TEXT PRIMARY KEY,
                    prompt TEXT NOT NULL,
                    project_key TEXT,
                    provenance_json TEXT,
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

                CREATE TABLE IF NOT EXISTS attempts (
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
                    UNIQUE(task_id, attempt_index),
                    FOREIGN KEY(task_id) REFERENCES tasks(task_id)
                );

                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    task_id TEXT NOT NULL,
                    attempt_id INTEGER,
                    event TEXT NOT NULL,
                    detail TEXT,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS submission_checks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    attempt_id INTEGER NOT NULL,
                    submission_index INTEGER NOT NULL,
                    source_path TEXT NOT NULL,
                    snapshot_path TEXT NOT NULL,
                    status TEXT NOT NULL,
                    reason_json TEXT,
                    created_at TEXT NOT NULL,
                    UNIQUE(attempt_id, submission_index),
                    FOREIGN KEY(attempt_id) REFERENCES attempts(id)
                );
                """
            )
            self._ensure_column(connection, "attempts", "accepted_submission_id", "INTEGER")
            self._ensure_column(connection, "attempts", "audit_path", "TEXT")
            self._ensure_column(connection, "attempts", "reason_json", "TEXT")
            self._ensure_column(connection, "tasks", "provenance_json", "TEXT")

    def _ensure_column(
        self,
        connection: sqlite3.Connection,
        table: str,
        column: str,
        declaration: str,
    ) -> None:
        columns = {
            str(row["name"])
            for row in connection.execute(f"PRAGMA table_info({table})").fetchall()
        }
        if column not in columns:
            connection.execute(
                f"ALTER TABLE {table} ADD COLUMN {column} {declaration}"
            )

    def submit(
        self,
        *,
        task_id: str,
        prompt: str,
        project_key: str | None = None,
        provenance: dict[str, str] | None = None,
        priority: int = 0,
    ) -> RuntimeTask:
        task_id = task_id.strip()
        prompt = prompt.strip()
        if not task_id:
            raise ValueError("task_id must not be empty")
        if not re.fullmatch(r"[A-Za-z0-9._-]+", task_id):
            raise ValueError(
                "task_id may contain only letters, digits, dot, underscore, and dash"
            )
        if not prompt:
            raise ValueError("prompt must not be empty")
        if provenance is not None:
            if not isinstance(provenance, dict) or not provenance:
                raise ValueError("provenance must be a non-empty object when supplied")
            if any(not isinstance(key, str) or not isinstance(value, str) or not value for key, value in provenance.items()):
                raise ValueError("provenance must contain non-empty string keys and values")
        now = utc_now()
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO tasks (
                    task_id, prompt, project_key, provenance_json, priority, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    task_id,
                    prompt,
                    project_key or None,
                    json.dumps(provenance, ensure_ascii=False, sort_keys=True) if provenance else None,
                    int(priority),
                    now,
                    now,
                ),
            )
            connection.execute(
                """
                INSERT INTO events (task_id, event, created_at)
                VALUES (?, 'submitted', ?)
                """,
                (task_id, now),
            )
        return RuntimeTask(
            task_id=task_id,
            prompt=prompt,
            project_key=project_key or None,
            provenance=provenance,
            priority=int(priority),
        )

    def claim(self, *, owner: str, lease_seconds: int) -> RuntimeTask | None:
        if lease_seconds <= 0:
            raise ValueError("lease_seconds must be positive")
        now = datetime.now(UTC)
        now_text = now.isoformat()
        expires = (now + timedelta(seconds=lease_seconds)).isoformat()
        with self.transaction() as connection:
            connection.execute(
                """
                UPDATE tasks
                SET status = 'queued', lease_owner = NULL, lease_expires_at = NULL,
                    updated_at = ?
                WHERE status IN ('running', 'verifying', 'diagnosing')
                  AND lease_expires_at IS NOT NULL
                  AND lease_expires_at < ?
                  AND cancel_requested = 0
                """,
                (now_text, now_text),
            )
            row = connection.execute(
                """
                SELECT task_id, prompt, project_key, provenance_json, priority, status, attempt_index
                FROM tasks AS candidate
                WHERE candidate.status = 'queued'
                  AND candidate.cancel_requested = 0
                  AND (
                    candidate.project_key IS NULL
                    OR NOT EXISTS (
                      SELECT 1
                      FROM tasks AS active
                      WHERE active.status IN ('running', 'verifying', 'diagnosing')
                        AND active.project_key = candidate.project_key
                    )
                  )
                ORDER BY candidate.priority DESC, candidate.created_at, candidate.task_id
                LIMIT 1
                """
            ).fetchone()
            if row is None:
                return None
            connection.execute(
                """
                UPDATE tasks
                SET status = 'running', lease_owner = ?, lease_expires_at = ?,
                    updated_at = ?
                WHERE task_id = ?
                """,
                (owner, expires, now_text, row["task_id"]),
            )
            connection.execute(
                """
                INSERT INTO events (task_id, event, detail, created_at)
                VALUES (?, 'claimed', ?, ?)
                """,
                (row["task_id"], owner, now_text),
            )
            return RuntimeTask(
                task_id=row["task_id"],
                prompt=row["prompt"],
                project_key=row["project_key"],
                provenance=(json.loads(row["provenance_json"]) if row["provenance_json"] else None),
                priority=row["priority"],
                status="running",
                attempt_index=row["attempt_index"],
            )

    def heartbeat(self, *, task_id: str, owner: str, lease_seconds: int) -> bool:
        expires = (
            datetime.now(UTC) + timedelta(seconds=lease_seconds)
        ).isoformat()
        with self.connect() as connection:
            cursor = connection.execute(
                """
                UPDATE tasks
                SET lease_expires_at = ?, updated_at = ?
                WHERE task_id = ? AND lease_owner = ?
                  AND status IN ('running', 'verifying', 'diagnosing')
                """,
                (expires, utc_now(), task_id, owner),
            )
        return cursor.rowcount == 1

    def start_attempt(
        self,
        *,
        task_id: str,
        attempt_index: int,
        kind: AttemptKind,
        workspace: Path,
    ) -> int:
        with self.connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO attempts (
                    task_id, attempt_index, kind, status, workspace, started_at
                ) VALUES (?, ?, ?, 'running', ?, ?)
                ON CONFLICT(task_id, attempt_index) DO UPDATE SET
                    kind = excluded.kind,
                    status = 'running',
                    workspace = excluded.workspace,
                    started_at = excluded.started_at,
                    completed_at = NULL,
                    error = NULL,
                    agent_returncode = NULL,
                    agent_timed_out = 0,
                    result_path = NULL,
                    verification_path = NULL,
                    accepted_submission_id = NULL,
                    audit_path = NULL,
                    reason_json = NULL
                RETURNING id
                """,
                (
                    task_id,
                    attempt_index,
                    kind,
                    str(workspace),
                    utc_now(),
                ),
            )
            connection.execute(
                """
                UPDATE tasks SET attempt_index = ?, updated_at = ?
                WHERE task_id = ?
                """,
                (attempt_index, utc_now(), task_id),
            )
            row = cursor.fetchone()
        if row is None:
            raise RuntimeError("attempt row was not created")
        return int(row["id"])

    def finish_attempt(
        self,
        *,
        attempt_id: int,
        status: str,
        error: str | None = None,
        agent_returncode: int | None = None,
        agent_timed_out: bool = False,
        result_path: Path | None = None,
        verification_path: Path | None = None,
        audit_path: Path | None = None,
        reason: FailureReason | None = None,
    ) -> None:
        with self.connect() as connection:
            connection.execute(
                """
                UPDATE attempts
                SET status = ?, completed_at = ?, error = ?,
                    agent_returncode = ?, agent_timed_out = ?,
                    result_path = ?, verification_path = ?, audit_path = ?,
                    reason_json = ?
                WHERE id = ?
                """,
                (
                    status,
                    utc_now(),
                    error,
                    agent_returncode,
                    int(agent_timed_out),
                    str(result_path) if result_path else None,
                    str(verification_path) if verification_path else None,
                    str(audit_path) if audit_path else None,
                    json.dumps(reason.to_dict(), ensure_ascii=False) if reason else None,
                    attempt_id,
                ),
            )

    def get_attempt(self, attempt_id: int) -> dict[str, object] | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM attempts WHERE id = ?",
                (attempt_id,),
            ).fetchone()
        return dict(row) if row else None

    def record_submission_check(
        self,
        *,
        attempt_id: int,
        source_path: Path,
        snapshot_path: Path,
        status: str,
        reason: FailureReason | None,
        result_path: Path | None = None,
    ) -> dict[str, Any]:
        with self.transaction() as connection:
            row = connection.execute(
                """
                SELECT COALESCE(MAX(submission_index), 0) + 1 AS next_index
                FROM submission_checks
                WHERE attempt_id = ?
                """,
                (attempt_id,),
            ).fetchone()
            submission_index = int(row["next_index"])
            cursor = connection.execute(
                """
                INSERT INTO submission_checks (
                    attempt_id, submission_index, source_path, snapshot_path,
                    status, reason_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    attempt_id,
                    submission_index,
                    str(source_path),
                    str(snapshot_path),
                    status,
                    json.dumps(reason.to_dict(), ensure_ascii=False) if reason else None,
                    utc_now(),
                ),
            )
            submission_id = int(cursor.lastrowid)
            if status == "accepted":
                connection.execute(
                    """
                    UPDATE attempts
                    SET accepted_submission_id = ?, result_path = ?
                    WHERE id = ?
                    """,
                    (
                        submission_id,
                        str(result_path or snapshot_path),
                        attempt_id,
                    ),
                )
        return {
            "id": submission_id,
            "attempt_id": attempt_id,
            "submission_index": submission_index,
            "status": status,
            "snapshot_path": str(snapshot_path),
            "reason": reason.to_dict() if reason else None,
        }

    def submissions_for(self, attempt_id: int) -> list[dict[str, object]]:
        with self.connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM submission_checks
                WHERE attempt_id = ?
                ORDER BY submission_index
                """,
                (attempt_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def accepted_submission(self, attempt_id: int) -> dict[str, object] | None:
        with self.connect() as connection:
            row = connection.execute(
                """
                SELECT submission_checks.*
                FROM attempts
                JOIN submission_checks
                  ON submission_checks.id = attempts.accepted_submission_id
                WHERE attempts.id = ?
                """,
                (attempt_id,),
            ).fetchone()
        return dict(row) if row else None

    def record_event(
        self,
        *,
        task_id: str,
        event: str,
        attempt_id: int | None = None,
        detail: str | None = None,
    ) -> None:
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO events (task_id, attempt_id, event, detail, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (task_id, attempt_id, event, detail, utc_now()),
            )

    def set_status(
        self,
        *,
        task_id: str,
        status: str,
        final_json: Path | None = None,
        release_lease: bool = False,
    ) -> None:
        lease_owner = None if release_lease else "__keep__"
        with self.connect() as connection:
            if lease_owner is None:
                connection.execute(
                    """
                    UPDATE tasks
                    SET status = ?, final_json = COALESCE(?, final_json),
                        lease_owner = NULL, lease_expires_at = NULL,
                        updated_at = ?
                    WHERE task_id = ?
                    """,
                    (
                        status,
                        str(final_json) if final_json else None,
                        utc_now(),
                        task_id,
                    ),
                )
            else:
                connection.execute(
                    """
                    UPDATE tasks
                    SET status = ?, final_json = COALESCE(?, final_json),
                        updated_at = ?
                    WHERE task_id = ?
                    """,
                    (
                        status,
                        str(final_json) if final_json else None,
                        utc_now(),
                        task_id,
                    ),
                )

    def cancel(self, task_id: str) -> bool:
        with self.connect() as connection:
            cursor = connection.execute(
                """
                UPDATE tasks
                SET cancel_requested = 1,
                    status = CASE
                      WHEN status = 'queued' THEN 'cancelled'
                      ELSE status
                    END,
                    updated_at = ?
                WHERE task_id = ?
                """,
                (utc_now(), task_id),
            )
        return cursor.rowcount == 1

    def cancellation_requested(self, task_id: str) -> bool:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT cancel_requested FROM tasks WHERE task_id = ?",
                (task_id,),
            ).fetchone()
        return bool(row and row["cancel_requested"])

    def get(self, task_id: str) -> dict[str, object] | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM tasks WHERE task_id = ?",
                (task_id,),
            ).fetchone()
        return dict(row) if row else None

    def list_tasks(self) -> list[dict[str, object]]:
        with self.connect() as connection:
            rows = connection.execute(
                """
                SELECT task_id, project_key, provenance_json, priority, status, attempt_index,
                       created_at, updated_at, final_json
                FROM tasks
                ORDER BY priority DESC, created_at, task_id
                """
            ).fetchall()
        return [dict(row) for row in rows]

    def has_pending_tasks(self) -> bool:
        with self.connect() as connection:
            row = connection.execute(
                """
                SELECT 1
                FROM tasks
                WHERE status IN ('queued', 'running', 'verifying', 'diagnosing')
                  AND cancel_requested = 0
                LIMIT 1
                """
            ).fetchone()
        return row is not None

    def attempts_for(self, task_id: str) -> list[dict[str, object]]:
        with self.connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM attempts
                WHERE task_id = ?
                ORDER BY attempt_index
                """,
                (task_id,),
            ).fetchall()
        return [dict(row) for row in rows]
