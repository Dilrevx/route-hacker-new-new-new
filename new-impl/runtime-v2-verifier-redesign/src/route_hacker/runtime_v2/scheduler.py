"""Fixed-size concurrent scheduler for runtime-v2 tasks."""

from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from .orchestrator import RuntimeV2Orchestrator
from .queue import QueueStore


class RuntimeScheduler:
    def __init__(
        self,
        *,
        queue: QueueStore,
        orchestrator: RuntimeV2Orchestrator,
        workers: int,
        lease_seconds: int,
        poll_seconds: float = 2.0,
        idle_rounds: int = 3,
    ):
        if workers <= 0:
            raise ValueError("workers must be positive")
        self.queue = queue
        self.orchestrator = orchestrator
        self.workers = workers
        self.lease_seconds = lease_seconds
        self.poll_seconds = poll_seconds
        self.idle_rounds = idle_rounds

    def run_until_idle(self) -> list[dict[str, Any]]:
        stop = threading.Event()
        results: list[dict[str, Any]] = []
        with ThreadPoolExecutor(max_workers=self.workers) as executor:
            futures = [
                executor.submit(self._worker, f"runtime-v2-worker-{index + 1}", stop)
                for index in range(self.workers)
            ]
            for future in as_completed(futures):
                results.extend(future.result())
        return results

    def _worker(self, owner: str, stop: threading.Event) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        idle = 0
        while not stop.is_set() and idle < self.idle_rounds:
            task = self.queue.claim(owner=owner, lease_seconds=self.lease_seconds)
            if task is None:
                if self.queue.has_pending_tasks():
                    idle = 0
                else:
                    idle += 1
                time.sleep(self.poll_seconds)
                continue
            idle = 0
            heartbeat_stop = threading.Event()
            heartbeat = threading.Thread(
                target=self._heartbeat,
                args=(task.task_id, owner, heartbeat_stop),
                daemon=True,
            )
            heartbeat.start()
            try:
                results.append(self.orchestrator.run_task(task))
            except Exception as exc:
                final = {
                    "task_id": task.task_id,
                    "status": "failed",
                    "error": f"{type(exc).__name__}: {exc}",
                }
                results.append(
                    self.orchestrator._finish(task, final, "failed")
                )
            finally:
                heartbeat_stop.set()
                heartbeat.join(timeout=1.0)
        return results

    def _heartbeat(
        self,
        task_id: str,
        owner: str,
        stop: threading.Event,
    ) -> None:
        interval = max(1.0, min(60.0, self.lease_seconds / 3))
        while not stop.wait(interval):
            if not self.queue.heartbeat(
                task_id=task_id,
                owner=owner,
                lease_seconds=self.lease_seconds,
            ):
                return
