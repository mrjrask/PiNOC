"""Independent, failure-isolated polling scheduler."""
from __future__ import annotations

import logging
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

LOG = logging.getLogger("pinoc.collectors")
UTC = timezone.utc


@dataclass
class CollectionTask:
    name: str
    interval: float
    collect: Callable[[], None]


@dataclass
class TaskStats:
    """Per-task run bookkeeping, read by pinoc.self_monitoring.

    ``last_lag_seconds`` is how late the most recent run started relative to
    when it was actually due (``next_run`` at submit time) -- a busy executor
    (every worker occupied by a slow collect()) or a stalled scheduler thread
    both show up here as growing lag, without this module needing to know
    anything about *why*.
    """
    total_runs: int = 0
    success_count: int = 0
    error_count: int = 0
    consecutive_errors: int = 0
    last_run_at: Optional[str] = None
    last_success_at: Optional[str] = None
    last_error: Optional[str] = None
    last_duration_seconds: Optional[float] = None
    last_lag_seconds: Optional[float] = None
    max_lag_seconds: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_runs": self.total_runs, "success_count": self.success_count,
            "error_count": self.error_count, "consecutive_errors": self.consecutive_errors,
            "last_run_at": self.last_run_at, "last_success_at": self.last_success_at,
            "last_error": self.last_error, "last_duration_seconds": self.last_duration_seconds,
            "last_lag_seconds": self.last_lag_seconds, "max_lag_seconds": self.max_lag_seconds,
        }


class CollectionScheduler:
    def __init__(self, tasks: List[CollectionTask]) -> None:
        self.tasks = tasks
        self.stop_event = threading.Event()
        self.wake_event = threading.Event()
        self.lock = threading.RLock()
        self.executor = ThreadPoolExecutor(max_workers=max(1, len(tasks)), thread_name_prefix="collector")
        self.futures: Dict[str, Future[None]] = {}
        self.next_run: Dict[str, float] = {task.name: 0.0 for task in tasks}
        # Success/failure/lag bookkeeping per task, surfaced by
        # pinoc.self_monitoring as per-domain collector health and cache
        # staleness -- a task's last successful run is exactly when its
        # results were published into the shared state cache.
        self.stats: Dict[str, TaskStats] = {task.name: TaskStats() for task in tasks}
        self.last_loop_at = time.monotonic()
        self.thread = threading.Thread(target=self._run, name="collector-scheduler", daemon=True)

    def start(self) -> None:
        self.thread.start()

    def refresh(self) -> None:
        with self.lock:
            for task in self.tasks:
                self.next_run[task.name] = 0.0
        self.wake_event.set()

    def refresh_task(self, name: str) -> None:
        """Schedule one collector domain without executing it in the caller."""
        with self.lock:
            if name in self.next_run:self.next_run[name]=0.0
        self.wake_event.set()

    def _safe_run(self, task: CollectionTask, scheduled_for: float = 0.0) -> None:
        start = time.monotonic()
        lag = max(0.0, start - scheduled_for) if scheduled_for else 0.0
        error: Optional[str] = None
        try:
            task.collect()
        except Exception as exc:
            error = str(exc) or exc.__class__.__name__
            LOG.exception("%s collection failed", task.name)
        duration = time.monotonic() - start
        stamp = datetime.now(UTC).isoformat()
        with self.lock:
            stats = self.stats.setdefault(task.name, TaskStats())
            stats.total_runs += 1
            stats.last_run_at = stamp
            stats.last_duration_seconds = duration
            stats.last_lag_seconds = lag
            stats.max_lag_seconds = max(stats.max_lag_seconds, lag)
            if error is None:
                stats.success_count += 1
                stats.consecutive_errors = 0
                stats.last_success_at = stamp
            else:
                stats.error_count += 1
                stats.consecutive_errors += 1
                stats.last_error = error

    def _run(self) -> None:
        while not self.stop_event.is_set():
            now = time.monotonic()
            with self.lock:
                self.last_loop_at = now
                for task in self.tasks:
                    future: Optional[Future[None]] = self.futures.get(task.name)
                    if future is not None and not future.done():
                        continue
                    if now >= self.next_run[task.name]:
                        scheduled_for = self.next_run[task.name]
                        self.futures[task.name] = self.executor.submit(self._safe_run, task, scheduled_for)
                        self.next_run[task.name] = now + max(1.0, float(task.interval))
            self.wake_event.wait(0.25)
            self.wake_event.clear()

    def stop(self) -> None:
        self.stop_event.set()
        self.wake_event.set()
        if self.thread.is_alive():
            self.thread.join(timeout=5)
        self.executor.shutdown(wait=False)

    # -- introspection, for pinoc.self_monitoring ---------------------------
    def stats_snapshot(self) -> Dict[str, Dict[str, Any]]:
        """Per-task run/success/error/lag bookkeeping as plain dicts."""
        with self.lock:
            return {name: stats.to_dict() for name, stats in self.stats.items()}

    def heartbeat_snapshot(self) -> Dict[str, Any]:
        """How long since the scheduler loop last iterated (a fully-stalled
        scheduler thread -- deadlock, an unhandled exception escaping
        ``_run`` -- shows up here even though no task lag would catch it),
        plus each task's most recent and worst-seen start lag."""
        with self.lock:
            age = max(0.0, time.monotonic() - self.last_loop_at)
            tasks = {name: {"last_lag_seconds": stats.last_lag_seconds, "max_lag_seconds": stats.max_lag_seconds}
                     for name, stats in self.stats.items()}
        return {"heartbeat_age_seconds": age, "tasks": tasks}

    def task_intervals(self) -> Dict[str, float]:
        return {task.name: float(task.interval) for task in self.tasks}
