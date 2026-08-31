"""Independent, failure-isolated polling scheduler."""
from __future__ import annotations

import logging
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional

LOG = logging.getLogger("pinoc.collectors")


@dataclass
class CollectionTask:
    name: str
    interval: float
    collect: Callable[[], None]


class CollectionScheduler:
    def __init__(self, tasks: List[CollectionTask]) -> None:
        self.tasks = tasks
        self.stop_event = threading.Event()
        self.wake_event = threading.Event()
        self.lock = threading.RLock()
        self.executor = ThreadPoolExecutor(max_workers=max(1, len(tasks)), thread_name_prefix="collector")
        self.futures: Dict[str, Future[None]] = {}
        self.next_run: Dict[str, float] = {task.name: 0.0 for task in tasks}
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

    def _safe_run(self, task: CollectionTask) -> None:
        try:
            task.collect()
        except Exception:
            LOG.exception("%s collection failed", task.name)

    def _run(self) -> None:
        while not self.stop_event.is_set():
            now = time.monotonic()
            with self.lock:
                for task in self.tasks:
                    future: Optional[Future[None]] = self.futures.get(task.name)
                    if future is not None and not future.done():
                        continue
                    if now >= self.next_run[task.name]:
                        self.futures[task.name] = self.executor.submit(self._safe_run, task)
                        self.next_run[task.name] = now + max(1.0, float(task.interval))
            self.wake_event.wait(0.25)
            self.wake_event.clear()

    def stop(self) -> None:
        self.stop_event.set()
        self.wake_event.set()
        if self.thread.is_alive():
            self.thread.join(timeout=5)
        self.executor.shutdown(wait=False)
