"""Failure-isolated background collection primitives."""
from __future__ import annotations

import logging
import threading
import time
from abc import ABC, abstractmethod
from typing import Any, Callable, Iterable

from pinoc.models import DeviceState
from pinoc.state import PiNOCState

LOG = logging.getLogger("pinoc.collectors")


class Collector(ABC):
    name = "collector"
    interval = 10.0

    @abstractmethod
    def collect(self) -> Iterable[DeviceState]:
        raise NotImplementedError

    def safe_collect(self) -> list[DeviceState]:
        try:
            return list(self.collect())
        except Exception as exc:
            LOG.warning("%s collection failed: %s", self.name, exc)
            return []


class BackgroundCollector:
    """Runs the existing complete snapshot collector away from UI threads."""
    def __init__(self, state: PiNOCState, collect: Callable[[], Any], normalize: Callable[[Any], Iterable[DeviceState]], interval: float = 10.0) -> None:
        self.state, self.collect, self.normalize = state, collect, normalize
        self.interval = max(1.0, float(interval))
        self.stop_event = threading.Event()
        self.refresh_event = threading.Event()
        self.thread = threading.Thread(target=self._run, name="pinoc-collector", daemon=True)

    def start(self) -> None:
        if not self.thread.is_alive():
            self.thread.start()

    def refresh(self) -> None:
        self.refresh_event.set()

    def _run(self) -> None:
        while not self.stop_event.is_set():
            started = time.monotonic()
            try:
                snapshot = self.collect()
                self.state.publish(self.normalize(snapshot), snapshot)
            except Exception as exc:
                LOG.exception("collection cycle failed: %s", exc)
            delay = max(0.0, self.interval - (time.monotonic() - started))
            self.refresh_event.wait(delay)
            self.refresh_event.clear()

    def stop(self) -> None:
        self.stop_event.set()
        self.refresh_event.set()
        if self.thread.is_alive():
            self.thread.join(timeout=5)
