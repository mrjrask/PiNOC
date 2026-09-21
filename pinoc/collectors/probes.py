"""Interval-bounded probe runner executed by the collection scheduler.

Probes run *from the PiNOC host* on the scheduler thread pool — never from an
HTTP request — and merge their results into the shared state cache without
touching any other integration.  Each check keeps its own interval and only
re-runs when due, so a fleet of probes stays cheap and predictable.
"""
from __future__ import annotations

import logging
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from pinoc.database import utcnow
from pinoc.device_config import DeviceConfig
from pinoc.integrations import probe
from pinoc.state import PiNOCState

LOG = logging.getLogger("pinoc.collectors.probes")


class ProbeCollector:
    def __init__(
        self,
        state: PiNOCState,
        devices_provider: Callable[[], List[DeviceConfig]],
        config: Optional[Dict[str, Any]] = None,
        runner: Optional[Callable[..., Dict[str, Any]]] = None,
        clock: Optional[Callable[[], float]] = None,
    ) -> None:
        self.state = state
        self.devices_provider = devices_provider
        self.config = config or {}
        self.runner = runner or probe.run_check
        self.clock = clock or time.monotonic
        self._last_run: Dict[Tuple[str, str], float] = {}
        self._last_results: Dict[str, Dict[str, Any]] = {}

    def collect(self) -> None:
        now = self.clock()
        try:
            devices = list(self.devices_provider())
        except Exception:
            LOG.exception("probe device list unavailable")
            return
        for device in devices:
            try:
                self._collect_device(device, now)
            except Exception:
                LOG.exception("[probe] collection failed for %s", device.id)

    def _collect_device(self, device: DeviceConfig, now: float) -> None:
        configured = (device.integrations or {}).get("probe")
        if isinstance(configured, bool):
            configured = {} if configured else None
        enabled = configured is not None and (configured or {}).get("enabled", True)
        checks = ([check for check in (configured or {}).get("checks", []) if check.get("enabled", True)]
                  if enabled else [])
        # A check removed, renamed, disabled, or the whole probe integration
        # turned off in config must not leave its stale result/run-timestamp
        # in memory indefinitely -- reconcile against the currently
        # configured check names on every cycle, even down to none left.
        self._prune_stale_checks(device.id, {check["name"] for check in checks})
        if not checks:
            return
        ran_any = False
        for check in checks:
            key = (device.id, check["name"])
            interval = float(check.get("interval_seconds", probe.DEFAULT_INTERVAL))
            last = self._last_run.get(key)
            if last is not None and now - last < interval:
                continue
            self._last_run[key] = now
            try:
                result = self.runner(dict(check))
            except Exception as exc:  # a broken check must never break siblings
                LOG.warning("[probe] %s/%s failed to run: %s", device.id, check["name"], exc)
                result = {"name": check["name"], "kind": check["kind"], "ok": False,
                          "status": None, "latency_ms": None,
                          "error": f"probe runner error: {exc.__class__.__name__}",
                          "checked_at": utcnow()}
            self._last_results.setdefault(device.id, {})[check["name"]] = result
            ran_any = True
        if not ran_any:
            return
        results = [self._last_results[device.id][check["name"]] for check in checks
                   if check["name"] in self._last_results[device.id]]
        status = probe.normalize(configured or {}, results, utcnow())
        self.state.set_integration(device.id, "probe", status)

    def reset_device(self, device_id: str) -> None:
        """Force all of a device's checks to re-run on the next cycle."""
        for key in [key for key in self._last_run if key[0] == device_id]:
            del self._last_run[key]

    def _prune_stale_checks(self, device_id: str, current_names: "set[str]") -> None:
        results = self._last_results.get(device_id)
        if results:
            for name in [name for name in results if name not in current_names]:
                del results[name]
            if not results:
                del self._last_results[device_id]
        for key in [key for key in self._last_run if key[0] == device_id and key[1] not in current_names]:
            del self._last_run[key]
