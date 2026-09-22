"""Bounded device-to-device ping/latency matrix collector.

Samples a configured (explicit, or capped auto-derived from the device
inventory -- see :mod:`pinoc.topology`) set of device pairs on a schedule,
and writes each sample into the shared history database
(``network_matrix_samples``), the same store every other collector uses --
no parallel storage.

Sampling runs *from the source device*, over SSH, mirroring how the fleet
collector already reaches every device (see
:mod:`pinoc.collectors.fleet`), except when the source is the local PiNOC
host itself, in which case the ping runs directly. So a sampled pair
measures genuine device-to-device reachability, not just PiNOC-host-to-
device latency.
"""
from __future__ import annotations

import logging
import re
import subprocess
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from pinoc.database import utcnow
from pinoc.device_config import DeviceConfig
from pinoc.topology import parse_topology_config

LOG = logging.getLogger("pinoc.collectors.network_matrix")

# Matches the summary line `ping -q` prints, e.g.
# "rtt min/avg/max/mdev = 1.234/2.345/3.456/0.123 ms".
_RTT_RE = re.compile(r"=\s*[\d.]+/([\d.]+)/[\d.]+")
# Matches "3 packets transmitted, 3 received, 0% packet loss, ...".
_LOSS_RE = re.compile(r"([\d.]+)%\s+packet loss")


def parse_ping_output(text: str) -> Dict[str, Optional[float]]:
    """Extract average round-trip time and packet loss from ``ping -q``
    output (both BSD and iputils formats share this summary line)."""
    loss_match = _LOSS_RE.search(text or "")
    rtt_match = _RTT_RE.search(text or "")
    return {
        "loss_percent": float(loss_match.group(1)) if loss_match else None,
        "latency_ms": float(rtt_match.group(1)) if rtt_match else None,
    }


def build_ping_argv(source: DeviceConfig, target_address: str, count: int, timeout: float) -> List[str]:
    """The ping command to run, and -- for every source but the local
    PiNOC host -- the SSH wrapper that runs it *from that device*."""
    per_packet_timeout = max(1, int(round(timeout)))
    ping = ["ping", "-c", str(count), "-W", str(per_packet_timeout), "-q", target_address]
    if source.collection_method == "local":
        return ping
    return ["ssh", "-p", str(source.ssh_port), "-o", f"ConnectTimeout={per_packet_timeout}",
            "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new",
            f"{source.ssh_user}@{source.address}", *ping]


def sample_pair(source: DeviceConfig, target: DeviceConfig, runner: Optional[Callable[..., Any]] = None,
                count: int = 3, timeout: float = 2.0) -> Dict[str, Any]:
    """Ping ``target`` from ``source`` and return one normalized sample.

    ``runner`` is injectable for tests; it must accept the argv list and a
    ``timeout`` keyword and return an object with ``.returncode``,
    ``.stdout``, ``.stderr`` -- exactly ``subprocess.CompletedProcess``,
    matching how ``FleetCollector`` and ``pinoc.integrations.probe`` make
    their own command execution injectable.
    """
    argv = build_ping_argv(source, target.address, count, timeout)
    exec_ = runner or (lambda args, timeout: subprocess.run(args, capture_output=True, text=True, timeout=timeout))
    budget = timeout * count + 5
    try:
        proc = exec_(argv, timeout=budget)
    except Exception as exc:  # a broken pair must never break the collector or its siblings
        return {"ok": False, "latency_ms": None, "loss_percent": 100.0,
                "error": f"{exc.__class__.__name__}: {exc}"}
    parsed = parse_ping_output((proc.stdout or "") + (proc.stderr or ""))
    loss = parsed["loss_percent"]
    ok = proc.returncode == 0 and loss is not None and loss < 100.0
    error = None
    if not ok:
        error = f"ping exited {proc.returncode}" if loss is None else f"{loss:.0f}% packet loss"
    return {"ok": ok, "latency_ms": parsed["latency_ms"],
            "loss_percent": loss if loss is not None else 100.0, "error": error}


class NetworkMatrixCollector:
    """Samples every configured/derived pair on its own interval, the same
    per-check due/interval pattern :class:`pinoc.collectors.probes.
    ProbeCollector` uses for user-defined checks."""

    def __init__(
        self,
        db: Any,
        devices_provider: Callable[[], List[DeviceConfig]],
        config: Optional[Dict[str, Any]] = None,
        runner: Optional[Callable[..., Any]] = None,
        clock: Optional[Callable[[], float]] = None,
    ) -> None:
        self.db = db
        self.devices_provider = devices_provider
        self.config = config or {}
        self.runner = runner
        self.clock = clock or time.monotonic
        self._last_run: Dict[Tuple[str, str], float] = {}

    def collect(self) -> None:
        if self.db is None:
            return
        try:
            devices = list(self.devices_provider())
        except Exception:
            LOG.exception("network matrix device list unavailable")
            return
        by_id = {device.id: device for device in devices}
        tags = {device.id: device.tags for device in devices}
        try:
            topology = parse_topology_config(self.config, by_id.keys(), tags)
        except Exception:
            LOG.exception("invalid network_topology configuration; skipping this cycle")
            return
        if not topology.enabled or not topology.pairs:
            return
        now = self.clock()
        for source_id, target_id in topology.pairs:
            source, target = by_id.get(source_id), by_id.get(target_id)
            if source is None or target is None:
                continue
            key = (source_id, target_id)
            last = self._last_run.get(key)
            if last is not None and now - last < topology.interval_seconds:
                continue
            self._last_run[key] = now
            try:
                result = sample_pair(source, target, runner=self.runner,
                                     count=topology.ping_count, timeout=topology.ping_timeout_seconds)
            except Exception as exc:
                LOG.warning("[network-matrix] %s -> %s failed: %s", source_id, target_id, exc)
                result = {"ok": False, "latency_ms": None, "loss_percent": 100.0,
                          "error": f"collector error: {exc.__class__.__name__}"}
            self._record(source_id, target_id, result)

    def _record(self, source_id: str, target_id: str, result: Dict[str, Any]) -> None:
        try:
            self.db.execute(
                "INSERT OR IGNORE INTO network_matrix_samples"
                "(timestamp,source_id,target_id,latency_ms,loss_percent,ok,error) VALUES(?,?,?,?,?,?,?)",
                (utcnow(), source_id, target_id, result.get("latency_ms"), result.get("loss_percent"),
                 int(bool(result.get("ok"))), result.get("error")))
        except Exception:
            LOG.exception("failed to record network matrix sample %s -> %s", source_id, target_id)

    def reset_pair(self, source_id: str, target_id: str) -> None:
        """Force one pair to re-sample on the next cycle."""
        self._last_run.pop((source_id, target_id), None)
