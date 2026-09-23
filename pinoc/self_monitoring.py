"""Self-monitoring: the console watches itself (enhancement #11).

Gathers signals about PiNOC's own health -- collector success rate, shared
state-cache staleness, history database size/retention, scheduler tick lag,
agent reachability, and queued-action depth -- and opens/resolves alerts
through the *exact same* ``alerts`` table and open/resolve lifecycle every
device alert uses (see ``pinoc.history.HistoryManager._reconcile``): same
columns, same unique-open-fingerprint semantics, same acknowledge/mute path,
same alerts page. They are tagged onto a synthetic ``pinoc-console``
device_id and prefixed ``console_self_`` so an operator can tell at a glance
that an alert is about the console itself, not about a monitored device.

The pure ``*_health``/``*_staleness``/... functions below take plain dicts
and lists (a ``CollectionScheduler.stats_snapshot()``, a list of ``agents``
rows, ...) so they are independently testable with fake/injected inputs,
without a running scheduler or a real database. :class:`SelfMonitoringService`
wires them to live sources and mirrors the ``RemediationService``/
``RolloutService`` poll-loop shape: a single daemon thread ticks on an
interval, is fully optional (a missing db/scheduler simply produces fewer
signals), and never lets a tick's exception escape.
"""
from __future__ import annotations

import json
import logging
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pinoc.database import utcnow

LOG = logging.getLogger("pinoc.self_monitoring")
UTC = timezone.utc

# Synthetic device_id these alerts are opened against -- never a real fleet
# device, so it can never collide with one -- and the alert_type prefix that
# marks every alert this module opens as being about the console itself.
CONSOLE_DEVICE_ID = "pinoc-console"
ALERT_PREFIX = "console_self_"

# History tables whose row counts are cheap enough to surface on every tick
# (COUNT(*) on an indexed/small table); large raw-metric tables are the ones
# retention enforcement (pinoc.history.HistoryManager.maintenance) actually
# bounds, so their row counts double as evidence retention is keeping up.
ROW_COUNT_TABLES = (
    "device_metrics", "network_metrics", "storage_metrics",
    "events", "alerts", "action_jobs", "service_logs",
)

DEFAULTS: Dict[str, Any] = {
    "interval_seconds": 30,
    "consecutive_failure_threshold": 3,
    "cache_stale_multiplier": 3.0,
    "cache_stale_minimum_seconds": 60.0,
    "database_size_ceiling_bytes": 2 * 1024 ** 3,
    "database_retention_stale_seconds": 7200.0,
    "scheduler_heartbeat_stale_seconds": 30.0,
    "scheduler_lag_seconds": 30.0,
    "agent_offline_seconds": 600.0,
    "queue_backlog_depth": 20,
    "queue_backlog_age_seconds": 900.0,
}


def _cfg(config: Optional[Dict[str, Any]], key: str) -> Any:
    return (config or {}).get(key, DEFAULTS[key])


def _age_seconds(iso_value: Optional[str], now: datetime) -> Optional[float]:
    if not iso_value:
        return None
    try:
        dt = datetime.fromisoformat(str(iso_value))
    except (TypeError, ValueError):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return max(0.0, (now - dt.astimezone(UTC)).total_seconds())


# -- pure signal computations (independently testable) -----------------------

def collector_health(task_stats: Dict[str, Dict[str, Any]],
                      config: Optional[Dict[str, Any]] = None) -> Dict[str, Dict[str, Any]]:
    """Per-domain collection success rate, from the scheduler's own
    ``stats_snapshot()`` (or an equivalent fake in tests)."""
    threshold = int(_cfg(config, "consecutive_failure_threshold"))
    out: Dict[str, Dict[str, Any]] = {}
    for name, stats in (task_stats or {}).items():
        total = int(stats.get("total_runs") or 0)
        success = int(stats.get("success_count") or 0)
        consecutive_errors = int(stats.get("consecutive_errors") or 0)
        out[name] = {
            "total_runs": total,
            "success_count": success,
            "error_count": int(stats.get("error_count") or 0),
            "success_rate": (success / total) if total else None,
            "consecutive_errors": consecutive_errors,
            "last_error": stats.get("last_error"),
            "last_run_at": stats.get("last_run_at"),
            "last_success_at": stats.get("last_success_at"),
            "failing": consecutive_errors >= threshold,
        }
    return out


def cache_staleness(task_stats: Dict[str, Dict[str, Any]], intervals: Dict[str, float],
                     now: Optional[datetime] = None,
                     config: Optional[Dict[str, Any]] = None) -> Dict[str, Dict[str, Any]]:
    """Age of each domain's last successful publish into the shared state
    cache. Every collector task publishes into ``PiNOCState`` synchronously
    within its own ``collect()``, so a task's last successful run *is* the
    point that domain's slice of the cache was last refreshed -- this reuses
    that bookkeeping rather than adding new per-domain timestamps to
    ``PiNOCState`` itself for the same information."""
    now = now or datetime.now(UTC)
    multiplier = float(_cfg(config, "cache_stale_multiplier"))
    minimum = float(_cfg(config, "cache_stale_minimum_seconds"))
    out: Dict[str, Dict[str, Any]] = {}
    for name, stats in (task_stats or {}).items():
        age = _age_seconds(stats.get("last_success_at"), now)
        interval = float(intervals.get(name) or 0)
        stale_after = max(minimum, interval * multiplier) if interval else minimum
        out[name] = {
            "age_seconds": age,
            "interval_seconds": interval or None,
            "stale_after_seconds": stale_after,
            "stale": age is not None and age > stale_after,
        }
    return out


def database_health(status: Dict[str, Any], row_counts: Optional[Dict[str, Optional[int]]] = None,
                     now: Optional[datetime] = None,
                     config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Database size + retention-enforcement freshness, from
    ``Database.status()`` (which already tracks ``last_retention_cleanup``;
    see ``HistoryManager.maintenance``) plus a few row counts."""
    now = now or datetime.now(UTC)
    ceiling = int(_cfg(config, "database_size_ceiling_bytes"))
    retention_stale_after = float(_cfg(config, "database_retention_stale_seconds"))
    size_bytes = int(status.get("size_bytes") or 0)
    retention_age = _age_seconds(status.get("last_retention_cleanup"), now)
    return {
        "status": status.get("status"),
        "size_bytes": size_bytes,
        "size_ceiling_bytes": ceiling,
        "size_ratio": (size_bytes / ceiling) if ceiling else None,
        "over_size_ceiling": bool(ceiling) and size_bytes >= ceiling,
        "row_counts": row_counts or {},
        "last_retention_cleanup": status.get("last_retention_cleanup"),
        "retention_age_seconds": retention_age,
        "retention_lagging": retention_age is not None and retention_age > retention_stale_after,
        "error": status.get("error") or None,
    }


def scheduler_lag(snapshot: Dict[str, Any], now: Optional[datetime] = None,
                   config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """``snapshot`` is ``CollectionScheduler.heartbeat_snapshot()``: how
    stale the scheduler's own loop heartbeat is, plus each task's worst
    observed start lag (how far behind its due time it actually ran)."""
    heartbeat_threshold = float(_cfg(config, "scheduler_heartbeat_stale_seconds"))
    lag_threshold = float(_cfg(config, "scheduler_lag_seconds"))
    heartbeat_age = snapshot.get("heartbeat_age_seconds")
    tasks = snapshot.get("tasks") or {}
    worst = max((float(t.get("max_lag_seconds") or 0) for t in tasks.values()), default=0.0)
    heartbeat_stalled = heartbeat_age is not None and heartbeat_age > heartbeat_threshold
    return {
        "heartbeat_age_seconds": heartbeat_age,
        "heartbeat_stalled": heartbeat_stalled,
        "max_task_lag_seconds": worst,
        "lagging": worst > lag_threshold or heartbeat_stalled,
        "tasks": tasks,
    }


def agent_reachability(agent_rows: Optional[List[Dict[str, Any]]], now: Optional[datetime] = None,
                        config: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """Last-seen staleness per row of the ``agents`` table."""
    now = now or datetime.now(UTC)
    offline_after = float(_cfg(config, "agent_offline_seconds"))
    out: List[Dict[str, Any]] = []
    for row in agent_rows or []:
        age = _age_seconds(row.get("last_seen"), now)
        enabled = bool(row.get("enabled", 1))
        out.append({
            "agent_id": row.get("agent_id"),
            "device_id": row.get("device_id"),
            "hostname": row.get("hostname"),
            "enabled": enabled,
            "status": row.get("status"),
            "last_seen": row.get("last_seen"),
            "age_seconds": age,
            "offline": bool(enabled and (age is None or age > offline_after)),
        })
    return out


def queue_depth(job_rows: Optional[List[Dict[str, Any]]], now: Optional[datetime] = None,
                 config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """``job_rows``: ``action_jobs`` rows with status in ('queued','running')."""
    now = now or datetime.now(UTC)
    depth_threshold = int(_cfg(config, "queue_backlog_depth"))
    age_threshold = float(_cfg(config, "queue_backlog_age_seconds"))
    queued = [r for r in job_rows or [] if r.get("status") == "queued"]
    running = [r for r in job_rows or [] if r.get("status") == "running"]
    oldest_age: Optional[float] = None
    for row in queued:
        age = _age_seconds(row.get("requested_at"), now)
        if age is not None and (oldest_age is None or age > oldest_age):
            oldest_age = age
    depth = len(queued) + len(running)
    return {
        "queued": len(queued),
        "running": len(running),
        "depth": depth,
        "oldest_queued_age_seconds": oldest_age,
        "backlogged": depth >= depth_threshold or (oldest_age is not None and oldest_age > age_threshold),
    }


def _row_counts(db: Any, tables: tuple) -> Dict[str, Optional[int]]:
    counts: Dict[str, Optional[int]] = {}
    for table in tables:
        try:
            counts[table] = db.scalar(f"SELECT COUNT(*) FROM {table}")
        except Exception:  # noqa: BLE001 - a bad table name must never break the tick
            counts[table] = None
    return counts


class SelfMonitoringService:
    """Ticks on an interval: builds a :meth:`snapshot`, then opens/resolves
    ``console_self_*`` alerts for whichever signals crossed a threshold.

    ``db`` is the shared history ``Database`` (alerts are persisted and read
    back through it, exactly like every other alert); ``scheduler`` is the
    live ``pinoc.collectors.scheduler.CollectionScheduler`` (its
    ``stats_snapshot()``/``heartbeat_snapshot()``/``task_intervals()``);
    ``state`` is the shared ``PiNOCState``, refreshed the same way
    ``HistoryManager._refresh_cache`` does. All three -- and ``notifier`` --
    are optional: a missing one simply means fewer signals/alerts, never an
    error.
    """

    def __init__(self, db: Any = None, state: Any = None, scheduler: Any = None,
                 config: Optional[Dict[str, Any]] = None, notifier: Any = None,
                 interval: Optional[int] = None) -> None:
        self.db = db
        self.state = state
        self.scheduler = scheduler
        self.config = config or {}
        self.notifier = notifier
        self.interval = max(5, int(interval if interval is not None else _cfg(self.config, "interval_seconds")))
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self._run, name="pinoc-self-monitoring", daemon=True)

    # -- lifecycle -----------------------------------------------------------
    def start(self) -> None:
        if self.db is not None:
            self.thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        self.stop_event.set()
        if self.thread.is_alive():
            self.thread.join(timeout)

    def _run(self) -> None:
        while not self.stop_event.is_set():
            try:
                self.tick()
            except Exception:
                LOG.exception("self-monitoring tick failed")
            self.stop_event.wait(self.interval)

    # -- read side: the Console status page reads this directly -------------
    def snapshot(self) -> Dict[str, Any]:
        now = datetime.now(UTC)
        task_stats = self.scheduler.stats_snapshot() if self.scheduler is not None else {}
        intervals = self.scheduler.task_intervals() if self.scheduler is not None else {}
        heartbeat = self.scheduler.heartbeat_snapshot() if self.scheduler is not None else {
            "heartbeat_age_seconds": None, "tasks": {}}
        db_available = self.db is not None and self.db.available
        db_status = self.db.status() if self.db is not None else {"status": "disabled"}
        row_counts = _row_counts(self.db, ROW_COUNT_TABLES) if db_available else {}
        agent_rows = self.db.rows("SELECT * FROM agents") if db_available else []
        job_rows = self.db.rows(
            "SELECT * FROM action_jobs WHERE status IN ('queued','running')") if db_available else []
        return {
            "generated_at": now.isoformat(),
            "collectors": collector_health(task_stats, self.config),
            "cache": cache_staleness(task_stats, intervals, now, self.config),
            "database": database_health(db_status, row_counts, now, self.config),
            "scheduler": scheduler_lag(heartbeat, now, self.config),
            "agents": agent_reachability(agent_rows, now, self.config),
            "queue": queue_depth(job_rows, now, self.config),
        }

    # -- write side: alert open/resolve, through the existing lifecycle -----
    def tick(self) -> Dict[str, Any]:
        report = self.snapshot()
        if self.db is not None and self.db.available:
            try:
                self._reconcile(report)
            except Exception:
                LOG.exception("self-monitoring alert reconcile failed")
        return report

    def _reconcile(self, report: Dict[str, Any]) -> None:
        active: List[tuple] = []  # (alert_type, resource, severity, message)
        threshold = int(_cfg(self.config, "consecutive_failure_threshold"))
        for name, info in report["collectors"].items():
            if info["failing"]:
                detail = f" ({info['last_error']})" if info.get("last_error") else ""
                severity = "critical" if info["consecutive_errors"] >= threshold * 2 else "warning"
                active.append((f"{ALERT_PREFIX}collector_failing", name, severity,
                                f"{name} collection has failed {info['consecutive_errors']} times in a row{detail}"))
        for name, info in report["cache"].items():
            if info["stale"]:
                active.append((f"{ALERT_PREFIX}cache_stale", name, "warning",
                                f"{name} cache is {int(info['age_seconds'] or 0)}s old "
                                f"(expected refresh every {int(info['interval_seconds'] or 0)}s)"))
        db_info = report["database"]
        if db_info.get("status") == "unavailable":
            active.append((f"{ALERT_PREFIX}database_unavailable", "database", "critical",
                            f"History database is unavailable: {db_info.get('error') or 'unknown error'}"))
        if db_info.get("over_size_ceiling"):
            active.append((f"{ALERT_PREFIX}database_size", "database", "warning",
                            f"History database is {db_info['size_bytes'] / (1024 * 1024):.0f} MiB "
                            f"(ceiling {db_info['size_ceiling_bytes'] / (1024 * 1024):.0f} MiB)"))
        if db_info.get("retention_lagging"):
            active.append((f"{ALERT_PREFIX}database_retention_lag", "retention", "warning",
                            f"Retention cleanup last ran {int(db_info['retention_age_seconds'] or 0)}s ago"))
        sched_info = report["scheduler"]
        if sched_info.get("lagging"):
            active.append((f"{ALERT_PREFIX}scheduler_lag", "scheduler", "warning",
                            f"Collector scheduler is lagging (heartbeat "
                            f"{int(sched_info['heartbeat_age_seconds'] or 0)}s, "
                            f"max task lag {sched_info['max_task_lag_seconds']:.0f}s)"))
        for agent in report["agents"]:
            if agent["offline"]:
                resource = agent.get("agent_id") or agent.get("device_id") or "unknown"
                label = agent.get("hostname") or agent.get("device_id") or resource
                active.append((f"{ALERT_PREFIX}agent_offline", resource, "warning",
                                f"Agent {label} has not reported in {int(agent['age_seconds'] or 0)}s"))
        queue_info = report["queue"]
        if queue_info.get("backlogged"):
            active.append((f"{ALERT_PREFIX}action_queue_backlog", "actions", "warning",
                            f"Action queue depth is {queue_info['depth']} "
                            f"(oldest queued job {int(queue_info['oldest_queued_age_seconds'] or 0)}s)"))
        self._apply(active)

    def _apply(self, active: List[tuple]) -> None:
        stamp = utcnow()
        existing = {row["fingerprint"]: row for row in self.db.rows(
            "SELECT * FROM alerts WHERE device_id=? AND resolved_at IS NULL", (CONSOLE_DEVICE_ID,))}
        seen = set()
        opened: List[Dict[str, Any]] = []
        resolved: List[Dict[str, Any]] = []
        for alert_type, resource, severity, message in active:
            fingerprint = f"{CONSOLE_DEVICE_ID}:{alert_type}:{resource}"
            seen.add(fingerprint)
            if fingerprint in existing:
                row = existing[fingerprint]
                self.db.execute("UPDATE alerts SET last_seen_at=?,severity=?,message=? WHERE alert_id=?",
                                 (stamp, severity, message, row["alert_id"]))
            else:
                alert_id = self.db.execute(
                    "INSERT INTO alerts(device_id,alert_type,severity,message,fingerprint,opened_at,"
                    "last_seen_at,state,metadata_json) VALUES(?,?,?,?,?,?,?,?,?)",
                    (CONSOLE_DEVICE_ID, alert_type, severity, message, fingerprint, stamp, stamp,
                     "active", json.dumps({"resource": resource})))
                opened.append({"alert_id": alert_id, "device_id": CONSOLE_DEVICE_ID, "alert_type": alert_type,
                               "severity": severity, "message": message})
        for fingerprint, row in existing.items():
            if fingerprint not in seen:
                self.db.execute("UPDATE alerts SET resolved_at=?,state='resolved' WHERE alert_id=?",
                                 (stamp, row["alert_id"]))
                resolved.append(row)
        if opened or resolved:
            self._notify(opened, resolved)
        if self.state is not None:
            self.state.set_alerts(self.db.rows(
                "SELECT * FROM alerts WHERE resolved_at IS NULL ORDER BY "
                "CASE severity WHEN 'critical' THEN 3 WHEN 'degraded' THEN 2 WHEN 'warning' THEN 1 ELSE 0 END DESC"))

    def _notify(self, opened: List[Dict[str, Any]], resolved: List[Dict[str, Any]]) -> None:
        if self.notifier is None:
            return
        for row in opened:
            try:
                self.notifier.enqueue("open", row, "PiNOC console")
            except Exception:
                LOG.warning("self-monitoring open notification failed", exc_info=True)
        for row in resolved:
            try:
                self.notifier.enqueue("resolve", row, "PiNOC console")
            except Exception:
                LOG.warning("self-monitoring resolve notification failed", exc_info=True)
