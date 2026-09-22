"""Automatic playbook remediation ("self-healing").

A playbook may declare a ``remediation`` block (see :mod:`pinoc.playbooks`)
that binds one safe-registry action to the alert type it treats, with an
execution policy:

* ``auto``    -- run automatically, subject to a per-alert cooldown, a
  max-attempts cap, and maintenance-window awareness (deferred while the
  device is in maintenance);
* ``approve`` -- surface a pending approve/deny decision instead of running
  automatically. An operator's decision reuses the exact same enqueue path
  as ``auto`` (see :meth:`RemediationService.decide`).

Every run -- automatic or operator-approved -- is enqueued through the
shared :class:`pinoc.actions.ActionDispatcher`. There is no separate
execution mechanism, so a remediation run shows up in ``action_jobs`` and
the audit trail exactly like a manual or scheduled action.

A recovered device resolves its own alert through
:class:`pinoc.history.HistoryManager`'s existing reconcile path -- this
service does not resolve alerts itself. It only resets its own bookkeeping
(attempt count, cooldown, any pending approval) once that has happened, so
the *next* occurrence of the same alert starts from a clean slate.

State lives in ``remediation_runs``, keyed by the alert's ``fingerprint``
(the same stable "device + alert type + resource" key HistoryManager already
uses to track one alert across its open lifetime -- see
``HistoryManager._reconcile``), so cooldown/attempts survive this process
restarting but reset naturally once the alert is resolved and a later
occurrence reopens it under a fresh row.
"""
from __future__ import annotations

import logging
import threading
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from pinoc.actions import ActionError
from pinoc.database import utcnow
from pinoc.playbooks import match as match_playbook

LOG = logging.getLogger("pinoc.remediation")
UTC = timezone.utc

# Dispatch failures (device offline, action no longer approved, a conflicting
# job already queued, ...) still count as an attempt against max_attempts --
# an unreachable device must not be retried every tick forever -- but are
# retried sooner than a full cooldown so a transient failure recovers fast.
DISPATCH_RETRY_SECONDS = 60


def now_utc() -> datetime:
    return datetime.now(UTC)


def _as_utc(value: Any) -> datetime:
    dt = value if isinstance(value, datetime) else datetime.fromisoformat(str(value))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


class RemediationService:
    """Owns the ``remediation_runs`` table and drives self-healing playbooks.

    ``actions`` is the shared :class:`pinoc.actions.ActionDispatcher`; every
    run is enqueued through it, so it is indistinguishable in the action-job
    and audit tables from a manual click (it carries
    ``requested_by='remediation'`` for automatic runs, or the deciding
    operator's identity for an approved one, plus a ``fingerprint``/
    ``playbook_id`` parameter).
    """

    def __init__(self, db, actions, state=None, playbooks=None, notifier=None, interval: int = 20) -> None:
        self.db = db
        self.actions = actions
        self.state = state
        self.playbooks = playbooks or []
        self.notifier = notifier
        self.interval = max(5, int(interval))
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self._run, name="pinoc-remediation", daemon=True)

    # -- lifecycle -----------------------------------------------------------
    def start(self) -> None:
        if self.db is not None and self.actions is not None:
            self.thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        self.stop_event.set()
        if self.thread.is_alive():
            self.thread.join(timeout)

    def set_playbooks(self, playbooks) -> None:
        """Swap in a freshly (re)loaded playbook list, e.g. after a config save."""
        self.playbooks = playbooks or []

    # -- reads -----------------------------------------------------------------
    def get(self, fingerprint: str) -> Optional[Dict[str, Any]]:
        rows = self.db.rows("SELECT * FROM remediation_runs WHERE fingerprint=?", (fingerprint,))
        return rows[0] if rows else None

    def list(self, device_id: Optional[str] = None) -> List[Dict[str, Any]]:
        if device_id:
            return self.db.rows("SELECT * FROM remediation_runs WHERE device_id=? ORDER BY updated_at DESC", (device_id,))
        return self.db.rows("SELECT * FROM remediation_runs ORDER BY updated_at DESC")

    def pending_approvals(self) -> List[Dict[str, Any]]:
        return self.db.rows("SELECT * FROM remediation_runs WHERE approval_status='pending' ORDER BY updated_at DESC")

    # -- engine ------------------------------------------------------------
    def _run(self) -> None:
        while not self.stop_event.is_set():
            try:
                self.tick()
            except Exception:
                LOG.exception("remediation tick failed")
            self.stop_event.wait(self.interval)

    def tick(self) -> None:
        if self.db is None or self.actions is None or not self.db.available:
            return
        open_alerts = self.db.rows("SELECT * FROM alerts WHERE resolved_at IS NULL")
        self._reconcile_resolved({a["fingerprint"] for a in open_alerts})
        if not self.playbooks:
            return
        for alert in open_alerts:
            try:
                self._process(alert)
            except Exception:
                LOG.exception("remediation failed for alert %s", alert.get("alert_id"))

    def _reconcile_resolved(self, open_fingerprints) -> None:
        """Reset bookkeeping for any remediation whose alert is no longer open.

        A device that recovers has its alert auto-resolved by
        :class:`pinoc.history.HistoryManager` on the very next poll,
        independent of this service; this only notices that it happened and
        clears attempts/cooldown/any pending approval so the *next*
        occurrence of the same alert type starts fresh.
        """
        rows = self.db.rows("SELECT * FROM remediation_runs WHERE attempts>0 OR approval_status IS NOT NULL")
        now = utcnow()
        for row in rows:
            if row["fingerprint"] in open_fingerprints:
                continue
            if row["approval_status"] == "pending":
                self.actions.audit("remediation", "system", None, row["device_id"], "remediation.cancelled",
                                   row["target"], {"playbook_id": row["playbook_id"], "fingerprint": row["fingerprint"]},
                                   "allowed", "cancelled", error="alert resolved before a decision was made")
            self.db.execute(
                "UPDATE remediation_runs SET attempts=0,cooldown_until=NULL,approval_status=NULL,"
                "decided_by=NULL,decided_at=NULL,last_status='resolved',updated_at=? WHERE fingerprint=?",
                (now, row["fingerprint"]))

    def _process(self, alert: Dict[str, Any]) -> None:
        playbook = match_playbook(self.playbooks, alert.get("alert_type"))
        remediation = (playbook or {}).get("remediation")
        if not remediation:
            return
        fingerprint = alert["fingerprint"]
        row = self._ensure_row(fingerprint, alert, playbook, remediation)
        if row["approval_status"] in ("pending", "denied"):
            return  # awaiting (or already refused) an operator decision
        device = self.state.device(alert["device_id"]) if self.state is not None else None
        if remediation["respect_maintenance"] and device and device.get("maintenance"):
            if row["last_status"] != "deferred_maintenance":
                self.db.execute(
                    "UPDATE remediation_runs SET last_status='deferred_maintenance',updated_at=? WHERE fingerprint=?",
                    (utcnow(), fingerprint))
            return
        now = now_utc()
        if row["cooldown_until"] and _as_utc(row["cooldown_until"]) > now:
            return
        if row["attempts"] >= row["max_attempts"]:
            if row["last_status"] != "attempts_exhausted":
                self.db.execute(
                    "UPDATE remediation_runs SET last_status='attempts_exhausted',updated_at=? WHERE fingerprint=?",
                    (utcnow(), fingerprint))
            return
        if row["policy"] == "auto":
            self._dispatch(row, actor="remediation", role="system")
        else:
            self._request_approval(row)

    def _ensure_row(self, fingerprint: str, alert: Dict[str, Any], playbook: Dict[str, Any],
                     remediation: Dict[str, Any]) -> Dict[str, Any]:
        existing = self.get(fingerprint)
        if existing:
            return existing
        target = remediation.get("target") or self._resource_target(remediation["action"], fingerprint)
        stamp = utcnow()
        self.db.execute(
            "INSERT INTO remediation_runs(fingerprint,device_id,playbook_id,alert_type,action,target,policy,"
            "cooldown_seconds,max_attempts,attempts,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,0,?,?)",
            (fingerprint, alert["device_id"], playbook["id"], alert["alert_type"], remediation["action"], target,
             remediation["policy"], remediation["cooldown_seconds"], remediation["max_attempts"], stamp, stamp))
        return self.get(fingerprint)

    @staticmethod
    def _resource_target(action: str, fingerprint: str) -> Optional[str]:
        """Derive a service-management target from the alert's fingerprint.

        A fingerprint is ``"{device_id}:{alert_type}:{resource}"`` (see
        ``HistoryManager._reconcile``); for a per-service alert (e.g.
        ``service_failed:sshd.service``) that resource *is* the systemd unit
        name, and it is stable for the lifetime of this fingerprint, so it
        only needs to be resolved once, here, rather than re-derived on every
        tick from the (possibly since-changed) alert row.
        """
        if not action.startswith("service."):
            return None
        parts = fingerprint.split(":", 2)
        resource = parts[2] if len(parts) == 3 else ""
        return resource or None

    def _dispatch(self, row: Dict[str, Any], actor: str, role: str,
                  source_ip: Optional[str] = None) -> Dict[str, Any]:
        fingerprint = row["fingerprint"]
        target = row["target"]
        params = {"playbook_id": row["playbook_id"], "fingerprint": fingerprint, "remediation": True}
        try:
            job = self.actions.enqueue(row["action"], row["device_id"], target, actor, role, source_ip, params)
            status = "queued"
        except ActionError as exc:
            job = None
            status = "dispatch_failed"
            # enqueue() only audits on success (ActionDispatcher.validate()
            # raises before anything is written), so a dispatch failure needs
            # its own audit entry -- same pattern as ScheduleService.
            self.actions.audit(actor, role, source_ip, row["device_id"], "remediation.dispatch_failed", target,
                               params, "denied", "failed", error=str(exc))
        stamp = utcnow()
        attempts = int(row["attempts"]) + 1
        cooldown_seconds = row["cooldown_seconds"] if job is not None else min(int(row["cooldown_seconds"]), DISPATCH_RETRY_SECONDS)
        cooldown_until = (now_utc() + timedelta(seconds=cooldown_seconds)).isoformat()
        self.db.execute(
            "UPDATE remediation_runs SET attempts=?,last_attempt_at=?,last_job_id=?,last_status=?,"
            "cooldown_until=?,updated_at=? WHERE fingerprint=?",
            (attempts, stamp, job["job_id"] if job else None, status, cooldown_until, stamp, fingerprint))
        return self.get(fingerprint)

    def _request_approval(self, row: Dict[str, Any]) -> None:
        if row["approval_status"] == "pending":
            return  # already awaiting a decision; do not spam the audit trail every tick
        stamp = utcnow()
        self.db.execute(
            "UPDATE remediation_runs SET approval_status='pending',last_status='pending_approval',"
            "decided_by=NULL,decided_at=NULL,updated_at=? WHERE fingerprint=?", (stamp, row["fingerprint"]))
        self.actions.audit("remediation", "system", None, row["device_id"], "remediation.approval_requested",
                           row["target"], {"playbook_id": row["playbook_id"], "action": row["action"],
                                           "fingerprint": row["fingerprint"]},
                           "allowed", "pending_approval")
        if self.notifier is not None and getattr(self.notifier, "enabled", False):
            try:
                self.notifier.enqueue("open", {
                    "severity": "warning", "alert_type": "remediation_pending_approval",
                    "message": f"Remediation {row['action']} on {row['device_id']} needs approval",
                    "device_id": row["device_id"],
                })
            except Exception:  # noqa: BLE001 - a notification failure must not break the tick
                LOG.exception("remediation approval notification failed")

    # -- operator decision ---------------------------------------------------
    def decide(self, fingerprint: str, approve: bool, actor: str, role: str = "administrator",
              source_ip: Optional[str] = None) -> Dict[str, Any]:
        """Approve or deny a pending remediation; approval reuses ``_dispatch``.

        Cooldown and the attempts cap are already what gated *offering* this
        approval in the first place (see ``_process``); once an operator has
        made the call, that decision is not second-guessed here.
        """
        row = self.get(fingerprint)
        if row is None or row["approval_status"] != "pending":
            raise ValueError("no pending remediation approval for this alert")
        if not approve:
            stamp = utcnow()
            self.db.execute(
                "UPDATE remediation_runs SET approval_status='denied',last_status='denied',decided_by=?,"
                "decided_at=?,updated_at=? WHERE fingerprint=?", (actor, stamp, stamp, fingerprint))
            self.actions.audit(actor, role, source_ip, row["device_id"], "remediation.denied", row["target"],
                               {"playbook_id": row["playbook_id"], "action": row["action"]}, "allowed", "denied")
            return self.get(fingerprint)
        updated = self._dispatch(row, actor=actor, role=role, source_ip=source_ip)
        self.db.execute(
            "UPDATE remediation_runs SET approval_status='approved',decided_by=?,decided_at=? WHERE fingerprint=?",
            (actor, utcnow(), fingerprint))
        self.actions.audit(actor, role, source_ip, row["device_id"], "remediation.approved", row["target"],
                           {"playbook_id": row["playbook_id"], "action": row["action"], "job_id": updated.get("last_job_id")},
                           "allowed", "queued")
        return self.get(fingerprint)
