"""Outbound notification channels for alert open/resolve transitions.

Config section: {"enabled": bool, "open_severities": [...], "resolve_severities": [...],
"queue_size": int, "channels": [{"id", "kind": ntfy|smtp|webhook, "enabled", ...}]}

Delivery is queued and performed on a single daemon worker so alert
reconciliation (and the web request path) never blocks on a remote
endpoint.  ``sender`` is injectable for tests; channel credentials in
config.json are protected by the 0600 file mode and the redacting settings
API.
"""
from __future__ import annotations

import json
import logging
import queue
import smtplib
import threading
from email.message import EmailMessage
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import quote
from urllib.request import Request, urlopen

LOG = logging.getLogger("pinoc.notifications")

SEVERITIES = ("info", "warning", "degraded", "critical")
KINDS = ("ntfy", "smtp", "webhook")
NTFY_PRIORITIES = {"critical": "high", "degraded": "default"}
_RECENT_LIMIT = 20


class NotificationService:
    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None,
        state: Any = None,
        sender: Optional[Callable[[str, Dict[str, Any], Dict[str, Any]], Any]] = None,
        timeout: float = 10.0,
    ):
        self.config = config or {}
        self.state = state
        self.sender = sender
        self.timeout = timeout
        self.enabled = bool(self.config.get("enabled"))
        self.open_severities = set(self.config.get("open_severities") or [])
        self.resolve_severities = set(self.config.get("resolve_severities") or [])
        self.queue: "queue.Queue[Dict[str, Any]]" = queue.Queue(
            maxsize=max(1, int(self.config.get("queue_size", 200))))
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self._run, name="pinoc-notifications", daemon=True)
        self.lock = threading.Lock()
        self.dropped = 0
        self._channels = [dict(c) for c in (self.config.get("channels") or []) if isinstance(c, dict)]
        self._status = {
            c.get("id") or id(c): {"id": c.get("id"), "kind": c.get("kind"), "enabled": bool(c.get("enabled", True)),
                     "sent": 0, "failed": 0, "last_success": None, "last_error": None, "recent": []}
            for c in self._channels
        }

    # -- lifecycle ------------------------------------------------------
    def start(self) -> None:
        if self.enabled and self._channels:
            self.thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        self.stop_event.set()
        if self.thread.is_alive():
            self.thread.join(timeout)

    # -- enqueueing (called from the history worker) ---------------------
    def enqueue(self, transition: str, alert: Dict[str, Any], device_name: Optional[str] = None) -> None:
        if transition not in ("open", "resolve", "test"):
            return
        if not self.enabled or self.stop_event.is_set():
            return
        message = self._message(transition, alert, device_name)
        if message is None:
            return
        try:
            self.queue.put_nowait(message)
        except queue.Full:
            self.dropped += 1
            LOG.warning("notification queue full; dropped %s for %s", transition, device_name)

    def _message(self, transition: str, alert: Dict[str, Any], device_name: Optional[str]) -> Optional[Dict[str, Any]]:
        severity = alert.get("severity") or "info"
        if transition == "open" and self.open_severities and severity not in self.open_severities:
            return None
        if transition == "resolve" and self.resolve_severities and severity not in self.resolve_severities:
            return None
        device_name = device_name or alert.get("friendly_name") or alert.get("hostname") or alert.get("device_id") or "device"
        alert_type = alert.get("alert_type") or "alert"
        subject = f"PiNOC {transition}: {device_name} — {alert_type}"
        if transition == "resolve":
            subject = f"PiNOC resolved: {device_name} — {alert_type}"
        body = f"{device_name}: {alert.get('message') or alert_type}"
        return {
            "transition": transition,
            "device_id": alert.get("device_id"),
            "device_name": device_name,
            "alert_type": alert_type,
            "severity": severity,
            "subject": subject,
            "body": body,
        }

    # -- worker ----------------------------------------------------------
    def _run(self) -> None:
        while not self.stop_event.is_set() or not self.queue.empty():
            try:
                message = self.queue.get(timeout=0.25)
            except queue.Empty:
                continue
            try:
                for channel in self._channels:
                    if not channel.get("enabled", True):
                        continue
                    ok, error = self._send(channel, message)
                    self._record(channel, message, ok, error)
            finally:
                self.queue.task_done()

    def _send(self, channel: Dict[str, Any], message: Dict[str, Any]) -> "tuple[bool, Optional[str]]":
        try:
            if self.sender is not None:
                result = self.sender(channel.get("kind"), channel, message)
                ok, error = self._coerce(result)
            elif channel.get("kind") == "ntfy":
                ok, error = self._send_ntfy(channel, message)
            elif channel.get("kind") == "smtp":
                ok, error = self._send_smtp(channel, message)
            elif channel.get("kind") == "webhook":
                ok, error = self._send_webhook(channel, message)
            else:
                ok, error = False, f"unknown channel kind {channel.get('kind')!r}"
            return ok, error
        except Exception as exc:  # one failing channel must not kill the worker
            LOG.warning("notification to %s failed: %s", channel.get("id"), exc)
            return False, str(exc)

    @staticmethod
    def _coerce(result: Any) -> "tuple[bool, Optional[str]]":
        if isinstance(result, tuple) and len(result) == 2:
            return bool(result[0]), (None if result[0] else str(result[1]))
        if isinstance(result, bool):
            return result, None
        return False, "invalid sender result"

    def _send_ntfy(self, channel: Dict[str, Any], message: Dict[str, Any]) -> "tuple[bool, Optional[str]]":
        url = f"{str(channel.get('url', '')).rstrip('/')}/{quote(str(channel['topic']))}"
        # HTTP headers are latin-1; keep Unicode-only to the message body.
        headers = {"Content-Type": "text/plain", "X-Title": _ascii_header(message["subject"][:512])}
        if message["severity"] in NTFY_PRIORITIES:
            headers["X-Priority"] = NTFY_PRIORITIES[message["severity"]]
        tags = channel.get("tags")
        if isinstance(tags, list) and tags:
            headers["X-Tags"] = _ascii_header(",".join(str(t) for t in tags))
        req = Request(url, data=message["body"].encode("utf-8"), headers=headers, method="POST")
        with urlopen(req, timeout=self.timeout) as response:
            if response.status >= 400:
                return False, f"ntfy HTTP {response.status}"
        return True, None

    def _send_smtp(self, channel: Dict[str, Any], message: Dict[str, Any]) -> "tuple[bool, Optional[str]]":
        email = EmailMessage()
        email["Subject"] = message["subject"]
        email["From"] = channel.get("from") or channel.get("username") or "pinoc"
        email["To"] = ", ".join(channel.get("to") or [])
        email.set_content(message["body"])
        with smtplib.SMTP(channel["host"], int(channel.get("port") or 25), timeout=self.timeout) as client:
            if channel.get("starttls"):
                client.starttls()
            if channel.get("username"):
                client.login(channel["username"], channel.get("password") or "")
            client.send_message(email)
        return True, None

    def _send_webhook(self, channel: Dict[str, Any], message: Dict[str, Any]) -> "tuple[bool, Optional[str]]":
        payload = {
            "source": "pinoc",
            "transition": message["transition"],
            "device_id": message["device_id"],
            "device_name": message["device_name"],
            "alert_type": message["alert_type"],
            "severity": message["severity"],
            "subject": message["subject"],
            "body": message["body"],
        }
        req = Request(channel["url"], data=json.dumps(payload).encode("utf-8"),
                      headers={"Content-Type": "application/json", "User-Agent": "pinoc-notifications"}, method="POST")
        with urlopen(req, timeout=self.timeout) as response:
            if response.status >= 400:
                return False, f"webhook HTTP {response.status}"
        return True, None

    def _record(self, channel: Dict[str, Any], message: Dict[str, Any], ok: bool, error: Optional[str]) -> None:
        stamp = _now_iso()
        with self.lock:
            status = self._status.get(channel.get("id")) or self._status.get(id(channel))
            if status is None:
                return
            if ok:
                status["sent"] += 1
                status["last_success"] = stamp
                status["last_error"] = None
            else:
                status["failed"] += 1
                status["last_error"] = error
            status["recent"].append({"time": stamp, "transition": message["transition"],
                                      "alert_type": message["alert_type"], "device": message["device_name"],
                                      "ok": ok, "error": error})
            status["recent"] = status["recent"][-_RECENT_LIMIT:]

    # -- introspection / manual tests -------------------------------------
    def status(self) -> Dict[str, Any]:
        with self.lock:
            return {
                "enabled": self.enabled,
                "open_severities": sorted(self.open_severities),
                "resolve_severities": sorted(self.resolve_severities),
                "queued": self.queue.qsize(),
                "dropped": self.dropped,
                "channels": [dict(s, recent=list(s["recent"])) for s in self._status.values()],
            }

    def test_channel(self, channel_id: str) -> Optional[Dict[str, Any]]:
        """Send one test message to a single channel, synchronously."""
        channel = next((c for c in self._channels if c.get("id") == channel_id), None)
        if channel is None:
            return None
        message = self._message("test", {"device_id": None, "device_name": channel_id,
                                          "alert_type": "notification_test", "severity": "info",
                                          "message": "Test message from PiNOC"}, channel_id)
        ok, error = self._send(channel, message)
        self._record(channel, message, ok, error)
        return {"ok": ok, "error": error, "channel": channel_id}

    def channels(self) -> List[Dict[str, Any]]:
        return [dict(c) for c in self._channels]


def _now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


def _ascii_header(value: str) -> str:
    return value.encode("ascii", "replace").decode()
