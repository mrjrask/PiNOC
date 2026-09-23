"""User-defined HTTP/TCP health probes for arbitrary services.

A device may declare any number of read-only checks (``integrations.probe``)
that run *from the PiNOC host* on their own intervals.  Results are normalized
into an :class:`IntegrationStatus` whose ``conditions`` feed the durable alert
engine, so a failed probe opens a first-class alert with the same lifecycle as
every other condition.  Probes never execute remote commands, never follow
user input, and only speak HTTP(S) or raw TCP to explicitly configured
targets on a trusted network.
"""
from __future__ import annotations

import re
import ssl
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

CHECK_KINDS = ("http_get", "http_head", "tcp", "tls_cert")
MAX_CHECKS = 20
MAX_PATTERN = 500
MIN_TIMEOUT = 0.5
MAX_TIMEOUT = 60.0
MIN_INTERVAL = 5.0
MAX_INTERVAL = 86400.0
DEFAULT_TIMEOUT = 5.0
DEFAULT_INTERVAL = 60.0
# A result older than this many intervals is considered stale and failing.
STALE_INTERVALS = 4.0
# tls_cert's 30/7/1-day expiry ladder: severity escalates as the
# certificate's expiry approaches, exactly like a probe check's own
# warning/critical severity except this one is fixed rather than
# per-check-configurable, since it names a specific, well-known cadence.
CERT_NOTICE_DAYS = 30.0
CERT_WARNING_DAYS = 7.0
CERT_CRITICAL_DAYS = 1.0

_NAME = re.compile(r"[A-Za-z0-9_.-]{1,64}\Z")
_HTTP_METHODS = {"http_get": "GET", "http_head": "HEAD"}


class ProbeConfigError(ValueError):
    """A probe check failed validation."""


def _number(raw: Any, label: str, default: float) -> float:
    try:
        return float(raw if raw is not None else default)
    except (TypeError, ValueError):
        raise ProbeConfigError(f"{label} must be a number") from None


def validate_check(raw: Any, index: int = 0) -> Dict[str, Any]:
    """Validate and normalize one probe check entry."""
    if not isinstance(raw, dict):
        raise ProbeConfigError(f"probe check #{index + 1}: entry must be an object")
    label = f"probe check #{index + 1} {raw.get('name') or ''}".strip()
    name = str(raw.get("name") or "").strip()
    if not _NAME.fullmatch(name):
        raise ProbeConfigError(
            f"probe check #{index + 1}: name is required (1-64 letters, digits, '.', '_', '-')")
    label = f"probe check {name}"
    kind = str(raw.get("kind", "http_get")).lower()
    if kind not in CHECK_KINDS:
        raise ProbeConfigError(f"{label}: kind must be one of {', '.join(CHECK_KINDS)}")
    timeout = _number(raw.get("timeout_seconds"), f"{label}: timeout_seconds", DEFAULT_TIMEOUT)
    if not MIN_TIMEOUT <= timeout <= MAX_TIMEOUT:
        raise ProbeConfigError(f"{label}: timeout_seconds must be between {MIN_TIMEOUT} and {MAX_TIMEOUT}")
    interval = _number(raw.get("interval_seconds"), f"{label}: interval_seconds", DEFAULT_INTERVAL)
    if not MIN_INTERVAL <= interval <= MAX_INTERVAL:
        raise ProbeConfigError(f"{label}: interval_seconds must be between {MIN_INTERVAL} and {MAX_INTERVAL}")
    severity = "critical" if raw.get("critical", False) else "warning"
    if severity not in ("warning", "critical"):
        raise ProbeConfigError(f"{label}: severity must be warning or critical")
    check: Dict[str, Any] = {
        "name": name, "kind": kind, "timeout_seconds": timeout, "interval_seconds": interval,
        "severity": severity, "enabled": bool(raw.get("enabled", True)),
    }
    if kind in ("tcp", "tls_cert"):
        host = str(raw.get("host") or "").strip()
        if not host or len(host) > 253:
            raise ProbeConfigError(f"{label}: host is required for {kind} checks")
        try:
            port = int(raw.get("port"))
        except (TypeError, ValueError):
            raise ProbeConfigError(f"{label}: port must be an integer for {kind} checks") from None
        if not 1 <= port <= 65535:
            raise ProbeConfigError(f"{label}: port must be between 1 and 65535")
        check.update(host=host, port=port)
        return check
    url = str(raw.get("url") or "").strip()
    try:
        parsed = urllib.parse.urlsplit(url)
    except ValueError:
        raise ProbeConfigError(f"{label}: url is not valid") from None
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ProbeConfigError(f"{label}: url must be an absolute http(s) URL")
    if parsed.username is not None or parsed.password is not None:
        raise ProbeConfigError(f"{label}: credentials are not allowed in probe URLs")
    check["url"] = url
    expected = raw.get("expected_status", 200)
    if isinstance(expected, (list, tuple)):
        statuses = list(expected)
    else:
        statuses = [expected]
    for status in statuses:
        try:
            status = int(status)
        except (TypeError, ValueError):
            raise ProbeConfigError(f"{label}: expected_status must be an integer") from None
        if not 100 <= status <= 599:
            raise ProbeConfigError(f"{label}: expected_status must be between 100 and 599")
    check["expected_status"] = statuses
    pattern = str(raw.get("pattern") or "").strip()
    if pattern:
        if len(pattern) > MAX_PATTERN:
            raise ProbeConfigError(f"{label}: pattern must be at most {MAX_PATTERN} characters")
        try:
            compiled = re.compile(pattern)
        except re.error:
            raise ProbeConfigError(f"{label}: pattern is not a valid regular expression") from None
        check["pattern"] = pattern
        check["_pattern"] = compiled
    check["allow_insecure_tls"] = bool(raw.get("allow_insecure_tls", False))
    check["timeout_seconds"] = timeout
    return check


def validate_probes(device_label: str, value: Any) -> Dict[str, Any]:
    """Validate the whole ``integrations.probe`` configuration object."""
    if not isinstance(value, dict):
        raise ProbeConfigError(f"device {device_label}: probe must be an object with a checks list")
    checks_raw = value.get("checks", [])
    if not isinstance(checks_raw, list):
        raise ProbeConfigError(f"device {device_label}: probe.checks must be a list")
    if len(checks_raw) > MAX_CHECKS:
        raise ProbeConfigError(f"device {device_label}: at most {MAX_CHECKS} probe checks are allowed")
    checks = [validate_check(item, index) for index, item in enumerate(checks_raw)]
    names = [check["name"] for check in checks]
    if len(names) != len(set(names)):
        raise ProbeConfigError(f"device {device_label}: probe check names must be unique")
    probes = dict(value)
    probes["checks"] = checks
    return probes


def _default_cert_fetcher(host: str, port: int, timeout: float) -> Dict[str, Any]:
    """Connect, complete a TLS handshake, and return the peer certificate
    dict (``ssl.SSLSocket.getpeercert()``'s shape, e.g. a ``notAfter``
    string). No certificate data is retained beyond this one call."""
    context = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as raw_socket:
        with context.wrap_socket(raw_socket, server_hostname=host) as tls_socket:
            return tls_socket.getpeercert() or {}


def run_check(
    check: Dict[str, Any],
    opener: Optional[Callable] = None,
    connector: Optional[Callable] = None,
    clock: Optional[Callable[[], float]] = None,
    now: Optional[str] = None,
    cert_fetcher: Optional[Callable[[str, int, float], Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Execute one check and return a normalized result.

    ``opener`` and ``connector`` are injectable for tests; the defaults use
    ``urllib`` and ``socket``. ``cert_fetcher`` is the ``tls_cert`` kind's
    equivalent injection point. No shell, no subprocess, no code execution.
    """
    from pinoc.database import utcnow

    started = (clock or time.monotonic)()
    result: Dict[str, Any] = {"name": check["name"], "kind": check["kind"],
                              "ok": False, "status": None, "latency_ms": None, "error": None,
                              "checked_at": now or utcnow()}
    if check["kind"] == "tcp":
        open_connection = connector or socket.create_connection
        try:
            handle = open_connection((check["host"], check["port"]), timeout=check["timeout_seconds"])
            handle.close()
        except (OSError, ValueError) as exc:
            result["error"] = f"connection to {check['host']}:{check['port']} failed: {exc.__class__.__name__}"
        else:
            result["ok"] = True
            result["status"] = "reachable"
    elif check["kind"] == "tls_cert":
        fetch_cert = cert_fetcher or _default_cert_fetcher
        try:
            cert = fetch_cert(check["host"], check["port"], check["timeout_seconds"])
            not_after = cert.get("notAfter") if isinstance(cert, dict) else None
            if not not_after:
                raise ValueError("certificate carried no notAfter field")
            expires_epoch = ssl.cert_time_to_seconds(not_after)
            expires_at = datetime.fromtimestamp(expires_epoch, timezone.utc)
            days_remaining = (expires_at - datetime.now(timezone.utc)).total_seconds() / 86400.0
            result["status"] = "valid"
            result["days_remaining"] = round(days_remaining, 2)
            result["expires_at"] = expires_at.isoformat()
            result["ok"] = days_remaining > CERT_NOTICE_DAYS
            if not result["ok"]:
                result["error"] = (f"certificate for {check['host']}:{check['port']} "
                                   f"expires in {days_remaining:.1f} day(s)")
        except (OSError, ValueError, ssl.SSLError) as exc:
            result["error"] = f"certificate check for {check['host']}:{check['port']} failed: {exc.__class__.__name__}: {exc}"
    else:
        request = urllib.request.Request(check["url"], method=_HTTP_METHODS[check["kind"]],
                                         headers={"User-Agent": "PiNOC-Probe/2.0",
                                                  "Accept": "*/*"})
        context = None
        if check["url"].startswith("https:") and check.get("allow_insecure_tls"):
            context = ssl._create_unverified_context()  # noqa: S323 - explicit operator opt-in
        open_request = opener or (lambda req, timeout: urllib.request.urlopen(req, timeout=timeout, context=context))
        try:
            response = open_request(request, timeout=check["timeout_seconds"])
        except urllib.error.HTTPError as exc:
            status = exc.code
            body = ""
            try:
                body = exc.read(8192).decode("utf-8", "replace")
            except (OSError, ValueError):
                pass
            result["status"] = status
            if status in check["expected_status"]:
                result["ok"] = _pattern_matches(check, body, result)
            else:
                result["error"] = f"unexpected status {status} (expected {check['expected_status']})"
        except (OSError, ValueError) as exc:
            result["error"] = f"request failed: {exc.__class__.__name__}"
        else:
            status = response.status
            result["status"] = status
            body = ""
            if check["kind"] == "http_get":
                try:
                    body = response.read(65536).decode("utf-8", "replace")
                except (OSError, ValueError):
                    body = ""
            if status in check["expected_status"]:
                result["ok"] = _pattern_matches(check, body, result)
            else:
                result["error"] = f"unexpected status {status} (expected {check['expected_status']})"
            response.close()
    elapsed = ((clock or time.monotonic)() - started) * 1000.0
    result["latency_ms"] = round(elapsed, 1)
    return result


def _pattern_matches(check: Dict[str, Any], body: str, result: Dict[str, Any]) -> bool:
    pattern = check.get("_pattern")
    if pattern is None:
        return True
    if not pattern.search(body or ""):
        result["error"] = "response did not match expected pattern"
        return False
    return True


def normalize(
    probes: Dict[str, Any],
    results: List[Dict[str, Any]],
    now: Optional[str] = None,
) -> Dict[str, Any]:
    """Build the probe ``IntegrationStatus`` from the latest results.

    Stale results (no successful run within ``STALE_INTERVALS`` intervals) are
    treated as failing so a stopped collector degrades the check instead of
    silently showing it green.
    """
    from pinoc.database import utcnow
    from .base import IntegrationStatus

    now = now or utcnow()
    now_stamp = _parse(now)
    checks = probes.get("checks", [])
    by_name = {result["name"]: result for result in results}
    normalized_checks: List[Dict[str, Any]] = []
    latencies: List[float] = []
    failing: List[Dict[str, Any]] = []
    cert_items: List[Dict[str, Any]] = []
    for check in checks:
        result = dict(by_name.get(check["name"], {"name": check["name"], "kind": check["kind"],
                                                  "ok": False, "status": None,
                                                  "latency_ms": None, "error": "no result yet"}))
        checked_at = result.get("checked_at")
        interval = float(check.get("interval_seconds", DEFAULT_INTERVAL))
        age = _age_seconds(checked_at, now_stamp) if result.get("ok") else None
        if age is not None and age > interval * STALE_INTERVALS:
            result = {**result, "ok": False,
                      "error": f"result stale ({int(age)}s without a successful run)"}
        # tls_cert checks get their own 30/7/1-day severity ladder below
        # (cert_expiry) instead of the generic probe_failed bucket, so a
        # slowly-approaching expiry reads as its own explainable alert
        # rather than an opaque "probe check failing".
        if check.get("kind") == "tls_cert":
            cert_items.append({"check": check, "result": result})
        elif not result.get("ok"):
            failing.append({"check": check, "result": result})
        latency = result.get("latency_ms")
        if latency is not None:
            latencies.append(float(latency))
        normalized_checks.append({key: result.get(key) for key in
                                  ("name", "kind", "url", "host", "port", "ok", "status",
                                   "latency_ms", "error", "checked_at", "days_remaining", "expires_at")})
    # The alert engine treats the condition type as a stable class, so all
    # failing checks on a device collapse into one explainable condition that
    # names every offender; the fingerprint stays one alert per device.
    conditions: List[Dict[str, Any]] = []
    if failing:
        severity = "critical" if any(item["check"].get("severity", "warning") == "critical"
                                     for item in failing) else "warning"
        details = "; ".join(
            f"'{item['check']['name']}' ({item['check']['kind']}): {item['result'].get('error') or 'unknown error'}"
            for item in failing)
        conditions.append({
            "type": "probe_failed",
            "severity": severity,
            "message": f"{len(failing)} probe check(s) failing: {details}"[:500],
        })
    cert_failed = 0
    cert_bands: List[tuple] = []
    for item in cert_items:
        days = item["result"].get("days_remaining")
        error = item["result"].get("error")
        if not item["result"].get("ok"):
            cert_failed += 1
        if days is None:
            if error:
                cert_bands.append(("critical", item, None))
            continue
        if days <= CERT_CRITICAL_DAYS:
            band = "critical"
        elif days <= CERT_WARNING_DAYS:
            band = "warning"
        elif days <= CERT_NOTICE_DAYS:
            band = "info"
        else:
            continue
        cert_bands.append((band, item, days))
    if cert_bands:
        rank = {"info": 0, "warning": 1, "critical": 2}
        severity = max(cert_bands, key=lambda entry: rank[entry[0]])[0]
        details = "; ".join(
            f"'{item['check']['name']}' ({item['check'].get('host')}:{item['check'].get('port')}) " +
            (f"expires in {days:.1f} day(s)" if days is not None else
             (item["result"].get("error") or "certificate check failed"))
            for _band, item, days in cert_bands)
        conditions.append({
            "type": "cert_expiry",
            "severity": severity,
            "message": f"{len(cert_bands)} certificate(s) nearing expiry: {details}"[:500],
        })
    failed = len(failing) + cert_failed
    data = {
        "checks": normalized_checks,
        "checks_total": len(checks),
        "failed_checks": failed,
        "response_latency_ms": round(sum(latencies) / len(latencies), 1) if latencies else None,
    }
    status = IntegrationStatus(
        name="probe",
        enabled=bool(checks),
        available=bool(checks),
        health="critical" if any(condition["severity"] == "critical" for condition in conditions)
        else "warning" if conditions
        else ("healthy" if checks else "unsupported"),
        last_success=None if conditions else now,
        last_attempt=now,
        data_source="probe",
        error=f"{failed} of {len(checks)} probe checks failing" if failed else None,
        data=data,
        critical=bool(probes.get("critical", False)),
    )
    value = status.to_dict()
    # ``conditions`` carries the alert engine contract; keep it in the published
    # status so the history writer can see it, but it is internal.
    value["conditions"] = conditions
    return value


def _parse(stamp: str):
    from datetime import datetime, timezone

    try:
        return datetime.fromisoformat(stamp.replace("Z", "+00:00"))
    except (ValueError, AttributeError, TypeError):
        return None


def _age_seconds(checked_at: Optional[str], now_stamp) -> Optional[float]:
    from datetime import timezone

    stamp = _parse(checked_at) if isinstance(checked_at, str) else None
    if stamp is None or now_stamp is None:
        return None
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=timezone.utc)
    if now_stamp.tzinfo is None:
        now_stamp = now_stamp.replace(tzinfo=timezone.utc)
    return (now_stamp - stamp).total_seconds()
