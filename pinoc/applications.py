"""Application model (PiNOC 2.0 Phase 1, P1-R02).

An *application* is the logical software capability an operator actually
thinks in ("is the desk display working?"), and an *instance* binds one
application to a device plus its implementation (a systemd unit, a PM2
app, a container, or a plain process). One application may run on several
devices at once; each instance keeps fully independent state, so a
redundant pair shows one healthy and one degraded instead of blurring
into a single averaged answer.

Design notes (spec section P1-R02):

* Health checks execute through **registered strategies only**. The API
  accepts a strategy *name* plus a small closed set of parameters (unit
  name, http(s) URL, host/port, command *template* name, integration
  name). It can never carry an arbitrary shell command from the browser --
  ``command`` strategies reference templates defined in the operator's
  config file, which is the trust boundary.
* Every strategy yields one canonical state from :mod:`pinoc.envstates`
  plus reason codes, and is either *conclusive* (it observed something
  real -- healthy, a real failure, or an offline host) or *inconclusive*
  (the host/tool was not reachable, so nothing was learned). An
  inconclusive result never erases the last success: the instance simply
  ages under its freshness floor (healthy -> stale after the TTL, per the
  phase-wide observation contract).
* The poll thread (not request threads) runs the checks on
  ``applications.poll_seconds`` cadence, persists a bounded health
  snapshot per instance per tick (HistoryManager prunes it), emits a
  durable event on every state transition, and re-rolls the application
  state from its instances under the application's criticality policy --
  so a running process never masks a critical stale member inside a
  ``composite`` strategy, and a stopped *critical* unit degrades its
  instance.
* Application metadata (strategy config, endpoints, owner) is not a
  secret store: URLs may contain credentials for real endpoints, so every
  API output passes through the security layer's recursive ``redact()``
  before it leaves the process, and every policy change is audited.

The fleet collector's due-gated ``__APPS__`` section re-reports each
device's implementations on a low-frequency cycle (the collector refreshes
the spec map from :meth:`ApplicationService.device_app_specs` once per
collect()); its results land in ``DeviceState.app_checks`` and feed the
``process`` strategy, while ``systemd`` implementations also ride along in
the rich ``__SERVICES__`` path the ``service`` strategy reads.

This module also registers the ``application`` membership kind with the
P1-R01 project registry (:mod:`pinoc.projects`): an application's stored
health contributes to its project's rollup through the same source
mechanism devices use, and the full non-archived roster feeds the
unassigned-inventory view.
"""
from __future__ import annotations

import json
import logging
import re
import socket
import subprocess
import threading
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from pinoc import projects
from pinoc.database import Database, utcnow
from pinoc.envstates import (
    CRITICALITIES,
    RANK,
    age_seconds,
    escalate,
    fresh_state,
    format_duration,
    normalize_state,
    reason_code,
    rollup as _env_rollup,
    worst,
)

LOG = logging.getLogger("pinoc.applications")
UTC = timezone.utc

LIFECYCLES = ("planned", "active", "maintenance", "retired", "archived")
MECHANISMS = ("systemd", "pm2", "container", "process")
# Where an application's version string is believed to come from. Free
# display metadata (shown next to the app, never parsed) -- tracked
# independently of the host OS version, per the spec.
VERSION_SOURCES = ("manual", "git_tag", "git_branch", "package", "systemd", "container", "process")

# Synthetic device_id for app-level events (an app with no instances) --
# never a real fleet device, so it can't collide with one (the same pattern
# pinoc.slo.SLO_DEVICE_ID uses).
APPLICATION_DEVICE_ID = "pinoc-applications"

# Event severities for state transitions (HistoryManager's scale).
_SEVERITY = {
    "healthy": "info", "maintenance": "info", "unknown": "info",
    "stale": "warning", "warning": "warning", "degraded": "degraded",
    "offline": "critical", "critical": "critical",
}

# Bounds -- metadata is capped like every other registry in PiNOC.
MAX_NAME = 200
MAX_DESCRIPTION = 2000
MAX_VERSION = 200
MAX_REPOSITORY = 512
MAX_TARGET = 128
MAX_TAGS = 50
MAX_TAG_LEN = 100
MAX_ENDPOINTS = 50
MAX_ENDPOINT_LEN = 512
MAX_OWNER = 100
MAX_INSTANCES = 100
MAX_COMPOSITE_CHILDREN = 20
MAX_SNAPSHOTS = 50
MAX_STRATEGY_CHILDREN = 20

_SLUG_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?")
# Repository addresses accept explicit URLs (http, https, git, ssh) and the
# scp-style syntax git users actually type (user@host:path).
_REPOSITORY_RE = re.compile(r"(?:https?|git|ssh)://[^\s]{1,512}"
                           r"|[A-Za-z0-9._-]+@[A-Za-z0-9._-]+:[A-Za-z0-9._~/-]{1,256}")
_URL_RE = re.compile(r"https?://[^\s]{1,512}")
_HOSTPORT_RE = re.compile(r"[A-Za-z0-9._-]{1,253}:[0-9]{1,5}")
_TEMPLATE_NAME_RE = re.compile(r"[A-Za-z0-9._-]{1,64}")


class ApplicationError(ValueError):
    """Validation or lifecycle error; routes map it to 400/404/409."""


class ApplicationNotFound(ApplicationError):
    pass


# -- health strategy registry -------------------------------------------------
#
# A strategy is a *named* function of
# (service, app, instance, device, now) -> {"state", "conclusive",
# "reasons"}: exactly one canonical state plus human-readable reasons.
# `conclusive` is False when the check could not observe anything (host
# unreachable, tool missing, transport failure) -- those results age the
# instance under its freshness floor instead of moving it.
StrategyFn = Callable[["ApplicationService", Dict[str, Any], Dict[str, Any],
                       Optional[Dict[str, Any]], datetime], Dict[str, Any]]

_STRATEGIES: Dict[str, StrategyFn] = {}


def register_health_strategy(name: str, fn: StrategyFn) -> None:
    """Register a health strategy by name (built-ins register at import;
    integrations or operators can extend the set without touching this
    module's math)."""
    if not _TEMPLATE_NAME_RE.fullmatch(str(name)):
        raise ValueError(f"invalid strategy name: {name!r}")
    _STRATEGIES[str(name)] = fn


def strategy_names() -> List[str]:
    return sorted(_STRATEGIES)


def _device_name(device: Optional[Dict[str, Any]]) -> str:
    return str((device or {}).get("friendly_name") or (device or {}).get("hostname") or (device or {}).get("id") or "?")


def _meaningful_transition(previous: str, state: str) -> bool:
    """A stored state change worth a durable event. The first *quiet*
    observation of a never-checked object (unknown -> healthy/maintenance)
    is not one -- a fleet of new applications would otherwise page its way
    into existence at startup; any move out of unknown to a non-quiet state
    is a real signal, and so is any later change."""
    if previous == state:
        return False
    if previous == "unknown" and state in ("unknown", "healthy", "maintenance"):
        return False
    return True


def _offline_result(instance: Dict[str, Any]) -> Dict[str, Any]:
    return {"state": "offline", "conclusive": True,
            "reasons": [f"device {_device_name(instance.get('_device'))} is offline"]}


def _inconclusive(reason: str) -> Dict[str, Any]:
    return {"state": "unknown", "conclusive": False, "reasons": [reason]}


def _stopped_state(instance: Dict[str, Any]) -> str:
    """A stopped/failed implementation: the instance's own critical flag
    sets the floor (a *critical* unit that is down degrades its instance),
    and the application's criticality policy escalates it again in the
    rollup (see pinoc.envstates.escalate)."""
    return "degraded" if instance.get("critical") else "warning"


def _failed_state(instance: Dict[str, Any]) -> str:
    return "critical" if instance.get("critical") else "degraded"


def _strategy_service(service: "ApplicationService", app: Dict[str, Any],
                      instance: Dict[str, Any], device: Optional[Dict[str, Any]], now: datetime) -> Dict[str, Any]:
    """systemd unit state from the collector's rich __SERVICES__ path."""
    if device is None:
        return _inconclusive(f"no state for device {instance['device_id']!r}")
    if not device.get("online"):
        return _offline_result(instance)
    unit = str((instance.get("strategy") or {}).get("unit") or instance.get("target") or "")
    if not unit:
        return _inconclusive("no systemd unit configured for this instance")
    found = next((s for s in device.get("services") or [] if s.get("name") == unit), None)
    if found is None:
        return _inconclusive(f"unit {unit!r} not reported by the host")
    state = str(found.get("state") or "unknown")
    if state in ("running", "activating"):
        return {"state": "healthy", "conclusive": True, "reasons": []}
    if state == "failed":
        return {"state": _failed_state(instance), "conclusive": True,
                "reasons": [f"unit {unit} is failed"]}
    if state in ("stopped", "deactivating", "inactive"):
        return {"state": _stopped_state(instance), "conclusive": True,
                "reasons": [f"unit {unit} is {state}"]}
    return _inconclusive(f"unit {unit} state {state!r} not interpreted")


def _strategy_process(service: "ApplicationService", app: Dict[str, Any],
                      instance: Dict[str, Any], device: Optional[Dict[str, Any]], now: datetime) -> Dict[str, Any]:
    """Plain-process state from the collector's due-gated __APPS__ section
    (DeviceState.app_checks): pm2 pid, docker container state, or pgrep --
    one simple status line per requested implementation."""
    if device is None:
        return _inconclusive(f"no state for device {instance['device_id']!r}")
    if not device.get("online"):
        return _offline_result(instance)
    params = instance.get("strategy") or {}
    name = str(params.get("name") or instance.get("target") or "")
    kind = str(params.get("kind") or instance.get("mechanism") or "process")
    if not name:
        return _inconclusive("no process name configured for this instance")
    found = next((c for c in device.get("app_checks") or []
                  if c.get("name") == name and c.get("kind") == kind), None)
    if found is None:
        return _inconclusive(f"host reported no {kind} check for {name!r}")
    status = str(found.get("status") or "unknown").lower()
    if status == "running":
        return {"state": "healthy", "conclusive": True, "reasons": []}
    if status == "stopped":
        return {"state": _stopped_state(instance), "conclusive": True,
                "reasons": [f"{kind} {name!r} is stopped"]}
    return _inconclusive(f"{kind} {name!r} status {status!r} not interpretable")


def _strategy_http(service: "ApplicationService", app: Dict[str, Any],
                   instance: Dict[str, Any], device: Optional[Dict[str, Any]], now: datetime) -> Dict[str, Any]:
    """HTTP endpoint check, executed from the poll thread only (never in a
    request thread). A real response (any status code) is conclusive; a
    transport failure is inconclusive -- it keeps the last success and lets
    the freshness floor age it."""
    if device is not None and not device.get("online"):
        return _offline_result(instance)
    url = str((instance.get("strategy") or {}).get("url") or "")
    if not url:
        endpoints = app.get("endpoints") or []
        url = next((e for e in endpoints if _URL_RE.fullmatch(str(e))), "")
    if not _URL_RE.fullmatch(url):
        return _inconclusive("no http(s) endpoint configured for this instance")
    label = url.split("://", 1)[-1].split("/", 1)[0][:64]
    try:
        with urllib.request.urlopen(url, timeout=service.http_timeout) as response:
            code = int(response.status)
    except urllib.error.HTTPError as exc:
        code = int(exc.code)  # the server answered: a real observation
    except urllib.error.URLError as exc:
        # Distinguish "the service is down" (the host answered with a
        # refusal) from "cannot tell" (timeout / DNS / blackholed) -- a
        # refused connection keeps the last success instead of flipping to
        # "unknown", exactly like the tcp strategy.
        reason = exc.reason if isinstance(exc.reason, BaseException) else None
        if isinstance(reason, ConnectionRefusedError) or "refused" in str(exc.reason).lower():
            state = "degraded" if instance.get("critical") else "warning"
            return {"state": state, "conclusive": True, "reasons": [f"endpoint {label!r} refused"]}
        return _inconclusive(f"endpoint {label!r} unreachable")
    except (socket.timeout, TimeoutError, OSError):
        return _inconclusive(f"endpoint {label!r} unreachable")
    if 200 <= code < 400:
        return {"state": "healthy", "conclusive": True, "reasons": []}
    if code < 500:
        state = "degraded" if instance.get("critical") else "warning"
        return {"state": state, "conclusive": True, "reasons": [f"endpoint {label!r} returned HTTP {code}"]}
    state = "critical" if instance.get("critical") else "degraded"
    return {"state": state, "conclusive": True, "reasons": [f"endpoint {label!r} returned HTTP {code}"]}


def _strategy_tcp(service: "ApplicationService", app: Dict[str, Any],
                  instance: Dict[str, Any], device: Optional[Dict[str, Any]], now: datetime) -> Dict[str, Any]:
    """TCP port check from the poll thread: a port that refuses is a real
    "the service is down" observation; a timeout/DNS failure is
    inconclusive (the network, not the service, is the unknown)."""
    if device is not None and not device.get("online"):
        return _offline_result(instance)
    params = instance.get("strategy") or {}
    host = str(params.get("host") or "")
    port = params.get("port")
    if not host or isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        return _inconclusive("no host/port configured for this instance")
    try:
        with socket.create_connection((host, port), timeout=service.tcp_timeout):
            return {"state": "healthy", "conclusive": True, "reasons": []}
    except (ConnectionRefusedError, socket.timeout, TimeoutError, OSError):
        pass
    # Distinguish "the service is down" (refused) from "cannot tell"
    # (timeout / DNS / blackholed): refused means the host answered.
    try:
        with socket.create_connection((host, port), timeout=service.tcp_timeout):
            return {"state": "healthy", "conclusive": True, "reasons": []}
    except ConnectionRefusedError:
        state = "degraded" if instance.get("critical") else "warning"
        return {"state": state, "conclusive": True, "reasons": [f"port {host}:{port} refused"]}
    except (socket.gaierror, socket.timeout, TimeoutError, OSError):
        return _inconclusive(f"port {host}:{port} unreachable")


def _strategy_command(service: "ApplicationService", app: Dict[str, Any],
                      instance: Dict[str, Any], device: Optional[Dict[str, Any]], now: datetime) -> Dict[str, Any]:
    """Operator-registered *command template* check, run on the PiNOC host
    from the poll thread. The API only ever references a template by name;
    the template itself (command line + timeout) lives in the operator's
    config file, which is the trust boundary -- never the browser."""
    if device is not None and not device.get("online"):
        return _offline_result(instance)
    template_name = str((instance.get("strategy") or {}).get("template") or instance.get("target") or "")
    template = service.command_templates.get(template_name)
    if not template:
        return _inconclusive(f"command template {template_name!r} is not registered in the configuration")
    try:
        proc = subprocess.run(template["command"], shell=True, capture_output=True, text=True,
                              timeout=template["timeout_seconds"], cwd="/")
    except (subprocess.TimeoutExpired, OSError) as exc:
        return _inconclusive(f"command template {template_name!r} failed: {service.redact(str(exc))[:120]}")
    if proc.returncode == 0:
        return {"state": "healthy", "conclusive": True, "reasons": []}
    state = "degraded" if instance.get("critical") else "warning"
    detail = service.redact((proc.stderr or proc.stdout or "").strip())[:120]
    return {"state": state, "conclusive": True,
            "reasons": [f"command template {template_name!r} exited {proc.returncode}" + (f": {detail}" if detail else "")]}


def _strategy_integration(service: "ApplicationService", app: Dict[str, Any],
                          instance: Dict[str, Any], device: Optional[Dict[str, Any]], now: datetime) -> Dict[str, Any]:
    """State of a role integration the collector already computes for the
    device (raid, packages, adsb, ...): normalized to the canonical set, so
    an application can depend on the health of a whole subsystem."""
    if device is None:
        return _inconclusive(f"no state for device {instance['device_id']!r}")
    if not device.get("online"):
        return _offline_result(instance)
    name = str((instance.get("strategy") or {}).get("name") or instance.get("target") or "")
    if not name:
        return _inconclusive("no integration name configured for this instance")
    entry = (device.get("integrations") or {}).get(name)
    if not isinstance(entry, dict):
        return _inconclusive(f"integration {name!r} not reported by the device")
    raw = str(entry.get("health") or "unknown")
    if raw in ("unavailable", "unsupported"):
        return _inconclusive(f"integration {name!r} is {raw}")
    state = normalize_state(raw)
    if state in ("healthy", "maintenance"):
        return {"state": state, "conclusive": True, "reasons": []}
    return {"state": state, "conclusive": True,
            "reasons": [f"integration {name!r} is {raw}"]}


def _strategy_composite(service: "ApplicationService", app: Dict[str, Any],
                        instance: Dict[str, Any], device: Optional[Dict[str, Any]], now: datetime) -> Dict[str, Any]:
    """Worst-of across several child strategies. Each child resolves to a
    real state -- its own observation when conclusive, the instance's
    freshness floor when inconclusive -- and a child flagged ``critical``
    is escalated by the application's criticality policy before the worst
    is taken. This is what makes "a running process does not mask a
    critical stale feed" true: the healthy child cannot pull the average
    back down."""
    params = instance.get("strategy") or {}
    children = [c for c in (params.get("strategies") or []) if isinstance(c, dict)][:MAX_COMPOSITE_CHILDREN]
    if not children:
        return _inconclusive("composite strategy has no children")
    criticality = app.get("criticality") or "standard"
    reasons: List[str] = []
    states: List[str] = []
    for child in children:
        child_name = str(child.get("strategy") or "")
        fn = _STRATEGIES.get(child_name)
        if fn is None:
            reasons.append(f"unknown strategy {child_name!r}")
            states.append("unknown")
            continue
        child_instance = {**instance, "strategy": child}
        try:
            result = fn(service, app, child_instance, device, now)
        except Exception as exc:  # noqa: BLE001 -- one broken child degrades, never kills the tick
            LOG.warning("application %s child strategy %s failed: %s", app.get("slug"), child_name, exc)
            result = _inconclusive(f"strategy {child_name!r} failed")
        if result["conclusive"]:
            state = normalize_state(result["state"])
        else:
            state = fresh_state(instance.get("last_success_at"), service.freshness_seconds, now)
        if child.get("critical"):
            state = escalate(state, criticality)
        states.append(state)
        for reason in result["reasons"][:3]:
            reasons.append(f"{child_name}: {reason}")
    state = worst(*states) if states else "unknown"
    return {"state": state, "conclusive": True, "reasons": reasons[:12]}


for _name, _fn in (("service", _strategy_service), ("process", _strategy_process),
                   ("http", _strategy_http), ("tcp", _strategy_tcp),
                   ("command", _strategy_command), ("integration", _strategy_integration),
                   ("composite", _strategy_composite)):
    register_health_strategy(_name, _fn)


# -- payload codecs -----------------------------------------------------------

def _load_strategy(raw: Any, field: str, templates: Dict[str, Any]) -> Dict[str, Any]:
    """Validate a strategy object ({"strategy": name, ...params}) or a
    strategy name against the registry. Recursive for composites. Returns
    the normalized dict, or {} for an absent strategy (inherit/default)."""
    if raw is None or raw == {}:
        return {}
    if isinstance(raw, str):
        raw = {"strategy": raw}
    if not isinstance(raw, dict):
        raise ApplicationError(f"{field} must be a strategy object or a strategy name")
    name = str(raw.get("strategy") or "").strip().lower()
    if name not in _STRATEGIES:
        raise ApplicationError(f"{field}: unknown strategy {name!r} (registered: {', '.join(strategy_names())})")
    result = {"strategy": name}
    if name == "composite":
        children = raw.get("strategies", [])
        if not isinstance(children, list):
            raise ApplicationError(f"{field}: composite strategies must be a list")
        if len(children) > MAX_COMPOSITE_CHILDREN:
            raise ApplicationError(f"{field}: at most {MAX_COMPOSITE_CHILDREN} composite children")
        result["strategies"] = [_load_strategy(child, f"{field}.strategies[{i}]", templates)
                                for i, child in enumerate(children)]
        if not result["strategies"]:
            raise ApplicationError(f"{field}: a composite strategy needs at least one child")
    else:
        for key in ("unit", "name", "kind", "host", "template"):
            if key in raw:
                value = str(raw[key]).strip()
                if len(value) > MAX_TARGET:
                    raise ApplicationError(f"{field}.{key} is at most {MAX_TARGET} characters")
                result[key] = value
        if "url" in raw:
            url = str(raw["url"]).strip()
            if not _URL_RE.fullmatch(url):
                raise ApplicationError(f"{field}.url must be an http(s) URL")
            result["url"] = url
        if "port" in raw:
            port = raw["port"]
            if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
                raise ApplicationError(f"{field}.port must be an integer between 1 and 65535")
            result["port"] = port
        if "critical" in raw:
            if not isinstance(raw["critical"], bool):
                raise ApplicationError(f"{field}.critical must be a boolean")
            result["critical"] = bool(raw["critical"])
        if name == "command" and not result.get("template"):
            # A command strategy with no template name is a no-op; make the
            # operator say which registered template to run.
            raise ApplicationError(f"{field}.template is required for command strategies")
    if result.get("template") and templates and result.get("template") not in templates:
        raise ApplicationError(f"{field}.template {result['template']!r} is not registered "
                               f"(available: {', '.join(sorted(templates)) or 'none'})")
    return result


def _load_endpoints(raw: Any) -> List[str]:
    if raw is None:
        return []
    if isinstance(raw, str):
        raw = [part.strip() for part in raw.split(",")]
    if not isinstance(raw, list):
        raise ApplicationError("endpoints must be a list")
    values: List[str] = []
    for entry in raw[:MAX_ENDPOINTS]:
        text = str(entry).strip()
        if not text or len(text) > MAX_ENDPOINT_LEN:
            raise ApplicationError(f"endpoint entries are 1-{MAX_ENDPOINT_LEN} characters")
        if not (_URL_RE.fullmatch(text) or _HOSTPORT_RE.fullmatch(text)):
            raise ApplicationError(f"endpoint must be an http(s) URL or host:port: {text[:60]!r}")
        if text not in values:
            values.append(text)
    if len(raw) > MAX_ENDPOINTS:
        raise ApplicationError(f"endpoints may hold at most {MAX_ENDPOINTS} entries")
    return values


def _load_tags(raw: Any) -> List[str]:
    if raw is None:
        return []
    if isinstance(raw, str):
        raw = [part.strip() for part in raw.split(",")]
    if not isinstance(raw, list):
        raise ApplicationError("tags must be a list")
    values = [str(item).strip() for item in raw if str(item).strip()]
    if len(values) > MAX_TAGS:
        raise ApplicationError(f"tags may hold at most {MAX_TAGS} entries")
    if any(len(value) > MAX_TAG_LEN for value in values):
        raise ApplicationError(f"tags may be at most {MAX_TAG_LEN} characters")
    return values


def _default_strategy_for(mechanism: str, target: str) -> Dict[str, Any]:
    """The zero-config strategy implied by an instance's mechanism."""
    if mechanism == "systemd":
        return {"strategy": "service", "unit": target}
    if mechanism in ("pm2", "container"):
        return {"strategy": "process", "name": target, "kind": mechanism}
    return {"strategy": "process", "name": target, "kind": "process"}


# -- service ------------------------------------------------------------------

class ApplicationService:
    """CRUD + the background health poll for the application registry.

    ``db`` is the shared history :class:`~pinoc.database.Database` (the
    service degrades to empty reads, never raises, when it is absent or
    unavailable -- the same contract every other PiNOC service keeps);
    ``state`` is the shared :class:`~pinoc.state.PiNOCState` (live device
    state for the checks); ``history`` is the HistoryManager used for
    durable transition events; ``config`` is the top-level ``applications``
    configuration section; ``audit`` is an ActionDispatcher.audit-shaped
    callable for every state-changing operation; ``redact`` neutralizes
    secret material in URLs/reasons before they are stored or returned.
    """

    def __init__(self, db: Optional[Database] = None, state: Any = None, history: Any = None,
                 config: Optional[Dict[str, Any]] = None, audit: Optional[Callable[..., Any]] = None,
                 redact: Optional[Callable[[Any], Any]] = None) -> None:
        cfg = config or {}
        self.db = db
        self.state = state
        self.history = history
        self.audit = audit
        self.redact = redact if redact is not None else (lambda value: value)
        self.enabled = bool(cfg.get("enabled", True))
        self.poll_seconds = max(5.0, float(cfg.get("poll_seconds", 60)))
        self.http_timeout = max(0.5, float(cfg.get("http_timeout_seconds", 10)))
        self.tcp_timeout = max(0.5, float(cfg.get("tcp_timeout_seconds", 5)))
        self.freshness_seconds = max(10.0, float(cfg.get("freshness_seconds", 300)))
        self.command_templates = _parse_command_templates(cfg.get("command_templates"))
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self._run, name="pinoc-applications", daemon=True)

    # -- lifecycle ----------------------------------------------------------
    def start(self) -> None:
        if self.enabled and self.db is not None:
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
                LOG.exception("application health tick failed")
            self.stop_event.wait(self.poll_seconds)

    # -- plumbing -------------------------------------------------------------
    def _available(self) -> bool:
        return self.db is not None and bool(getattr(self.db, "available", False))

    def _audit(self, actor: str, action: str, target: Optional[str], params: Dict[str, Any]) -> None:
        if self.audit is None:
            return
        try:
            self.audit(actor, "administrator", None, None, action, target,
                       params, "allowed", "succeeded", None, None, None)
        except Exception:  # noqa: BLE001 -- audit bookkeeping must never break the write
            pass

    def _devices(self) -> Dict[str, Dict[str, Any]]:
        if self.state is None:
            return {}
        return {device["id"]: device for device in self.state.devices() if device.get("id")}

    def known_device_ids(self) -> set:
        if self.state is not None:
            return {device["id"] for device in self.state.devices() if device.get("id")}
        if self._available():
            return {row["device_id"] for row in self.db.rows("SELECT device_id FROM devices")}
        return set()

    # -- row codecs -----------------------------------------------------------
    @staticmethod
    def _decode_app(row: Dict[str, Any]) -> Dict[str, Any]:
        try:
            strategy = json.loads(row.get("health_strategy_json") or "null") or {}
            endpoints = json.loads(row.get("endpoints_json") or "[]")
            tags = json.loads(row.get("tags_json") or "[]")
            reasons = json.loads(row.get("health_reasons_json") or "[]")
        except (TypeError, ValueError):
            strategy, endpoints, tags, reasons = {}, [], [], []
        return {
            "id": row["slug"],
            "app_id": row["app_id"],
            "slug": row["slug"],
            "name": row["name"],
            "description": row.get("description") or "",
            "project": row.get("project_slug"),
            "lifecycle": row["lifecycle"],
            "archived": row["lifecycle"] == "archived",
            "criticality": row.get("criticality") or "standard",
            "version_source": row.get("version_source") or "manual",
            "version": row.get("version"),
            "repository": row.get("repository"),
            "strategy": strategy,
            "endpoints": endpoints,
            "tags": tags,
            "owner": row.get("owner") or None,
            "health": normalize_state(row.get("health")),
            "health_reasons": reasons,
            "last_success_at": row.get("last_success_at"),
            "last_checked_at": row.get("last_checked_at"),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "archived_at": row.get("archived_at"),
            "archived_reason": row.get("archived_reason") or None,
        }

    @staticmethod
    def _decode_instance(row: Dict[str, Any]) -> Dict[str, Any]:
        try:
            strategy = json.loads(row.get("strategy_json") or "null") or {}
            reasons = json.loads(row.get("health_reasons_json") or "[]")
        except (TypeError, ValueError):
            strategy, reasons = {}, []
        return {
            "id": row["instance_id"],
            "instance_id": row["instance_id"],
            "app": row["app_slug"],
            "device_id": row["device_id"],
            "mechanism": row.get("mechanism") or "systemd",
            "target": row.get("target") or "",
            "critical": bool(row.get("critical")),
            "enabled": bool(row.get("enabled", 1)),
            "strategy": strategy,
            "health": normalize_state(row.get("health")),
            "health_reasons": reasons,
            "last_success_at": row.get("last_success_at"),
            "last_checked_at": row.get("last_checked_at"),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def _fetch(self, app_id: Any) -> Optional[Dict[str, Any]]:
        if not self._available():
            return None
        key = str(app_id).strip()
        column = "app_id" if key.isdigit() else "slug"
        rows = self.db.rows(f"SELECT * FROM applications WHERE {column}=?", (key,))
        return self._decode_app(rows[0]) if rows else None

    def _require(self, app_id: Any) -> Dict[str, Any]:
        row = self._fetch(app_id)
        if row is None:
            raise ApplicationNotFound(f"application {app_id!r} not found")
        return row

    # -- CRUD --------------------------------------------------------------------
    def list(self, include_archived: bool = False, lifecycle: Optional[str] = None,
             project: Optional[str] = None) -> List[Dict[str, Any]]:
        if not self._available():
            return []
        where, args = ["1=1"], []
        if not include_archived:
            where.append("lifecycle <> 'archived'")
        if lifecycle:
            if lifecycle not in LIFECYCLES:
                raise ApplicationError(f"lifecycle must be one of {', '.join(LIFECYCLES)}")
            where.append("lifecycle = ?")
            args.append(lifecycle)
        if project:
            where.append("project_slug = ?")
            args.append(str(project).strip())
        rows = self.db.rows("SELECT * FROM applications WHERE " + " AND ".join(where) +
                            " ORDER BY name", tuple(args))
        apps = [self._decode_app(row) for row in rows]
        counts: Dict[str, int] = {}
        if apps:
            slugs = [app["id"] for app in apps]
            placeholders = ",".join("?" * len(slugs))
            for row in self.db.rows(
                    f"SELECT app_slug,COUNT(*) AS count FROM application_instances "
                    f"WHERE app_slug IN ({placeholders}) GROUP BY app_slug", tuple(slugs)):
                counts[row["app_slug"]] = row["count"]
        for app in apps:
            app["instance_count"] = counts.get(app["id"], 0)
        return apps

    def get(self, app_id: Any) -> Optional[Dict[str, Any]]:
        app = self._fetch(app_id)
        if app is None:
            return None
        result = dict(app)
        result["instances"] = self._instances_for(app["id"], app)
        return result

    def create(self, payload: Dict[str, Any], actor: str = "system") -> Dict[str, Any]:
        if not self._available():
            raise ApplicationError("history database is unavailable")
        if not isinstance(payload, dict):
            raise ApplicationError("payload must be an object")
        name = str(payload.get("name") or "").strip()
        if not name or len(name) > MAX_NAME:
            raise ApplicationError("name is required (max 200 characters)")
        slug = str(payload.get("slug") or "").strip().lower() or projects.slugify(name)
        if not _SLUG_RE.fullmatch(slug):
            raise ApplicationError("slug must be a simple lowercase identifier (letters, digits, dashes)")
        if self.db.rows("SELECT app_id FROM applications WHERE slug=?", (slug,)):
            raise ApplicationError(f"slug {slug!r} is already taken")
        lifecycle = str(payload.get("lifecycle") or "active").strip().lower()
        if lifecycle not in LIFECYCLES or lifecycle == "archived":
            raise ApplicationError(f"lifecycle must be one of {', '.join(LIFECYCLES[:-1])} (archiving is an operation)")
        criticality = str(payload.get("criticality") or "standard").strip().lower()
        if criticality not in CRITICALITIES:
            raise ApplicationError(f"criticality must be one of {', '.join(CRITICALITIES)}")
        version_source = str(payload.get("version_source") or "manual").strip().lower()
        if version_source not in VERSION_SOURCES:
            raise ApplicationError(f"version_source must be one of {', '.join(VERSION_SOURCES)}")
        version = str(payload.get("version") or "").strip()[:MAX_VERSION] or None
        repository = str(payload.get("repository") or "").strip()[:MAX_REPOSITORY] or None
        if repository and not _REPOSITORY_RE.fullmatch(repository):
            raise ApplicationError("repository must be an http(s), git, or ssh URL")
        project_slug = str(payload.get("project") or "").strip() or None
        if project_slug:
            if not self.db.rows("SELECT project_id FROM projects WHERE slug=?", (project_slug,)):
                raise ApplicationError(f"project {project_slug!r} not found")
        strategy = _load_strategy(payload.get("strategy"), "strategy", self.command_templates)
        description = str(payload.get("description") or "")[:MAX_DESCRIPTION]
        owner = str(payload.get("owner") or "").strip()[:MAX_OWNER] or None
        endpoints = _load_endpoints(payload.get("endpoints"))
        tags = _load_tags(payload.get("tags"))
        stamp = utcnow()
        self.db.execute(
            "INSERT INTO applications(slug,name,description,project_slug,lifecycle,criticality,"
            "version_source,version,repository,health_strategy_json,endpoints_json,tags_json,owner,"
            "created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (slug, name, description, project_slug, lifecycle, criticality, version_source,
             version, repository, json.dumps(strategy), json.dumps(endpoints), json.dumps(tags),
             owner, stamp, stamp))
        self._audit(actor, "application.create", slug,
                    {"name": name, "lifecycle": lifecycle, "criticality": criticality,
                     "strategy": strategy.get("strategy") if strategy else None})
        result = self._fetch(slug)
        assert result is not None
        result["instance_count"] = 0
        return result

    def update(self, app_id: Any, payload: Dict[str, Any], actor: str = "system") -> Dict[str, Any]:
        if not self._available():
            raise ApplicationError("history database is unavailable")
        current = self._require(app_id)
        if current["archived"]:
            raise ApplicationError("application is archived and read-only; restore it before editing")
        if not isinstance(payload, dict):
            raise ApplicationError("payload must be an object")
        fields: List[str] = []
        values: List[Any] = []
        audit_params: Dict[str, Any] = {}
        if "name" in payload:
            name = str(payload["name"] or "").strip()
            if not name or len(name) > MAX_NAME:
                raise ApplicationError("name must be 1-200 characters")
            fields.append("name=?"); values.append(name); audit_params["name"] = name
        if "description" in payload:
            fields.append("description=?"); values.append(str(payload["description"] or "")[:MAX_DESCRIPTION])
        if "owner" in payload:
            fields.append("owner=?"); values.append(str(payload["owner"] or "").strip()[:MAX_OWNER] or None)
        if "project" in payload:
            project_slug = str(payload["project"] or "").strip() or None
            if project_slug and not self.db.rows("SELECT project_id FROM projects WHERE slug=?", (project_slug,)):
                raise ApplicationError(f"project {project_slug!r} not found")
            fields.append("project_slug=?"); values.append(project_slug); audit_params["project"] = project_slug
        if "criticality" in payload:
            criticality = str(payload["criticality"] or "").strip().lower()
            if criticality not in CRITICALITIES:
                raise ApplicationError(f"criticality must be one of {', '.join(CRITICALITIES)}")
            if criticality != current["criticality"]:
                self._audit(actor, "application.criticality", current["id"],
                            {"old": current["criticality"], "new": criticality})
            fields.append("criticality=?"); values.append(criticality); audit_params["criticality"] = criticality
        if "lifecycle" in payload:
            lifecycle = str(payload["lifecycle"] or "").strip().lower()
            if lifecycle not in LIFECYCLES or lifecycle == "archived":
                raise ApplicationError("lifecycle must be one of planned, active, maintenance, or retired "
                                       "(archiving/restoring is an operation)")
            if lifecycle != current["lifecycle"]:
                self._audit(actor, "application.lifecycle", current["id"],
                            {"old": current["lifecycle"], "new": lifecycle})
            fields.append("lifecycle=?"); values.append(lifecycle); audit_params["lifecycle"] = lifecycle
        if "version_source" in payload:
            source = str(payload["version_source"] or "manual").strip().lower()
            if source not in VERSION_SOURCES:
                raise ApplicationError(f"version_source must be one of {', '.join(VERSION_SOURCES)}")
            fields.append("version_source=?"); values.append(source); audit_params["version_source"] = source
        if "version" in payload:
            fields.append("version=?"); values.append(str(payload["version"] or "").strip()[:MAX_VERSION] or None)
        if "repository" in payload:
            repository = str(payload["repository"] or "").strip()[:MAX_REPOSITORY] or None
            if repository and not _REPOSITORY_RE.fullmatch(repository):
                raise ApplicationError("repository must be an http(s), git, or ssh URL")
            fields.append("repository=?"); values.append(repository); audit_params["repository"] = repository
        if "endpoints" in payload:
            fields.append("endpoints_json=?"); values.append(json.dumps(_load_endpoints(payload["endpoints"])))
        if "tags" in payload:
            fields.append("tags_json=?"); values.append(json.dumps(_load_tags(payload["tags"])))
        if "strategy" in payload:
            strategy = _load_strategy(payload["strategy"], "strategy", self.command_templates)
            if strategy != (current.get("strategy") or {}):
                self._audit(actor, "application.strategy", current["id"],
                            {"old": current.get("strategy"), "new": strategy})
            fields.append("health_strategy_json=?"); values.append(json.dumps(strategy)); audit_params["strategy"] = strategy
        if not fields:
            return current
        values.extend([utcnow(), current["app_id"]])
        self.db.execute(
            f"UPDATE applications SET {', '.join(fields)},updated_at=? WHERE app_id=?", tuple(values))
        self._audit(actor, "application.update", current["id"], audit_params)
        return self._require(app_id)

    def archive(self, app_id: Any, actor: str = "system", reason: str = "") -> Dict[str, Any]:
        current = self._require(app_id)
        if current["archived"]:
            return current
        self.db.execute(
            "UPDATE applications SET lifecycle='archived',archived_at=?,archived_reason=?,updated_at=? "
            "WHERE app_id=?", (utcnow(), str(reason or "")[:500], utcnow(), current["app_id"]))
        self._audit(actor, "application.archive", current["id"],
                    {"previous_lifecycle": current["lifecycle"], "reason": str(reason or "")[:500]})
        return self._require(app_id)

    def restore(self, app_id: Any, actor: str = "system") -> Dict[str, Any]:
        current = self._require(app_id)
        if not current["archived"]:
            raise ApplicationError("only archived applications can be restored")
        self.db.execute(
            "UPDATE applications SET lifecycle='active',archived_at=NULL,archived_reason=NULL,updated_at=? "
            "WHERE app_id=?", (utcnow(), current["app_id"]))
        self._audit(actor, "application.restore", current["id"], {})
        return self._require(app_id)

    # -- instances ----------------------------------------------------------------
    def _instances_for(self, app_slug: str, app: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        if not self._available():
            return []
        rows = self.db.rows("SELECT * FROM application_instances WHERE app_slug=? "
                            "ORDER BY device_id,mechanism,target", (app_slug,))
        instances = [self._decode_instance(row) for row in rows]
        if app is not None:
            devices = self._devices()
            for instance in instances:
                device = devices.get(instance["device_id"]) or {}
                if not device and self._available():
                    row = self.db.rows("SELECT hostname,friendly_name FROM devices WHERE device_id=?",
                                       (instance["device_id"],))
                    if row:
                        device = row[0]
                instance["device"] = {
                    "id": instance["device_id"],
                    "hostname": device.get("hostname"),
                    "friendly_name": device.get("friendly_name"),
                    "online": bool(device.get("online")),
                }
        return instances

    def instances(self, app_id: Any) -> List[Dict[str, Any]]:
        current = self._require(app_id)
        return self._instances_for(current["id"])

    def add_instance(self, app_id: Any, payload: Dict[str, Any], actor: str = "system") -> Dict[str, Any]:
        if not self._available():
            raise ApplicationError("history database is unavailable")
        current = self._require(app_id)
        if current["archived"]:
            raise ApplicationError("application is archived and read-only; restore it before adding instances")
        if not isinstance(payload, dict):
            raise ApplicationError("payload must be an object")
        if len(self._instances_for(current["id"])) >= MAX_INSTANCES:
            raise ApplicationError(f"an application may have at most {MAX_INSTANCES} instances")
        device_id = str(payload.get("device_id") or "").strip()
        if not device_id:
            raise ApplicationError("device_id is required")
        known = self.known_device_ids()
        if known and device_id not in known:
            raise ApplicationError(f"unknown device: {device_id}")
        mechanism = str(payload.get("mechanism") or "systemd").strip().lower()
        if mechanism not in MECHANISMS:
            raise ApplicationError(f"mechanism must be one of {', '.join(MECHANISMS)}")
        target = str(payload.get("target") or "").strip()[:MAX_TARGET]
        if not target:
            raise ApplicationError("target is required")
        if not re.fullmatch(r"[A-Za-z0-9@:_.\-/]{1,128}", target):
            raise ApplicationError("target must be a simple identifier (unit name, app name, container, process)")
        critical = bool(payload.get("critical", False))
        enabled = bool(payload.get("enabled", True))
        strategy = _load_strategy(payload.get("strategy"), "strategy", self.command_templates)
        if self.db.rows(
                "SELECT instance_id FROM application_instances WHERE app_slug=? AND device_id=? "
                "AND mechanism=? AND target=?", (current["id"], device_id, mechanism, target)):
            raise ApplicationError(f"an instance of this application on {device_id} with that "
                                   f"{mechanism}/{target} already exists")
        stamp = utcnow()
        instance_id = self.db.execute(
            "INSERT INTO application_instances(app_slug,device_id,mechanism,target,critical,enabled,"
            "strategy_json,health,created_at,updated_at) VALUES(?,?,?,?,?,?,?,'unknown',?,?)",
            (current["id"], device_id, mechanism, target, 1 if critical else 0, 1 if enabled else 0,
             json.dumps(strategy), stamp, stamp))
        self._audit(actor, "application.instance.add", current["id"],
                    {"device_id": device_id, "mechanism": mechanism, "target": target,
                     "critical": critical, "strategy": strategy.get("strategy") if strategy else None})
        return self._decode_instance(self.db.rows(
            "SELECT * FROM application_instances WHERE instance_id=?", (instance_id,))[0])

    def _require_instance(self, app_id: Any, instance_id: Any) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        current = self._require(app_id)
        key = str(instance_id).strip()
        column = "instance_id" if key.isdigit() else "id"
        rows = self.db.rows(
            f"SELECT * FROM application_instances WHERE {column}=? AND app_slug=?", (key, current["id"]))
        if not rows:
            raise ApplicationNotFound(f"instance {instance_id!r} not found for this application")
        return current, self._decode_instance(rows[0])

    def update_instance(self, app_id: Any, instance_id: Any, payload: Dict[str, Any],
                        actor: str = "system") -> Dict[str, Any]:
        if not self._available():
            raise ApplicationError("history database is unavailable")
        current, instance = self._require_instance(app_id, instance_id)
        if current["archived"]:
            raise ApplicationError("application is archived and read-only; restore it before editing instances")
        if not isinstance(payload, dict):
            raise ApplicationError("payload must be an object")
        fields: List[str] = []
        values: List[Any] = []
        if "target" in payload:
            target = str(payload["target"] or "").strip()[:MAX_TARGET]
            if not target or not re.fullmatch(r"[A-Za-z0-9@:_.\-/]{1,128}", target):
                raise ApplicationError("target must be a simple identifier")
            if target != instance["target"]:
                conflict = self.db.rows(
                    "SELECT instance_id FROM application_instances WHERE app_slug=? AND device_id=? "
                    "AND mechanism=? AND target=? AND instance_id<>?",
                    (current["id"], instance["device_id"], instance["mechanism"], target,
                     instance["instance_id"]))
                if conflict:
                    raise ApplicationError("that instance already exists for this application/device")
            fields.append("target=?"); values.append(target)
        if "mechanism" in payload:
            mechanism = str(payload["mechanism"] or "").strip().lower()
            if mechanism not in MECHANISMS:
                raise ApplicationError(f"mechanism must be one of {', '.join(MECHANISMS)}")
            if mechanism != instance["mechanism"]:
                conflict = self.db.rows(
                    "SELECT instance_id FROM application_instances WHERE app_slug=? AND device_id=? "
                    "AND mechanism=? AND target=? AND instance_id<>?",
                    (current["id"], instance["device_id"], mechanism, instance["target"],
                     instance["instance_id"]))
                if conflict:
                    raise ApplicationError("that instance already exists for this application/device")
            fields.append("mechanism=?"); values.append(mechanism)
        if "critical" in payload:
            fields.append("critical=?"); values.append(1 if payload["critical"] else 0)
        if "enabled" in payload:
            fields.append("enabled=?"); values.append(1 if payload["enabled"] else 0)
        if "strategy" in payload:
            strategy = _load_strategy(payload["strategy"], "strategy", self.command_templates)
            if strategy != (instance.get("strategy") or {}):
                self._audit(actor, "application.instance.strategy", current["id"],
                            {"instance": instance["instance_id"], "old": instance.get("strategy"), "new": strategy})
            fields.append("strategy_json=?"); values.append(json.dumps(strategy))
        if not fields:
            return instance
        values.extend([utcnow(), instance["instance_id"]])
        self.db.execute(
            f"UPDATE application_instances SET {', '.join(fields)},updated_at=? WHERE instance_id=?",
            tuple(values))
        self._audit(actor, "application.instance.update", current["id"],
                    {"instance": instance["instance_id"], "changed": [f.split("=")[0] for f in fields]})
        return self._decode_instance(self.db.rows(
            "SELECT * FROM application_instances WHERE instance_id=?", (instance["instance_id"],))[0])

    def delete_instance(self, app_id: Any, instance_id: Any, actor: str = "system") -> Dict[str, Any]:
        if not self._available():
            raise ApplicationError("history database is unavailable")
        current, instance = self._require_instance(app_id, instance_id)
        if current["archived"]:
            raise ApplicationError("application is archived and read-only; restore it before removing instances")
        self.db.execute(
            "DELETE FROM application_instances WHERE instance_id=? AND app_slug=?",
            (instance["instance_id"], current["id"]))
        self.db.execute(
            "DELETE FROM application_health_snapshots WHERE instance_id=?", (instance["instance_id"],))
        self._audit(actor, "application.instance.remove", current["id"],
                    {"instance": instance["instance_id"], "device_id": instance["device_id"],
                     "mechanism": instance["mechanism"], "target": instance["target"]})
        return {"id": current["id"], "removed": instance["instance_id"]}

    # -- health poll (background thread) ---------------------------------------------
    def _resolve_strategy(self, app: Dict[str, Any], instance: Dict[str, Any]) -> Dict[str, Any]:
        strategy = instance.get("strategy") or app.get("strategy") or {}
        if not strategy:
            strategy = _default_strategy_for(instance["mechanism"], instance["target"])
        return strategy

    def _finalize(self, instance: Dict[str, Any], result: Dict[str, Any],
                  now: datetime, now_iso: str) -> Tuple[str, List[str], Optional[str]]:
        """Apply the phase-wide observation contract: a conclusive result
        *is* the health (and a healthy one refreshes last_success_at); an
        inconclusive one never erases the last success -- the stored state
        simply ages under the freshness floor."""
        if result.get("conclusive"):
            health = normalize_state(result.get("state"))
            reasons = [self.redact(r) for r in result.get("reasons") or []][:12]
            last_success = now_iso if health == "healthy" else instance.get("last_success_at")
        else:
            age = age_seconds(instance.get("last_success_at"), now)
            health = fresh_state(instance.get("last_success_at"), self.freshness_seconds, now)
            detail = " or ".join(str(r) for r in (result.get("reasons") or [])[:3]) or "check inconclusive"
            reasons = [f"last confirmed {format_duration(age)} ago "
                       f"({instance.get('health') or 'never'}); {self.redact(detail)}"]
            last_success = instance.get("last_success_at")
        return health, reasons, last_success

    def _tick_instance(self, app: Dict[str, Any], instance: Dict[str, Any],
                       device: Optional[Dict[str, Any]], now: datetime, now_iso: str) -> str:
        strategy = self._resolve_strategy(app, instance)
        # The strategy sees the *resolved* strategy (instance override, else
        # the application's, else the mechanism default) plus the live device
        # dict under `_device` for its reason strings.
        decorated = {**instance, "_device": device or {}, "strategy": strategy}
        fn = _STRATEGIES.get(strategy.get("strategy", ""))
        try:
            result = fn(self, app, decorated, device, now) if fn else _inconclusive("no strategy resolved")
        except Exception as exc:  # noqa: BLE001 -- one broken instance never breaks the tick
            LOG.warning("application %s instance %s check failed: %s",
                        app.get("slug"), instance.get("instance_id"), exc)
            result = _inconclusive(f"check failed: {self.redact(str(exc))[:120]}")
        health, reasons, last_success = self._finalize(instance, result, now, now_iso)
        self.db.execute(
            "UPDATE application_instances SET health=?,health_reasons_json=?,last_success_at=?,"
            "last_checked_at=?,updated_at=? WHERE instance_id=?",
            (health, json.dumps(reasons), last_success, now_iso, now_iso, instance["instance_id"]))
        self.db.execute(
            "INSERT INTO application_health_snapshots(app_slug,instance_id,device_id,health,"
            "reasons_json,strategy,source,observed_at,checked_at,ttl_seconds,confidence) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (app["slug"], instance["instance_id"], instance["device_id"], health, json.dumps(reasons),
             strategy.get("strategy", "composite") if strategy else "none",
             "strategy", now_iso, now_iso, int(self.freshness_seconds), 1.0 if result.get("conclusive") else 0.5))
        if _meaningful_transition(normalize_state(instance.get("health")), health):
            self._emit(app, instance, device, normalize_state(instance.get("health")), health, reasons, now_iso)
        return health

    def _emit(self, app: Dict[str, Any], instance: Optional[Dict[str, Any]],
              device: Optional[Dict[str, Any]], old: str, new: str, reasons: List[str], now_iso: str) -> None:
        if self.history is None:
            return
        name = app.get("name") or app["slug"]
        if instance:
            message = (f"{name}: instance on {_device_name(device)} "
                       f"({instance['mechanism']} {instance['target']}) {old} -> {new}")
            device_id = instance.get("device_id") or APPLICATION_DEVICE_ID
        else:
            message = f"{name} {old} -> {new}"
            device_id = APPLICATION_DEVICE_ID
        metadata = {"application": app["slug"], "previous": old, "current": new,
                    "reasons": reasons[:8]}
        if instance:
            metadata.update({"instance_id": instance["instance_id"],
                             "device_id": instance.get("device_id"),
                             "mechanism": instance["mechanism"], "target": instance["target"]})
        try:
            self.history.event(device_id, "application_health_changed",
                               _SEVERITY.get(normalize_state(new), "info"), message, metadata)
        except Exception:  # noqa: BLE001 -- event bookkeeping must never break the poll
            LOG.warning("application event enqueue failed for %s", app.get("slug"))

    def _tick_app(self, app: Dict[str, Any], devices: Dict[str, Dict[str, Any]],
                  now: datetime, now_iso: str) -> Dict[str, Any]:
        raw_instances = self.db.rows(
            "SELECT * FROM application_instances WHERE app_slug=? AND enabled=1", (app["slug"],))
        instances = [self._decode_instance(row) for row in raw_instances]
        states: List[Tuple[str, str, str]] = []
        for instance in instances:
            health = self._tick_instance(app, instance, devices.get(instance["device_id"]), now, now_iso)
            states.append((str(instance["instance_id"]), "instance", health))
        state, reasons = _env_rollup(states, app.get("criticality") or "standard")
        if app.get("lifecycle") == "retired":
            state = worst(state, "maintenance")
        if not instances:
            state, reasons = "unknown", ["no enabled instances"]
        previous = normalize_state(app.get("health"))
        last_success = now_iso if state == "healthy" else app.get("last_success_at")
        self.db.execute(
            "UPDATE applications SET health=?,health_reasons_json=?,last_success_at=?,last_checked_at=?,"
            "updated_at=? WHERE app_id=?",
            (state, json.dumps(reasons), last_success, now_iso, now_iso, app["app_id"]))
        if _meaningful_transition(previous, state):
            self._emit(app, None, None, previous, state, reasons, now_iso)
        return {"id": app["slug"], "name": app.get("name"), "health": state,
                "reasons": reasons, "instances": len(instances),
                "last_checked_at": now_iso}

    def tick(self, now: Optional[datetime] = None) -> Dict[str, Any]:
        """One health poll over every non-archived application. Runs on the
        service's poll thread; safe to call directly (tests do)."""
        now = now or datetime.now(UTC)
        now_iso = now.isoformat()
        if self.db is None or not self.db.available:
            return {"checked": 0, "applications": [], "generated_at": now_iso}
        apps = [self._decode_app(row) for row in self.db.rows(
            "SELECT * FROM applications WHERE lifecycle <> 'archived' ORDER BY name")]
        if not apps:
            return {"checked": 0, "applications": [], "generated_at": now_iso}
        devices = self._devices()
        entries = []
        for app in apps:
            try:
                entries.append(self._tick_app(app, devices, now, now_iso))
            except Exception:  # noqa: BLE001 -- one bad application never breaks the poll
                LOG.exception("application tick failed for %s", app.get("slug"))
                entries.append({"id": app["slug"], "health": app.get("health"), "error": "tick failed"})
        return {"checked": len(entries), "applications": entries, "generated_at": now_iso}

    # -- read side: health endpoint + snapshots ----------------------------------------
    def health(self, app_id: Any, now: Optional[datetime] = None) -> Dict[str, Any]:
        """The drill-down endpoint: current (poll-persisted) rollup plus
        per-instance state and recent health snapshots. Reads only -- the
        checks themselves run in the poll thread, never here."""
        app = self._require(app_id)
        instances = self._instances_for(app["id"], app)
        snapshots = []
        if self._available():
            rows = self.db.rows(
                "SELECT app_slug,instance_id,device_id,health,reasons_json,strategy,source,"
                "observed_at,checked_at,ttl_seconds,confidence FROM application_health_snapshots "
                "WHERE app_slug=? ORDER BY checked_at DESC LIMIT ?", (app["id"], MAX_SNAPSHOTS))
            for row in rows:
                try:
                    reasons = json.loads(row.get("reasons_json") or "[]")
                except (TypeError, ValueError):
                    reasons = []
                snapshots.append({**{k: row[k] for k in
                                      ("app_slug", "instance_id", "device_id", "health", "strategy",
                                       "source", "observed_at", "checked_at", "ttl_seconds", "confidence")},
                                  "reasons": reasons,
                                  "health_normalized": normalize_state(row.get("health"))})
        # Re-age the display under the freshness floor without re-running any
        # check: a stored healthy older than the TTL reads as "stale" here,
        # exactly as the next poll would persist it.
        now = now or datetime.now(UTC)
        for instance in instances:
            floored = fresh_state(instance.get("last_success_at"), self.freshness_seconds, now)
            if RANK[instance["health"]] < RANK[floored]:
                instance["health"] = floored
        return {
            "id": app["id"], "name": app["name"], "lifecycle": app["lifecycle"],
            "criticality": app["criticality"], "version": app.get("version"),
            "version_source": app.get("version_source"), "health": app["health"],
            "reasons": app["health_reasons"], "last_success_at": app.get("last_success_at"),
            "last_checked_at": app.get("last_checked_at"), "instances": instances,
            "snapshots": snapshots,
            "generated_at": now.isoformat(),
        }

    # -- fleet collector hook ---------------------------------------------------------
    def device_app_specs(self) -> Dict[str, List[str]]:
        """Which implementations each device should re-report to the fleet
        collector's due-gated __APPS__ section: one "kind|name" per enabled
        instance of every non-archived application (kind = the instance
        mechanism, name = its target). The collector refreshes this once
        per collect(); a broken source keeps the last good specs."""
        if not self._available():
            return {}
        specs: Dict[str, List[str]] = {}
        rows = self.db.rows(
            "SELECT device_id,mechanism,target FROM application_instances WHERE enabled=1 "
            "AND app_slug IN (SELECT slug FROM applications WHERE lifecycle <> 'archived') "
            "ORDER BY device_id,mechanism,target")
        for row in rows:
            entry = f"{row['mechanism']}|{row['target']}"
            bucket = specs.setdefault(row["device_id"], [])
            if entry not in bucket and len(bucket) < 50:
                bucket.append(entry)
        return specs


def _parse_command_templates(raw: Any) -> Dict[str, Dict[str, Any]]:
    """The operator-registered command-template allowlist. These run on the
    *PiNOC host* (not on the fleet device) from the poll thread; the config
    file is the trust boundary, the API can only reference names."""
    if not isinstance(raw, dict):
        return {}
    templates: Dict[str, Dict[str, Any]] = {}
    for name, entry in list(raw.items())[:100]:
        if not _TEMPLATE_NAME_RE.fullmatch(str(name)):
            LOG.warning("ignoring invalid command template name: %r", name)
            continue
        if not isinstance(entry, dict):
            continue
        command = entry.get("command")
        if not isinstance(command, str) or not command.strip() or len(command) > 512 or "\x00" in command:
            LOG.warning("ignoring invalid command template %r", name)
            continue
        timeout = entry.get("timeout_seconds", 30)
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 1 <= timeout <= 300:
            timeout = 30
        templates[str(name)] = {"command": command.strip(), "timeout_seconds": float(timeout)}
    return templates


# -- project registry sources (P1-R01 hook) -----------------------------------
#
# An application contributes to its project's health rollup through the
# exact same source mechanism the device kind uses: the stored (poll-
# persisted) health column, read from the shared database in request
# threads -- never a remote check. The full non-archived roster feeds the
# project page's unassigned-inventory view.


def _application_health_source(project_service: "projects.ProjectService",
                               object_ids: Sequence[str]) -> List[Dict[str, Any]]:
    by_slug: Dict[str, Dict[str, Any]] = {}
    if object_ids and project_service._available():
        placeholders = ",".join("?" * len(object_ids))
        rows = project_service.db.rows(
            f"SELECT slug,name,health FROM applications WHERE slug IN ({placeholders})",
            tuple(object_ids))
        by_slug = {row["slug"]: row for row in rows}
    entries: List[Dict[str, Any]] = []
    for object_id in object_ids:
        row = by_slug.get(object_id)
        if row is None:
            entries.append({"object_id": object_id, "health": "unknown", "name": object_id,
                            "reasons": [reason_code("application", "unknown", object_id)
                                        + " (not found or archived)"]})
            continue
        health = normalize_state(row.get("health"))
        entries.append({"object_id": object_id, "health": health,
                        "name": row.get("name") or object_id,
                        "reasons": [reason_code("application", health, object_id)]
                        if RANK[health] > RANK["healthy"] else []})
    return entries


def _application_roster(project_service: "projects.ProjectService") -> List[str]:
    if not project_service._available():
        return []
    return [row["slug"] for row in project_service.db.rows(
        "SELECT slug FROM applications WHERE lifecycle <> 'archived' ORDER BY slug")]


projects.register_member_source("application", _application_health_source)
projects.register_roster_source("application", _application_roster)
