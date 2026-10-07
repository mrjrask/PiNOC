"""Canonical environment health states, shared by every Phase 1 model.

The Phase 1 spec's phase-wide contract (appendix) requires that every
environment object -- project, application, repository, feed, software
component, venv -- reports exactly one *canonical* health state, that every
state carries reason codes and timestamps, and that a failed collection
never erases the last success.

This module is the single home for that contract:

* :data:`HEALTH_STATES` / :func:`rank_of` / :func:`worst` -- the eight
  canonical states in strict severity order, and the worst-of aggregation
  every rollup uses.
* :func:`escalate` / :func:`rollup` -- the criticality policy: how a
  member's state counts against the container that groups it (a *critical*
  project does not shrug off a warning).
* :func:`parse_ts` / :func:`age_seconds` / :func:`is_stale` -- freshness
  math shared by every "stale observation" rule (a failed collection keeps
  the last success; staleness is judged on its age alone).

Kept free of any pinoc module import so any Phase 1 service (and their
tests) can depend on it without a cycle.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

UTC = timezone.utc

# The eight canonical states, in *strict severity order*: index in this
# tuple is the severity rank. ``maintenance`` and ``healthy`` rank 0/1 on
# purpose -- planned downtime is a state, not a problem, and must never
# count against a rollup.
HEALTH_STATES = ("healthy", "maintenance", "unknown", "stale", "warning", "degraded", "offline", "critical")

RANK: Dict[str, int] = {state: index for index, state in enumerate(HEALTH_STATES)}

# Object criticalities (projects, applications, feeds, ...).
CRITICALITIES = ("low", "standard", "high", "critical")

# Criticality policy for rollups: how a *member's* state is counted when
# computing the container's state. A "critical" project that owns a
# warning-level feed is, to its operator, a degraded project -- the
# escalation table is the single place that policy lives.
_ESCALATION: Dict[str, Dict[str, str]] = {
    "low": {},
    "standard": {"stale": "warning"},
    "high": {"warning": "degraded", "stale": "degraded"},
    "critical": {"warning": "degraded", "stale": "critical", "degraded": "critical"},
}

# Human-facing label for a canonical state, used in reason strings.
_STATE_MESSAGES = {
    "healthy": "healthy",
    "maintenance": "in maintenance",
    "unknown": "state unknown (no recent observation)",
    "stale": "stale (observation older than its freshness threshold)",
    "warning": "warning",
    "degraded": "degraded",
    "offline": "offline",
    "critical": "critical",
}


def is_valid_state(health: Any) -> bool:
    return str(health) in RANK


def normalize_state(health: Any) -> str:
    """Coerce an arbitrary reported health string to a canonical state.

    Anything outside the eight canonical states (a legacy "unavailable", an
    integration's "unsupported", a collector error string) becomes
    ``unknown`` rather than leaking a model-specific vocabulary through a
    rollup.
    """
    state = str(health or "").strip().lower()
    return state if state in RANK else "unknown"


def rank_of(health: Any) -> int:
    return RANK.get(str(health or ""), RANK["unknown"])


def worst(*states: Any) -> str:
    """The most severe canonical state among those given."""
    candidates = [normalize_state(s) for s in states]
    if not candidates:
        return "unknown"
    return max(candidates, key=rank_of)


def escalate(health: Any, criticality: str) -> str:
    """Apply the criticality policy to one member's state."""
    state = normalize_state(health)
    if state in ("healthy", "maintenance"):
        return state
    return _ESCALATION.get(str(criticality) if criticality in _ESCALATION else "standard", {}).get(state, state)


def state_message(health: Any) -> str:
    return _STATE_MESSAGES.get(normalize_state(health), _STATE_MESSAGES["unknown"])


def rollup(members: Iterable[Tuple[str, str, str]], criticality: str = "standard") -> Tuple[str, List[str]]:
    """Aggregate member ``(object_id, kind, health)`` tuples into
    ``(container_state, reason_codes)``.

    * members in ``maintenance`` are excluded entirely (planned downtime
      counts neither for nor against);
    * every other member's state is escalated per the criticality policy
      (:func:`escalate`) before the worst-of is taken;
    * reason codes are ``<kind>.<state>:<object_id>`` for every member
      whose (escalated) state is worse than healthy, so a health
      explanation always names its contributing objects.
    """
    escalated: List[Tuple[str, str, str]] = []
    reasons: List[str] = []
    for object_id, kind, health in members:
        state = normalize_state(health)
        if state == "maintenance":
            continue
        counted = escalate(state, criticality)
        escalated.append((object_id, kind, counted))
        if rank_of(counted) > RANK["healthy"]:
            reasons.append(f"{kind}.{counted}:{object_id}")
    if not escalated:
        return "healthy", reasons
    state = max((item[2] for item in escalated), key=rank_of)
    return state, reasons


def parse_ts(value: Optional[str]) -> Optional[datetime]:
    """Parse an ISO-8601 timestamp; naive values are assumed to be UTC."""
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value))
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed


def age_seconds(timestamp: Optional[str], now: Optional[datetime] = None) -> Optional[float]:
    """Age of a timestamp in seconds, or None when unparseable/absent."""
    parsed = parse_ts(timestamp)
    if parsed is None:
        return None
    now = now or datetime.now(UTC)
    return (now - parsed).total_seconds()


def is_stale(timestamp: Optional[str], threshold_seconds: float, now: Optional[datetime] = None) -> bool:
    """A *missing* observation is stale (there was never a success); a
    present one is stale once older than its freshness threshold."""
    age = age_seconds(timestamp, now)
    if age is None:
        return True
    return age >= float(threshold_seconds)


def fresh_state(last_success_at: Optional[str], threshold_seconds: float, now: Optional[datetime] = None) -> str:
    """The canonical state an object's *last stored success* implies right
    now: healthy while fresh, stale once the threshold has passed. A failed
    collection never moves an object to a worse state than this -- it keeps
    the last success and only ages it."""
    if last_success_at is None:
        return "unknown"
    return "stale" if is_stale(last_success_at, threshold_seconds, now) else "healthy"


def reason_code(kind: str, state: str, object_id: str) -> str:
    return f"{kind}.{normalize_state(state)}:{object_id}"


def duration_between(earlier: Optional[str], later: Optional[str] = None) -> Optional[float]:
    """Seconds between two timestamps (later defaults to now)."""
    a, b = parse_ts(earlier), parse_ts(later)
    if a is None or b is None:
        return None
    return max(0.0, (b - a).total_seconds())


def format_duration(seconds: Optional[float]) -> str:
    if seconds is None:
        return "—"
    seconds = int(seconds)
    if seconds < 90:
        return f"{seconds}s"
    if seconds < 5400:
        return f"{round(seconds / 60)}m"
    if seconds < 172800:
        return f"{round(seconds / 3600)}h"
    return f"{round(seconds / 86400)}d"
