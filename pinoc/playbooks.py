"""Validated alert runbooks (playbooks) with exact and prefix matching.

A playbook maps an alert type (or type prefix) to operator guidance: a
markdown runbook body, quick-action buttons restricted to the safe-action
registry, and reference links restricted to http(s) or same-origin paths.
Invalid entries are dropped by the web loader and rejected outright by
``validate_config`` so a typo cannot silently weaken or break guidance.
"""
from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Optional

MAX_PLAYBOOKS = 50
MAX_MARKDOWN = 20_000
MAX_ACTIONS = 10
MAX_LINKS = 10
MAX_TITLE = 120

ID_PATTERN = re.compile(r"[A-Za-z0-9._-]{1,64}")
ALERT_TYPE_PATTERN = re.compile(r"[a-z0-9_]{1,64}")
# Mirrors the safe-action registry in pinoc.actions (the web may pass the
# registry keys explicitly; this pattern is the decoupled default).
ACTION_PATTERN = re.compile(
    r"^(?:device\.(?:refresh|reboot|shutdown)|service\.(?:start|stop|restart)"
    r"|wireguard\.restart|desk_display\.restart|magicmirror\.restart"
    r"|pi_hotspot\.restart|package\.check)$"
)
LINK_PATTERN = re.compile(r"^(?:https?://|/)[A-Za-z0-9._\-/?&=%~#+:@]*$")


def _clean_entry(entry: Any, known_actions: Optional[Iterable[str]] = None) -> tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Validate one playbook; return (clean_entry, None) or (None, error)."""
    if not isinstance(entry, dict):
        return None, "playbook entries must be objects"
    playbook_id = str(entry.get("id") or "")
    if not ID_PATTERN.fullmatch(playbook_id):
        return None, f"invalid playbook id {playbook_id!r}"
    alert_type = str(entry.get("alert_type") or "")
    if not ALERT_TYPE_PATTERN.fullmatch(alert_type):
        return None, f"invalid alert_type {alert_type!r} in playbook {playbook_id!r}"
    title = str(entry.get("title") or "").strip()
    if not title or len(title) > MAX_TITLE:
        return None, f"playbook {playbook_id!r} needs a title of 1..{MAX_TITLE} characters"
    markdown = str(entry.get("markdown") or "").strip()
    if not markdown:
        return None, f"playbook {playbook_id!r} needs a markdown runbook body"
    if len(markdown) > MAX_MARKDOWN:
        return None, f"playbook {playbook_id!r} markdown exceeds {MAX_MARKDOWN} characters"
    actions = entry.get("actions")
    if actions is None:
        actions = []
    if not isinstance(actions, list) or len(actions) > MAX_ACTIONS:
        return None, f"playbook {playbook_id!r} actions must be a list of at most {MAX_ACTIONS}"
    known = set(known_actions) if known_actions else None
    cleaned_actions = []
    for action in actions:
        action = str(action)
        if (known is None and ACTION_PATTERN.fullmatch(action)) or (known is not None and action in known):
            if action not in cleaned_actions:
                cleaned_actions.append(action)
        else:
            return None, f"playbook {playbook_id!r} action {action!r} is not in the safe-action registry"
    links = entry.get("links")
    if links is None:
        links = []
    if not isinstance(links, list) or len(links) > MAX_LINKS:
        return None, f"playbook {playbook_id!r} links must be a list of at most {MAX_LINKS}"
    cleaned_links = []
    for link in links:
        link = str(link)
        if not LINK_PATTERN.fullmatch(link):
            return None, f"playbook {playbook_id!r} link {link!r} must be an http(s) or relative URL"
        if link not in cleaned_links:
            cleaned_links.append(link)
    return {"id": playbook_id, "alert_type": alert_type, "title": title,
            "markdown": markdown, "actions": cleaned_actions, "links": cleaned_links}, None


def load_playbooks(config: Optional[Dict[str, Any]], known_actions: Optional[Iterable[str]] = None) -> List[Dict[str, Any]]:
    """Parse the ``playbooks`` config group, dropping invalid entries."""
    raw = (config or {}).get("playbooks")
    if raw is None:
        return []
    if not isinstance(raw, list):
        return []
    result: List[Dict[str, Any]] = []
    seen = set()
    for entry in raw:
        if len(result) >= MAX_PLAYBOOKS:
            break
        clean, error = _clean_entry(entry, known_actions)
        if clean is None or clean["id"] in seen:
            continue
        seen.add(clean["id"])
        result.append(clean)
    return result


def validate_playbooks(entries: Any) -> None:
    """Strict config validation: raise on the first invalid playbook."""
    if entries is None:
        return
    if not isinstance(entries, list):
        raise ValueError("playbooks must be a list")
    if len(entries) > MAX_PLAYBOOKS:
        raise ValueError(f"at most {MAX_PLAYBOOKS} playbooks are allowed")
    seen = set()
    for entry in entries:
        clean, error = _clean_entry(entry)
        if error:
            raise ValueError(error)
        if clean["id"] in seen:
            raise ValueError(f"duplicate playbook id {clean['id']!r}")
        seen.add(clean["id"])


def match(playbooks: Optional[List[Dict[str, Any]]], alert_type: Optional[str]) -> Optional[Dict[str, Any]]:
    """Best playbook for an alert: exact type first, then type prefix."""
    if not playbooks or not alert_type:
        return None
    for playbook in playbooks:
        if playbook["alert_type"] == alert_type:
            return playbook
    for playbook in playbooks:
        if alert_type.startswith(playbook["alert_type"]):
            return playbook
    return None
