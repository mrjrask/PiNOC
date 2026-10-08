"""Repository model (PiNOC 2.0 Phase 1, P1-R03).

A *repository* is a canonical codebase identified by its remote: the
scp-style ``git@github.com:x/y.git``, ``ssh://``, ``https://``, and
trailing-``.git`` spellings of one remote all normalize to the same
``host/path`` identity, and a *deployment* is one working tree of that
codebase on one device -- the fact PiNOC already discovered but never
connected: *where a given revision is actually deployed*.

Design notes (spec section P1-R03):

* ``repositories`` is keyed by a stable slug plus a UNIQUE
  ``canonical_url``, so every spelling of one remote maps to exactly one
  object. A local path or IP change never creates a duplicate repository,
  and "which devices run this repository?" is answered from the durable
  ``deployments`` table alone -- no live SSH in any page render.
* ``deployments`` holds one working tree per (repository, device, local
  path), so multiple checkouts of one repository on one device are
  separate deployments that can sit on different commits. Each carries
  ``observed_commit_sha``/branch/dirty (what the sources saw) against the
  repository's ``desired_commit_sha``/``desired_branch`` (what the
  operator wants); point-in-time ``deployment_events`` stay in their own
  table, separate from current state, and history maintenance prunes them.
* Deployment state is one of ``clean / dirty / drifted / stale /
  unknown`` -- the spec's five distinguished conditions. The *concrete*
  state is derived from the last observed facts (uncommitted changes
  make it dirty; an observed revision or branch differing from the
  desired one makes it drifted; else clean); *stale* is the freshness
  overlay: once the last *revision* observation is older than
  ``repositories.stale_seconds`` the deployment reports stale while its
  last concrete state is preserved in the reasons -- a failed
  collection never erases the last success. ``unknown`` is a tree that
  is known (path/remote discovered) but whose revision no source has
  ever learned. The repository's own state is the worst rollup of its
  deployments, so one dirty checkout keeps the whole repository off
  "clean".
* Observations arrive through a background refresh thread that performs
  **local reads only** (the phase architecture invariant: no remote work
  in request threads, and no *new* remote work at all -- the underlying
  data flows through existing channels): the device state's
  ``integrations.git`` entries, the latest successful ``git_status``
  development job per approved workspace (its porcelain-v2 output), the
  ``workspaces`` table (operator-approved path+remote pairs), and the
  agent registration's ``candidates_json`` (discovered workspace roots
  with an origin URL). Per deployment the newest observation wins per
  field, and freshness timestamps always move *forward* -- an old source
  never rewinds the clock or clears a learned revision. A canonical URL
  no repository claims is auto-registered from discovery (name from the
  URL's last path segment) -- a collector-equivalent act like the
  ``devices`` table performs, and the one write this service makes
  without an audit row. Every *operator* CRUD operation is audited.
* Deployment to application/instance linkage is inferred
  deterministically from the *application's own* ``repository`` field
  (canonicalized) restricted to instances on the deployment's device.
  An ambiguous claim (two active applications on one remote, or two
  instances of one application on one device) is left unlinked rather
  than guessed -- P1-R08 reconciliation is where inferred links get
  accepted or rejected.
* Read-only by design: Phase 1 has no path into a repository's working
  tree (the spec defers state-changing git work to the Phase 2 job
  controls); the only writes are this service's own registry tables.
  Repository URLs may embed credentials, so every output strips the
  userinfo and passes through the security layer's recursive
  ``redact()`` before it leaves the process.

This module also registers the ``repository`` roster source with the
P1-R01 project registry (it feeds the unassigned-inventory view);
repositories are not health objects, so they contribute member *counts*
to project cards, not rollup states.
"""
from __future__ import annotations

import json
import logging
import re
import threading
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple
from urllib.parse import urlsplit, urlunsplit

from pinoc import projects
from pinoc.database import Database, utcnow
from pinoc.envstates import age_seconds, parse_ts, reason_code

LOG = logging.getLogger("pinoc.repositories")
UTC = timezone.utc

LIFECYCLES = ("planned", "active", "maintenance", "retired", "archived")
# The five deployment conditions the spec requires to be distinguishable.
DEPLOYMENT_STATES = ("clean", "dirty", "drifted", "stale", "unknown")
# Rollup ordering: clean (no problem) < unknown (never verified) <
# stale (information may be out of date) < drifted (on the wrong
# revision) < dirty (uncommitted changes are the most actionable
# condition). The worst of a repository's deployments is its state.
_STATE_RANK = {"clean": 0, "unknown": 1, "stale": 2, "drifted": 3, "dirty": 4}
# Observation sources (see the module docstring for where each one's
# data already comes from); the newest observation wins per field.
SOURCES = ("git_integration", "git_status", "workspaces", "agent_candidates")

# Bounds -- registry metadata is capped like every other PiNOC registry.
MAX_NAME = 200
MAX_DESCRIPTION = 2000
MAX_URL = 1024
MAX_BRANCH = 128
MAX_TECHNOLOGY = 64
MAX_SHA = 64
MAX_PATH = 512
MAX_SERVICE = 128
MAX_OWNER = 100
MAX_TAGS = 50
MAX_TAG_LEN = 100
MAX_SOURCE_PATHS = 50  # per source row, mirrors the fleet's caps
MAX_SCAN_ROWS = 5000   # per-tick bound on source scans


class RepositoryError(ValueError):
    """Validation or lifecycle error; routes map it to 400/404/409."""


class RepositoryNotFound(RepositoryError):
    pass


_SLUG_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?")
_SHA_RE = re.compile(r"[0-9a-fA-F]{7,64}")
_BRANCH_RE = re.compile(r"[A-Za-z0-9._/-]{1,128}")
_HOST_RE = re.compile(r"[A-Za-z0-9._-]+")
_PATH_RE = re.compile(r"[A-Za-z0-9._~/-]+")
_SERVICE_RE = re.compile(r"[A-Za-z0-9._:-]{1,128}")


# -- identity rules ---------------------------------------------------------
#
# The phase-wide identity contract (spec appendix): stable slugs/IDs are
# primary identities; URLs are attributes. But a repository's *natural*
# key is its remote, so the canonical form is the identity: host (lower
# case, explicit port kept) plus path (no userinfo, no credentials, no
# trailing slash, no ``.git`` suffix). ``git@github.com:x/y.git``,
# ``https://github.com/x/y``, and ``ssh://git@github.com/x/y.git`` all
# canonicalize to ``github.com/x/y``.


def canonical_repository_url(value: Any) -> Optional[str]:
    """Normalize a repository remote to its identity, or ``None`` when the
    value is not a repository URL at all (free text, a local path, or an
    unparseable URL must never invent a repository)."""
    text = str(value or "").strip()
    if not text or " " in text or "\t" in text or "\n" in text:
        return None
    if "://" in text:
        parsed = urlsplit(text)
        if parsed.scheme not in ("http", "https", "git", "ssh"):
            return None
        host = (parsed.hostname or "").lower()
        if not host:
            return None
        if parsed.port:
            host = f"{host}:{parsed.port}"
        path = (parsed.path or "").strip("/")
        if path.endswith(".git"):
            path = path[:-4]
        if not path or "//" in path:
            return None
        return f"{host}/{path}"
    # scp-style [user@]host:path -- partition on the first colon; the path
    # must be a plain forward-slash path (this rejects ``C:\...`` drives
    # and any other colon confusion), the host a plain DNS label.
    head, sep, path = text.partition(":")
    if not sep or not path:
        return None
    host = head.rsplit("@", 1)[-1].lower()
    if not _HOST_RE.fullmatch(host):
        return None
    path = path.strip("/")
    if path.endswith(".git"):
        path = path[:-4]
    if not path or not _PATH_RE.fullmatch(path):
        return None
    return f"{host}/{path}"


def display_repository_url(value: Any) -> Optional[str]:
    """A remote URL with any embedded credentials stripped, for display.
    ``https://user:pass@host/repo`` shows as ``https://host/repo``; the
    scp form drops the ``user@`` prefix. (Defense in depth -- the web
    layer additionally redacts everything.)"""
    text = str(value or "").strip()
    if not text:
        return None
    if "://" in text:
        parsed = urlsplit(text)
        if parsed.netloc and "@" in parsed.netloc:
            parsed = parsed._replace(netloc=parsed.netloc.rsplit("@", 1)[1])
            return urlunsplit(parsed)
        return text
    head, sep, path = text.partition(":")
    if sep and "@" in head:
        return head.rsplit("@", 1)[1] + ":" + path
    return text


def _parse_ab(value: Any) -> Optional[int]:
    """Parse a ``# branch.ab`` token: ``+3`` -> 3, ``~1`` -> 1, ``-``
    (no upstream) -> None."""
    token = str(value or "").strip().lstrip("+-~")
    if not token.isdigit():
        return None
    number = int(token)
    return number if number < 100000 else None


def parse_git_status_v2(stdout: Any) -> Dict[str, Any]:
    """Parse ``git status --porcelain=v2 --branch`` output (the output of
    the dev gateway's ``git_status`` read) into branch/revision/dirty
    facts. Any field left ``None`` was *not learned* -- empty or failed
    output must never be mistaken for a clean tree."""
    result: Dict[str, Any] = {"branch": None, "sha": None,
                              "ahead": None, "behind": None, "dirty": None}
    if not isinstance(stdout, str) or not stdout.strip():
        return result
    saw_header = False
    saw_entry = False
    for line in stdout.splitlines()[:1000]:  # bounded; a status output is small
        if not line.strip():
            continue
        if line.startswith("#"):
            saw_header = True
            if line.startswith("# branch.head "):
                result["branch"] = line.split(None, 2)[-1].strip()[:MAX_BRANCH] or None
            elif line.startswith("# branch.oid "):
                result["sha"] = line.split(None, 2)[-1].strip()[:MAX_SHA] or None
            elif line.startswith("# branch.ab "):
                parts = line.split()
                if len(parts) >= 3:
                    result["ahead"] = _parse_ab(parts[2])
                    if len(parts) > 3:
                        result["behind"] = _parse_ab(parts[3])
        else:
            saw_entry = True  # any file entry means an uncommitted change
    if saw_header or saw_entry:
        result["dirty"] = saw_entry
    return result


def _git_integration_entries(value: Any) -> List[Dict[str, Any]]:
    """Coerce the shapes device state's ``integrations.git`` may take into
    entry dicts (the ``pinoc.integrations.git.normalize`` contract:
    path/branch/commit/dirty/remote_url/...). Lenient by design: an
    unrecognized shape yields nothing and never raises -- a future agent
    or plugin may report any of them."""
    if value is None:
        return []
    if isinstance(value, dict):
        if isinstance(value.get("data"), (dict, list)):
            value = value.get("data")  # an IntegrationStatus wrapper nests its payload
        elif isinstance(value.get("repositories"), (dict, list)):
            value = value.get("repositories")
        elif isinstance(value.get("git"), (dict, list)):
            value = value.get("git")
        else:
            value = [value]  # one bare entry
    if isinstance(value, dict):
        value = [value]
    if not isinstance(value, list):
        return []
    entries: List[Dict[str, Any]] = []
    for entry in value[:MAX_SOURCE_PATHS]:
        if not isinstance(entry, dict):
            continue
        path = str(entry.get("path") or "").strip()
        url = entry.get("remote_url") or entry.get("remote") or entry.get("repository")
        if path and url:
            entries.append(entry)
    return entries


def slugify(name: str) -> str:
    """Derive a stable slug (a repository's default slug is its URL's
    last path segment)."""
    return projects.slugify(name)


def _load_tags(raw: Any) -> List[str]:
    if raw is None:
        return []
    if isinstance(raw, str):
        raw = [part.strip() for part in raw.split(",")]
    if not isinstance(raw, list):
        raise RepositoryError("tags must be a list (or comma-separated string)")
    values = [str(item).strip() for item in raw if str(item).strip()]
    if len(values) > MAX_TAGS:
        raise RepositoryError(f"tags may hold at most {MAX_TAGS} entries")
    if any(len(value) > MAX_TAG_LEN for value in values):
        raise RepositoryError(f"tags may be at most {MAX_TAG_LEN} characters")
    return values


def _unique_slug(base: str, taken: Sequence[str]) -> str:
    if base not in taken:
        return base
    for index in range(2, 100):
        candidate = f"{base}-{index}"
        if candidate not in taken:
            return candidate
    raise RepositoryError("cannot derive a unique slug for this name")


def _loads_list(raw: Any) -> List[Any]:
    if raw is None:
        return []
    try:
        value = json.loads(raw)
    except (TypeError, ValueError):
        return []
    return value if isinstance(value, list) else []


def _ts_value(value: Any, now: datetime) -> float:
    """A timestamp as a comparable float (epoch seconds); missing or
    unparseable values sort as the oldest possible."""
    parsed = parse_ts(value) if value else None
    if parsed is None:
        return 0.0
    return parsed.timestamp()


def _load_sha(value: Any, field: str) -> Optional[str]:
    if value is None or value == "":
        return None
    text = str(value).strip()[:MAX_SHA]
    if not _SHA_RE.fullmatch(text):
        raise RepositoryError(f"{field} must be a 7-64 character hex commit SHA")
    return text.lower()


def _clean_branch(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()[:MAX_BRANCH]
    if not text or not _BRANCH_RE.fullmatch(text):
        return None
    return text


def _clean_sha(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()[:MAX_SHA]
    if not _SHA_RE.fullmatch(text):
        return None
    return text.lower()


def _bounded_int(value: Any) -> Optional[int]:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    return number if -100000 <= number < 100000 else None


# -- service -----------------------------------------------------------------


class RepositoryService:
    """CRUD for the repository/deployment registries plus the background
    source refresh that keeps deployments current.

    ``db`` is the shared history :class:`~pinoc.database.Database` (the
    service degrades to empty reads, never raises, when it is absent or
    unavailable -- the same contract every other PiNOC service keeps);
    ``state`` is the shared :class:`~pinoc.state.PiNOCState` (live device
    state, source of the ``integrations.git`` observations); ``history``
    is the HistoryManager (retention for deployment events); ``config``
    is the top-level ``repositories`` configuration section; ``audit``
    records every operator state-changing operation; ``redact``
    neutralizes secret material before anything leaves the process.
    """

    def __init__(self, db: Optional[Database] = None, state: Any = None,
                 history: Any = None, config: Optional[Dict[str, Any]] = None,
                 audit: Optional[Callable[..., Any]] = None,
                 redact: Optional[Callable[[Any], Any]] = None) -> None:
        cfg = config or {}
        self.db = db
        self.state = state
        self.history = history
        self.audit = audit
        self.redact = redact if redact is not None else (lambda value: value)
        self.enabled = bool(cfg.get("enabled", True))
        self.refresh_seconds = max(5.0, float(cfg.get("refresh_seconds", 300)))
        self.stale_seconds = max(60.0, float(cfg.get("stale_seconds", 86400)))
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self._run, name="pinoc-repositories", daemon=True)

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
                LOG.exception("repository source refresh failed")
            self.stop_event.wait(self.refresh_seconds)

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

    def _device_info(self) -> Dict[str, Dict[str, Any]]:
        devices = self._devices()
        if devices:
            return {device_id: {"id": device_id,
                                "hostname": device.get("hostname"),
                                "friendly_name": device.get("friendly_name"),
                                "online": bool(device.get("online"))}
                    for device_id, device in devices.items()}
        if self._available():
            return {row["device_id"]: {"id": row["device_id"], "hostname": row.get("hostname"),
                                       "friendly_name": row.get("friendly_name"),
                                       "online": False}
                    for row in self.db.rows("SELECT device_id,hostname,friendly_name FROM devices")}
        return {}

    # -- row codecs -----------------------------------------------------------
    @staticmethod
    def _decode_repo(row: Dict[str, Any]) -> Dict[str, Any]:
        try:
            tags = json.loads(row.get("tags_json") or "[]")
            reasons = json.loads(row.get("state_reasons_json") or "[]")
        except (TypeError, ValueError):
            tags, reasons = [], []
        return {
            "id": row["slug"],
            "repo_id": row["repo_id"],
            "slug": row["slug"],
            "name": row["name"],
            "description": row.get("description") or "",
            "canonical_url": row["canonical_url"],
            "remote_url": display_repository_url(row.get("remote_url")) or None,
            "default_branch": row.get("default_branch") or None,
            "technology": row.get("technology") or None,
            "project": row.get("project_slug"),
            "owner": row.get("owner") or None,
            "tags": tags,
            "lifecycle": row["lifecycle"],
            "archived": row["lifecycle"] == "archived",
            "desired_commit_sha": row.get("desired_commit_sha") or None,
            "desired_branch": row.get("desired_branch") or None,
            "state": row.get("state") or "unknown",
            "state_reasons": reasons,
            "last_observed_at": row.get("last_observed_at"),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "archived_at": row.get("archived_at"),
            "archived_reason": row.get("archived_reason") or None,
        }

    @staticmethod
    def _decode_deployment(row: Dict[str, Any]) -> Dict[str, Any]:
        try:
            reasons = json.loads(row.get("state_reasons_json") or "[]")
        except (TypeError, ValueError):
            reasons = []
        sha = row.get("observed_commit_sha")
        return {
            "id": row["deployment_id"],
            "deployment_id": row["deployment_id"],
            "repository": row["repo_slug"],
            "local_path": row.get("local_path") or "",
            "application": row.get("application_slug"),
            "instance_id": row.get("instance_id"),
            "service": row.get("service") or None,
            "branch": row.get("branch") or None,
            "observed_commit_sha": sha,
            "observed_short_sha": (sha or "")[:7] or None,
            "dirty": bool(row.get("dirty")),
            "ahead": row.get("ahead"),
            "behind": row.get("behind"),
            "state": row.get("state") or "unknown",
            "state_reasons": reasons,
            "source": row.get("source") or None,
            "last_seen_at": row.get("last_seen_at"),
            "last_observed_at": row.get("last_observed_at"),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def _fetch(self, repo_id: Any) -> Optional[Dict[str, Any]]:
        if not self._available():
            return None
        key = str(repo_id).strip()
        column = "repo_id" if key.isdigit() else "slug"
        rows = self.db.rows(f"SELECT * FROM repositories WHERE {column}=?", (key,))
        return self._decode_repo(rows[0]) if rows else None

    def _require(self, repo_id: Any) -> Dict[str, Any]:
        row = self._fetch(repo_id)
        if row is None:
            raise RepositoryNotFound(f"repository {repo_id!r} not found")
        return row

    def _fetch_deployment(self, deployment_id: Any) -> Optional[Dict[str, Any]]:
        if not self._available():
            return None
        key = str(deployment_id).strip()
        if not key.isdigit():
            return None
        rows = self.db.rows("SELECT * FROM deployments WHERE deployment_id=?", (key,))
        if not rows:
            return None
        deployment = self._decode_deployment(rows[0])
        deployment["device"] = self._device_info().get(rows[0]["device_id"])
        return deployment

    def _require_deployment(self, deployment_id: Any) -> Dict[str, Any]:
        row = self._fetch_deployment(deployment_id)
        if row is None:
            raise RepositoryNotFound(f"deployment {deployment_id!r} not found")
        return row

    # -- repository CRUD -------------------------------------------------------
    def list(self, include_archived: bool = False, lifecycle: Optional[str] = None,
             project: Optional[str] = None, state: Optional[str] = None) -> List[Dict[str, Any]]:
        if not self._available():
            return []
        where, args = ["1=1"], []
        if not include_archived:
            where.append("lifecycle <> 'archived'")
        if lifecycle:
            if lifecycle not in LIFECYCLES:
                raise RepositoryError(f"lifecycle must be one of {', '.join(LIFECYCLES)}")
            where.append("lifecycle = ?")
            args.append(lifecycle)
        if project:
            where.append("project_slug = ?")
            args.append(str(project).strip())
        if state:
            if state not in DEPLOYMENT_STATES:
                raise RepositoryError(f"state must be one of {', '.join(DEPLOYMENT_STATES)}")
            where.append("state = ?")
            args.append(state)
        rows = self.db.rows("SELECT * FROM repositories WHERE " + " AND ".join(where) +
                            " ORDER BY name", tuple(args))
        repos = [self._decode_repo(row) for row in rows]
        if repos:
            slugs = [repo["id"] for repo in repos]
            placeholders = ",".join("?" * len(slugs))
            counts: Dict[str, int] = {}
            for row in self.db.rows(
                    f"SELECT repo_slug,COUNT(*) AS count FROM deployments "
                    f"WHERE repo_slug IN ({placeholders}) GROUP BY repo_slug", tuple(slugs)):
                counts[row["repo_slug"]] = row["count"]
            for repo in repos:
                repo["deployment_count"] = counts.get(repo["id"], 0)
        return repos

    def get(self, repo_id: Any) -> Optional[Dict[str, Any]]:
        repo = self._fetch(repo_id)
        if repo is None:
            return None
        result = dict(repo)
        result["deployments"] = self._deployments_for([repo["id"]])
        return result

    def create(self, payload: Dict[str, Any], actor: str = "system") -> Dict[str, Any]:
        if not self._available():
            raise RepositoryError("history database is unavailable")
        if not isinstance(payload, dict):
            raise RepositoryError("payload must be an object")
        name = str(payload.get("name") or "").strip()
        if not name or len(name) > MAX_NAME:
            raise RepositoryError("name is required (max 200 characters)")
        url = str(payload.get("url") or "").strip()[:MAX_URL]
        canonical = canonical_repository_url(url)
        if not canonical:
            raise RepositoryError("url must be a repository remote "
                                  "(https://host/path, git@host:path, ssh://, or git://)")
        if self.db.rows("SELECT repo_id FROM repositories WHERE canonical_url=?", (canonical,)):
            raise RepositoryError(f"a repository for {canonical!r} already exists")
        slug = str(payload.get("slug") or "").strip().lower() or slugify(canonical.rsplit("/", 1)[-1])
        if not _SLUG_RE.fullmatch(slug):
            raise RepositoryError("slug must be a simple lowercase identifier (letters, digits, dashes)")
        taken = [row["slug"] for row in self.db.rows("SELECT slug FROM repositories")]
        if slug in taken:
            raise RepositoryError(f"slug {slug!r} is already taken")
        lifecycle = str(payload.get("lifecycle") or "active").strip().lower()
        if lifecycle not in LIFECYCLES or lifecycle == "archived":
            raise RepositoryError(
                f"lifecycle must be one of {', '.join(LIFECYCLES[:-1])} (archiving is an operation)")
        technology = str(payload.get("technology") or "").strip()[:MAX_TECHNOLOGY] or None
        branch = str(payload.get("default_branch") or "").strip()[:MAX_BRANCH] or None
        if branch and not _BRANCH_RE.fullmatch(branch):
            raise RepositoryError("default_branch must be a simple branch name")
        desired_sha = _load_sha(payload.get("desired_commit_sha"), "desired_commit_sha")
        desired_branch = str(payload.get("desired_branch") or "").strip()[:MAX_BRANCH] or None
        if desired_branch and not _BRANCH_RE.fullmatch(desired_branch):
            raise RepositoryError("desired_branch must be a simple branch name")
        project_slug = str(payload.get("project") or "").strip() or None
        if project_slug and not self.db.rows(
                "SELECT project_id FROM projects WHERE slug=?", (project_slug,)):
            raise RepositoryError(f"project {project_slug!r} not found")
        description = str(payload.get("description") or "")[:MAX_DESCRIPTION]
        owner = str(payload.get("owner") or "").strip()[:MAX_OWNER] or None
        tags = _load_tags(payload.get("tags"))
        stamp = utcnow()
        repo_id = self.db.execute(
            "INSERT INTO repositories(slug,name,description,canonical_url,remote_url,"
            "default_branch,technology,project_slug,owner,tags_json,lifecycle,"
            "desired_commit_sha,desired_branch,state,state_reasons_json,created_at,updated_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,'unknown','[]',?,?)",
            (slug, name, description, canonical, url, branch, technology, project_slug,
             owner, json.dumps(tags), lifecycle, desired_sha, desired_branch, stamp, stamp))
        self._audit(actor, "repository.create", slug,
                    {"canonical_url": canonical, "lifecycle": lifecycle,
                     "desired_commit_sha": desired_sha, "desired_branch": desired_branch})
        return self._decode_repo(self.db.rows(
            "SELECT * FROM repositories WHERE repo_id=?", (repo_id,))[0])

    def update(self, repo_id: Any, payload: Dict[str, Any], actor: str = "system") -> Dict[str, Any]:
        if not self._available():
            raise RepositoryError("history database is unavailable")
        current = self._require(repo_id)
        if current["lifecycle"] == "archived":
            raise RepositoryError("repository is archived and read-only; restore it before editing")
        if not isinstance(payload, dict):
            raise RepositoryError("payload must be an object")
        fields: List[str] = []
        values: List[Any] = []
        audit_params: Dict[str, Any] = {}
        if "name" in payload:
            name = str(payload["name"] or "").strip()
            if not name or len(name) > MAX_NAME:
                raise RepositoryError("name must be 1-200 characters")
            fields.append("name=?")
            values.append(name)
            audit_params["name"] = name
        if "url" in payload:
            # The canonical URL is the identity: a different remote is a
            # *different* repository (R08 reconciliation merges those),
            # so this field may only re-spell the same remote.
            canonical = canonical_repository_url(payload["url"])
            if not canonical:
                raise RepositoryError("url must be a repository remote")
            if canonical != current["canonical_url"]:
                raise RepositoryError("the remote URL is this repository's identity; "
                                      "a different remote is a different repository")
            fields.append("remote_url=?")
            values.append(str(payload["url"]).strip()[:MAX_URL] or None)
        if "description" in payload:
            fields.append("description=?")
            values.append(str(payload["description"] or "")[:MAX_DESCRIPTION])
            audit_params["description"] = values[-1]
        if "default_branch" in payload:
            branch = str(payload["default_branch"] or "").strip()[:MAX_BRANCH] or None
            if branch and not _BRANCH_RE.fullmatch(branch):
                raise RepositoryError("default_branch must be a simple branch name")
            fields.append("default_branch=?")
            values.append(branch)
            audit_params["default_branch"] = branch
        if "technology" in payload:
            tech = str(payload["technology"] or "").strip()[:MAX_TECHNOLOGY] or None
            fields.append("technology=?")
            values.append(tech)
            audit_params["technology"] = tech
        if "project" in payload:
            project_slug = str(payload["project"] or "").strip() or None
            if project_slug and not self.db.rows(
                    "SELECT project_id FROM projects WHERE slug=?", (project_slug,)):
                raise RepositoryError(f"project {project_slug!r} not found")
            fields.append("project_slug=?")
            values.append(project_slug)
            audit_params["project"] = project_slug
        if "owner" in payload:
            owner = str(payload["owner"] or "").strip()[:MAX_OWNER] or None
            fields.append("owner=?")
            values.append(owner)
            audit_params["owner"] = owner
        if "tags" in payload:
            tags = _load_tags(payload["tags"])
            fields.append("tags_json=?")
            values.append(json.dumps(tags))
            audit_params["tags"] = tags
        if "desired_commit_sha" in payload:
            sha = _load_sha(payload["desired_commit_sha"], "desired_commit_sha")
            fields.append("desired_commit_sha=?")
            values.append(sha)
            if sha != current["desired_commit_sha"]:
                self._audit(actor, "repository.desired_revision", current["id"],
                            {"old": current["desired_commit_sha"], "new": sha})
        if "desired_branch" in payload:
            branch = str(payload["desired_branch"] or "").strip()[:MAX_BRANCH] or None
            if branch and not _BRANCH_RE.fullmatch(branch):
                raise RepositoryError("desired_branch must be a simple branch name")
            fields.append("desired_branch=?")
            values.append(branch)
            if branch != current["desired_branch"]:
                self._audit(actor, "repository.desired_branch", current["id"],
                            {"old": current["desired_branch"], "new": branch})
        if "lifecycle" in payload:
            lifecycle = str(payload["lifecycle"] or "").strip().lower()
            if lifecycle not in LIFECYCLES or lifecycle == "archived":
                raise RepositoryError(
                    f"lifecycle must be one of {', '.join(LIFECYCLES[:-1])} (archiving is an operation)")
            fields.append("lifecycle=?")
            values.append(lifecycle)
            if lifecycle != current["lifecycle"]:
                self._audit(actor, "repository.lifecycle", current["id"],
                            {"old": current["lifecycle"], "new": lifecycle})
        if not fields:
            return current
        stamp = utcnow()
        values.append(stamp)
        values.append(int(current["repo_id"]))
        self.db.execute(
            f"UPDATE repositories SET {', '.join(fields)},updated_at=? WHERE repo_id=?",
            tuple(values))
        if audit_params:
            self._audit(actor, "repository.update", current["id"], audit_params)
        row = self.db.rows("SELECT * FROM repositories WHERE repo_id=?",
                           (int(current["repo_id"]),))[0]
        return self._decode_repo(row)

    def archive(self, repo_id: Any, actor: str = "system", reason: str = "") -> Dict[str, Any]:
        current = self._require(repo_id)
        if current["lifecycle"] == "archived":
            return current  # idempotent: no duplicate audit row
        stamp = utcnow()
        self.db.execute(
            "UPDATE repositories SET lifecycle='archived',archived_at=?,archived_reason=?,"
            "updated_at=? WHERE repo_id=?",
            (stamp, reason[:MAX_DESCRIPTION] or None, stamp, int(current["repo_id"])))
        self._audit(actor, "repository.archive", current["id"], {"reason": reason or None})
        row = self.db.rows("SELECT * FROM repositories WHERE repo_id=?",
                           (int(current["repo_id"]),))[0]
        return self._decode_repo(row)

    def restore(self, repo_id: Any, actor: str = "system") -> Dict[str, Any]:
        current = self._require(repo_id)
        if current["lifecycle"] != "archived":
            raise RepositoryError("only archived repositories can be restored")
        stamp = utcnow()
        self.db.execute(
            "UPDATE repositories SET lifecycle='active',archived_at=NULL,archived_reason=NULL,"
            "updated_at=? WHERE repo_id=?", (stamp, int(current["repo_id"])))
        self._audit(actor, "repository.restore", current["id"], {})
        row = self.db.rows("SELECT * FROM repositories WHERE repo_id=?",
                           (int(current["repo_id"]),))[0]
        return self._decode_repo(row)

    # -- deployments -------------------------------------------------------------
    def _deployments_for(self, repo_slugs: Sequence[str]) -> List[Dict[str, Any]]:
        rows = self.db.rows(
            f"SELECT * FROM deployments WHERE repo_slug IN ({','.join('?' * len(repo_slugs))}) "
            "ORDER BY device_id,local_path", tuple(repo_slugs))
        devices = self._device_info()
        result = []
        for row in rows:
            deployment = self._decode_deployment(row)
            deployment["device"] = devices.get(row["device_id"])
            result.append(deployment)
        return result

    def deployments(self, repository: Optional[str] = None, device: Optional[str] = None,
                    project: Optional[str] = None, application: Optional[str] = None,
                    state: Optional[str] = None) -> List[Dict[str, Any]]:
        if not self._available():
            return []
        where, args = ["1=1"], []
        if repository:
            key = str(repository).strip()
            if key.isdigit():
                where.append("d.repo_slug=(SELECT slug FROM repositories WHERE repo_id=?)")
                args.append(key)
            else:
                where.append("d.repo_slug=?")
                args.append(key)
        if device:
            where.append("d.device_id=?")
            args.append(str(device).strip())
        if project:
            where.append("r.project_slug=?")
            args.append(str(project).strip())
        if application:
            where.append("d.application_slug=?")
            args.append(str(application).strip())
        if state:
            if state not in DEPLOYMENT_STATES:
                raise RepositoryError(f"state must be one of {', '.join(DEPLOYMENT_STATES)}")
            where.append("d.state=?")
            args.append(state)
        rows = self.db.rows(
            "SELECT d.* FROM deployments d JOIN repositories r ON r.slug=d.repo_slug "
            "WHERE " + " AND ".join(where) + " ORDER BY d.device_id,d.local_path", tuple(args))
        devices = self._device_info()
        result = []
        for row in rows:
            deployment = self._decode_deployment(row)
            deployment["device"] = devices.get(row["device_id"])
            result.append(deployment)
        return result

    def deployment(self, deployment_id: Any) -> Optional[Dict[str, Any]]:
        return self._fetch_deployment(deployment_id)

    def update_deployment(self, deployment_id: Any, payload: Dict[str, Any],
                          actor: str = "system") -> Dict[str, Any]:
        if not self._available():
            raise RepositoryError("history database is unavailable")
        current = self._require_deployment(deployment_id)
        if not isinstance(payload, dict):
            raise RepositoryError("payload must be an object")
        # Only operator *annotations* are writable; every observation
        # field (path, revision, dirty, source) is owned by the sources.
        fields: List[str] = []
        values: List[Any] = []
        audit_params: Dict[str, Any] = {}
        if "service" in payload:
            service = str(payload["service"] or "").strip()[:MAX_SERVICE] or None
            if service and not _SERVICE_RE.fullmatch(service):
                raise RepositoryError("service must be a simple identifier (unit name)")
            fields.append("service=?")
            values.append(service)
            audit_params["service"] = service
        if "application" in payload:
            app_slug = str(payload["application"] or "").strip().lower() or None
            if app_slug:
                if not _SLUG_RE.fullmatch(app_slug):
                    raise RepositoryError("application must be a valid application slug")
                if not self.db.rows("SELECT app_id FROM applications WHERE slug=?", (app_slug,)):
                    raise RepositoryError(f"application {app_slug!r} not found")
            fields.append("application_slug=?")
            values.append(app_slug)
            audit_params["application"] = app_slug
        if not fields:
            return current
        stamp = utcnow()
        values.append(stamp)
        values.append(int(current["deployment_id"]))
        self.db.execute(
            f"UPDATE deployments SET {', '.join(fields)},updated_at=? WHERE deployment_id=?",
            tuple(values))
        self._audit(actor, "deployment.update", str(current["deployment_id"]), audit_params)
        return self._require_deployment(deployment_id)

    def project_software(self, project_id: Any) -> Dict[str, Any]:
        """The project software view: the project's repositories and their
        deployments grouped by application (spec: "the project software
        endpoint groups deployments by application")."""
        if not self._available():
            raise RepositoryError("repository registry is not available")
        key = str(project_id).strip()
        column = "project_id" if key.isdigit() else "slug"
        rows = self.db.rows(
            f"SELECT project_id,slug,name,lifecycle FROM projects WHERE {column}=?", (key,))
        if not rows:
            raise RepositoryNotFound(f"project {project_id!r} not found")
        project = rows[0]
        # The project's repositories: declared membership plus repositories
        # whose project pointer says the same thing (both spellings exist;
        # the union is the set of truth).
        member_slugs = {row["object_id"] for row in self.db.rows(
            "SELECT object_id FROM project_members WHERE project_id=? AND kind='repository' "
            "AND removed_at IS NULL", (project["project_id"],))}
        direct_slugs = {row["slug"] for row in self.db.rows(
            "SELECT slug FROM repositories WHERE project_slug=?", (project["slug"],))}
        slugs = sorted((member_slugs | direct_slugs) - {None})
        existing = {row["slug"] for row in self.db.rows(
            f"SELECT slug FROM repositories WHERE slug IN ({','.join('?' * max(len(slugs), 1))})",
            tuple(slugs))} if slugs else set()
        repos: List[Dict[str, Any]] = []
        if slugs:
            for row in self.db.rows(
                    f"SELECT * FROM repositories WHERE slug IN ({','.join('?' * len(slugs))}) "
                    "ORDER BY name", tuple(slugs)):
                if row["slug"] not in existing:
                    continue
                repo = self._decode_repo(row)
                count_rows = self.db.rows(
                    "SELECT COUNT(*) AS count FROM deployments WHERE repo_slug=?",
                    (row["slug"],))
                repo["deployment_count"] = count_rows[0]["count"] if count_rows else 0
                repos.append(repo)
        deployments = self._deployments_for(slugs) if slugs else []
        apps = {row["slug"]: row.get("name") for row in self.db.rows(
            "SELECT slug,name FROM applications")}
        groups: Dict[Optional[str], List[Dict[str, Any]]] = {}
        for deployment in deployments:
            groups.setdefault(deployment["application"], []).append(deployment)
        ordered: List[Dict[str, Any]] = []
        for app_slug in sorted(groups, key=lambda item: (item is None, item or "")):
            ordered.append({
                "application": app_slug,
                "application_name": apps.get(app_slug) if app_slug else None,
                "deployment_count": len(groups[app_slug]),
                "deployments": groups[app_slug],
            })
        return {
            "project": {"id": project["slug"], "name": project["name"],
                        "lifecycle": project["lifecycle"]},
            "repositories": repos,
            "groups": ordered,
        }

    # -- source refresh (background thread only; local reads) -------------------
    def tick(self, now: Optional[datetime] = None) -> Dict[str, Any]:
        """One source refresh + full state re-derivation. Called by the
        background thread on ``refresh_seconds`` cadence and by tests
        directly; it is all local reads plus this service's own tables."""
        if not self._available():
            return {"status": "unavailable"}
        now = now or datetime.now(UTC)
        stamp = now.isoformat()
        observations = self._collect_observations(now)
        auto_registered = 0
        for (canonical, device_id, path), obs in sorted(observations.items()):
            try:
                if self._apply_observation(canonical, device_id, path, obs, now, stamp):
                    auto_registered += 1
            except Exception:
                LOG.exception("repository observation failed (%s)", canonical)
        state_changes = self._rederive_states(now, stamp)
        return {"status": "ok", "observations": len(observations),
                "auto_registered": auto_registered, "state_changes": state_changes}

    def _collect_observations(self, now: datetime) -> Dict[Tuple[str, str, str], Dict[str, Any]]:
        """Merge every local source into per-deployment observations.

        All inputs are local reads: device state (in-memory cache), the
        agents/workspaces/development_jobs tables -- the remote work was
        done by the agent, the fleet, and the (operator-approved)
        development jobs that produced them.
        """
        observations: Dict[Tuple[str, str, str], Dict[str, Any]] = {}

        def add(canonical: Optional[str], device_id: Any, path: Any, source: str,
                observed_at: Any, **fields: Any) -> None:
            if not canonical or not device_id or not path:
                return
            key = (canonical, str(device_id), str(path)[:MAX_PATH])
            raw = str(observed_at).strip() if observed_at else ""
            obs: Dict[str, Any] = {field: value for field, value in fields.items()
                                   if value is not None}
            obs.update({"source": source, "observed_at": raw,
                        "_ts": _ts_value(raw, now) if raw else 0.0})
            existing = observations.get(key)
            if existing is None:
                observations[key] = obs
                return
            # Newest observation wins per field; on ties a field the
            # incumbent already knows keeps its value.
            if obs["_ts"] > existing["_ts"]:
                existing.update(obs)
            elif obs["_ts"] == existing["_ts"]:
                for field, value in obs.items():
                    if field != "source" and existing.get(field) is None:
                        existing[field] = value

        devices = self._devices()
        # 1) live device state: integrations.git entries (the richest
        #    source: branch, SHA, dirty, ahead/behind) when whatever
        #    feeds it reports them.
        for device in devices.values():
            entries = _git_integration_entries((device.get("integrations") or {}).get("git"))
            if not entries:
                continue
            observed_at = device.get("last_seen") or now.isoformat()
            for entry in entries:
                add(canonical_repository_url(entry.get("remote_url")
                                             or entry.get("remote") or entry.get("repository")),
                    device.get("id"), entry.get("path"), "git_integration", observed_at,
                    branch=_clean_branch(entry.get("branch")),
                    observed_commit_sha=_clean_sha(entry.get("commit") or entry.get("short_commit")),
                    dirty=bool(entry["dirty"]) if entry.get("dirty") is not None else None,
                    ahead=_bounded_int(entry.get("ahead")),
                    behind=_bounded_int(entry.get("behind")),
                    remote_url=entry.get("remote_url"))
        # 2) the latest successful git_status development job per workspace
        #    (porcelain-v2 output parsed into branch/SHA/dirty).
        rows = self.db.rows(
            "SELECT j.device_id, w.path, w.repository, j.stdout, j.completed_at "
            "FROM development_jobs j JOIN workspaces w ON w.workspace_id=j.workspace_id "
            "WHERE j.job_type='git_status' AND j.status='succeeded' AND j.exit_code=0 AND "
            "j.completed_at=(SELECT MAX(j2.completed_at) FROM development_jobs j2 "
            "WHERE j2.job_type='git_status' AND j2.status='succeeded' "
            "AND j2.workspace_id=j.workspace_id) "
            f"ORDER BY j.completed_at DESC LIMIT {MAX_SCAN_ROWS}")
        for row in rows:
            parsed = parse_git_status_v2(row["stdout"])
            add(canonical_repository_url(row["repository"]), row["device_id"], row["path"],
                "git_status", row["completed_at"],
                branch=parsed["branch"], observed_commit_sha=parsed["sha"], dirty=parsed["dirty"],
                ahead=parsed["ahead"], behind=parsed["behind"],
                remote_url=row["repository"])
        # 3) operator-approved development workspaces (path + remote URL).
        for row in self.db.rows(
                "SELECT device_id,path,repository,updated_at FROM workspaces "
                "WHERE repository IS NOT NULL AND repository<>'' "
                f"LIMIT {MAX_SCAN_ROWS}"):
            add(canonical_repository_url(row["repository"]), row["device_id"], row["path"],
                "workspaces", row["updated_at"], remote_url=row["repository"])
        # 4) agent registration candidates (discovered workspace roots;
        #    path + origin URL only -- the remote discovery path).
        for row in self.db.rows(
                "SELECT device_id,candidates_json,last_seen FROM agents "
                f"WHERE enabled=1 AND credential_revoked=0 LIMIT {MAX_SCAN_ROWS}"):
            for candidate in _loads_list(row.get("candidates_json"))[:MAX_SOURCE_PATHS]:
                if not isinstance(candidate, dict):
                    continue
                url = candidate.get("repository")
                if url is False or not url:
                    continue  # a checkout without an origin cannot be canonicalized
                add(canonical_repository_url(url), row["device_id"], candidate.get("path"),
                    "agent_candidates", row.get("last_seen"), remote_url=str(url))
        return observations

    def _apply_observation(self, canonical: str, device_id: str, path: str,
                           obs: Dict[str, Any], now: datetime, stamp: str) -> bool:
        """Upsert one deployment from one merged observation. Returns True
        when the observation required auto-registering a new repository.
        Freshness timestamps only move forward and learned revision facts
        are only ever replaced by *newer* observations -- an old source
        can confirm a tree still exists (last_seen) but cannot rewind
        its revision or dirty state."""
        created = self._find_or_create_repository(canonical, obs.get("remote_url"), stamp)
        if created is None:
            return False
        repo_slug, new_repo = created
        branch = _clean_branch(obs.get("branch"))
        sha = _clean_sha(obs.get("observed_commit_sha"))
        dirty = obs.get("dirty")
        ahead = _bounded_int(obs.get("ahead"))
        behind = _bounded_int(obs.get("behind"))
        has_revision = any(value is not None for value in (branch, sha, dirty, ahead, behind))
        app_slug, instance_id = self._application_link(canonical, device_id)
        existing = self.db.rows(
            "SELECT * FROM deployments WHERE repo_slug=? AND device_id=? AND local_path=?",
            (repo_slug, device_id, path))
        observed_at = obs.get("observed_at") or stamp
        observed_ts = obs.get("_ts") or _ts_value(observed_at, now)
        if existing:
            row = existing[0]
            fields: List[str] = []
            values: List[Any] = []
            stored_seen_ts = _ts_value(row.get("last_seen_at"), now)
            if observed_ts > stored_seen_ts:
                fields.append("last_seen_at=?")
                values.append(observed_at)
            stored_rev_ts = _ts_value(row.get("last_observed_at"), now)
            # The source label follows the newest contributor, so an old
            # source cannot relabel a deployment a newer one owns.
            if observed_ts >= max(stored_seen_ts, stored_rev_ts) and observed_ts > 0:
                fields.append("source=?")
                values.append(obs.get("source") or "agent_candidates")
            if has_revision and observed_ts >= stored_rev_ts and observed_ts > 0:
                fields.append("last_observed_at=?")
                values.append(observed_at)
                for column, value in (("branch", branch), ("observed_commit_sha", sha),
                                      ("dirty", dirty), ("ahead", ahead), ("behind", behind)):
                    if value is None:
                        continue  # this source did not report it: never clear learned facts
                    if column == "dirty":
                        fields.append("dirty=?")
                        values.append(1 if value else 0)
                    else:
                        fields.append(f"{column}=?")
                        values.append(value)
            values.append(stamp)
            values.append(row["deployment_id"])
            self.db.execute(
                f"UPDATE deployments SET {', '.join(fields)},updated_at=? WHERE deployment_id=?",
                tuple(values))
            deployment_id = row["deployment_id"]
        else:
            deployment_id = self.db.execute(
                "INSERT INTO deployments(repo_slug,device_id,local_path,application_slug,"
                "instance_id,branch,observed_commit_sha,dirty,ahead,behind,state,"
                "state_reasons_json,source,last_seen_at,last_observed_at,created_at,updated_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?, 'unknown','[]',?,?,?,?,?)",
                tuple(self._deployment_insert_values(
                    repo_slug, device_id, path, app_slug, instance_id, branch, sha,
                    dirty, ahead, behind, obs.get("source") or "agent_candidates",
                    observed_at, observed_at if has_revision else None, stamp)))
            self._record_event(repo_slug, deployment_id, device_id, "observed",
                               None, "unknown", None, sha,
                               obs.get("source") or "agent_candidates",
                               [f"deployment discovered via "
                                f"{obs.get('source') or 'agent_candidates'}"],
                               observed_at, stamp)
        self._rederive_one(deployment_id, now, stamp)
        return new_repo

    @staticmethod
    def _deployment_insert_values(repo_slug: str, device_id: str, path: str,
                                  app_slug: Optional[str], instance_id: Optional[int],
                                  branch: Optional[str], sha: Optional[str],
                                  dirty: Optional[bool], ahead: Optional[int],
                                  behind: Optional[int], source: str,
                                  seen_at: str, observed_at: Optional[str], stamp: str):
        return [repo_slug, device_id, path, app_slug, instance_id, branch, sha,
                1 if dirty else 0, ahead, behind, source, seen_at, observed_at,
                stamp, stamp]

    def _find_or_create_repository(self, canonical: str, remote_url: Any,
                                   stamp: str) -> Optional[Tuple[str, bool]]:
        """Resolve a canonical URL to its repository row, auto-registering
        one when discovery met a remote nothing claimed yet. Returns
        ``(slug, newly_created)`` or ``None`` when the slug space is
        exhausted (the observation is then skipped, never crashed on)."""
        rows = self.db.rows("SELECT * FROM repositories WHERE canonical_url=?", (canonical,))
        if rows:
            if remote_url and remote_url != rows[0].get("remote_url"):
                self.db.execute(
                    "UPDATE repositories SET remote_url=?,updated_at=? WHERE repo_id=?",
                    (str(remote_url)[:MAX_URL], stamp, rows[0]["repo_id"]))
            return rows[0]["slug"], False
        name = canonical.rsplit("/", 1)[-1][:MAX_NAME] or canonical
        taken = {row["slug"] for row in self.db.rows("SELECT slug FROM repositories")}
        try:
            slug = _unique_slug(slugify(name), taken)
        except RepositoryError:
            LOG.warning("cannot auto-register repository %s (slug space exhausted)", canonical)
            return None
        repo_id = self.db.execute(
            "INSERT INTO repositories(slug,name,description,canonical_url,remote_url,"
            "tags_json,lifecycle,state,state_reasons_json,created_at,updated_at) "
            "VALUES(?,?,?,?,?,?,'active','unknown','[]',?,?)",
            (slug, name, "Discovered from fleet git sources", canonical,
             str(remote_url)[:MAX_URL] if remote_url else None, "[]", stamp, stamp))
        LOG.info("auto-registered repository %s from discovery (%s)", slug, canonical)
        return slug, True

    def _application_link(self, canonical: str,
                          device_id: str) -> Tuple[Optional[str], Optional[int]]:
        """Deterministic deployment to application/instance linkage from the
        application's own repository field, restricted to applications that
        have an instance on the working tree's device. An application that
        only points at the same remote from elsewhere is not attributed here;
        ambiguous claims (two applications present on the device, or two
        instances of one) stay unlinked -- R08 reconciliation owns those
        judgment calls."""
        if not self._available():
            return None, None
        rows = self.db.rows(
            "SELECT a.slug,a.repository,i.instance_id,i.device_id,i.enabled "
            "FROM applications a LEFT JOIN application_instances i ON i.app_slug=a.slug "
            "WHERE a.lifecycle<>'archived' AND a.repository IS NOT NULL "
            "AND a.repository<>''")
        claims: Dict[str, List[Dict[str, Any]]] = {}
        for row in rows:
            match = canonical_repository_url(row["repository"])
            if match == canonical:
                claims.setdefault(row["slug"], []).append(row)
        if not claims:
            return None, None
        # Restrict to applications actually present on this device: a working
        # tree is attributed to an application that has an instance here, not
        # one that merely points at the same remote from elsewhere.
        on_device = {slug for slug, members in claims.items()
                     if any(member["device_id"] == device_id and member["enabled"]
                            for member in members)}
        if not on_device or len(on_device) > 1:
            return None, None  # nobody here, or two applications here: ambiguous
        slug = sorted(on_device)[0]
        instances = [member["instance_id"] for member in claims[slug]
                     if member["instance_id"] is not None
                     and member["device_id"] == device_id and member["enabled"]]
        return slug, (instances[0] if len(instances) == 1 else None)

    # -- state derivation ---------------------------------------------------------
    def _derive_deployment_state(self, row: Dict[str, Any],
                                 now: datetime) -> Tuple[str, List[str]]:
        deployment_id = row.get("deployment_id")
        desired_sha = row.get("repo_desired_sha") or row.get("desired_commit_sha")
        desired_branch = row.get("repo_desired_branch") or row.get("desired_branch")
        if not row.get("last_observed_at"):
            return "unknown", [reason_code("deployment", "unknown", deployment_id)
                               + " (revision never observed)"]
        age = age_seconds(row["last_observed_at"], now)
        if row.get("dirty"):
            concrete = "dirty"
        elif self._is_drifted(row, desired_sha, desired_branch):
            concrete = "drifted"
        else:
            concrete = "clean"
        # A *missing* age (unparseable timestamp) behaves like an infinite
        # one: the observation can no longer be trusted fresh.
        if age is None or age > self.stale_seconds:
            code = reason_code("deployment", "stale", deployment_id)
            if age is None:
                return "stale", [code + " (observation timestamp unparseable)"]
            return "stale", [code + f" (last {concrete}; revision observation "
                                    f"{int(age)}s old, floor {int(self.stale_seconds)}s)"]
        if concrete == "clean":
            return "clean", []
        reasons = [reason_code("deployment", concrete, deployment_id)]
        if concrete == "drifted":
            observed = (row.get("observed_commit_sha") or "")[:7]
            reasons.append(f"observed {observed or row.get('branch') or 'unknown revision'} "
                           f"vs desired {desired_sha[:7] if desired_sha else desired_branch}")
        return concrete, reasons

    @staticmethod
    def _is_drifted(row: Dict[str, Any], desired_sha: Optional[str],
                    desired_branch: Optional[str]) -> bool:
        """A deployment is drifted when any *known* comparison disagrees;
        unknown facts never drift (a missing observed SHA cannot differ
        from the desired one)."""
        observed = row.get("observed_commit_sha")
        if desired_sha and observed:
            observed_l, desired_l = observed.lower(), desired_sha.lower()
            if observed_l != desired_l and not (
                    observed_l.startswith(desired_l)
                    or desired_l.startswith(observed_l)):
                return True
        if desired_branch and row.get("branch") and row["branch"] != desired_branch:
            return True
        return False

    def _rederive_one(self, deployment_id: int, now: datetime, stamp: str) -> None:
        rows = self.db.rows(
            "SELECT d.*, r.desired_commit_sha AS repo_desired_sha, "
            "r.desired_branch AS repo_desired_branch "
            "FROM deployments d JOIN repositories r ON r.slug=d.repo_slug "
            "WHERE d.deployment_id=?", (deployment_id,))
        if rows:
            self._apply_state(rows[0], now, stamp)

    def _rederive_states(self, now: datetime, stamp: str) -> int:
        """Age every deployment under its freshness floor, record an event
        on each real transition, then roll up every repository state."""
        rows = self.db.rows(
            "SELECT d.*, r.desired_commit_sha AS repo_desired_sha, "
            "r.desired_branch AS repo_desired_branch "
            "FROM deployments d JOIN repositories r ON r.slug=d.repo_slug")
        changes = 0
        for row in rows:
            changes += self._apply_state(row, now, stamp)
        for slug in {row["slug"] for row in self.db.rows("SELECT slug FROM repositories")}:
            self._rollup_repository(slug, now, stamp)
        return changes

    def _apply_state(self, row: Dict[str, Any], now: datetime, stamp: str) -> int:
        """Apply one re-derivation: update the state columns and record an
        event only when something actually changed (otherwise every tick
        would write -- and event -- every row)."""
        state, reasons = self._derive_deployment_state(row, now)
        stored_reasons = _loads_list(row.get("state_reasons_json"))
        if state == row.get("state") and reasons == stored_reasons:
            return 0
        self.db.execute(
            "UPDATE deployments SET state=?,state_reasons_json=?,updated_at=? "
            "WHERE deployment_id=?",
            (state, json.dumps(reasons), stamp, row["deployment_id"]))
        self._record_event(row["repo_slug"], row["deployment_id"], row["device_id"],
                           "state_changed", row.get("state"), state,
                           row.get("observed_commit_sha"), row.get("observed_commit_sha"),
                           row.get("source"), reasons, row.get("last_observed_at"), stamp)
        return 1

    def _rollup_repository(self, repo_slug: str, now: datetime, stamp: str) -> None:
        rows = self.db.rows("SELECT deployment_id,state,state_reasons_json "
                            "FROM deployments WHERE repo_slug=?", (repo_slug,))
        if not rows:
            state, reasons = "unknown", ["no deployments observed yet"]
        else:
            counts: Dict[str, int] = {}
            for row in rows:
                counts[row["state"]] = counts.get(row["state"], 0) + 1
            state = max((row["state"] for row in rows), key=lambda s: _STATE_RANK.get(s, 0))
            summary = ", ".join(f"{counts[s]} {s}" for s in DEPLOYMENT_STATES if counts.get(s))
            reasons = [f"{len(rows)} deployment(s): {summary}"]
            for row in rows:
                if row["state"] == state:
                    for reason in _loads_list(row.get("state_reasons_json"))[:3]:
                        if reason not in reasons:
                            reasons.append(reason)
        current = self.db.rows("SELECT * FROM repositories WHERE slug=?", (repo_slug,))
        if not current:
            return
        current = current[0]
        stored_reasons = _loads_list(current.get("state_reasons_json"))
        if current.get("state") == state and stored_reasons == reasons:
            return
        self.db.execute(
            "UPDATE repositories SET state=?,state_reasons_json=?,"
            "last_observed_at=COALESCE((SELECT MAX(last_seen_at) FROM deployments "
            "WHERE repo_slug=?),last_observed_at),updated_at=? WHERE repo_id=?",
            (state, json.dumps(reasons), repo_slug, stamp, current["repo_id"]))
        if current.get("state") != state:
            self._record_event(repo_slug, None, None, "state_changed",
                               current.get("state"), state, None, None, None,
                               reasons, None, stamp)

    def _record_event(self, repo_slug: str, deployment_id: Optional[int],
                      device_id: Optional[str], event_type: str,
                      old_state: Optional[str], new_state: Optional[str],
                      old_sha: Optional[str], new_sha: Optional[str],
                      source: Optional[str], reasons: List[str],
                      observed_at: Any, recorded_at: str) -> None:
        """A point-in-time event, kept in its own table (spec: "keep
        deployment events separate from current state"); history
        maintenance prunes it."""
        try:
            self.db.execute(
                "INSERT INTO deployment_events(repo_slug,deployment_id,device_id,"
                "event_type,old_state,new_state,old_sha,new_sha,source,reasons_json,"
                "observed_at,recorded_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (repo_slug, deployment_id, device_id, event_type, old_state, new_state,
                 old_sha, new_sha, source, json.dumps(reasons or []), observed_at,
                 recorded_at))
        except Exception:
            LOG.exception("could not record deployment event %s", event_type)


# -- project registry hooks ---------------------------------------------------
#
# The P1-R01 unassigned-inventory view subtracts project membership from
# each kind's full roster; this is the repositories' half of that.
# Repositories are not health objects, so only the roster (not a health
# source) is registered.


def _repository_roster(project_service: "projects.ProjectService") -> List[str]:
    if not project_service._available():
        return []
    return [row["slug"] for row in project_service.db.rows(
        "SELECT slug FROM repositories WHERE lifecycle <> 'archived' ORDER BY slug")]


projects.register_roster_source("repository", _repository_roster)
