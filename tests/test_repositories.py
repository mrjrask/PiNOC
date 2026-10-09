"""Coverage for the repository and deployment model (PiNOC 2.0 Phase 1,
P1-R03).

Twelve layers:

* :class:`TestDatabaseSchema` -- migration 22 (repositories, deployments,
  deployment events) and the identity/working-tree uniqueness constraints.
* :class:`TestCanonicalUrl` -- the spec's "no duplicate repository objects"
  rule: every spelling of one remote normalizes to one identity, and
  credentials/paths/IPs never invent a repository.
* :class:`TestParseGitStatusV2` -- the porcelain-v2 reader that turns a
  ``git_status`` development job into branch/revision/dirty facts (a failed
  or empty output is *not* a clean tree).
* :class:`TestServiceCrud` -- repository registry CRUD: defaults, slugs,
  validation, archive/read-only/restore, integer+slug addressing.
* :class:`TestDeploymentsSources` -- one source-refresh tick driven directly
  against a real database and state cache: every source, the two-devices /
  path-change / IP-change acceptance criteria, newest-wins merge, and the
  five states (clean/dirty/drifted/stale/unknown) under the freshness floor.
* :class:`TestEventsRollup` -- point-in-time events on real transitions only,
  and the worst-of repository rollup.
* :class:`TestAppLinkage` -- deterministic deployment to application/instance
  linkage from the application's own repository field (ambiguity stays
  unlinked for P1-R08).
* :class:`TestProjectIntegration` -- the P1-R01 roster hook and the
  per-project software view.
* :class:`TestWeb` -- the HTTP surface: auth gating, viewer/admin roles, the
  token-scope table, CRUD round trips, and credential redaction.
* :class:`TestConfigValidation` -- the ``repositories`` configuration bounds.
* :class:`TestNoDatabase` -- graceful degradation to empty reads.
* :class:`TestHistoryRetention` -- ``HistoryManager.maintenance()`` prunes
  deployment events on their own retention.
"""
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from pinoc.config_store import validate_config, validate_repositories
from pinoc.database import Database, SCHEMA_VERSION
from pinoc.history import HistoryManager
from pinoc.models import DeviceState
from pinoc.repositories import (
    DEPLOYMENT_STATES,
    LIFECYCLES,
    RepositoryError,
    RepositoryNotFound,
    RepositoryService,
    canonical_repository_url,
    display_repository_url,
    parse_git_status_v2,
)
from pinoc.state import PiNOCState
from pinoc.web.app import create_app

UTC = timezone.utc
NOW = datetime(2026, 10, 6, 12, 0, 0, tzinfo=UTC)
# A shared remote whose every spelling normalizes to ``github.com/x/y``.
REMOTE = "https://github.com/x/y.git"
CANONICAL = "github.com/x/y"
# Repository registry config used by service-level tests (tight staleness so
# the freshness floor is easy to trip in a fixed-clock test).
DEFAULT_REPO_CONFIG = {"enabled": True, "refresh_seconds": 300, "stale_seconds": 300}

# A clean porcelain-v2 status (headers only: a working tree with no changes).
STATUS_CLEAN = "# branch.head main\n# branch.oid abcdef0123456789abcdef0123456789abcdef01\n"
# A modified working tree on a specific revision with upstream tracking.
STATUS_DIRTY = (
    "# branch.head main\n# branch.oid abcdef0123456789abcdef0123456789abcdef01\n"
    "# branch.ab +2 ~1\n M tracked.py\n?? untracked.py\n"
)


class _RecordingHistory:
    """Duck-typed stand-in for HistoryManager in service-level tests: the
    service keeps it only to satisfy the constructor contract, so a recorder
    is the cleanest way to assert nothing else breaks."""

    def __init__(self):
        self.events = []

    def event(self, device_id, event_type, severity, message, metadata=None):
        self.events.append({"device_id": device_id, "type": event_type,
                            "severity": severity, "message": message,
                            "metadata": metadata or {}})


def _record_audit(self, user, role, ip, device, action, target, params, auth,
                  result=None, exit_code=None, duration=None, error=None):
    self.audit.append({"user": user, "action": action, "target": target,
                       "params": params, "result": result})


def _device_row(self, device_id, hostname=None):
    self.db.execute(
        "INSERT OR IGNORE INTO devices(device_id,hostname,friendly_name,created_at,updated_at) "
        "VALUES(?,?,?,?,?)",
        (device_id, hostname or device_id, device_id.title(),
         NOW.isoformat(), NOW.isoformat()))


def _setup_service(self, with_state=False, config=None):
    self._tmp = tempfile.TemporaryDirectory()
    self.addCleanup(self._tmp.cleanup)
    self.db = Database(f"{self._tmp.name}/db.sqlite")
    assert self.db.initialize()
    self.audit = []
    self.history = _RecordingHistory()
    self.state = PiNOCState() if with_state else None
    self.service = RepositoryService(
        self.db, state=self.state, history=self.history,
        config=config if config is not None else DEFAULT_REPO_CONFIG,
        audit=_record_audit.__get__(self, type(self)))
    self._device_row = lambda device_id, hostname=None: _device_row(
        self, device_id, hostname=hostname)


def _git_integration(self, device_id, path, url, branch=None, commit=None,
                     dirty=None, ahead=None, behind=None, last_seen=None,
                     hostname=None):
    """Report the ``integrations.git`` entries the state cache carries for a
    device -- the richest source (branch, revision, dirty, ahead/behind)."""
    entry = {"path": path, "remote_url": url}
    for key, value in (("branch", branch), ("commit", commit),
                       ("dirty", dirty), ("ahead", ahead), ("behind", behind)):
        if value is not None:
            entry[key] = value
    self.state.publish([
        DeviceState(id=device_id, hostname=hostname or device_id,
                    friendly_name=(hostname or device_id).title(), online=True,
                    last_seen=last_seen, integrations={"git": {"data": [entry]}})
    ])


def _agent_candidate(self, device_id, path, url, last_seen=None):
    """Insert an outbound agent registration carrying a discovered workspace
    root (path + origin URL) in its candidates_json."""
    self.db.execute(
        "INSERT INTO agents(agent_id,device_id,credential_hash,agent_version,"
        "protocol_version,status,candidates_json,created_at,last_seen) "
        "VALUES(?,?,?,?,?,?,?,?,?)",
        (f"agent-{device_id}", device_id, "x" * 32, "1.0.0", 1, "active",
         json.dumps([{"path": path, "repository": url}]),
         NOW.isoformat(), last_seen or NOW.isoformat()))


def _workspace(self, device_id, path, url, updated_at=None, workspace_id=None):
    """Insert an operator-approved development workspace (path + remote)."""
    self.db.execute(
        "INSERT INTO workspaces(workspace_id,device_id,path,repository,"
        "created_at,updated_at) VALUES(?,?,?,?,?,?)",
        (workspace_id or f"ws-{device_id}-{path}", device_id, path, url,
         NOW.isoformat(), updated_at or NOW.isoformat()))


def _git_status_job(self, device_id, path, url, stdout, completed_at=None,
                    workspace_id=None):
    """Persist a *successful* ``git_status`` development job for a workspace
    (its stdout is the porcelain-v2 output the service parses)."""
    _workspace(self, device_id, path, url, updated_at=completed_at,
                workspace_id=workspace_id)
    self.db.execute(
        "INSERT INTO development_jobs(job_id,device_id,workspace_id,job_type,"
        "requested_by,requested_at,completed_at,status,exit_code,timeout_seconds,"
        "stdout) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
        (f"job-{workspace_id or (device_id + '-' + path)}", device_id,
         workspace_id or f"ws-{device_id}-{path}", "git_status", "operator",
         NOW.isoformat(), completed_at or NOW.isoformat(), "succeeded", 0,
         30, stdout))


def _application(self, slug, repository=None, device_id=None, count=1):
    """Insert an application (optionally with a repository remote) plus one
    or more instances on a device -- the inputs to the linkage inference."""
    self.db.execute(
        "INSERT INTO applications(slug,name,repository,lifecycle,created_at,"
        "updated_at) VALUES(?,?,?,?,?,?)",
        (slug, slug.title(), repository, "active", NOW.isoformat(), NOW.isoformat()))
    for index in range(count):
        target = f"{slug}.service" if index == 0 else f"{slug}-b{index}.service"
        self.db.execute(
            "INSERT INTO application_instances(app_slug,device_id,mechanism,target,"
            "enabled,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
            (slug, device_id, "systemd", target, 1,
             NOW.isoformat(), NOW.isoformat()))


def _project(self, slug, name=None):
    self.db.execute(
        "INSERT INTO projects(project_id,slug,name,description,created_at,updated_at)"
        " VALUES(?,?,?,?,?,?)",
        (1 if slug == "proj" else 0, slug, name or slug.title(), "",
         NOW.isoformat(), NOW.isoformat()))


# -- schema ---------------------------------------------------------------

class TestDatabaseSchema(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.db = Database(f"{self._tmp.name}/db.sqlite")
        assert self.db.initialize()

    def test_schema_version_matches_constant(self):
        # Repositories introduced schema v22; assert the DB migrated to the
        # current constant (later Phase 1 migrations advance it further).
        self.assertGreaterEqual(SCHEMA_VERSION, 22)
        self.assertEqual(self.db.scalar("SELECT version FROM schema_version"), SCHEMA_VERSION)

    def test_migration_creates_the_three_tables(self):
        tables = {row["name"] for row in self.db.rows(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        for name in ("repositories", "deployments", "deployment_events"):
            self.assertIn(name, tables)

    def test_migration_creates_the_indexes(self):
        indexes = {row["name"] for row in self.db.rows(
            "SELECT name FROM sqlite_master WHERE type='index'")}
        for name in ("repos_project", "deployments_repo", "deployments_device",
                     "deployments_application", "deployment_events_repo_time",
                     "deployment_events_recorded"):
            self.assertIn(name, indexes)

    def test_deployment_unique_working_tree_key(self):
        self.db.execute(
            "INSERT INTO repositories(slug,name,canonical_url,created_at,updated_at)"
            " VALUES('y','Y','github.com/x/y',?,?)", (NOW.isoformat(), NOW.isoformat()))
        self.db.execute(
            "INSERT INTO deployments(repo_slug,device_id,local_path,state,"
            "state_reasons_json,created_at,updated_at) "
            "VALUES('y','pi','/srv/a','unknown','[]',?,?)",
            (NOW.isoformat(), NOW.isoformat()))
        # The same (repository, device, local path) cannot appear twice -- the
        # deployments upsert key the service relies on.
        with self.assertRaises(Exception):
            self.db.execute(
                "INSERT INTO deployments(repo_slug,device_id,local_path,state,"
                "state_reasons_json,created_at,updated_at) "
                "VALUES('y','pi','/srv/a','unknown','[]',?,?)",
                (NOW.isoformat(), NOW.isoformat()))

    def test_repository_unique_canonical(self):
        self.db.execute(
            "INSERT INTO repositories(slug,name,canonical_url,created_at,updated_at)"
            " VALUES('a','A','github.com/x/y',?,?)", (NOW.isoformat(), NOW.isoformat()))
        with self.assertRaises(Exception):
            self.db.execute(
                "INSERT INTO repositories(slug,name,canonical_url,created_at,updated_at)"
                " VALUES('b','B','github.com/x/y',?,?)",
                (NOW.isoformat(), NOW.isoformat()))


# -- canonical identity ---------------------------------------------------

class TestCanonicalUrl(unittest.TestCase):
    def test_every_scheme_spelling_is_one_identity(self):
        spellings = [
            f"git@github.com:x/y.git",
            "https://github.com/x/y",
            "ssh://git@github.com/x/y.git",
            "git://github.com/x/y.git",
            "https://github.com/x/y.git",
            "https://GITHUB.com/x/y",
        ]
        for spelling in spellings:
            self.assertEqual(canonical_repository_url(spelling), "github.com/x/y",
                             msg=spelling)

    def test_git_suffix_is_ignored(self):
        self.assertEqual(canonical_repository_url("https://github.com/x/y.git"),
                         canonical_repository_url("https://github.com/x/y"))

    def test_credentials_are_ignored_for_identity(self):
        self.assertEqual(canonical_repository_url("https://user:pass@github.com/x/y"),
                         "github.com/x/y")
        self.assertEqual(canonical_repository_url("https://user@github.com/x/y"),
                         "github.com/x/y")

    def test_explicit_port_is_part_of_identity(self):
        self.assertEqual(canonical_repository_url("git://github.com:8080/x/y"),
                         "github.com:8080/x/y")
        # A ported and a portless remote are different remotes.
        self.assertNotEqual(canonical_repository_url("https://github.com:8443/x/y"),
                            "github.com/x/y")

    def test_windows_drive_path_is_rejected(self):
        self.assertIsNone(canonical_repository_url(r"C:\code\repo"))

    def test_free_text_is_rejected(self):
        self.assertIsNone(canonical_repository_url("the repo in /srv"))
        self.assertIsNone(canonical_repository_url("a b c"))

    def test_empty_and_whitespace_rejected(self):
        self.assertIsNone(canonical_repository_url(""))
        self.assertIsNone(canonical_repository_url("   "))
        self.assertIsNone(canonical_repository_url(None))

    def test_host_but_no_path_is_rejected(self):
        self.assertIsNone(canonical_repository_url("https://github.com"))

    def test_display_strips_credentials(self):
        self.assertEqual(display_repository_url("https://user:pass@github.com/x/y"),
                         "https://github.com/x/y")
        self.assertEqual(display_repository_url("git@github.com:x/y.git"),
                         "github.com:x/y.git")
        # A credential-free URL is returned unchanged.
        self.assertEqual(display_repository_url("https://github.com/x/y"),
                         "https://github.com/x/y")

    def test_different_remotes_stay_separate(self):
        self.assertNotEqual(canonical_repository_url("https://github.com/x/y"),
                            canonical_repository_url("https://gitlab.com/x/y"))


class TestCanonicalNoDuplicate(unittest.TestCase):
    """The spec acceptance criterion: an IP or path change must not create a
    duplicate repository object, and two spellings of one remote map to one
    object."""

    def setUp(self):
        _setup_service(self, with_state=True)
        self._device_row("pi")
        self._device_row("spare")

    def test_observation_via_different_spelling_matches_created_repo(self):
        # Created with the https spelling ...
        repo = self.service.create({"name": "Y", "url": REMOTE})
        # ... and re-observed through the scp spelling lands on the same row.
        _git_integration(self, "pi", "/srv/app", "git@github.com:x/y.git",
                         branch="main", commit="abcdef0123", last_seen=NOW.isoformat())
        self.service.tick(now=NOW)
        repos = self.service.list(include_archived=True)
        self.assertEqual(len(repos), 1)
        self.assertEqual(repos[0]["id"], repo["id"])
        self.assertEqual(repos[0]["canonical_url"], CANONICAL)

    def test_ip_and_path_changes_create_no_new_repository(self):
        repo = self.service.create({"name": "Y", "url": REMOTE})
        # A path move on the same device ...
        _git_integration(self, "pi", "/opt/old", REMOTE, branch="main",
                         commit="abcdef0123", last_seen=NOW.isoformat())
        self.service.tick(now=NOW)
        _git_integration(self, "pi", "/opt/new", REMOTE, branch="main",
                         commit="abcdef0123", last_seen=(NOW + timedelta(hours=1)).isoformat())
        self.service.tick(now=NOW + timedelta(hours=1))
        repos = self.service.list(include_archived=True)
        self.assertEqual(len(repos), 1, "a path move must not duplicate the repo")
        self.assertEqual(len(self.service.deployments()), 2)  # two working trees


# -- porcelain-v2 parser --------------------------------------------------

class TestParseGitStatusV2(unittest.TestCase):
    def test_clean_tree(self):
        result = parse_git_status_v2(STATUS_CLEAN)
        self.assertEqual(result["branch"], "main")
        self.assertEqual(result["sha"], "abcdef0123456789abcdef0123456789abcdef01")
        self.assertIs(result["dirty"], False)
        self.assertIsNone(result["ahead"])
        self.assertIsNone(result["behind"])

    def test_modified_entries_are_dirty(self):
        self.assertIs(parse_git_status_v2(STATUS_DIRTY)["dirty"], True)

    def test_ahead_behind(self):
        result = parse_git_status_v2(STATUS_DIRTY)
        self.assertEqual(result["ahead"], 2)
        self.assertEqual(result["behind"], 1)

    def test_no_upstream_is_none(self):
        result = parse_git_status_v2("# branch.head main\n# branch.oid abc123\n# branch.ab -\n")
        self.assertIsNone(result["ahead"])
        self.assertIsNone(result["behind"])

    def test_detached_head(self):
        result = parse_git_status_v2("# HEAD detached from abc123\n# branch.oid abc123\n")
        self.assertIsNone(result["branch"])
        self.assertEqual(result["sha"], "abc123")

    def test_empty_output_learns_nothing(self):
        result = parse_git_status_v2("")
        self.assertEqual(result, {"branch": None, "sha": None,
                                  "ahead": None, "behind": None, "dirty": None})

    def test_non_string_input_is_empty(self):
        self.assertEqual(parse_git_status_v2(None),
                         {"branch": None, "sha": None,
                          "ahead": None, "behind": None, "dirty": None})
        self.assertEqual(parse_git_status_v2(123),
                         {"branch": None, "sha": None,
                          "ahead": None, "behind": None, "dirty": None})

    def test_failed_job_never_read_as_clean(self):
        # An empty/failed stdout must not be mistaken for a clean tree.
        self.assertIsNone(parse_git_status_v2("")["dirty"])


# -- service CRUD ---------------------------------------------------------

class TestServiceCrud(unittest.TestCase):
    def setUp(self):
        _setup_service(self)
        self._device_row("pi")
        _project(self, "proj")

    def test_create_defaults_and_slug(self):
        repo = self.service.create({"name": "Y", "url": REMOTE})
        self.assertEqual(repo["slug"], "y")
        self.assertEqual(repo["canonical_url"], CANONICAL)
        self.assertEqual(repo["lifecycle"], "active")
        self.assertEqual(repo["state"], "unknown")
        self.assertFalse(repo["archived"])
        self.assertEqual(repo["tags"], [])
        # The URL with credentials is stripped for display.
        self.assertEqual(repo["remote_url"], "https://github.com/x/y.git")

    def test_create_explicit_slug(self):
        repo = self.service.create({"name": "Y", "url": REMOTE, "slug": "myrepo"})
        self.assertEqual(repo["slug"], "myrepo")

    def test_create_requires_name(self):
        with self.assertRaises(RepositoryError):
            self.service.create({"url": REMOTE})

    def test_create_rejects_bad_url(self):
        with self.assertRaises(RepositoryError):
            self.service.create({"name": "X", "url": "not a url at all"})
        with self.assertRaises(RepositoryError):
            self.service.create({"name": "X", "url": r"C:\repo"})

    def test_create_rejects_duplicate_canonical(self):
        self.service.create({"name": "Y", "url": REMOTE})
        # The same remote under a different spelling is the same identity.
        with self.assertRaises(RepositoryError):
            self.service.create({"name": "Y2", "url": "git@github.com:x/y"})

    def test_create_rejects_taken_slug(self):
        self.service.create({"name": "Y", "url": REMOTE, "slug": "taken"})
        with self.assertRaises(RepositoryError):
            self.service.create({"name": "Z", "url": "https://gitlab.com/a/b",
                                 "slug": "taken"})

    def test_create_rejects_bad_sha(self):
        with self.assertRaises(RepositoryError):
            self.service.create({"name": "Y", "url": REMOTE,
                                 "desired_commit_sha": "xyz"})

    def test_create_rejects_bad_branch(self):
        with self.assertRaises(RepositoryError):
            self.service.create({"name": "Y", "url": REMOTE,
                                 "default_branch": "a b c"})

    def test_create_rejects_unknown_project(self):
        with self.assertRaises(RepositoryError):
            self.service.create({"name": "Y", "url": REMOTE, "project": "ghost"})

    def test_create_accepts_known_project(self):
        repo = self.service.create({"name": "Y", "url": REMOTE, "project": "proj"})
        self.assertEqual(repo["project"], "proj")

    def test_create_rejects_archived_lifecycle(self):
        with self.assertRaises(RepositoryError):
            self.service.create({"name": "Y", "url": REMOTE,
                                 "lifecycle": "archived"})

    def test_get_by_id_and_slug(self):
        repo = self.service.create({"name": "Y", "url": REMOTE})
        self.assertEqual(self.service.get(repo["repo_id"])["slug"], "y")
        self.assertEqual(self.service.get("y")["slug"], "y")
        self.assertIsNone(self.service.get("missing"))
        self.assertIsNone(self.service.get("999999"))

    def test_list_filters(self):
        self.service.create({"name": "Y", "url": REMOTE, "project": "proj",
                             "tags": ["a", "b"]})
        self.service.create({"name": "Z", "url": "https://gitlab.com/a/z"})
        self.assertEqual(len(self.service.list()), 2)
        self.assertEqual([r["slug"] for r in self.service.list(project="proj")],
                         ["y"])
        self.assertEqual([r["slug"] for r in self.service.list(state="unknown")],
                         ["y", "z"])
        with self.assertRaises(RepositoryError):
            self.service.list(state="bogus")
        with self.assertRaises(RepositoryError):
            self.service.list(lifecycle="bogus")

    def test_update_metadata_is_audited(self):
        self.service.create({"name": "Y", "url": REMOTE})
        self.service.update("y", {"name": "Y-Display", "owner": "jason",
                                  "tags": ["kiosk"], "technology": "python"})
        repo = self.service.get("y")
        self.assertEqual(repo["name"], "Y-Display")
        self.assertEqual(repo["owner"], "jason")
        self.assertEqual(repo["tags"], ["kiosk"])
        self.assertEqual(repo["technology"], "python")
        actions = {row["action"] for row in self.audit}
        self.assertIn("repository.update", actions)

    def test_update_resets_desired_revision(self):
        self.service.create({"name": "Y", "url": REMOTE})
        updated = self.service.update("y", {"desired_commit_sha": "0" * 40,
                                            "desired_branch": "release"})
        self.assertEqual(updated["desired_commit_sha"], "0" * 40)
        self.assertEqual(updated["desired_branch"], "release")
        self.assertTrue(any(row["action"] == "repository.desired_revision"
                            for row in self.audit))

    def test_update_identity_url_change_rejected(self):
        self.service.create({"name": "Y", "url": REMOTE})
        # A *different* remote is a different repository; only re-spelling is
        # allowed on this field.
        with self.assertRaises(RepositoryError):
            self.service.update("y", {"url": "https://gitlab.com/other/repo"})

    def test_update_url_re_spell_allowed(self):
        self.service.create({"name": "Y", "url": REMOTE})
        updated = self.service.update("y", {"url": "https://github.com/x/y"})
        self.assertEqual(updated["canonical_url"], CANONICAL)

    def test_update_archived_is_read_only(self):
        self.service.create({"name": "Y", "url": REMOTE})
        self.service.archive("y")
        with self.assertRaises(RepositoryError):
            self.service.update("y", {"name": "Nope"})

    def test_update_empty_payload_is_noop(self):
        repo = self.service.create({"name": "Y", "url": REMOTE})
        self.assertEqual(self.service.update("y", {})["name"], repo["name"])
        self.assertFalse(any(row["action"] == "repository.update" for row in self.audit))

    def test_archive_and_restore(self):
        self.service.create({"name": "Y", "url": REMOTE})
        archived = self.service.archive("y", reason="moved on")
        self.assertTrue(archived["archived"])
        # Idempotent: a second archive records no new audit row.
        before = len(self.audit)
        self.service.archive("y")
        self.assertEqual(len(self.audit), before)
        restored = self.service.restore("y")
        self.assertFalse(restored["archived"])
        self.assertFalse(restored["archived_at"])

    def test_restore_non_archived_rejected(self):
        self.service.create({"name": "Y", "url": REMOTE})
        with self.assertRaises(RepositoryError):
            self.service.restore("y")


# -- deployment sources and the five states -------------------------------

class TestDeploymentsSources(unittest.TestCase):
    def setUp(self):
        _setup_service(self, with_state=True)
        self._device_row("pi")
        self._device_row("spare")
        # One repository, desired revision pinned so clean/drifted are distinct.
        self.repo = self.service.create(
            {"name": "Y", "url": REMOTE,
             "desired_commit_sha": "abcdef0123456789", "desired_branch": "main"})

    def test_git_integration_source(self):
        _git_integration(self, "pi", "/srv/app", REMOTE, branch="main",
                         commit="abcdef0123456789", dirty=False,
                         last_seen=NOW.isoformat())
        result = self.service.tick(now=NOW)
        self.assertEqual(result["status"], "ok")
        [dep] = self.service.deployments()
        self.assertEqual(dep["device"]["id"], "pi")
        self.assertEqual(dep["local_path"], "/srv/app")
        self.assertEqual(dep["branch"], "main")
        self.assertEqual(dep["observed_commit_sha"], "abcdef0123456789")
        self.assertEqual(dep["source"], "git_integration")

    def test_agent_candidates_source(self):
        _agent_candidate(self, "pi", "/root/checkout", "git@github.com:x/y.git",
                         last_seen=NOW.isoformat())
        self.service.tick(now=NOW)
        [dep] = self.service.deployments()
        self.assertEqual(dep["source"], "agent_candidates")
        # A candidate without an origin cannot be canonicalized.
        self.db.execute(
            "UPDATE agents SET candidates_json=?",
            (json.dumps([{"path": "/root/plain", "repository": False}]),))
        self.assertEqual(self.service.deployments(), self.service.deployments())

    def test_workspaces_source(self):
        _workspace(self, "pi", "/ws/app", REMOTE, updated_at=NOW.isoformat())
        self.service.tick(now=NOW)
        [dep] = self.service.deployments()
        self.assertEqual(dep["source"], "workspaces")
        self.assertEqual(dep["local_path"], "/ws/app")
        self.assertIsNone(dep["branch"])  # workspaces learn no revision

    def test_git_status_job_source(self):
        _git_status_job(self, "pi", "/ws/app", REMOTE, STATUS_DIRTY,
                        completed_at=NOW.isoformat())
        self.service.tick(now=NOW)
        [dep] = self.service.deployments()
        self.assertEqual(dep["source"], "git_status")
        self.assertEqual(dep["observed_commit_sha"],
                         "abcdef0123456789abcdef0123456789abcdef01")
        self.assertEqual(dep["observed_short_sha"], "abcdef0")
        self.assertTrue(dep["dirty"])
        self.assertEqual(dep["ahead"], 2)
        self.assertEqual(dep["behind"], 1)

    def test_only_latest_job_per_workspace(self):
        # Two git_status jobs for one workspace: only the latest is read.
        _workspace(self, "pi", "/ws/app", REMOTE, updated_at=NOW.isoformat())
        self.db.execute(
            "INSERT INTO development_jobs(job_id,device_id,workspace_id,job_type,"
            "requested_by,requested_at,completed_at,status,exit_code,timeout_seconds,"
            "stdout) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            ("job-old", "pi", "ws-pi-/ws/app", "git_status", "operator",
             NOW.isoformat(), NOW.isoformat(), "succeeded", 0, 30, STATUS_DIRTY))
        self.db.execute(
            "INSERT INTO development_jobs(job_id,device_id,workspace_id,job_type,"
            "requested_by,requested_at,completed_at,status,exit_code,timeout_seconds,"
            "stdout) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            ("job-new", "pi", "ws-pi-/ws/app", "git_status", "operator",
             NOW.isoformat(), (NOW + timedelta(hours=1)).isoformat(),
             "succeeded", 0, 30, STATUS_CLEAN))
        self.service.tick(now=NOW + timedelta(hours=1))
        [dep] = self.service.deployments()
        self.assertIs(dep["dirty"], False)  # the newer, clean job won

    def test_two_devices_different_commits_are_two_deployments(self):
        _git_integration(self, "pi", "/srv/app", REMOTE, branch="main",
                         commit="aaaa1111", last_seen=NOW.isoformat())
        _git_integration(self, "spare", "/srv/app", REMOTE, branch="main",
                         commit="bbbb2222", last_seen=NOW.isoformat())
        self.service.tick(now=NOW)
        deps = self.service.deployments()
        self.assertEqual(len(deps), 2)
        self.assertEqual({d["device"]["id"] for d in deps}, {"pi", "spare"})
        self.assertEqual({d["observed_commit_sha"] for d in deps},
                         {"aaaa1111", "bbbb2222"})
        # The *repository* object is still singular -- the working trees are
        # the separate objects.
        self.assertEqual(len(self.service.list(include_archived=True)), 1)

    def test_path_change_is_new_deployment_same_repo(self):
        _git_integration(self, "pi", "/opt/old", REMOTE, branch="main",
                         commit="aaa111", last_seen=NOW.isoformat())
        self.service.tick(now=NOW)
        self.assertEqual(len(self.service.deployments()), 1)
        _git_integration(self, "pi", "/opt/new", REMOTE, branch="main",
                         commit="aaa111", last_seen=(NOW + timedelta(hours=1)).isoformat())
        self.service.tick(now=NOW + timedelta(hours=1))
        self.assertEqual(len(self.service.deployments()), 2)
        self.assertEqual(len(self.service.list(include_archived=True)), 1)

    def test_clean_when_matching_desired(self):
        _git_integration(self, "pi", "/srv/app", REMOTE, branch="main",
                         commit="abcdef0123456789", dirty=False,
                         last_seen=NOW.isoformat())
        self.service.tick(now=NOW)
        [dep] = self.service.deployments()
        self.assertEqual(dep["state"], "clean")
        self.assertEqual(dep["state_reasons"], [])

    def test_dirty_on_uncommitted_changes(self):
        _git_integration(self, "pi", "/srv/app", REMOTE, branch="main",
                         commit="abcdef0123456789", dirty=True,
                         last_seen=NOW.isoformat())
        self.service.tick(now=NOW)
        self.assertEqual(self.service.deployments()[0]["state"], "dirty")

    def test_drifted_on_sha_mismatch(self):
        _git_integration(self, "pi", "/srv/app", REMOTE, branch="main",
                         commit="0000000deadbeef", dirty=False,
                         last_seen=NOW.isoformat())
        self.service.tick(now=NOW)
        dep = self.service.deployments()[0]
        self.assertEqual(dep["state"], "drifted")
        self.assertTrue(any("desired" in reason for reason in dep["state_reasons"]))

    def test_short_sha_prefix_is_not_drifted(self):
        # An observed short SHA that is a prefix of the desired one matches.
        _git_integration(self, "pi", "/srv/app", REMOTE, branch="main",
                         commit="abcdef0", dirty=False, last_seen=NOW.isoformat())
        self.service.tick(now=NOW)
        self.assertEqual(self.service.deployments()[0]["state"], "clean")

    def test_drifted_on_branch_mismatch(self):
        _git_integration(self, "pi", "/srv/app", REMOTE, branch="feature",
                         commit="abcdef0123456789", dirty=False,
                         last_seen=NOW.isoformat())
        self.service.tick(now=NOW)
        self.assertEqual(self.service.deployments()[0]["state"], "drifted")

    def test_unknown_never_observed(self):
        # Only a path+remote is known; no source ever learned a revision.
        _workspace(self, "pi", "/ws/app", REMOTE, updated_at=NOW.isoformat())
        self.service.tick(now=NOW)
        [dep] = self.service.deployments()
        self.assertEqual(dep["state"], "unknown")
        self.assertIsNone(dep["observed_commit_sha"])

    def test_stale_after_freshness_floor(self):
        _git_integration(self, "pi", "/srv/app", REMOTE, branch="main",
                         commit="0000000deadbeef", dirty=False,
                         last_seen=NOW.isoformat())
        self.service.tick(now=NOW)          # drifted, fresh
        self.assertEqual(self.service.deployments()[0]["state"], "drifted")
        # Age past the floor without a newer observation ...
        self.service.tick(now=NOW + timedelta(seconds=3600))
        dep = self.service.deployments()[0]
        self.assertEqual(dep["state"], "stale")
        # ... and the last concrete state is preserved in the reason.
        self.assertTrue(any("last drifted" in reason for reason in dep["state_reasons"]))

    def test_failed_collection_never_erases_last_success(self):
        # The source reports a clean tree once; then it vanishes (the device
        # goes offline and the state is empty). The deployment ages to stale,
        # it does not revert to unknown or lose its learned facts.
        _git_integration(self, "pi", "/srv/app", REMOTE, branch="main",
                         commit="abcdef0123456789", dirty=False,
                         last_seen=NOW.isoformat())
        self.service.tick(now=NOW)
        self.state.publish([], replace=True)  # the fleet observation is gone
        self.service.tick(now=NOW + timedelta(seconds=3600))
        dep = self.service.deployments()[0]
        self.assertEqual(dep["state"], "stale")
        self.assertEqual(dep["observed_commit_sha"], "abcdef0123456789")

    def test_newer_source_wins_over_older(self):
        # An older git_integration (dirty) and a newer git_status (clean) hit
        # the same working tree; the newer observation wins per field.
        _git_integration(self, "pi", "/ws/app", REMOTE, branch="main",
                         commit="abcdef0123456789", dirty=True,
                         last_seen=NOW.isoformat())
        _git_status_job(self, "pi", "/ws/app", REMOTE, STATUS_CLEAN,
                        completed_at=(NOW + timedelta(hours=1)).isoformat())
        self.service.tick(now=NOW + timedelta(hours=1))
        [dep] = self.service.deployments()
        self.assertIs(dep["dirty"], False)
        self.assertEqual(dep["state"], "clean")
        self.assertEqual(dep["source"], "git_status")

    def test_older_source_does_not_rewind_earlier_state(self):
        # A newer clean tick sets the clock forward; an *older* source reported
        # afterwards must not rewind the last-observed timestamp.
        _git_integration(self, "pi", "/srv/app", REMOTE, branch="main",
                         commit="abcdef0123456789", dirty=False,
                         last_seen=(NOW + timedelta(hours=1)).isoformat())
        self.service.tick(now=NOW + timedelta(hours=1))
        before = self.service.deployments()[0]["last_observed_at"]
        # Re-report the same (now older) integration at the original time.
        _git_integration(self, "pi", "/srv/app", REMOTE, branch="main",
                         commit="abcdef0123456789", dirty=False,
                         last_seen=NOW.isoformat())
        self.service.tick(now=NOW + timedelta(hours=1))
        after = self.service.deployments()[0]["last_observed_at"]
        self.assertGreaterEqual(self._ts(after), self._ts(before))

    def test_auto_registers_unclaimed_remote(self):
        # A remote nothing has claimed yet is auto-registered from discovery.
        _git_integration(self, "pi", "/srv/app", "https://gitlab.com/z/w.git",
                         branch="main", commit="aaaa1111",
                         last_seen=NOW.isoformat())
        result = self.service.tick(now=NOW)
        self.assertEqual(result["auto_registered"], 1)
        repos = self.service.list(include_archived=True)
        self.assertEqual({r["slug"] for r in repos}, {"w", "y"})
        discovered = next(r for r in repos if r["slug"] == "w")
        self.assertEqual(discovered["name"], "w")
        self.assertEqual(discovered["remote_url"], "https://gitlab.com/z/w.git")
        self.assertEqual(discovered["description"],
                         "Discovered from fleet git sources")

    def _ts(self, value):
        parsed = datetime.fromisoformat(value) if value else None
        return parsed.timestamp() if parsed else 0.0


# -- events and rollup ----------------------------------------------------

class TestEventsRollup(unittest.TestCase):
    def setUp(self):
        _setup_service(self, with_state=True)
        self._device_row("pi")
        self._device_row("spare")
        self.repo = self.service.create(
            {"name": "Y", "url": REMOTE,
             "desired_commit_sha": "abcdef0123456789", "desired_branch": "main"})

    def test_event_on_discovery_and_transition(self):
        _git_integration(self, "pi", "/srv/app", REMOTE, branch="main",
                         commit="0000000deadbeef", dirty=False,
                         last_seen=NOW.isoformat())
        self.service.tick(now=NOW)
        events = self.db.rows(
            "SELECT event_type,old_state,new_state FROM deployment_events")
        self.assertTrue(any(e["event_type"] == "observed" for e in events))
        self.assertTrue(any(e["event_type"] == "state_changed"
                            and e["new_state"] == "drifted" for e in events))

    def test_no_event_on_unchanged_tick(self):
        _git_integration(self, "pi", "/srv/app", REMOTE, branch="main",
                         commit="abcdef0123456789", dirty=False,
                         last_seen=NOW.isoformat())
        self.service.tick(now=NOW)
        first = self.db.scalar("SELECT COUNT(*) FROM deployment_events")
        # Identical re-observation at the same instant: nothing changes, no new
        # event is written on the next identical tick.
        self.service.tick(now=NOW)
        second = self.db.scalar("SELECT COUNT(*) FROM deployment_events")
        self.assertEqual(first, second)

    def test_repository_rollup_is_worst_of_deployments(self):
        _git_integration(self, "pi", "/srv/app", REMOTE, branch="main",
                         commit="abcdef0123456789", dirty=False,
                         last_seen=NOW.isoformat())
        _git_integration(self, "spare", "/srv/app", REMOTE, branch="main",
                         commit="abcdef0123456789", dirty=True,
                         last_seen=NOW.isoformat())
        self.service.tick(now=NOW)
        self.assertEqual(self.service.get(self.repo["id"])["state"], "dirty")

    def test_repository_without_deployments_is_unknown(self):
        self.service.tick(now=NOW)
        repo = self.service.get(self.repo["id"])
        self.assertEqual(repo["state"], "unknown")
        self.assertTrue(any("no deployments" in reason
                            for reason in repo["state_reasons"]))

    def test_rollup_reasons_summarize_counts(self):
        _git_integration(self, "pi", "/srv/app", REMOTE, branch="main",
                         commit="abcdef0123456789", dirty=False,
                         last_seen=NOW.isoformat())
        _git_integration(self, "spare", "/srv/app", REMOTE, branch="main",
                         commit="0000000deadbeef", dirty=False,
                         last_seen=NOW.isoformat())
        self.service.tick(now=NOW)
        repo = self.service.get(self.repo["id"])
        self.assertEqual(repo["state"], "drifted")
        self.assertTrue(any("1 drifted" in reason for reason in repo["state_reasons"]))
        self.assertTrue(any("1 clean" in reason for reason in repo["state_reasons"]))


# -- application / instance linkage ---------------------------------------

class TestAppLinkage(unittest.TestCase):
    def setUp(self):
        _setup_service(self, with_state=True)
        self._device_row("pi")
        self._device_row("spare")
        # The repository that the application's own field points at.
        self.service.create({"name": "Y", "url": REMOTE})

    def test_single_app_single_instance_is_linked(self):
        _application(self, "desk", repository=REMOTE, device_id="pi", count=1)
        _git_integration(self, "pi", "/srv/app", REMOTE, branch="main",
                         commit="abcdef0123", last_seen=NOW.isoformat())
        self.service.tick(now=NOW)
        [dep] = self.service.deployments()
        self.assertEqual(dep["application"], "desk")
        self.assertIsNotNone(dep["instance_id"])

    def test_two_apps_same_remote_same_device_stay_unlinked(self):
        _application(self, "desk", repository=REMOTE, device_id="pi", count=1)
        _application(self, "score", repository=REMOTE, device_id="pi", count=1)
        _git_integration(self, "pi", "/srv/app", REMOTE, branch="main",
                         commit="abcdef0123", last_seen=NOW.isoformat())
        self.service.tick(now=NOW)
        [dep] = self.service.deployments()
        self.assertIsNone(dep["application"])
        self.assertIsNone(dep["instance_id"])

    def test_two_instances_of_one_app_link_app_not_instance(self):
        _application(self, "desk", repository=REMOTE, device_id="pi", count=2)
        _git_integration(self, "pi", "/srv/app", REMOTE, branch="main",
                         commit="abcdef0123", last_seen=NOW.isoformat())
        self.service.tick(now=NOW)
        [dep] = self.service.deployments()
        self.assertEqual(dep["application"], "desk")
        self.assertIsNone(dep["instance_id"])  # two instances: ambiguous

    def test_instance_on_other_device_not_linked_here(self):
        _application(self, "desk", repository=REMOTE, device_id="spare", count=1)
        _git_integration(self, "pi", "/srv/app", REMOTE, branch="main",
                         commit="abcdef0123", last_seen=NOW.isoformat())
        self.service.tick(now=NOW)
        [dep] = self.service.deployments()
        self.assertIsNone(dep["application"])

    def test_no_claiming_app_stays_unlinked(self):
        _git_integration(self, "pi", "/srv/app", REMOTE, branch="main",
                         commit="abcdef0123", last_seen=NOW.isoformat())
        self.service.tick(now=NOW)
        [dep] = self.service.deployments()
        self.assertIsNone(dep["application"])


# -- project registry integration -----------------------------------------

class TestProjectIntegration(unittest.TestCase):
    def setUp(self):
        _setup_service(self)
        self._device_row("pi")
        self._project = None
        from pinoc.projects import ProjectService
        self._project = ProjectService(self.db, audit=_record_audit.__get__(self, type(self)))
        self._project.create({"name": "Display", "slug": "display"})

    def test_roster_source_is_registered(self):
        self.service.create({"name": "Y", "url": REMOTE})
        self.service.create({"name": "Z", "url": "https://gitlab.com/a/z"})
        unassigned = self._project.unassigned("repository")
        self.assertEqual(sorted(unassigned["unassigned"]), ["y", "z"])

    def test_archived_repos_are_not_in_roster(self):
        repo = self.service.create({"name": "Y", "url": REMOTE})
        self.service.archive(repo["id"])
        self.assertEqual(self._project.unassigned("repository")["unassigned"], [])

    def test_project_software_groups_by_application(self):
        self.service.create({"name": "Y", "url": REMOTE})
        # Two deployments of the same repo: one linked to an app, one unlinked.
        self.db.execute(
            "INSERT INTO applications(slug,name,repository,lifecycle,created_at,updated_at)"
            " VALUES('desk','Desk',?,'active',?,?)",
            (REMOTE, NOW.isoformat(), NOW.isoformat()))
        self._seed_deployment("pi", "/srv/app", "desk")
        self._seed_deployment("spare", "/srv/app", None)
        # The repository is tied to the project through the membership table;
        # project_software lives on the repository service and reads both the
        # declared membership and the repository's own project pointer.
        self._add_project_membership()
        grouped = self.service.project_software("display")
        self.assertEqual(len(grouped["groups"]), 2)
        # The linked group sorts before the unlinked (None) group.
        self.assertEqual(grouped["groups"][0]["application"], "desk")
        self.assertIsNone(grouped["groups"][1]["application"])
        self.assertEqual(grouped["groups"][0]["application_name"], "Desk")
        self.assertEqual(sum(g["deployment_count"] for g in grouped["groups"]), 2)

    def test_project_software_unknown_project_raises(self):
        with self.assertRaises(RepositoryNotFound):
            self.service.project_software("ghost")

    def _add_project_membership(self):
        self.db.execute(
            "INSERT INTO project_members(project_id,kind,object_id,added_at)"
            " VALUES(1,'repository','y',?)", (NOW.isoformat(),))

    def _seed_deployment(self, device_id, path, app_slug):
        self._device_row(device_id)
        self.db.execute(
            "INSERT INTO deployments(repo_slug,device_id,local_path,application_slug,"
            "state,state_reasons_json,created_at,updated_at)"
            " VALUES('y',?,?,?,'unknown','[]',?,?)",
            (device_id, path, app_slug, NOW.isoformat(), NOW.isoformat()))


# -- web surface ----------------------------------------------------------

class TestWeb(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.db = Database(f"{self._tmp.name}/db.sqlite")
        assert self.db.initialize()
        self.history = HistoryManager(self.db, {})
        self.state = PiNOCState()
        self.state.publish([
            DeviceState(id="pi", hostname="pi", friendly_name="Pi", online=True,
                        health="healthy", integrations={
                            "git": {"data": [{"path": "/srv/app",
                                              "remote_url": REMOTE,
                                              "branch": "main",
                                              "commit": "abcdef0123",
                                              "dirty": False}]}})
        ], replace=True)
        self.app = create_app(
            self.state, {"TESTING": True, "AUTH_ENABLED": True,
                         "SECRET_KEY": "test-secret", "DATABASE": self.db},
            self.history, None)
        self.security = self.app.extensions["pinoc_security"]
        self.security.create_user("alice", "pw1234567890", "viewer")
        self.security.create_user("bob", "pw1234567890", "administrator")
        self.client = self.app.test_client()
        self.db.execute(
            "INSERT INTO projects(project_id,slug,name,created_at,updated_at)"
            " VALUES(1,'display','Display',?,?)", (NOW.isoformat(), NOW.isoformat()))
        self.service = self.app.extensions["pinoc_repositories"]
        self.service.create({"name": "Y", "url": REMOTE})

    def tearDown(self):
        actions = self.app.extensions.get("pinoc_actions")
        if actions:
            actions.stop()

    def _login(self, username, password="pw1234567890"):
        self.client.get("/login")
        with self.client.session_transaction() as session:
            csrf = session["csrf_token"]
        return self.client.post(
            "/login", data={"username": username, "password": password,
                            "csrf_token": csrf})

    def _csrf(self):
        with self.client.session_transaction() as session:
            return session["csrf_token"]

    def _post(self, path, body=None):
        return self.client.post(path, json=body or {},
                                headers={"X-CSRF-Token": self._csrf()})

    def _patch(self, path, body=None):
        return self.client.patch(path, json=body or {},
                                 headers={"X-CSRF-Token": self._csrf()})

    def test_app_builds_and_exposes_service(self):
        self.assertIsNotNone(self.service)
        self._login("bob")
        self.assertEqual(self.client.get("/repositories").status_code, 200)

    def test_unauthenticated_api_is_401(self):
        self.assertEqual(self.client.get("/api/v1/repositories").status_code, 401)
        self.assertEqual(self.client.get("/api/v1/deployments").status_code, 401)
        self.assertEqual(self.client.get("/api/v1/repositories/y").status_code, 401)
        self.assertEqual(self.client.get("/repositories").status_code, 302)

    def test_viewer_reads_but_cannot_write(self):
        self._login("alice")
        self.assertEqual(self.client.get("/api/v1/repositories").status_code, 200)
        self.assertEqual(self.client.get("/api/v1/repositories/y").status_code, 200)
        self.assertEqual(self.client.get("/api/v1/deployments").status_code, 200)
        self.assertEqual(
            self.client.get("/api/v1/projects/display/software").status_code, 200)
        self.assertEqual(self._post("/api/v1/repositories",
                                    {"name": "Z", "url": "https://g.co/a/b"}).status_code, 403)
        self.assertEqual(self._patch("/api/v1/repositories/y",
                                     {"name": "Nope"}).status_code, 403)
        self.assertEqual(self._post("/api/v1/repositories/y/archive", {}).status_code, 403)
        self.assertEqual(
            self._patch("/api/v1/deployments/1", {"service": "x"}).status_code, 403)

    def test_token_scope_permissions_registered(self):
        permissions = self.app.config["TOKEN_SCOPE_PERMISSIONS"]
        for endpoint, permission in {
            "api_v1_repositories": "view",
            "api_v1_repositories_create": "config.write",
            "api_v1_repository": "view",
            "api_v1_repository_update": "config.write",
            "api_v1_repository_archive": "config.write",
            "api_v1_repository_restore": "config.write",
            "api_v1_deployments": "view",
            "api_v1_deployment": "view",
            "api_v1_deployment_update": "config.write",
            "api_v1_project_software": "view",
        }.items():
            self.assertEqual(permissions[endpoint], permission, msg=endpoint)

    def test_admin_create_get_update(self):
        self._login("bob")
        response = self._post("/api/v1/repositories",
                              {"name": "Y2", "url": "https://gitlab.com/p/q", "slug": "y2"})
        self.assertEqual(response.status_code, 201, response.get_data(as_text=True))
        self.assertEqual(response.get_json()["repository"]["slug"], "y2")
        self.assertEqual(self.client.get("/api/v1/repositories/y2").status_code, 200)
        updated = self._patch("/api/v1/repositories/y2", {"description": "d"})
        self.assertEqual(updated.status_code, 200)
        self.assertEqual(updated.get_json()["repository"]["description"], "d")
        self.assertEqual(self.client.get("/api/v1/repositories/nope").status_code, 404)

    def test_admin_validation_errors(self):
        self._login("bob")
        self.assertEqual(self._post("/api/v1/repositories",
                                    {"url": REMOTE}).status_code, 400)  # no name
        self.assertEqual(self._post("/api/v1/repositories",
                                    {"name": "Y2", "url": REMOTE}).status_code, 409)  # dup canonical
        self.assertEqual(self._post("/api/v1/repositories",
                                    {"name": "Z", "url": "bogus"}).status_code, 400)

    def test_admin_archive_restore(self):
        self._login("bob")
        self.assertEqual(self._post("/api/v1/repositories/y/archive", {}).status_code, 200)
        self.assertTrue(self.client.get(
            "/api/v1/repositories/y?include_archived=true").get_json()["repository"]["archived"])
        self.assertEqual(self._post("/api/v1/repositories/y/restore", {}).status_code, 200)
        self.assertFalse(self.client.get(
            "/api/v1/repositories/y").get_json()["repository"]["archived"])

    def test_deployments_endpoint(self):
        self._login("bob")
        self.service.create({"name": "Z", "url": "https://gitlab.com/a/b"})
        self.db.execute(
            "INSERT INTO deployments(repo_slug,device_id,local_path,state,"
            "state_reasons_json,created_at,updated_at)"
            " VALUES('y','pi','/srv/app','clean','[]',?,?)",
            (NOW.isoformat(), NOW.isoformat()))
        response = self.client.get("/api/v1/deployments")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.get_json()["deployments"]), 1)
        # Filtered by repository.
        self.assertEqual(len(self.client.get(
            "/api/v1/deployments?repository=z").get_json()["deployments"]), 0)
        # Single deployment by id.
        self.assertEqual(self.client.get("/api/v1/deployments/1").status_code, 200)

    def test_project_software_endpoint(self):
        self._login("bob")
        self.db.execute(
            "INSERT INTO deployments(repo_slug,device_id,local_path,application_slug,"
            "state,state_reasons_json,created_at,updated_at)"
            " VALUES('y','pi','/srv/app','desk','clean','[]',?,?)",
            (NOW.isoformat(), NOW.isoformat()))
        response = self.client.get("/api/v1/projects/display/software")
        self.assertEqual(response.status_code, 200)
        body = response.get_json()
        self.assertEqual(body["project"]["id"], "display")

    def test_credentials_are_redacted(self):
        # A remote that embeds a token must never leak it into an API response.
        self._login("bob")
        self.service.create({"name": "Secure", "slug": "secure",
                             "url": "https://api_key_supersecret@git.example.com/s/r"})
        response = self.client.get("/api/v1/repositories/secure")
        text = response.get_data(as_text=True)
        self.assertNotIn("api_key_supersecret", text)


# -- configuration validation ---------------------------------------------

class TestConfigValidation(unittest.TestCase):
    def test_valid_section_accepted(self):
        validate_repositories({"repositories": {
            "enabled": False, "refresh_seconds": 60, "stale_seconds": 300,
            "event_retention_days": 35}})

    def test_absent_section_is_valid(self):
        validate_repositories({})
        validate_repositories({"repositories": None})

    def test_invalid_values_rejected(self):
        cases = [
            {"repositories": "on"},
            {"repositories": {"enabled": "yes"}},
            {"repositories": {"refresh_seconds": 4}},
            {"repositories": {"refresh_seconds": 86401}},
            {"repositories": {"refresh_seconds": "fast"}},
            {"repositories": {"refresh_seconds": True}},
            {"repositories": {"stale_seconds": 59}},
            {"repositories": {"stale_seconds": 2592001}},
            {"repositories": {"event_retention_days": 0}},
            {"repositories": {"event_retention_days": 3651}},
            {"repositories": {"event_retention_days": 1.5}},
        ]
        for value in cases:
            with self.assertRaises(ValueError, msg=value):
                validate_repositories(value)

    def test_validate_config_runs_repositories(self):
        base = {"devices": [], "polling": {"fleet_seconds": 10}}
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(validate_config(
                {**base, "repositories": {"stale_seconds": 300}}, Path(tmp)),
                {**base, "repositories": {"stale_seconds": 300}})
            with self.assertRaises(ValueError):
                validate_config(
                    {**base, "repositories": {"stale_seconds": 5}}, Path(tmp))


# -- no-database degradation ----------------------------------------------

class TestNoDatabase(unittest.TestCase):
    def setUp(self):
        self.service = RepositoryService(None, state=PiNOCState(),
                                         config=DEFAULT_REPO_CONFIG)

    def test_list_is_empty(self):
        self.assertEqual(self.service.list(include_archived=True), [])

    def test_get_is_none(self):
        self.assertIsNone(self.service.get("y"))

    def test_create_raises(self):
        with self.assertRaises(RepositoryError):
            self.service.create({"name": "Y", "url": REMOTE})

    def test_deployments_is_empty(self):
        self.assertEqual(self.service.deployments(), [])

    def test_tick_reports_unavailable(self):
        self.assertEqual(self.service.tick(now=NOW)["status"], "unavailable")


# -- history retention ----------------------------------------------------

class TestHistoryRetention(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.db = Database(f"{self._tmp.name}/db.sqlite")
        assert self.db.initialize()
        self.now = datetime.now(UTC)
        old = (self.now - timedelta(days=2)).isoformat()
        recent = self.now.isoformat()
        self.db.execute(
            "INSERT INTO deployment_events(repo_slug,event_type,recorded_at)"
            " VALUES('y','state_changed',?)", (old,))
        self.db.execute(
            "INSERT INTO deployment_events(repo_slug,event_type,recorded_at)"
            " VALUES('y','state_changed',?)", (recent,))

    def test_old_events_are_pruned(self):
        history = HistoryManager(self.db, {}, repositories={"event_retention_days": 1})
        history.maintenance(now=self.now)
        self.assertEqual(self.db.scalar("SELECT COUNT(*) FROM deployment_events"), 1)
        self.assertEqual(self.db.rows(
            "SELECT recorded_at FROM deployment_events")[0]["recorded_at"],
            self.now.isoformat())

    def test_default_retention_is_long(self):
        history = HistoryManager(self.db, {})  # 35-day default
        history.maintenance(now=self.now)
        self.assertEqual(self.db.scalar("SELECT COUNT(*) FROM deployment_events"), 2)


if __name__ == "__main__":
    unittest.main()
