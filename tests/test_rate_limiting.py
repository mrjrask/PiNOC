import time

import pytest

from pinoc.config_store import validate_config
from pinoc.database import Database
from pinoc.history import HistoryManager
from pinoc.models import DeviceState
from pinoc.security import DEFAULT_RATE_LIMIT, SlidingWindow, SecurityManager
from pinoc.state import PiNOCState
from pinoc.web.app import create_app

class Coordinator:
    def __init__(self):
        self.refreshed = []
    def refresh_device(self, device):
        self.refreshed.append(device)
    def refresh(self):
        self.refreshed.append("all")

def fixture(tmp_path, rate_limit=None, auth_enabled=True):
    db = Database(str(tmp_path / "db.sqlite"))
    assert db.initialize()
    history = HistoryManager(db, {})
    security = SecurityManager(db, auth_enabled, rate_limit)
    security.create_user("person", "correct horse battery", "administrator")
    state = PiNOCState()
    state.publish([DeviceState("pi", "pi", "Pi", online=True, address="host", collection_method="ssh", manageable_services=["demo.service"])])
    config = {"TESTING": True, "AUTH_ENABLED": auth_enabled, "SECRET_KEY": "test-secret", "DATABASE": db}
    if rate_limit is not None:
        config["RATE_LIMIT"] = rate_limit
    app = create_app(state, config, history, Coordinator())
    return app, db

def login(client, password="wrong"):
    client.get("/login")
    with client.session_transaction() as session:
        csrf = session["csrf_token"]
    return client.post("/login", data={"username": "person", "password": password, "csrf_token": csrf})

def test_sliding_window_expiry_and_key_eviction(tmp_path):
    window = SlidingWindow(0.05, max_keys=2)
    window.record("a")
    window.record("b")
    window.record("c")
    assert len(window.entries) <= 2
    assert "c" in window.entries
    assert window.count("c") == 1
    time.sleep(0.06)
    assert window.count("c") == 0
    assert "c" not in window.entries

def test_login_lockout_transitions_to_429_and_audits(tmp_path):
    app, db = fixture(tmp_path, rate_limit={"login_window_seconds": 300, "login_max_failed": 3, "lockout_seconds": 900})
    c = app.test_client()
    assert login(c).status_code == 200
    assert login(c).status_code == 200
    # The attempt that crosses the limit starts the lockout and receives 429.
    locked = login(c)
    assert locked.status_code == 429
    assert "Too many" in locked.json["error"]
    # A correct password does not bypass an active lockout.
    assert login(c, "correct horse battery").status_code == 429
    assert db.scalar("SELECT COUNT(*) FROM audit_records WHERE action='auth.lockout'") == 1
    app.extensions["pinoc_actions"].stop()

def test_login_success_clears_failures_and_lockout(tmp_path):
    app, db = fixture(tmp_path, rate_limit={"login_window_seconds": 300, "login_max_failed": 2, "lockout_seconds": 900})
    c = app.test_client()
    assert login(c).status_code == 200
    assert login(c, "correct horse battery").status_code == 302
    security = app.extensions["pinoc_security"]
    assert not security.login_lockouts
    # After a successful login the failure window restarts from zero.
    assert login(c).status_code == 200
    assert login(c).status_code == 429
    app.extensions["pinoc_actions"].stop()

def test_authenticate_lockout_semantics(tmp_path):
    db = Database(str(tmp_path / "db.sqlite"))
    assert db.initialize()
    security = SecurityManager(db, True, {"login_window_seconds": 300, "login_max_failed": 2, "lockout_seconds": 900})
    security.create_user("person", "correct horse battery", "viewer")
    security.create_user("other", "another secret phrase", "viewer")
    assert security.authenticate("person", "nope", "10.0.0.1") == (None, "Invalid username or password.", False)
    assert security.authenticate("person", "nope", "10.0.0.1") == (None, "Too many login attempts; try again later.", True)
    assert security.authenticate("person", "correct horse battery", "10.0.0.1") == (None, "Too many login attempts; try again later.", True)
    assert security.db.scalar("SELECT COUNT(*) FROM audit_records WHERE action='auth.lockout'") == 1
    # The lockout key is per (ip, username): another account is unaffected.
    assert security.authenticate("other", "correct horse battery", "10.0.0.1") == (None, "Invalid username or password.", False)
    security.login_lockouts[("10.0.0.1", "person")] = time.monotonic() - 1
    row, error, locked = security.authenticate("person", "correct horse battery", "10.0.0.1")
    assert row is not None and error is None and locked is False

def test_login_source_lockout_cannot_be_bypassed_by_rotating_usernames(tmp_path):
    db = Database(str(tmp_path / "db.sqlite"))
    assert db.initialize()
    security = SecurityManager(db, True, {
        "login_window_seconds": 300,
        "login_max_failed": 5,
        "login_max_failed_per_source": 3,
        "lockout_seconds": 900,
    })
    security.create_user("person", "correct horse battery", "viewer")
    for username in ("unknown-one", "unknown-two"):
        assert security.authenticate(username, "wrong", "10.0.0.1")[2] is False
    assert security.authenticate("unknown-three", "wrong", "10.0.0.1")[2] is True
    # The source ceiling also blocks a valid account and does not affect a
    # different source address.
    assert security.authenticate("person", "correct horse battery", "10.0.0.1")[2] is True
    row, error, locked = security.authenticate("person", "correct horse battery", "10.0.0.2")
    assert row is not None and error is None and locked is False
    audit = db.rows("SELECT parameters_json FROM audit_records WHERE action='auth.lockout'")
    assert len(audit) == 1
    assert '"scope": "source"' in audit[0]["parameters_json"]

def test_unauthenticated_api_requests_are_rate_limited(tmp_path):
    app, db = fixture(tmp_path, rate_limit={"api_window_seconds": 60, "api_max_unauthenticated": 3})
    c = app.test_client()
    assert c.get("/").status_code == 302
    for _ in range(3):
        assert c.get("/api/devices").status_code == 401
    blocked = c.get("/api/devices")
    assert blocked.status_code == 429
    assert blocked.headers["Retry-After"] == "60"
    # Bearer-token requests carry an identity and are exempt from the limit.
    security = app.extensions["pinoc_security"]
    token = security.create_token("person", ["read:fleet"])
    assert c.get("/api/devices", headers={"Authorization": "Bearer " + token}).status_code == 200
    app.extensions["pinoc_actions"].stop()

def test_authenticated_browser_is_exempt_from_api_limit(tmp_path):
    app, db = fixture(tmp_path, rate_limit={"api_window_seconds": 60, "api_max_unauthenticated": 2})
    c = app.test_client()
    assert login(c, "correct horse battery").status_code == 302
    for _ in range(6):
        assert c.get("/api/devices").status_code == 200
    app.extensions["pinoc_actions"].stop()

def test_disabled_auth_is_not_rate_limited(tmp_path):
    app, db = fixture(tmp_path, auth_enabled=False, rate_limit={"api_window_seconds": 60, "api_max_unauthenticated": 2})
    c = app.test_client()
    for _ in range(5):
        assert c.get("/api/devices").status_code == 200
    app.extensions["pinoc_actions"].stop()

def test_defaults_are_sensible():
    assert DEFAULT_RATE_LIMIT == {"login_window_seconds": 300, "login_max_failed": 5, "login_max_failed_per_source": 20, "lockout_seconds": 900, "api_window_seconds": 60, "api_max_unauthenticated": 120}

def test_validate_config_security_rate_limit(tmp_path):
    base = {"devices": [], "polling": {"fleet_seconds": 10}}
    good = {**base, "security": {"rate_limit": {"login_max_failed": 3, "api_window_seconds": 60, "lockout_seconds": 900}}}
    assert validate_config(good, tmp_path) is good
    assert validate_config({**base, "security": {}}, tmp_path) is not None
    bad_limits = (
        {"login_max_failed": 0},
        {"login_max_failed": -1},
        {"login_max_failed": "five"},
        {"login_max_failed": True},
        {"login_max_failed_per_source": 0},
        {"unknown_setting": 1},
        {"api_max_unauthenticated": 100000},
    )
    for bad in bad_limits:
        with pytest.raises(ValueError):
            validate_config({**base, "security": {"rate_limit": bad}}, tmp_path)
    with pytest.raises(ValueError):
        validate_config({**base, "security": "nope"}, tmp_path)
    with pytest.raises(ValueError):
        validate_config({**base, "security": {"rate_limit": "nope"}}, tmp_path)
