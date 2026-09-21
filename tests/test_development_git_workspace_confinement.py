"""git's -C/--git-dir/--work-tree must stay inside the approved workspace."""
import pytest

from pinoc.database import Database
from pinoc.development import DevelopmentGateway, DevError, PROTOCOL_VERSION


def setup(tmp_path):
    db = Database(str(tmp_path / "pinoc.db"))
    assert db.initialize()
    gw = DevelopmentGateway(db, str(tmp_path / "jobs"), {}, "test-credential-key")
    return db, gw


def enroll(gw):
    code = gw.enrollment_code("pi", "admin")
    return gw.enroll({
        "enrollment_code": code, "hostname": "mock", "model": "Pi",
        "architecture": "aarch64", "agent_version": "1.0.0",
        "protocol_version": PROTOCOL_VERSION, "capabilities": {},
    })


def workspace(gw, path):
    return gw.save_workspace({
        "workspace_id": "project", "device_id": "pi", "path": str(path),
        "mode": "development", "approved": True,
        "allowed_job_types": ["command"], "allowed_commands": ["git"], "allowed_env": [],
    })


def identity(**kw):
    return {"username": "codex", "role": "administrator", "token": True, "token_id": "t",
            "scopes": ["dev:command"], "devices": [], "workspaces": [], "job_types": [], **kw}


def submit(gw, argv):
    return gw.submit(identity(), {"device_id": "pi", "workspace_id": "project",
                                   "job_type": "command", "argv": argv})


def test_path_options_that_escape_the_workspace_are_rejected(tmp_path):
    _, gw = setup(tmp_path)
    enroll(gw)
    root = tmp_path / "repo"
    root.mkdir()
    workspace(gw, root)
    escapes = [
        ["git", "-C", "/etc", "log"],
        ["git", "-C", "/etc/passwd", "log"],
        ["git", "-C", "..", "log"],
        ["git", "-C", "../../etc", "log"],
        ["git", "--git-dir=/etc/.git", "log"],
        ["git", "--work-tree=/tmp", "status"],
        ["git", "--work-tree", "/tmp", "status"],
        # --exec-path/--namespace/--super-prefix have no legitimate use here
        # and are rejected outright, regardless of value.
        ["git", "--exec-path", str(root), "status"],
        ["git", "--namespace=x", "log"],
        ["git", "--super-prefix=/", "log"],
    ]
    for argv in escapes:
        with pytest.raises(DevError) as error:
            submit(gw, argv)
        assert error.value.error_type == "authorization_denied"


def test_path_options_within_the_workspace_are_allowed(tmp_path):
    _, gw = setup(tmp_path)
    enroll(gw)
    root = tmp_path / "repo"
    root.mkdir()
    (root / "sub").mkdir()
    workspace(gw, root)
    allowed = [
        ["git", "-C", ".", "status"],
        ["git", "-C", str(root), "status"],
        ["git", "-C", "sub", "status"],
        ["git", "--git-dir=" + str(root / ".git"), "log"],
        ["git", "--work-tree", str(root), "status"],
    ]
    for argv in allowed:
        job = submit(gw, argv)
        assert job["status"] == "queued"


if __name__ == "__main__":
    import unittest
    unittest.main()
