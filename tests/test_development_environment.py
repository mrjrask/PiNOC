import json

from pinoc.database import Database
from pinoc.development import DevelopmentGateway, PROTOCOL_VERSION


def _identity():
    return {"username": "codex", "role": "administrator", "token": True,
            "token_id": "token", "scopes": ["dev:read", "dev:test"],
            "devices": [], "workspaces": [], "job_types": []}


def test_secret_environment_is_encrypted_at_rest_and_restored_for_agent(tmp_path):
    db = Database(str(tmp_path / "development.sqlite"))
    assert db.initialize()
    gateway = DevelopmentGateway(db, str(tmp_path / "jobs"), {}, "stable-key")
    code = gateway.enrollment_code("pi", "admin")
    gateway.enroll({"enrollment_code": code, "hostname": "pi", "model": "Pi",
                    "architecture": "aarch64", "agent_version": "1.0.0",
                    "protocol_version": PROTOCOL_VERSION, "capabilities": {}})
    root = tmp_path / "workspace"
    root.mkdir()
    gateway.save_workspace({"workspace_id": "project", "device_id": "pi", "path": str(root),
                            "mode": "development", "approved": True,
                            "allowed_job_types": ["test"], "allowed_env": ["API_TOKEN"],
                            "test_profiles": {"unit": {"argv": ["python3", "-V"],
                                                            "environment": {"API_TOKEN": "real-secret"}}}})
    stored_profiles = db.scalar("SELECT test_profiles_json FROM workspaces WHERE workspace_id=?",
                                ("project",))
    assert "real-secret" not in stored_profiles
    assert "__encrypted__" in json.loads(stored_profiles)
    assert gateway.workspace("project")["test_profiles"]["unit"]["environment"] == {
        "API_TOKEN": "[REDACTED]"
    }
    job = gateway.submit(_identity(), {"device_id": "pi", "workspace_id": "project",
                                       "job_type": "test", "profile": "unit"})
    stored = db.scalar("SELECT environment_json FROM development_jobs WHERE job_id=?", (job["job_id"],))
    assert "real-secret" not in stored
    assert "__encrypted__" in json.loads(stored)
    wire = gateway._wire_job(gateway.job(job["job_id"]))
    assert wire["environment"] == {"API_TOKEN": "real-secret"}
    assert wire["workspace"]["test_profiles"]["unit"]["environment"] == {
        "API_TOKEN": "[REDACTED]"
    }


def test_legacy_plaintext_profile_secrets_are_encrypted_on_read(tmp_path):
    db = Database(str(tmp_path / "development.sqlite"))
    assert db.initialize()
    gateway = DevelopmentGateway(db, str(tmp_path / "jobs"), {}, "stable-key")
    root = tmp_path / "workspace"
    root.mkdir()
    gateway.save_workspace({"workspace_id": "legacy", "device_id": "pi", "path": str(root),
                            "test_profiles": {}})
    legacy_profiles = {"unit": {"environment": {"API_TOKEN": "legacy-secret"}}}
    db.execute("UPDATE workspaces SET test_profiles_json=? WHERE workspace_id=?",
               (json.dumps(legacy_profiles), "legacy"))

    workspace = gateway.workspace("legacy")

    assert workspace["test_profiles"]["unit"]["environment"]["API_TOKEN"] == "[REDACTED]"
    stored = db.scalar("SELECT test_profiles_json FROM workspaces WHERE workspace_id=?",
                       ("legacy",))
    assert "legacy-secret" not in stored
    assert "__encrypted__" in json.loads(stored)
    assert gateway.workspace("legacy", include_secrets=True)["test_profiles"] == legacy_profiles
