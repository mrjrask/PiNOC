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
    job = gateway.submit(_identity(), {"device_id": "pi", "workspace_id": "project",
                                       "job_type": "test", "profile": "unit"})
    stored = db.scalar("SELECT environment_json FROM development_jobs WHERE job_id=?", (job["job_id"],))
    assert "real-secret" not in stored
    assert "__encrypted__" in json.loads(stored)
    wire = gateway._wire_job(gateway.job(job["job_id"]))
    assert wire["environment"] == {"API_TOKEN": "real-secret"}
