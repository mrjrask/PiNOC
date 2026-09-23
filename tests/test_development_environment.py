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
    envelope = json.loads(stored)["__pinoc_environment__"]
    assert envelope["version"] == 1
    assert envelope["encoding"] == "fernet"
    wire = gateway._wire_job(gateway.job(job["job_id"]))
    assert wire["environment"] == {"API_TOKEN": "real-secret"}


def test_reserved_looking_environment_key_is_not_treated_as_ciphertext(tmp_path):
    db = Database(str(tmp_path / "development.sqlite"))
    assert db.initialize()
    gateway = DevelopmentGateway(db, str(tmp_path / "jobs"), {}, "stable-key")
    encoded = gateway._encode_environment({"__encrypted__": "ordinary-value"})
    row = {"environment_json": encoded}
    assert json.loads(encoded)["__pinoc_environment__"]["encoding"] == "plain"
    assert gateway._decode_environment(row) == {"__encrypted__": "ordinary-value"}


def test_redacted_profile_update_preserves_encrypted_secret(tmp_path):
    db = Database(str(tmp_path / "development.sqlite"))
    assert db.initialize()
    gateway = DevelopmentGateway(db, str(tmp_path / "jobs"), {}, "stable-key")
    root = tmp_path / "workspace"
    root.mkdir()
    original = {"workspace_id": "project", "device_id": "pi", "path": str(root),
                "test_profiles": {"deploy": {"environment": {
                    "API_TOKEN": "real-secret"}, "timeout": 10}}}
    shown = gateway.save_workspace(original)
    stored = db.scalar("SELECT test_profiles_json FROM workspaces WHERE workspace_id='project'")
    assert "real-secret" not in stored
    assert shown["test_profiles"]["deploy"]["environment"]["API_TOKEN"] == "[REDACTED]"
    assert gateway.workspaces()[0]["test_profiles"]["deploy"]["environment"]["API_TOKEN"] == "[REDACTED]"

    shown["test_profiles"]["deploy"]["timeout"] = 20
    gateway.save_workspace(shown)
    profile = gateway.workspace("project")["test_profiles"]["deploy"]
    assert profile["environment"]["API_TOKEN"] == "real-secret"
    assert profile["timeout"] == 20


def test_metadata_like_profile_names_are_nested_in_plain_envelope(tmp_path):
    db = Database(str(tmp_path / "development.sqlite"))
    assert db.initialize()
    gateway = DevelopmentGateway(db, str(tmp_path / "jobs"), {}, "stable-key")
    root = tmp_path / "workspace"
    root.mkdir()
    profiles = {"__encrypted__": {"argv": ["python3", "-V"]},
                "__pinoc_profiles__": {"version": 1, "encoding": "fernet",
                                       "payload": "not-ciphertext"}}
    gateway.save_workspace({"workspace_id": "project", "device_id": "pi",
                            "path": str(root), "test_profiles": profiles})
    stored = json.loads(db.scalar(
        "SELECT test_profiles_json FROM workspaces WHERE workspace_id='project'"))
    assert stored["__pinoc_profiles__"]["encoding"] == "plain"
    assert stored["__pinoc_profiles__"]["payload"] == profiles
    assert gateway.workspace("project")["test_profiles"] == profiles
