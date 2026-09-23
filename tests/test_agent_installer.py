from pathlib import Path


SCRIPT = (Path(__file__).parents[1] / "install_agent.sh").read_text(encoding="utf-8")


def test_agent_installer_installs_runtime_prerequisites():
    assert "python3-venv" in SCRIPT
    assert "python3-cryptography" in SCRIPT
    assert "bubblewrap" in SCRIPT
    assert "--system-site-packages" in SCRIPT


def test_agent_installer_does_not_mask_dependency_failures():
    assert "|| true" not in SCRIPT
    assert "pip install" not in SCRIPT
    assert "from cryptography.fernet import Fernet" in SCRIPT
