from pathlib import Path


ROOT = Path(__file__).parents[1]


def test_development_requirements_include_runtime_and_pytest():
    requirements = (ROOT / "requirements-dev.txt").read_text(encoding="utf-8")
    assert "-r requirements.txt" in requirements
    assert "pytest" in requirements


def test_readme_bootstraps_development_requirements():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "apt-get install -y python3-venv python3-cryptography" in readme
    assert "python3 -m venv --system-site-packages .venv" in readme
    assert "pip install -r requirements-dev.txt" in readme
