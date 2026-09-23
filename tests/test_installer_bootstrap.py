from pathlib import Path


SCRIPT = (Path(__file__).parents[1] / "install.sh").read_text(encoding="utf-8")


def test_installer_bootstraps_dependencies_before_validation():
    setup = SCRIPT.index("  setup_venv\n", SCRIPT.index("main() {"))
    validation = SCRIPT.index('"$VENV_DIR/bin/python" -m pinoc.validate_config')
    assert setup < validation
    assert "python3 -m pinoc.validate_config" not in SCRIPT


def test_installer_checks_root_before_bootstrap_work():
    main = SCRIPT.index("main() {")
    root = SCRIPT.index("  need_root", main)
    assert root < SCRIPT.index("  install_system_dependencies", main)
