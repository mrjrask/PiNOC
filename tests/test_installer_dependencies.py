from pathlib import Path
import unittest

INSTALLER = Path(__file__).parents[1] / "install.sh"
REQUIREMENTS = Path(__file__).parents[1] / "requirements.txt"

class InstallerDependenciesTest(unittest.TestCase):
    def test_installer_is_web_only(self):
        script = INSTALLER.read_text(encoding="utf-8")
        requirements = REQUIREMENTS.read_text(encoding="utf-8").lower()
        self.assertNotIn("enable_spi", script)
        self.assertNotIn("PINOC_DISPLAY_ENABLED", script)
        self.assertNotIn("pillow", requirements)
        self.assertNotIn("displayhatmini", requirements)
        self.assertIn("waitress", requirements)

    def test_service_omits_unavailable_supplementary_groups(self):
        script = INSTALLER.read_text(encoding="utf-8")
        self.assertIn("mapfile -t groups < <(existing_hardware_groups)", script)
        self.assertIn("if ((${#groups[@]})); then", script)
        self.assertIn("sed -i '/^SupplementaryGroups=/d' \"$tmp_service\"", script)

if __name__ == "__main__":
    unittest.main()
