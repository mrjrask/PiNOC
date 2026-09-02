from pathlib import Path
import unittest


INSTALLER = Path(__file__).parents[1] / "install.sh"


class InstallerDependenciesTest(unittest.TestCase):
    def test_installer_includes_freetype_runtime_for_pillow_fonts(self):
        script = INSTALLER.read_text(encoding="utf-8")
        dependency_block = script.split("APT_PACKAGES=(", 1)[1].split(")", 1)[0]

        self.assertIn("libfreetype6", dependency_block.split())
        self.assertIn("ImageFont.truetype", script)


if __name__ == "__main__":
    unittest.main()
