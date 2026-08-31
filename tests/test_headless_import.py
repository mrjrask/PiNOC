import os
import subprocess
import sys
import unittest


class HeadlessImportTest(unittest.TestCase):
    def test_web_only_import_does_not_load_display_hardware(self):
        env = dict(os.environ, PINOC_DISPLAY_ENABLED="0")
        code = (
            "import sys, pi_noc; "
            "assert 'board' not in sys.modules; "
            "assert 'digitalio' not in sys.modules; "
            "assert 'PIL.Image' not in sys.modules"
        )
        result = subprocess.run(
            [sys.executable, "-c", code], env=env, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
