import subprocess
import sys
import unittest


class WebOnlyRuntimeTest(unittest.TestCase):
    def test_runtime_does_not_load_removed_display_hardware(self):
        code = (
            "import sys, pi_noc; "
            "assert 'board' not in sys.modules; "
            "assert 'digitalio' not in sys.modules; "
            "assert 'PIL.Image' not in sys.modules"
        )
        result = subprocess.run(
            [sys.executable, "-c", code], text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
