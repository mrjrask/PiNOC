import subprocess
import sys
import unittest
from unittest.mock import patch

import pi_noc


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

    def test_i2c_bus_dependencies_are_loaded_when_sensor_collection_needs_them(self):
        class FakeBusio:
            @staticmethod
            def I2C(clock, data):
                return clock, data

        class FakeBoard:
            SCL = "clock"
            SDA = "data"

        modules = {"busio": FakeBusio, "board": FakeBoard}
        with patch.object(
            pi_noc.importlib,
            "import_module",
            side_effect=modules.__getitem__,
        ) as import_module:
            self.assertEqual(pi_noc.create_i2c_bus(), ("clock", "data"))

        self.assertEqual(
            [call.args[0] for call in import_module.call_args_list],
            ["busio", "board"],
        )


if __name__ == "__main__":
    unittest.main()
