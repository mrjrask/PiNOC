import subprocess
import sys
import unittest
from unittest.mock import MagicMock, patch

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

    def test_web_server_failure_propagates_and_stops_backends(self):
        history = MagicMock()
        coordinator = MagicMock()
        failure = OSError("address already in use")
        with (
            patch("pinoc.database.Database"),
            patch("pinoc.history.HistoryManager", return_value=history),
            patch.object(pi_noc, "SharedSnapshotCoordinator", return_value=coordinator),
            patch("pinoc.web.create_app", return_value=object()),
            patch("pinoc.web.serve", side_effect=failure),
        ):
            with self.assertRaisesRegex(OSError, "address already in use"):
                pi_noc.main()

        coordinator.stop.assert_called_once_with()
        history.stop.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
