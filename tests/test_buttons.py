import types
import unittest
from unittest.mock import patch

import pi_noc


class ButtonsTest(unittest.TestCase):
    def test_hardware_modules_are_loaded_lazily(self):
        board = types.SimpleNamespace(
            D4=4,
            D5=5,
            D6=6,
            D16=16,
            D17=17,
            D22=22,
            D23=23,
            D24=24,
            D27=27,
        )

        class DigitalInOut:
            def __init__(self, pin):
                self.pin = pin
                self.direction = None
                self.pull = None

        digitalio = types.SimpleNamespace(
            DigitalInOut=DigitalInOut,
            Direction=types.SimpleNamespace(INPUT="input"),
            Pull=types.SimpleNamespace(UP="up"),
        )

        modules = {"board": board, "digitalio": digitalio}
        with patch.object(
            pi_noc.importlib,
            "import_module",
            side_effect=lambda name: modules[name],
        ) as import_module:
            buttons = pi_noc.Buttons()

        self.assertEqual(set(buttons.devices), {"A", "B", "LEFT", "RIGHT", "UP", "DOWN", "CENTER"})
        self.assertEqual(buttons.devices["A"].pin, board.D5)
        self.assertEqual(
            [call.args[0] for call in import_module.call_args_list],
            ["board", "digitalio"],
        )


if __name__ == "__main__":
    unittest.main()
