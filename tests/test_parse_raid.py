import sys
import types
import unittest


def install_import_stubs():
    class BoardStub(types.ModuleType):
        def __getattr__(self, name):
            value = object()
            setattr(self, name, value)
            return value

    board = BoardStub("board")
    sys.modules.setdefault("board", board)

    digitalio = types.ModuleType("digitalio")
    digitalio.DigitalInOut = object
    digitalio.Direction = types.SimpleNamespace(INPUT="INPUT", OUTPUT="OUTPUT")
    digitalio.Pull = types.SimpleNamespace(UP="UP", DOWN="DOWN")
    sys.modules.setdefault("digitalio", digitalio)


install_import_stubs()

from pi_noc import parse_raid


MDSTAT = """Personalities : [raid1]
md0 : active raid1 sdb1[1] sda1[0]
      976630336 blocks super 1.2 [2/2] [UU]

unused devices: <none>
"""


class ParseRaidTest(unittest.TestCase):
    def test_accepts_bare_md_device_name(self):
        self.assertEqual(parse_raid(MDSTAT, "md0"), ("CLEAN", "UU"))

    def test_accepts_dev_absolute_device_path(self):
        self.assertEqual(parse_raid(MDSTAT, "/dev/md0"), ("CLEAN", "UU"))

    def test_accepts_dev_relative_device_path(self):
        self.assertEqual(parse_raid(MDSTAT, "dev/md0"), ("CLEAN", "UU"))

    def test_missing_array_uses_normalized_device_name(self):
        self.assertEqual(
            parse_raid(MDSTAT, "/dev/md1"),
            ("MISSING", "/dev/md1 not in mdstat"),
        )

    def test_empty_normalized_device_is_unknown(self):
        self.assertEqual(
            parse_raid(MDSTAT, " /dev/ "),
            ("UNKNOWN", "No RAID device configured"),
        )


if __name__ == "__main__":
    unittest.main()
