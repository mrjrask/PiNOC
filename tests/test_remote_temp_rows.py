import sys
import types
import unittest
from unittest.mock import patch


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

from pi_noc import (
    CONFIG,
    FONT_NORMAL,
    FONT_SMALL,
    LocalStatus,
    RemoteStatus,
    Snapshot,
    TempDevice,
    VPNStatus,
    build_remote_temp_rows,
)


def make_snapshot(temp_devices):
    return Snapshot(
        collected_at=0.0,
        vpn=VPNStatus(),
        remote=RemoteStatus(),
        local=LocalStatus(),
        temp_devices=temp_devices,
    )


class RemoteTempRowsTest(unittest.TestCase):
    def test_device_rows_do_not_include_endpoint_url(self):
        snapshot = make_snapshot(
            [
                TempDevice(
                    device_id="sensor-1",
                    hostname="Sensor 1",
                    celsius=22.5,
                    fahrenheit=72.5,
                    last_seen=90.0,
                    ip="http://example.test/temps",
                )
            ]
        )

        with patch("pi_noc.time.time", return_value=120.0):
            rows = build_remote_temp_rows(snapshot)

        self.assertEqual(rows, [("Sensor 1", "22.5C 30s", FONT_NORMAL)])

    def test_empty_rows_show_endpoint_url_being_checked(self):
        snapshot = make_snapshot([])
        endpoint = "http://example.test/temps"

        with patch.dict(CONFIG["remote_temp_monitor"], {"endpoint": endpoint}):
            rows = build_remote_temp_rows(snapshot)

        self.assertEqual(
            rows,
            [
                ("No monitors found", "", FONT_NORMAL),
                ("Looking for", endpoint, FONT_SMALL),
            ],
        )


if __name__ == "__main__":
    unittest.main()
