import sys
import types
import unittest
from datetime import datetime, timezone
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
    SharedSnapshotCoordinator,
    TempDevice,
    VPNStatus,
    build_remote_temp_rows,
)
from pinoc.state import PiNOCState
from pinoc.models import DeviceState


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

    def test_shared_collector_expires_stale_temperature_devices(self):
        state = PiNOCState()
        coordinator = SharedSnapshotCoordinator(state)
        coordinator.temp_devices["stale"] = TempDevice(
            device_id="stale", hostname="Stale", celsius=20, fahrenheit=68,
            last_seen=0, ip="sensor",
        )
        try:
            with patch.dict(CONFIG["remote_temp_monitor"], {"enabled": False, "max_device_age": 1}):
                coordinator.collect_temperatures()
            self.assertIsNone(state.device("stale"))
        finally:
            coordinator.stop()

    def test_fleet_local_device_replaces_legacy_local_device_with_a_different_id(self):
        state = PiNOCState()
        coordinator = SharedSnapshotCoordinator(state)
        coordinator.local_fleet_ids = {"pinoc"}
        coordinator.fleet_devices = [DeviceState(
            id="pinoc", hostname="pinoc", friendly_name="PiNOC", collection_method="local"
        )]
        try:
            coordinator._publish()
            device_ids = {device["id"] for device in state.devices()}
            self.assertIn("pinoc", device_ids)
            self.assertFalse(any(device_id.startswith("local:") for device_id in device_ids))
        finally:
            coordinator.stop()

    def test_fleet_device_preserves_legacy_applications_and_raid_health(self):
        state = PiNOCState()
        coordinator = SharedSnapshotCoordinator(state)
        coordinator.snapshot.remote.online = True
        coordinator.snapshot.remote.raid_status = "DEGRADED"
        coordinator.snapshot.remote.smb_sessions = 2
        coordinator.fleet_devices = [DeviceState(
            id="cm5-file-server", hostname="cm5", friendly_name="CM5", online=True,
            health="healthy", last_successful_collection=datetime.now(timezone.utc).isoformat(),
        )]
        try:
            coordinator._publish()
            device = state.device("cm5-file-server")
            self.assertEqual(device["applications"]["samba"]["sessions"], 2)
            self.assertEqual(device["applications"]["raid"]["status"], "DEGRADED")
            self.assertEqual(device["health"], "critical")
        finally:
            coordinator.stop()


if __name__ == "__main__":
    unittest.main()
