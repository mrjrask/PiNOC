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
    LocalStatus,
    RemoteStatus,
    Snapshot,
    VPNStatus,
    network_available,
    vpn_required,
)


class VPNOptionalWifiTest(unittest.TestCase):
    def test_vpn_not_required_on_wiffy(self):
        local = LocalStatus(wifi_ssid="wiffy")

        with patch.dict(CONFIG, {"vpn_optional_wifi_networks": ["wiffy", "wiffyToo"]}):
            self.assertFalse(vpn_required(local))

    def test_vpn_not_required_on_wiffy_too(self):
        snapshot = Snapshot(
            collected_at=0.0,
            vpn=VPNStatus(),
            remote=RemoteStatus(),
            local=LocalStatus(wifi_ssid="wiffyToo"),
        )

        with patch.dict(CONFIG, {"vpn_optional_wifi_networks": ["wiffy", "wiffyToo"]}):
            self.assertTrue(network_available(snapshot))

    def test_vpn_required_on_unknown_wifi(self):
        snapshot = Snapshot(
            collected_at=0.0,
            vpn=VPNStatus(),
            remote=RemoteStatus(),
            local=LocalStatus(wifi_ssid="guest"),
        )

        with patch.dict(CONFIG, {"vpn_optional_wifi_networks": ["wiffy", "wiffyToo"]}):
            self.assertTrue(vpn_required(snapshot.local))
            self.assertFalse(network_available(snapshot))


if __name__ == "__main__":
    unittest.main()
