import time
import unittest

from pinoc.collectors.base import Collector
from pinoc.models import DeviceState
from pinoc.state import PiNOCState
try:
    from pinoc.web import create_app
except ModuleNotFoundError:
    create_app = None


class BrokenCollector(Collector):
    name = "broken"
    def collect(self):
        raise RuntimeError("expected failure")


class SharedStateTest(unittest.TestCase):
    def test_device_normalization_is_json_safe(self):
        device = DeviceState(id="stable-id", hostname="pi", friendly_name="Pi")
        self.assertEqual(DeviceState.from_dict(device.to_dict()).id, "stable-id")

    def test_collector_failure_is_isolated(self):
        self.assertEqual(BrokenCollector().safe_collect(), [])


@unittest.skipIf(create_app is None, "Flask dependency is not installed")
class APIBackendTest(unittest.TestCase):
    def setUp(self):
        self.state = PiNOCState()
        self.device = DeviceState(id="stable-id", hostname="pi", friendly_name="Pi",
                                  online=True, health="healthy", last_seen="2026-08-31T00:00:00Z",
                                  services=[{"name": "ssh.service", "state": "active"}])
        self.state.publish([self.device])
        self.client = create_app(self.state, {"TESTING": True}).test_client()

    def test_api_reads_cached_devices(self):
        response = self.client.get("/api/devices")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["devices"][0]["id"], "stable-id")

    def test_required_api_and_health_responses(self):
        self.assertEqual(self.client.get("/health").get_json()["online"], 1)
        self.assertEqual(self.client.get("/api/status").status_code, 200)
        self.assertEqual(self.client.get("/api/devices/stable-id").status_code, 200)
        self.assertEqual(self.client.get("/api/devices/stable-id/services").get_json()["services"][0]["state"], "active")
        self.assertEqual(self.client.get("/api/alerts").get_json(), {"alerts": []})

    def test_unknown_device_is_404(self):
        self.assertEqual(self.client.get("/api/devices/missing").status_code, 404)

if __name__ == "__main__":
    unittest.main()
