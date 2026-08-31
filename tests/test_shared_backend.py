import importlib.util
import unittest

from pinoc.collectors.base import Collector
from pinoc.models import DeviceState
from pinoc.state import PiNOCState

FLASK_AVAILABLE = importlib.util.find_spec("flask") is not None


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

    def test_authoritative_publish_removes_missing_devices(self):
        state = PiNOCState()
        state.publish([DeviceState(id="sensor", hostname="sensor", friendly_name="Sensor",
                                   online=True, health="healthy")], replace=True)
        state.publish([], replace=True)
        self.assertEqual(state.devices(), [])

    def test_offline_update_preserves_last_successful_seen_time(self):
        state = PiNOCState()
        state.publish([DeviceState(id="cm5", hostname="cm5", friendly_name="CM5",
                                   online=True, health="healthy", last_seen="seen")])
        state.publish([DeviceState(id="cm5", hostname="cm5", friendly_name="CM5",
                                   online=False, health="offline")])
        self.assertEqual(state.device("cm5")["last_seen"], "seen")


@unittest.skipUnless(FLASK_AVAILABLE, "Flask dependency is not installed")
class APIBackendTest(unittest.TestCase):
    def setUp(self):
        from pinoc.web import create_app
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

    def test_status_summary_preserves_updates_available(self):
        self.state.publish([DeviceState(id="updates", hostname="updates", friendly_name="Updates",
                                        applications={"updates_available": 3})])
        self.assertEqual(self.state.summary()["updates_available"], 3)

    def test_health_is_starting_before_first_collection(self):
        from pinoc.web import create_app
        response = create_app(PiNOCState(), {"TESTING": True}).test_client().get("/health")
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.get_json()["status"], "starting")

    def test_health_is_degraded_when_cache_is_stale(self):
        self.state._last_collection = "2000-01-01T00:00:00+00:00"
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.get_json()["status"], "degraded")

if __name__ == "__main__":
    unittest.main()
