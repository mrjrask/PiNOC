"""A device in maintenance keeps that status even with a pre-existing open alert."""
import unittest

from pinoc.models import DeviceState
from pinoc.state import PiNOCState


class MaintenanceHealthTest(unittest.TestCase):
    def test_pre_existing_alert_does_not_override_maintenance_health(self):
        state = PiNOCState()
        device = DeviceState(id="pi", hostname="pi", friendly_name="Pi", online=True, health="maintenance")
        state.publish([device], replace=True)

        # history._alerts() never resolves an alert that was already open
        # before maintenance started, so it keeps showing up in the
        # fleet-wide "SELECT * FROM alerts WHERE resolved_at IS NULL" query
        # that feeds set_alerts() every cycle.
        state.set_alerts([{"device_id": "pi", "alert_type": "high_cpu",
                            "severity": "critical", "message": "boom"}])

        result = state.device("pi")
        self.assertEqual(result["health"], "maintenance")
        # The alert itself should still be visible on the device.
        self.assertEqual(len(result["alerts"]), 1)

    def test_non_maintenance_device_still_escalates_on_active_alert(self):
        state = PiNOCState()
        device = DeviceState(id="pi", hostname="pi", friendly_name="Pi", online=True, health="healthy")
        state.publish([device], replace=True)

        state.set_alerts([{"device_id": "pi", "alert_type": "high_cpu",
                            "severity": "critical", "message": "boom"}])

        result = state.device("pi")
        self.assertEqual(result["health"], "critical")


if __name__ == "__main__":
    unittest.main()
