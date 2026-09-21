"""Coverage for pinoc.integrations.adsb's dump1090-fa/SkyAware normalization."""
import unittest

from pinoc.integrations.adsb import compare


class CompareUniqueAircraftTest(unittest.TestCase):
    def test_single_receiver_reports_its_own_aircraft_as_unique(self):
        # With no other receiver to compare against, every aircraft the
        # lone receiver sees is trivially unique to it -- not an empty
        # list, which is what "no other receivers" used to be conflated
        # with "shares everything it sees".
        receivers = [{"device_id": "pi-1", "data": {"aircraft_ids": ["ABC123", "DEF456"]}}]
        result = compare(receivers)
        self.assertEqual(result["receivers"][0]["unique_aircraft"], ["ABC123", "DEF456"])
        self.assertEqual(result["aircraft_seen_by_all"], [])
        self.assertEqual(result["receiver_count"], 1)

    def test_no_receivers_returns_empty(self):
        result = compare([])
        self.assertEqual(result["receivers"], [])
        self.assertEqual(result["aircraft_seen_by_all"], [])
        self.assertEqual(result["receiver_count"], 0)

    def test_two_receivers_still_compute_unique_and_common(self):
        receivers = [
            {"device_id": "pi-1", "data": {"aircraft_ids": ["ABC123", "DEF456"]}},
            {"device_id": "pi-2", "data": {"aircraft_ids": ["DEF456", "GHI789"]}},
        ]
        result = compare(receivers)
        self.assertEqual(result["receivers"][0]["unique_aircraft"], ["ABC123"])
        self.assertEqual(result["receivers"][1]["unique_aircraft"], ["GHI789"])
        self.assertEqual(result["aircraft_seen_by_all"], ["DEF456"])


if __name__ == "__main__":
    unittest.main()
