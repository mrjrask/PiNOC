"""Coverage for alert correlation: shared-cause clustering, conservative
grouping (never suppressing the underlying alerts), and cluster-level
notification batching."""
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from pinoc.config_store import validate_config
from pinoc.correlation import CorrelationEngine, context_hints, describe_context, trigger_class
from pinoc.database import Database
from pinoc.history import HistoryManager
from pinoc.state import PiNOCState
from pinoc.web.app import create_app

UTC = timezone.utc


class Recorder:
    def __init__(self, sink):
        self.sink = sink

    def enqueue(self, transition, alert, device_name):
        self.sink.append((transition, dict(alert), device_name))


class PureFunctionTest(unittest.TestCase):
    def test_trigger_class_groups_related_alert_types(self):
        self.assertEqual(trigger_class("device_offline"), "connectivity")
        self.assertEqual(trigger_class("high_temperature"), trigger_class("critical_temperature"))
        self.assertEqual(trigger_class("totally_unknown_type"), "totally_unknown_type")

    def test_context_hints_prefers_available_network_fields(self):
        hints = context_hints({"network": {"ssid": "HomeWiFi", "default_gateway": "192.168.1.1", "ip": "192.168.1.42"}})
        self.assertEqual(hints, {"ssid": "HomeWiFi", "gateway": "192.168.1.1", "ip_prefix": "192.168.1.0/24"})
        self.assertEqual(context_hints(None), {})
        self.assertEqual(context_hints({"network": {}, "ip": "10.0.0.5"}), {"ip_prefix": "10.0.0.0/24"})

    def test_describe_context_is_explainable(self):
        self.assertIn("HomeWiFi", describe_context("ssid", "HomeWiFi"))
        self.assertIn("192.168.1.1", describe_context("gateway", "192.168.1.1"))
        self.assertIn("router", describe_context("gateway", "192.168.1.1", "router"))
        self.assertIn("10.0.0.0/24", describe_context("ip_prefix", "10.0.0.0/24"))


class CorrelationIntegrationTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db = Database(f"{self._tmp.name}/db.sqlite")
        assert self.db.initialize()
        self.recorder = []
        self.history = HistoryManager(self.db, {}, None, notifier=Recorder(self.recorder))

    def tearDown(self):
        self._tmp.cleanup()

    @staticmethod
    def device(device_id, online=True, ssid="HomeWiFi", gateway="192.168.1.1", ip="192.168.1.10", **extra):
        base = {
            "id": device_id, "hostname": device_id, "friendly_name": device_id.title(),
            "online": online, "maintenance": False,
            "cpu": {"utilization_percent": 10.0, "temperature_c": 45.0},
            "memory": {"percent": 30.0}, "storage": [], "media": [], "services": [],
            "integrations": {}, "hardware": {}, "uptime_seconds": 3600,
            "network": {"ssid": ssid, "default_gateway": gateway, "ip": ip},
        }
        base.update(extra)
        return base

    def stamp(self, offset_seconds):
        return (datetime.now(UTC) + timedelta(seconds=offset_seconds)).isoformat()

    def open_alert_types(self):
        return {row["alert_type"] for row in self.db.rows("SELECT alert_type FROM alerts WHERE resolved_at IS NULL")}

    def test_devices_sharing_a_gateway_cluster_and_others_stay_out(self):
        # a and b share a gateway/SSID; c is on a different network entirely.
        self.history._device(self.device("a"), self.stamp(0))
        self.history._device(self.device("b"), self.stamp(0))
        self.history._device(self.device("c"), self.stamp(0))
        self.assertEqual(self.recorder, [])  # all healthy: nothing opened yet

        self.history._device(self.device("a", online=False), self.stamp(10))
        self.history._device(self.device("b", online=False), self.stamp(11))
        self.history._device(self.device("c", online=False, ssid="OfficeWiFi", gateway="10.0.0.1", ip="10.0.0.5"), self.stamp(12))

        # Every device still has its own independent alert row -- grouping
        # never suppresses or merges the underlying alerts.
        alerts = self.db.rows("SELECT * FROM alerts WHERE resolved_at IS NULL ORDER BY device_id")
        self.assertEqual([row["device_id"] for row in alerts], ["a", "b", "c"])
        self.assertTrue(all(row["alert_type"] == "device_offline" for row in alerts))

        clusters = self.db.rows("SELECT * FROM alert_clusters")
        self.assertEqual(len(clusters), 1)
        cluster = clusters[0]
        self.assertEqual(cluster["trigger_class"], "connectivity")
        self.assertIn(cluster["context_key"], ("ssid", "gateway"))

        member_devices = {row["device_id"] for row in self.db.rows(
            "SELECT device_id FROM alerts WHERE cluster_id=?", (cluster["cluster_id"],))}
        self.assertEqual(member_devices, {"a", "b"})
        # c never joins: different SSID, gateway, and subnet.
        c_row = next(row for row in alerts if row["device_id"] == "c")
        self.assertIsNone(c_row["cluster_id"])

    def test_notifications_fire_once_for_the_cluster_not_per_member(self):
        for name in ("a", "b", "c"):
            self.history._device(self.device(name), self.stamp(0))
        self.history._device(self.device("a", online=False), self.stamp(10))
        opens_after_a = [t for t in self.recorder if t[0] == "open"]
        self.assertEqual(len(opens_after_a), 1)
        self.assertEqual(opens_after_a[0][1]["alert_type"], "device_offline")

        self.history._device(self.device("b", online=False), self.stamp(11))
        opens_after_b = [t for t in self.recorder if t[0] == "open"]
        # One more notification -- the new cluster -- not a second per-device one.
        self.assertEqual(len(opens_after_b), 2)
        self.assertEqual(opens_after_b[1][1]["alert_type"], "cluster_connectivity")

        self.history._device(self.device("c", online=False), self.stamp(12))
        opens_after_c = [t for t in self.recorder if t[0] == "open"]
        # c silently joins the existing cluster: no third notification at all.
        self.assertEqual(len(opens_after_c), 2)

        # Recovery: bring all three back online. Only the last recovery
        # (which empties the cluster) should produce a cluster-level resolve;
        # the earlier members must not each fire their own resolve either.
        self.history._device(self.device("a"), self.stamp(20))
        self.history._device(self.device("b"), self.stamp(21))
        resolves_before_last = [t for t in self.recorder if t[0] == "resolve"]
        self.assertEqual(resolves_before_last, [])
        self.history._device(self.device("c"), self.stamp(22))
        resolves = [t for t in self.recorder if t[0] == "resolve"]
        self.assertEqual(len(resolves), 1)
        self.assertEqual(resolves[0][1]["alert_type"], "cluster_connectivity")
        self.assertEqual(self.db.rows("SELECT COUNT(*) AS n FROM alerts WHERE resolved_at IS NULL"), [{"n": 0}])
        self.assertEqual(self.db.rows("SELECT COUNT(*) AS n FROM alert_clusters WHERE resolved_at IS NULL"), [{"n": 0}])

    def test_different_trigger_classes_never_cluster_together(self):
        self.history._device(self.device("a"), self.stamp(0))
        self.history._device(self.device("b"), self.stamp(0))
        # Same network context, but one alert type is connectivity and the
        # other is a resource alert -- they must not be treated as one cause.
        self.history._device(self.device("a", online=False), self.stamp(10))
        self.history._device(self.device("b", **{"cpu": {"utilization_percent": 10.0, "temperature_c": 90.0}}), self.stamp(11))
        self.assertEqual(self.db.rows("SELECT COUNT(*) AS n FROM alert_clusters"), [{"n": 0}])

    def test_correlation_can_be_disabled_and_falls_back_to_per_alert_notifications(self):
        recorder = []
        history = HistoryManager(self.db, {}, None, notifier=Recorder(recorder), correlation={"enabled": False})
        history._device(self.device("x"), self.stamp(0))
        history._device(self.device("y"), self.stamp(0))
        history._device(self.device("x", online=False), self.stamp(10))
        history._device(self.device("y", online=False), self.stamp(11))
        opens = [t for t in recorder if t[0] == "open"]
        self.assertEqual(len(opens), 2)  # no clustering at all: one notification per device
        self.assertEqual(self.db.rows("SELECT COUNT(*) AS n FROM alert_clusters"), [{"n": 0}])

    def test_engine_defaults_are_conservative_group_only(self):
        engine = CorrelationEngine(self.db, {})
        self.assertTrue(engine.enabled)
        self.assertGreaterEqual(engine.min_members, 2)


class ApiTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db = Database(f"{self._tmp.name}/db.sqlite")
        assert self.db.initialize()
        self.history = HistoryManager(self.db, {}, None)
        self.client = create_app(PiNOCState(), {"TESTING": True}, self.history).test_client()

    def tearDown(self):
        self._tmp.cleanup()

    def test_alert_clusters_endpoint_shows_members_and_shared_context(self):
        now = datetime.now(UTC)

        def device(device_id, online):
            return {"id": device_id, "hostname": device_id, "friendly_name": device_id.title(),
                    "online": online, "maintenance": False,
                    "cpu": {"utilization_percent": 10.0, "temperature_c": 45.0}, "memory": {"percent": 30.0},
                    "storage": [], "media": [], "services": [], "integrations": {}, "hardware": {},
                    "uptime_seconds": 3600, "network": {"ssid": "HomeWiFi", "default_gateway": "192.168.1.1", "ip": "192.168.1.10"}}

        for name in ("a", "b"):
            self.history._device(device(name, True), now.isoformat())
        self.history._device(device("a", False), (now + timedelta(seconds=10)).isoformat())
        self.history._device(device("b", False), (now + timedelta(seconds=11)).isoformat())

        body = self.client.get("/api/alert-clusters").get_json()
        self.assertEqual(len(body["clusters"]), 1)
        cluster = body["clusters"][0]
        self.assertEqual(cluster["member_count"], 2)
        self.assertEqual(cluster["open_member_count"], 2)
        self.assertEqual({m["device_id"] for m in cluster["members"]}, {"a", "b"})
        self.assertIn("HomeWiFi", cluster["context_label"])
        self.assertTrue(body["status"]["enabled"])
        self.assertGreaterEqual(body["status"]["min_members"], 2)

        empty = self.client.get("/api/alert-clusters?state=all").get_json()
        self.assertGreaterEqual(len(empty["clusters"]), 1)

    def test_alert_clusters_endpoint_fetches_members_in_one_query(self):
        # api_alert_clusters() previously issued one "SELECT ... FROM
        # alerts WHERE cluster_id=?" per cluster (N+1) -- with several
        # simultaneous clusters (a fleet-wide outage, the exact scenario
        # this feature targets), it should fetch every cluster's members
        # in a single query instead.
        now = datetime.now(UTC)

        def device(device_id, ssid, gateway, online):
            return {"id": device_id, "hostname": device_id, "friendly_name": device_id.title(),
                    "online": online, "maintenance": False,
                    "cpu": {"utilization_percent": 10.0, "temperature_c": 45.0}, "memory": {"percent": 30.0},
                    "storage": [], "media": [], "services": [], "integrations": {}, "hardware": {},
                    "uptime_seconds": 3600, "network": {"ssid": ssid, "default_gateway": gateway, "ip": f"{gateway[:-1]}10"}}

        groups = [("a1", "a2", "NetA", "192.168.1.1"), ("b1", "b2", "NetB", "192.168.2.1"),
                 ("c1", "c2", "NetC", "192.168.3.1")]
        for x, y, ssid, gw in groups:
            self.history._device(device(x, ssid, gw, True), now.isoformat())
            self.history._device(device(y, ssid, gw, True), now.isoformat())
        for offset, (x, y, ssid, gw) in enumerate(groups):
            self.history._device(device(x, ssid, gw, False), (now + timedelta(seconds=10 + offset)).isoformat())
            self.history._device(device(y, ssid, gw, False), (now + timedelta(seconds=20 + offset)).isoformat())

        queries = []
        real_rows = self.db.rows
        def counting_rows(sql, params=()):
            if "FROM alerts" in sql and "cluster_id" in sql:
                queries.append(sql)
            return real_rows(sql, params)
        self.db.rows = counting_rows
        try:
            body = self.client.get("/api/alert-clusters").get_json()
        finally:
            self.db.rows = real_rows
        self.assertEqual(len(body["clusters"]), 3)
        self.assertEqual(len(queries), 1)


class ConfigValidationTest(unittest.TestCase):
    def test_alert_correlation_section_is_validated(self):
        base = {"polling": {}, "devices": []}
        validate_config({**base, "alert_correlation": {"enabled": True, "window_seconds": 120, "min_members": 3}})
        with self.assertRaises(ValueError):
            validate_config({**base, "alert_correlation": {"window_seconds": 10}})
        with self.assertRaises(ValueError):
            validate_config({**base, "alert_correlation": {"min_members": 1}})
        with self.assertRaises(ValueError):
            validate_config({**base, "alert_correlation": "nope"})


if __name__ == "__main__":
    unittest.main()
