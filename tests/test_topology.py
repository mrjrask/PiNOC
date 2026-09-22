"""Coverage for pinoc.topology: bounded segment/pair derivation, config
validation, persistent-degradation detection, and feeding that into alert
correlation as shared-cause context."""
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from pinoc.config_store import validate_config
from pinoc.correlation import CorrelationEngine, describe_context
from pinoc.database import Database, utcnow
from pinoc.history import HistoryManager
from pinoc.state import PiNOCState
from pinoc.topology import (
    NetworkTopology,
    TopologyConfigError,
    pair_degraded,
    pair_status,
    parse_topology_config,
)
from pinoc.web.app import create_app

UTC = timezone.utc


class ParseTopologyConfigTest(unittest.TestCase):
    def test_disabled_by_default(self):
        config = parse_topology_config(None, {"a", "b"})
        self.assertFalse(config.enabled)

    def test_explicit_segments_and_pairs(self):
        raw = {
            "enabled": True, "gateway": "192.168.1.1",
            "segments": [{"name": "up", "devices": ["a", "b"]},
                        {"name": "down", "devices": ["c"]}],
            "pairs": [["a", "b"], ["a", "c"]],
        }
        config = parse_topology_config(raw, {"a", "b", "c"})
        self.assertTrue(config.enabled)
        self.assertEqual(config.gateway, "192.168.1.1")
        self.assertEqual({s.name for s in config.segments}, {"up", "down"})
        self.assertEqual(config.pairs, (("a", "b"), ("a", "c")))
        self.assertEqual(config.segment_for("a"), "up")
        self.assertEqual(config.segment_for("c"), "down")
        self.assertIsNone(config.segment_for("nope"))

    def test_pairs_ignore_unknown_or_self_devices(self):
        raw = {"enabled": True, "pairs": [["a", "ghost"], ["a", "a"], ["a", "b"]]}
        config = parse_topology_config(raw, {"a", "b"})
        self.assertEqual(config.pairs, (("a", "b"),))

    def test_pairs_deduplicate_regardless_of_order(self):
        raw = {"enabled": True, "pairs": [["a", "b"], ["b", "a"]]}
        config = parse_topology_config(raw, {"a", "b"})
        self.assertEqual(len(config.pairs), 1)

    def test_explicit_pairs_are_capped_at_max_pairs(self):
        ids = [f"d{i}" for i in range(20)]
        pairs = [[ids[i], ids[i + 1]] for i in range(len(ids) - 1)]  # 19 pairs
        raw = {"enabled": True, "pairs": pairs, "max_pairs": 5}
        config = parse_topology_config(raw, set(ids))
        self.assertEqual(len(config.pairs), 5)

    def test_auto_segments_group_by_shared_tag_and_bound_pairs(self):
        # Devices sharing a tag form a segment; a lone device with no shared
        # tag falls into the "lan" catch-all only when there's another
        # leftover to pair it with.
        ids = {"a", "b", "c", "solo"}
        tags = {"a": ("upstairs",), "b": ("upstairs",), "c": ("upstairs",), "solo": ()}
        config = parse_topology_config({"enabled": True}, ids, tags)
        names = {s.name for s in config.segments}
        self.assertIn("upstairs", names)
        upstairs = next(s for s in config.segments if s.name == "upstairs")
        self.assertEqual(set(upstairs.devices), {"a", "b", "c"})
        # a solo device with no shared tag and no leftover peer forms no pair.
        self.assertTrue(all("solo" not in (s, t) for s, t in config.pairs))
        # Auto-derivation chains within a segment (n-1 pairs for n members),
        # never a full mesh (which would be n*(n-1)/2 for n=3, i.e. 3 pairs).
        self.assertEqual(len([1 for s, t in config.pairs if s in upstairs.devices and t in upstairs.devices]), 2)

    def test_auto_pairs_are_bounded_not_quadratic_for_a_large_fleet(self):
        ids = [f"d{i}" for i in range(200)]
        tags = {d: ("lan",) for d in ids}
        config = parse_topology_config({"enabled": True, "max_pairs": 30}, set(ids), tags)
        self.assertEqual(len(config.pairs), 30)  # capped, not the 199-pair full chain

    def test_rejects_malformed_config(self):
        with self.assertRaises(TopologyConfigError):
            parse_topology_config({"segments": "nope"}, {"a"})
        with self.assertRaises(TopologyConfigError):
            parse_topology_config({"pairs": [["a"]]}, {"a"})
        with self.assertRaises(TopologyConfigError):
            parse_topology_config({"max_pairs": 0}, {"a"})
        with self.assertRaises(TopologyConfigError):
            parse_topology_config({"thresholds": {"loss_warning_percent": 150}}, {"a"})
        with self.assertRaises(TopologyConfigError):
            parse_topology_config({"segments": [{"name": "x", "devices": ["a"]},
                                                {"name": "x", "devices": ["b"]}]}, {"a", "b"})

    def test_latency_critical_must_be_at_least_latency_warning(self):
        with self.assertRaises(TopologyConfigError):
            parse_topology_config(
                {"thresholds": {"latency_warning_ms": 100, "latency_critical_ms": 50}}, {"a"})


class DegradationTest(unittest.TestCase):
    def setUp(self):
        self.config = parse_topology_config(
            {"enabled": True, "pairs": [["a", "b"]],
             "thresholds": {"latency_warning_ms": 50, "latency_critical_ms": 150,
                            "loss_warning_percent": 10, "persistence_samples": 3}},
            {"a", "b"})

    def test_needs_enough_samples_to_call_it_persistent(self):
        samples = [{"ok": True, "latency_ms": 999, "loss_percent": 0}]
        self.assertFalse(pair_degraded(samples, self.config))

    def test_one_bad_sample_is_not_persistent(self):
        # newest-first, as pair_samples() returns them
        samples = [{"ok": True, "latency_ms": 999, "loss_percent": 0},
                  {"ok": True, "latency_ms": 5, "loss_percent": 0},
                  {"ok": True, "latency_ms": 5, "loss_percent": 0}]
        self.assertFalse(pair_degraded(samples, self.config))

    def test_persistent_high_latency_is_degraded(self):
        samples = [{"ok": True, "latency_ms": 200, "loss_percent": 0}] * 3
        self.assertTrue(pair_degraded(samples, self.config))

    def test_persistent_loss_is_degraded(self):
        samples = [{"ok": True, "latency_ms": 1, "loss_percent": 50}] * 3
        self.assertTrue(pair_degraded(samples, self.config))

    def test_failed_pings_count_as_breaching(self):
        samples = [{"ok": False, "latency_ms": None, "loss_percent": 100}] * 3
        self.assertTrue(pair_degraded(samples, self.config))


class PairStatusAndNetworkTopologyTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db = Database(f"{self._tmp.name}/db.sqlite")
        assert self.db.initialize()

    def tearDown(self):
        self._tmp.cleanup()

    def _insert(self, source, target, latency, loss, ok=True, offset=0):
        stamp = (datetime.now(UTC) + timedelta(seconds=offset)).isoformat()
        self.db.execute(
            "INSERT INTO network_matrix_samples(timestamp,source_id,target_id,latency_ms,loss_percent,ok,error) "
            "VALUES(?,?,?,?,?,?,?)", (stamp, source, target, latency, loss, int(ok), None))

    def test_pair_status_ok_when_healthy(self):
        config = parse_topology_config(
            {"enabled": True, "pairs": [["a", "b"]]}, {"a", "b"})
        for i in range(5):
            self._insert("a", "b", 5.0, 0.0, offset=i)
        status = pair_status(self.db, "a", "b", config)
        self.assertEqual(status["severity"], "ok")
        self.assertFalse(status["degraded"])

    def test_pair_status_degraded_then_critical(self):
        config = parse_topology_config(
            {"enabled": True, "pairs": [["a", "b"]],
             "thresholds": {"latency_warning_ms": 50, "latency_critical_ms": 150,
                            "persistence_samples": 3}},
            {"a", "b"})
        for i in range(3):
            self._insert("a", "b", 80.0, 0.0, offset=i)
        warning = pair_status(self.db, "a", "b", config)
        self.assertEqual(warning["severity"], "warning")
        for i in range(3, 6):
            self._insert("a", "b", 200.0, 0.0, offset=i)
        critical = pair_status(self.db, "a", "b", config)
        self.assertEqual(critical["severity"], "critical")

    def test_network_topology_segment_status_and_degraded_lookup(self):
        raw = {"enabled": True, "gateway": "192.168.1.1",
              "segments": [{"name": "upstairs", "devices": ["a", "b"]},
                          {"name": "downstairs", "devices": ["c", "d"]}],
              "pairs": [["a", "b"], ["c", "d"]],
              "thresholds": {"latency_warning_ms": 50, "persistence_samples": 2}}
        config = parse_topology_config(raw, {"a", "b", "c", "d"})
        for i in range(2):
            self._insert("a", "b", 500.0, 0.0, offset=i)  # upstairs: degraded
        for i in range(2):
            self._insert("c", "d", 5.0, 0.0, offset=i)  # downstairs: healthy
        topo = NetworkTopology(self.db, config)
        statuses = {s["name"]: s for s in topo.segment_statuses()}
        # 500ms is past the (default) latency_critical_ms threshold too.
        self.assertEqual(statuses["upstairs"]["status"], "critical")
        self.assertEqual(statuses["downstairs"]["status"], "ok")
        self.assertEqual(topo.degraded_segment_for("a"), "upstairs")
        self.assertEqual(topo.degraded_segment_for("b"), "upstairs")
        self.assertIsNone(topo.degraded_segment_for("c"))
        self.assertIsNone(topo.degraded_segment_for("unknown-device"))

    def test_degraded_segment_for_is_none_when_disabled(self):
        config = parse_topology_config({"enabled": False, "pairs": [["a", "b"]]}, {"a", "b"})
        topo = NetworkTopology(self.db, config)
        self.assertIsNone(topo.degraded_segment_for("a"))


class ConfigValidationTest(unittest.TestCase):
    def test_network_topology_section_is_validated(self):
        base = {"polling": {}, "devices": [
            {"id": "a", "hostname": "a", "collection_method": "local"},
            {"id": "b", "hostname": "b", "address": "b.local"},
        ]}
        validate_config({**base, "network_topology": {
            "enabled": True, "pairs": [["a", "b"]]}})
        with self.assertRaises(ValueError):
            validate_config({**base, "network_topology": {"max_pairs": 0}})
        with self.assertRaises(ValueError):
            validate_config({**base, "network_topology": "nope"})
        with self.assertRaises(ValueError):
            validate_config({**base, "network_topology": {
                "thresholds": {"loss_warning_percent": -1}}})


class CorrelationEngineTopologyIntegrationTest(unittest.TestCase):
    """CorrelationEngine + a stubbed topology: a device-id -> segment lookup
    that only returns a name when that segment is persistently degraded."""

    class StubTopology:
        def __init__(self, degraded_map):
            self.degraded_map = degraded_map

        def degraded_segment_for(self, device_id):
            return self.degraded_map.get(device_id)

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db = Database(f"{self._tmp.name}/db.sqlite")
        assert self.db.initialize()

    def tearDown(self):
        self._tmp.cleanup()

    def _open_alert(self, device_id, alert_type, severity, stamp):
        return self.db.execute(
            "INSERT INTO alerts(device_id,alert_type,severity,message,fingerprint,opened_at,last_seen_at,state,"
            "metadata_json) VALUES(?,?,?,?,?,?,?,?,?)",
            (device_id, alert_type, severity, "msg", f"{device_id}:{alert_type}:", stamp, stamp, "active", "{}"))

    def test_degraded_segment_clusters_devices_with_no_other_shared_context(self):
        stamp = utcnow()
        a_id = self._open_alert("a", "high_cpu", "warning", stamp)
        b_id = self._open_alert("b", "high_cpu", "warning", stamp)
        # No shared SSID/gateway/subnet at all -- only the topology segment.
        device_context = {"a": {"network": {}}, "b": {"network": {}}}
        topology = self.StubTopology({"a": "upstairs", "b": "upstairs"})
        engine = CorrelationEngine(self.db, {"min_members": 2}, topology=topology)
        outcome = engine.reconcile({a_id, b_id}, [], device_context, stamp)
        self.assertEqual(outcome.absorbed_open, {a_id, b_id})
        clusters = self.db.rows("SELECT * FROM alert_clusters")
        self.assertEqual(len(clusters), 1)
        self.assertEqual(clusters[0]["context_key"], "segment")
        self.assertEqual(clusters[0]["context_value"], "upstairs")
        self.assertIn("network segment", describe_context("segment", "upstairs"))

    def test_no_cluster_once_the_segment_recovers(self):
        stamp = utcnow()
        a_id = self._open_alert("a", "high_cpu", "warning", stamp)
        b_id = self._open_alert("b", "high_cpu", "warning", stamp)
        device_context = {"a": {"network": {}}, "b": {"network": {}}}
        topology = self.StubTopology({})  # nothing degraded
        engine = CorrelationEngine(self.db, {"min_members": 2}, topology=topology)
        outcome = engine.reconcile({a_id, b_id}, [], device_context, stamp)
        self.assertEqual(outcome.absorbed_open, set())
        self.assertEqual(self.db.rows("SELECT COUNT(*) AS n FROM alert_clusters"), [{"n": 0}])

    def test_topology_lookup_failure_does_not_break_correlation(self):
        class Boom:
            def degraded_segment_for(self, device_id):
                raise RuntimeError("db unavailable")

        stamp = utcnow()
        a_id = self._open_alert("a", "device_offline", "critical", stamp)
        b_id = self._open_alert("b", "device_offline", "critical", stamp)
        device_context = {"a": {"network": {"ssid": "HomeWiFi"}}, "b": {"network": {"ssid": "HomeWiFi"}}}
        engine = CorrelationEngine(self.db, {"min_members": 2}, topology=Boom())
        outcome = engine.reconcile({a_id, b_id}, [], device_context, stamp)
        # Falls back to the ordinary SSID hint instead of raising.
        self.assertEqual(outcome.absorbed_open, {a_id, b_id})
        self.assertEqual(self.db.rows("SELECT context_key FROM alert_clusters")[0]["context_key"], "ssid")


class HistoryManagerEndToEndTopologyTest(unittest.TestCase):
    """The full feed path: HistoryManager builds a real NetworkTopology from
    live device tags + sampled history and hands it to CorrelationEngine."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db = Database(f"{self._tmp.name}/db.sqlite")
        assert self.db.initialize()

    def tearDown(self):
        self._tmp.cleanup()

    @staticmethod
    def device(device_id, online, tags=("upstairs",), **extra):
        base = {
            "id": device_id, "hostname": device_id, "friendly_name": device_id.title(),
            "online": online, "maintenance": False, "tags": list(tags),
            "cpu": {"utilization_percent": 10.0, "temperature_c": 45.0},
            "memory": {"percent": 30.0}, "storage": [], "media": [], "services": [],
            "integrations": {}, "hardware": {}, "uptime_seconds": 3600,
            # Deliberately different networks: no ssid/gateway/subnet overlap,
            # so only the topology segment can explain a shared cause.
            "network": {"ssid": f"ssid-{device_id}", "default_gateway": f"10.0.{device_id}.1",
                       "ip": f"10.0.{device_id}.5"},
        }
        base.update(extra)
        return base

    def _record_sample(self, source, target, latency, offset):
        stamp = (datetime.now(UTC) + timedelta(seconds=offset)).isoformat()
        self.db.execute(
            "INSERT INTO network_matrix_samples(timestamp,source_id,target_id,latency_ms,loss_percent,ok,error) "
            "VALUES(?,?,?,?,?,?,?)", (stamp, source, target, latency, 0.0, 1, None))

    def test_persistent_pair_degradation_surfaces_as_cluster_context(self):
        network_topology = {
            "enabled": True, "pairs": [["a", "b"]],
            "thresholds": {"latency_warning_ms": 50, "persistence_samples": 2},
        }
        history = HistoryManager(self.db, {}, None, network_topology=network_topology)
        now = datetime.now(UTC)
        # Both devices healthy first, in the same tagged segment.
        history._device(self.device("a", True), now.isoformat())
        history._device(self.device("b", True), now.isoformat())

        # The pair between them is persistently slow.
        for i in range(2):
            self._record_sample("a", "b", 500.0, i)

        # Unrelated high-CPU alerts on both -- no shared ssid/gateway/subnet.
        history._device(self.device("a", True, cpu={"utilization_percent": 95.0, "temperature_c": 45.0}),
                        (now + timedelta(seconds=310)).isoformat())
        history.cpu_since["a"] = now - timedelta(seconds=400)  # force cpu_duration_seconds past
        history._device(self.device("b", True, cpu={"utilization_percent": 95.0, "temperature_c": 45.0}),
                        (now + timedelta(seconds=311)).isoformat())
        history.cpu_since["b"] = now - timedelta(seconds=400)
        history._device(self.device("a", True, cpu={"utilization_percent": 95.0, "temperature_c": 45.0}),
                        (now + timedelta(seconds=320)).isoformat())
        history._device(self.device("b", True, cpu={"utilization_percent": 95.0, "temperature_c": 45.0}),
                        (now + timedelta(seconds=321)).isoformat())

        clusters = self.db.rows("SELECT * FROM alert_clusters")
        self.assertEqual(len(clusters), 1)
        self.assertEqual(clusters[0]["context_key"], "segment")
        self.assertEqual(clusters[0]["trigger_class"], "cpu")
        member_devices = {row["device_id"] for row in self.db.rows(
            "SELECT device_id FROM alerts WHERE cluster_id=?", (clusters[0]["cluster_id"],))}
        self.assertEqual(member_devices, {"a", "b"})

    def test_no_segment_context_when_pair_is_healthy(self):
        network_topology = {
            "enabled": True, "pairs": [["a", "b"]],
            "thresholds": {"latency_warning_ms": 500, "persistence_samples": 2},
        }
        history = HistoryManager(self.db, {}, None, network_topology=network_topology)
        now = datetime.now(UTC)
        history._device(self.device("a", True), now.isoformat())
        history._device(self.device("b", True), now.isoformat())
        for i in range(2):
            self._record_sample("a", "b", 1.0, i)  # comfortably healthy
        history._device(self.device("a", False), (now + timedelta(seconds=10)).isoformat())
        history._device(self.device("b", False), (now + timedelta(seconds=11)).isoformat())
        # Different ssid/gateway/subnet and a healthy pair: nothing to
        # correlate on, so no cluster forms.
        self.assertEqual(self.db.rows("SELECT COUNT(*) AS n FROM alert_clusters"), [{"n": 0}])


class WebSurfacingTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db = Database(f"{self._tmp.name}/db.sqlite")
        assert self.db.initialize()
        self.history = HistoryManager(self.db, {}, None)
        self.state = PiNOCState()

    def tearDown(self):
        self._tmp.cleanup()

    def _client(self, network_topology):
        return create_app(self.state, {"TESTING": True, "PINOC_CONFIG": {"network_topology": network_topology}},
                          self.history).test_client()

    def test_topology_page_renders(self):
        client = self._client({})
        response = client.get("/topology")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Network topology", response.data)

    def test_api_reports_disabled_when_unconfigured(self):
        client = self._client(None)
        body = client.get("/api/network-topology").get_json()
        self.assertFalse(body["enabled"])

    def test_api_reports_segments_and_pairs_when_enabled(self):
        from pinoc.models import DeviceState

        self.state.publish([
            DeviceState(id="a", hostname="a", friendly_name="A", online=True,
                       collection_method="local", tags=("upstairs",)),
            DeviceState(id="b", hostname="b", friendly_name="B", online=True,
                       collection_method="ssh", tags=("upstairs",)),
        ], replace=True)
        self.db.execute(
            "INSERT INTO network_matrix_samples(timestamp,source_id,target_id,latency_ms,loss_percent,ok,error) "
            "VALUES(?,?,?,?,?,?,?)", (utcnow(), "a", "b", 3.0, 0.0, 1, None))
        client = self._client({"enabled": True, "gateway": "192.168.1.1", "pairs": [["a", "b"]]})
        body = client.get("/api/network-topology").get_json()
        self.assertTrue(body["enabled"])
        self.assertEqual(body["gateway"], "192.168.1.1")
        self.assertEqual(len(body["pairs"]), 1)
        self.assertEqual(body["pairs"][0]["source_id"], "a")
        self.assertEqual(len(body["segments"]), 1)
        self.assertEqual(body["segments"][0]["name"], "upstairs")


if __name__ == "__main__":
    unittest.main()
