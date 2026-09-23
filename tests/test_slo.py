"""Coverage for SLOs and reliability scoring (pinoc/slo.py + the
`slo_summary` dashboard card type in pinoc/dashboards.py).

Five layers:

* :class:`ConfigValidationTest` -- ``parse_slo``/``validate_slos`` against
  good and bad ``slos`` config sections, including scope resolution against
  a known device/role/tag universe (mirrors ``pinoc.config_store``'s own
  validation call);
* :class:`ScopeResolutionTest` -- ``resolve_scope_devices`` against a fake
  device roster;
* :class:`AttainmentTest` -- time-weighted good/bad-seconds and pooled
  ``compute_attainment`` against a real ``Database``'s ``health_samples``
  rows;
* :class:`BurnRateTest` -- ``burn_rate`` math and ``SLOService.evaluate_one``
  threshold crossing (both windows must cross for ``firing``), using an
  explicit ``now`` so the test has no dependency on wall-clock timing;
* :class:`ServiceLifecycleTest` -- ``SLOService.tick()`` opening and then
  resolving a real ``slo_burn`` alert through the same ``alerts`` table
  every device alert uses;
* :class:`DashboardCardTest` -- the ``slo_summary`` card type's data
  resolution through ``pinoc.dashboards.resolve_card``.
"""
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from pinoc.dashboards import CARD_TYPES, resolve_card
from pinoc.database import Database
from pinoc.models import DeviceState
from pinoc.state import PiNOCState
from pinoc.slo import (
    SLOConfigError, SLOService, SLO_DEVICE_ID, ALERT_TYPE,
    burn_rate, compute_attainment, parse_slo, resolve_scope_devices, validate_slos,
    _device_seconds,
)

UTC = timezone.utc


def valid_slo(**overrides):
    base = {"id": "core-uptime", "name": "Core uptime",
            "scope": {"type": "role", "value": "file_server"},
            "target_percent": 99.5, "window_days": 30}
    base.update(overrides)
    return base


class ConfigValidationTest(unittest.TestCase):
    def test_parses_minimal_definition_with_defaults(self):
        parsed = parse_slo(valid_slo(), 0, known_roles={"file_server"})
        self.assertEqual(parsed["id"], "core-uptime")
        self.assertEqual(parsed["scope"], {"type": "role", "value": "file_server"})
        self.assertEqual(parsed["severity"], "critical")
        self.assertEqual(parsed["burn_rate"]["fast_window_minutes"], 60)
        self.assertEqual(parsed["burn_rate"]["slow_window_minutes"], 360)

    def test_scope_resolution_against_known_universe(self):
        # A device/role/tag scope value that does not exist in the fleet is
        # rejected -- the same way an unknown device id in network_topology is.
        parse_slo(valid_slo(scope={"type": "device", "value": "pi-a"}), 0,
                  known_device_ids={"pi-a", "pi-b"})
        with self.assertRaises(SLOConfigError):
            parse_slo(valid_slo(scope={"type": "device", "value": "ghost"}), 0,
                      known_device_ids={"pi-a", "pi-b"})
        parse_slo(valid_slo(scope={"type": "tag", "value": "production"}), 0, known_tags={"production"})
        with self.assertRaises(SLOConfigError):
            parse_slo(valid_slo(scope={"type": "tag", "value": "ghost"}), 0, known_tags={"production"})

    def test_membership_check_skipped_when_universe_empty(self):
        # SLOService parses its own config with no live roster in hand (the
        # config was already validated at save time) -- scope values must
        # not be rejected just because no known set was passed in.
        parse_slo(valid_slo(scope={"type": "role", "value": "anything"}), 0)

    def test_rejects_bad_scope_type(self):
        with self.assertRaises(SLOConfigError):
            parse_slo(valid_slo(scope={"type": "cluster", "value": "x"}), 0)

    def test_rejects_out_of_range_target(self):
        with self.assertRaises(SLOConfigError):
            parse_slo(valid_slo(target_percent=0), 0)
        with self.assertRaises(SLOConfigError):
            parse_slo(valid_slo(target_percent=150), 0)

    def test_rejects_missing_id(self):
        with self.assertRaises(SLOConfigError):
            parse_slo(valid_slo(id=""), 0)

    def test_rejects_bad_severity(self):
        with self.assertRaises(SLOConfigError):
            parse_slo(valid_slo(severity="urgent"), 0)

    def test_burn_rate_window_ordering_enforced(self):
        with self.assertRaises(SLOConfigError):
            parse_slo(valid_slo(burn_rate={"fast_window_minutes": 120, "slow_window_minutes": 60}), 0)

    def test_burn_rate_slow_window_cannot_exceed_slo_window(self):
        with self.assertRaises(SLOConfigError):
            parse_slo(valid_slo(window_days=1, burn_rate={"slow_window_minutes": 2000}), 0)

    def test_validate_slos_section_none_is_a_no_op(self):
        validate_slos({}, known_device_ids=set())

    def test_validate_slos_rejects_duplicate_ids(self):
        section = {"definitions": [valid_slo(), valid_slo()]}
        with self.assertRaises(SLOConfigError):
            validate_slos({"slos": section}, known_device_ids=set(), known_roles={"file_server"})

    def test_validate_slos_accepts_multiple_distinct_definitions(self):
        section = {"definitions": [valid_slo(), valid_slo(id="other", scope={"type": "tag", "value": "prod"})]}
        validate_slos({"slos": section}, known_device_ids=set(), known_roles={"file_server"}, known_tags={"prod"})

    def test_validate_slos_rejects_bad_interval_and_retention(self):
        with self.assertRaises(SLOConfigError):
            validate_slos({"slos": {"interval_seconds": 1}}, known_device_ids=set())
        with self.assertRaises(SLOConfigError):
            validate_slos({"slos": {"sample_retention_days": 0}}, known_device_ids=set())

    def test_config_store_wires_slo_validation_through_validate_config(self):
        # pinoc.config_store.validate_config computes known roles/tags from
        # the loaded device list and calls pinoc.slo.validate_slos with them.
        from pinoc.config_store import validate_config
        good = {"devices": [{"id": "pi-a", "hostname": "pi-a", "address": "pi-a",
                             "collection_method": "local", "roles": ["file_server"]}],
                "slos": {"definitions": [valid_slo(scope={"type": "role", "value": "file_server"})]}}
        validate_config(good)
        bad = {"devices": [{"id": "pi-a", "hostname": "pi-a", "address": "pi-a",
                            "collection_method": "local", "roles": ["file_server"]}],
               "slos": {"definitions": [valid_slo(scope={"type": "role", "value": "nope"})]}}
        with self.assertRaises(ValueError):
            validate_config(bad)


class ScopeResolutionTest(unittest.TestCase):
    def setUp(self):
        self.devices = [
            {"id": "pi-a", "roles": ["file_server"], "tags": ["production"]},
            {"id": "pi-b", "roles": ["file_server"], "tags": ["staging"]},
            {"id": "pi-c", "roles": ["vpn_server"], "tags": ["production"]},
        ]

    def test_device_scope(self):
        self.assertEqual(resolve_scope_devices({"type": "device", "value": "pi-b"}, self.devices), ["pi-b"])

    def test_role_scope_matches_every_device_with_that_role(self):
        self.assertEqual(resolve_scope_devices({"type": "role", "value": "file_server"}, self.devices),
                         ["pi-a", "pi-b"])

    def test_tag_scope_matches_every_device_with_that_tag(self):
        self.assertEqual(resolve_scope_devices({"type": "tag", "value": "production"}, self.devices),
                         ["pi-a", "pi-c"])

    def test_unknown_scope_value_resolves_to_no_devices(self):
        self.assertEqual(resolve_scope_devices({"type": "role", "value": "ghost"}, self.devices), [])


class AttainmentTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.db = Database(f"{self._tmp.name}/db.sqlite")
        self.assertTrue(self.db.initialize())
        self.now = datetime(2024, 6, 1, 12, 0, 0, tzinfo=UTC)

    def _insert(self, device_id, minutes_ago, health):
        stamp = (self.now - timedelta(minutes=minutes_ago)).isoformat()
        self.db.execute("INSERT INTO health_samples(timestamp,device_id,health,online) VALUES(?,?,?,?)",
                        (stamp, device_id, health, 0 if health in ("critical", "offline") else 1))

    def test_device_seconds_time_weighted_between_samples(self):
        window_start = self.now - timedelta(hours=1)
        rows = [{"timestamp": window_start.isoformat(), "health": "healthy"},
                {"timestamp": (window_start + timedelta(minutes=40)).isoformat(), "health": "critical"}]
        good, bad = _device_seconds(rows, window_start, self.now, cap_seconds=10_000)
        self.assertAlmostEqual(good, 40 * 60)
        self.assertAlmostEqual(bad, 20 * 60)

    def test_device_seconds_excludes_maintenance(self):
        window_start = self.now - timedelta(hours=1)
        rows = [{"timestamp": window_start.isoformat(), "health": "healthy"},
                {"timestamp": (window_start + timedelta(minutes=20)).isoformat(), "health": "maintenance"},
                {"timestamp": (window_start + timedelta(minutes=50)).isoformat(), "health": "critical"}]
        good, bad = _device_seconds(rows, window_start, self.now, cap_seconds=10_000)
        # [0,20) good, [20,50) excluded (maintenance), [50,60) bad.
        self.assertAlmostEqual(good, 20 * 60)
        self.assertAlmostEqual(bad, 10 * 60)

    def test_device_seconds_caps_long_gaps(self):
        window_start = self.now - timedelta(hours=1)
        rows = [{"timestamp": window_start.isoformat(), "health": "healthy"}]
        good, bad = _device_seconds(rows, window_start, self.now, cap_seconds=300)
        self.assertAlmostEqual(good, 300)
        self.assertAlmostEqual(bad, 0)

    def test_compute_attainment_single_device(self):
        for minutes_ago in range(60, -1, -10):
            self._insert("pi-a", minutes_ago, "healthy" if minutes_ago > 20 else "critical")
        result = compute_attainment(self.db, ["pi-a"], self.now - timedelta(hours=1), self.now)
        self.assertIsNotNone(result["attainment_percent"])
        # Roughly 40/60 minutes good (samples every 10 min, last two bad).
        self.assertGreater(result["attainment_percent"], 50)
        self.assertLess(result["attainment_percent"], 80)

    def test_compute_attainment_pools_across_devices_in_scope(self):
        # pi-a fully healthy, pi-b fully critical over the window -- pooled
        # attainment across the two must land at roughly 50%.
        for minutes_ago in range(30, -1, -5):
            self._insert("pi-a", minutes_ago, "healthy")
            self._insert("pi-b", minutes_ago, "critical")
        result = compute_attainment(self.db, ["pi-a", "pi-b"], self.now - timedelta(minutes=30), self.now)
        self.assertAlmostEqual(result["attainment_percent"], 50.0, delta=5.0)

    def test_compute_attainment_carries_forward_sample_before_window(self):
        # A single sample recorded well before the window still applies to
        # the whole window via carry-forward (no sample strictly inside it).
        self._insert("pi-a", 120, "critical")
        result = compute_attainment(self.db, ["pi-a"], self.now - timedelta(minutes=30), self.now,
                                    cap_seconds=10_000)
        self.assertEqual(result["attainment_percent"], 0.0)

    def test_compute_attainment_no_data_is_none(self):
        result = compute_attainment(self.db, ["ghost"], self.now - timedelta(hours=1), self.now)
        self.assertIsNone(result["attainment_percent"])


class BurnRateTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.db = Database(f"{self._tmp.name}/db.sqlite")
        self.assertTrue(self.db.initialize())
        self.now = datetime(2024, 6, 1, 12, 0, 0, tzinfo=UTC)
        self.state = PiNOCState()
        self.state.publish([DeviceState(id="pi-a", hostname="pi-a", friendly_name="Pi A",
                                        roles=["file_server"], online=True, health="healthy")],
                           replace=True)

    def _insert(self, minutes_ago, health):
        stamp = (self.now - timedelta(minutes=minutes_ago)).isoformat()
        self.db.execute("INSERT INTO health_samples(timestamp,device_id,health,online) VALUES(?,?,?,?)",
                        (stamp, "pi-a", health, 0 if health in ("critical", "offline") else 1))

    def test_burn_rate_formula(self):
        self.assertAlmostEqual(burn_rate(99.5, 99.5), 1.0)
        self.assertAlmostEqual(burn_rate(100.0, 99.5), 0.0)
        self.assertAlmostEqual(burn_rate(90.0, 99.5), 20.0)
        self.assertIsNone(burn_rate(None, 99.5))

    def test_evaluate_one_not_firing_when_healthy(self):
        for minutes_ago in range(360, -1, -10):
            self._insert(minutes_ago, "healthy")
        slo_def = parse_slo(valid_slo(scope={"type": "role", "value": "file_server"}, window_days=1), 0)
        service = SLOService(self.db, state=self.state, config={"definitions": []}, interval=9999)
        entry = service.evaluate_one(slo_def, self.state.devices(), now=self.now)
        self.assertFalse(entry["firing"])
        self.assertAlmostEqual(entry["attainment_percent"], 100.0, delta=0.01)
        self.assertAlmostEqual(entry["budget_remaining_percent"], 100.0, delta=0.5)

    def test_evaluate_one_fires_only_when_both_windows_burn(self):
        # A brief one-minute blip is a tiny fraction of either the default
        # 60-minute fast or 360-minute slow burn-rate window -- neither
        # window's burn rate reaches its threshold, so firing must stay
        # False even though the SLO went critical for a moment.
        for minutes_ago in range(360, -1, -5):
            self._insert(minutes_ago, "healthy")
        self._insert(1, "critical")
        slo_def = parse_slo(valid_slo(scope={"type": "role", "value": "file_server"}, window_days=1), 0)
        service = SLOService(self.db, state=self.state, config={"definitions": []}, interval=9999)
        entry = service.evaluate_one(slo_def, self.state.devices(), now=self.now)
        self.assertLess(entry["fast_burn_rate"], entry["fast_threshold"])
        self.assertLess(entry["slow_burn_rate"], entry["slow_threshold"])
        self.assertFalse(entry["firing"])

        # A sustained two-hour outage burns both windows' error budget past
        # threshold (fast window is entirely bad; the slow window is a third
        # bad) -- firing must flip to True.
        self.db.execute("DELETE FROM health_samples")
        for minutes_ago in range(360, -1, -5):
            self._insert(minutes_ago, "critical" if minutes_ago <= 120 else "healthy")
        entry = service.evaluate_one(slo_def, self.state.devices(), now=self.now)
        self.assertGreaterEqual(entry["fast_burn_rate"], entry["fast_threshold"])
        self.assertGreaterEqual(entry["slow_burn_rate"], entry["slow_threshold"])
        self.assertTrue(entry["firing"])

    def test_evaluate_one_insufficient_data(self):
        slo_def = parse_slo(valid_slo(scope={"type": "role", "value": "file_server"}), 0)
        service = SLOService(self.db, state=self.state, config={"definitions": []}, interval=9999)
        entry = service.evaluate_one(slo_def, self.state.devices(), now=self.now)
        self.assertTrue(entry["insufficient_data"])
        self.assertIsNone(entry["attainment_percent"])
        self.assertFalse(entry["firing"])


class ServiceLifecycleTest(unittest.TestCase):
    """SLOService.tick() opening and resolving a real alert end to end."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.db = Database(f"{self._tmp.name}/db.sqlite")
        self.assertTrue(self.db.initialize())
        self.state = PiNOCState()
        self.state.publish([DeviceState(id="pi-a", hostname="pi-a", friendly_name="Pi A",
                                        online=True, health="critical")], replace=True)
        self.now = datetime(2024, 6, 1, 12, 0, 0, tzinfo=UTC)

    def _insert(self, minutes_ago, health):
        stamp = (self.now - timedelta(minutes=minutes_ago)).isoformat()
        self.db.execute("INSERT INTO health_samples(timestamp,device_id,health,online) VALUES(?,?,?,?)",
                        (stamp, "pi-a", health, 0 if health in ("critical", "offline") else 1))

    def _open_alerts(self):
        return self.db.rows("SELECT * FROM alerts WHERE device_id=? AND resolved_at IS NULL", (SLO_DEVICE_ID,))

    def test_tick_opens_then_resolves_slo_burn_alert(self):
        for minutes_ago in range(40, -1, -5):
            self._insert(minutes_ago, "critical")
        config = {"definitions": [valid_slo(
            id="uptime", scope={"type": "device", "value": "pi-a"}, window_days=1,
            burn_rate={"fast_window_minutes": 10, "fast_threshold": 2,
                       "slow_window_minutes": 30, "slow_threshold": 2})]}
        service = SLOService(self.db, state=self.state, config=config, interval=9999)
        service.tick(now=self.now)
        opened = self._open_alerts()
        self.assertEqual(len(opened), 1)
        self.assertEqual(opened[0]["alert_type"], ALERT_TYPE)
        self.assertEqual(opened[0]["fingerprint"], f"{SLO_DEVICE_ID}:{ALERT_TYPE}:uptime")
        self.assertEqual(opened[0]["severity"], "critical")
        # The shared state cache reflects the new alert too, same as every
        # other alert-opening subsystem (self_monitoring, HistoryManager).
        self.assertTrue(any(a["fingerprint"] == opened[0]["fingerprint"] for a in self.state.alerts()))

        # Recovery: replace the bad history with healthy samples across the
        # whole burn-rate window -- the alert must resolve.
        self.db.execute("DELETE FROM health_samples")
        for minutes_ago in range(40, -1, -5):
            self._insert(minutes_ago, "healthy")
        service.tick(now=self.now)
        self.assertEqual(self._open_alerts(), [])
        self.assertFalse(any(a.get("device_id") == SLO_DEVICE_ID for a in self.state.alerts()))

    def test_no_definitions_is_a_no_op(self):
        service = SLOService(self.db, state=self.state, config={"definitions": []}, interval=9999)
        report = service.tick(now=self.now)
        self.assertEqual(report["slos"], [])
        self.assertEqual(self._open_alerts(), [])

    def test_invalid_definition_in_loaded_config_is_skipped_not_fatal(self):
        config = {"definitions": [{"id": "bad", "scope": {"type": "nonsense", "value": "x"},
                                   "target_percent": 99}]}
        service = SLOService(self.db, state=self.state, config=config, interval=9999)
        self.assertEqual(service.definitions, [])


class DashboardCardTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.db = Database(f"{self._tmp.name}/db.sqlite")
        self.assertTrue(self.db.initialize())
        self.state = PiNOCState()
        self.state.publish([DeviceState(id="pi-a", hostname="pi-a", friendly_name="Pi A",
                                        online=True, health="healthy")], replace=True)

    def test_card_type_registered(self):
        self.assertIn("slo_summary", CARD_TYPES)

    def test_slo_summary_card_without_service_errors_gracefully(self):
        rc = resolve_card({"id": "c1", "type": "slo_summary", "config": {"slo_id": "uptime"}}, self.state)
        self.assertEqual(rc["error"], "SLO service not available")
        self.assertIsNone(rc["data"])

    def test_slo_summary_card_resolves_live_data(self):
        # get_one()/resolve_card have no `now` override, so this uses real
        # wall-clock time -- samples are inserted immediately before the
        # call, well within every window used by the default SLO.
        now = datetime.now(UTC)
        for minutes_ago in range(60, -1, -5):
            stamp = (now - timedelta(minutes=minutes_ago)).isoformat()
            self.db.execute("INSERT INTO health_samples(timestamp,device_id,health,online) VALUES(?,?,?,?)",
                            (stamp, "pi-a", "healthy", 1))
        config = {"definitions": [valid_slo(id="uptime", scope={"type": "device", "value": "pi-a"})]}
        service = SLOService(self.db, state=self.state, config=config, interval=9999)
        rc = resolve_card({"id": "c1", "type": "slo_summary", "config": {"slo_id": "uptime"}},
                          self.state, slo_service=service)
        self.assertIsNone(rc["error"])
        self.assertEqual(rc["data"]["id"], "uptime")
        self.assertFalse(rc["data"]["firing"])
        self.assertAlmostEqual(rc["data"]["attainment_percent"], 100.0, delta=0.01)

    def test_slo_summary_card_unknown_id_errors(self):
        service = SLOService(self.db, state=self.state, config={"definitions": []}, interval=9999)
        rc = resolve_card({"id": "c1", "type": "slo_summary", "config": {"slo_id": "ghost"}},
                          self.state, slo_service=service)
        self.assertEqual(rc["error"], "SLO not found")


if __name__ == "__main__":
    unittest.main()
