"""Coverage for pinoc.collectors.network_matrix: ping-output parsing, the
local-vs-SSH command it builds per source device, and the collector's
interval-respecting, bounded sampling into history."""
import subprocess
import tempfile
import unittest

from pinoc.collectors.network_matrix import (
    NetworkMatrixCollector,
    build_ping_argv,
    parse_ping_output,
    sample_pair,
)
from pinoc.database import Database
from pinoc.device_config import DeviceConfig

LINUX_PING_SUMMARY = (
    "PING 192.168.1.50 (192.168.1.50) 56(84) bytes of data.\n\n"
    "--- 192.168.1.50 ping statistics ---\n"
    "3 packets transmitted, 3 received, 0% packet loss, time 2003ms\n"
    "rtt min/avg/max/mdev = 1.234/2.345/3.456/0.500 ms\n"
)

LOSSY_PING_SUMMARY = (
    "--- host ping statistics ---\n"
    "3 packets transmitted, 1 received, 66.6667% packet loss, time 2003ms\n"
    "rtt min/avg/max/mdev = 10.000/12.500/15.000/2.500 ms\n"
)

DEAD_PING_SUMMARY = (
    "--- host ping statistics ---\n"
    "3 packets transmitted, 0 received, 100% packet loss, time 2003ms\n"
)


def local_device(**overrides):
    base = dict(id="pinoc", hostname="pinoc", friendly_name="PiNOC", address="pinoc.local",
               collection_method="local")
    base.update(overrides)
    return DeviceConfig(**base)


def remote_device(device_id, **overrides):
    base = dict(id=device_id, hostname=device_id, friendly_name=device_id.title(),
               address=f"{device_id}.local", collection_method="ssh", ssh_user="pi", ssh_port=22)
    base.update(overrides)
    return DeviceConfig(**base)


class ParsePingOutputTest(unittest.TestCase):
    def test_parses_latency_and_loss(self):
        result = parse_ping_output(LINUX_PING_SUMMARY)
        self.assertAlmostEqual(result["latency_ms"], 2.345)
        self.assertAlmostEqual(result["loss_percent"], 0.0)

    def test_parses_partial_loss(self):
        result = parse_ping_output(LOSSY_PING_SUMMARY)
        self.assertAlmostEqual(result["latency_ms"], 12.5)
        self.assertAlmostEqual(result["loss_percent"], 66.6667)

    def test_total_loss_has_no_rtt_line(self):
        result = parse_ping_output(DEAD_PING_SUMMARY)
        self.assertIsNone(result["latency_ms"])
        self.assertAlmostEqual(result["loss_percent"], 100.0)

    def test_empty_text_is_all_none(self):
        result = parse_ping_output("")
        self.assertIsNone(result["latency_ms"])
        self.assertIsNone(result["loss_percent"])


class BuildPingArgvTest(unittest.TestCase):
    def test_local_source_pings_directly(self):
        argv = build_ping_argv(local_device(), "192.168.1.50", 3, 2.0)
        self.assertEqual(argv, ["ping", "-c", "3", "-W", "2", "-q", "192.168.1.50"])

    def test_remote_source_wraps_in_ssh_so_the_ping_runs_on_that_device(self):
        source = remote_device("piawaren", ssh_port=2222)
        argv = build_ping_argv(source, "192.168.1.60", 3, 2.0)
        self.assertEqual(argv[0], "ssh")
        self.assertIn("-p", argv)
        self.assertIn("2222", argv)
        self.assertIn("pi@piawaren.local", argv)
        # The ping itself is the tail of the ssh command -- it genuinely
        # runs on the source device, not on the PiNOC host.
        self.assertEqual(argv[-7:], ["ping", "-c", "3", "-W", "2", "-q", "192.168.1.60"])


class SamplePairTest(unittest.TestCase):
    def test_healthy_pair_is_ok(self):
        def runner(argv, timeout):
            return subprocess.CompletedProcess(argv, 0, LINUX_PING_SUMMARY, "")

        result = sample_pair(local_device(), remote_device("target"), runner=runner)
        self.assertTrue(result["ok"])
        self.assertAlmostEqual(result["latency_ms"], 2.345)
        self.assertIsNone(result["error"])

    def test_total_loss_is_not_ok(self):
        def runner(argv, timeout):
            return subprocess.CompletedProcess(argv, 1, DEAD_PING_SUMMARY, "")

        result = sample_pair(local_device(), remote_device("target"), runner=runner)
        self.assertFalse(result["ok"])
        self.assertEqual(result["loss_percent"], 100.0)
        self.assertIsNotNone(result["error"])

    def test_runner_exception_is_isolated_as_a_failed_sample(self):
        def boom(argv, timeout):
            raise OSError("ssh unreachable")

        result = sample_pair(local_device(), remote_device("target"), runner=boom)
        self.assertFalse(result["ok"])
        self.assertIn("OSError", result["error"])
        self.assertEqual(result["loss_percent"], 100.0)


class NetworkMatrixCollectorTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db = Database(f"{self._tmp.name}/db.sqlite")
        assert self.db.initialize()

    def tearDown(self):
        self._tmp.cleanup()

    def test_disabled_by_default_records_nothing(self):
        devices = [local_device(), remote_device("b")]
        collector = NetworkMatrixCollector(self.db, lambda: devices, {})
        collector.collect()
        self.assertEqual(self.db.rows("SELECT COUNT(*) AS n FROM network_matrix_samples"), [{"n": 0}])

    def test_samples_configured_pairs_and_respects_interval(self):
        devices = [local_device(), remote_device("b")]
        calls = []

        def runner(argv, timeout):
            calls.append(tuple(argv))
            return subprocess.CompletedProcess(argv, 0, LINUX_PING_SUMMARY, "")

        config = {"enabled": True, "pairs": [["pinoc", "b"]], "interval_seconds": 60}
        clock = {"t": 1000.0}
        collector = NetworkMatrixCollector(self.db, lambda: devices, config, runner=runner,
                                           clock=lambda: clock["t"])
        collector.collect()
        self.assertEqual(len(calls), 1)
        rows = self.db.rows("SELECT * FROM network_matrix_samples")
        self.assertEqual(len(rows), 1)
        self.assertEqual((rows[0]["source_id"], rows[0]["target_id"]), ("pinoc", "b"))
        self.assertAlmostEqual(rows[0]["latency_ms"], 2.345)
        self.assertEqual(rows[0]["ok"], 1)

        # Before the interval elapses, no new sample.
        clock["t"] += 30
        collector.collect()
        self.assertEqual(len(calls), 1)

        # After the interval, it samples again.
        clock["t"] += 40
        collector.collect()
        self.assertEqual(len(calls), 2)

    def test_pairs_referencing_a_removed_device_are_skipped_not_fatal(self):
        devices = [local_device()]  # "b" no longer configured
        config = {"enabled": True, "pairs": [["pinoc", "ghost"]], "interval_seconds": 60}
        collector = NetworkMatrixCollector(self.db, lambda: devices, config,
                                           runner=lambda a, timeout: self.fail("must not run"))
        collector.collect()  # must not raise
        self.assertEqual(self.db.rows("SELECT COUNT(*) AS n FROM network_matrix_samples"), [{"n": 0}])

    def test_bounded_pair_set_is_enforced_even_with_a_large_auto_derived_fleet(self):
        devices = [remote_device(f"d{i}", tags=("lan",)) for i in range(50)]
        calls = []

        def runner(argv, timeout):
            calls.append(argv)
            return subprocess.CompletedProcess(argv, 0, LINUX_PING_SUMMARY, "")

        config = {"enabled": True, "max_pairs": 10, "interval_seconds": 60}
        collector = NetworkMatrixCollector(self.db, lambda: devices, config, runner=runner,
                                           clock=lambda: 0.0)
        collector.collect()
        self.assertEqual(len(calls), 10)
        self.assertEqual(self.db.rows("SELECT COUNT(*) AS n FROM network_matrix_samples"), [{"n": 10}])

    def test_a_broken_runner_does_not_stop_the_remaining_pairs(self):
        devices = [remote_device("a", tags=("lan",)), remote_device("b", tags=("lan",)),
                  remote_device("c", tags=("lan",))]
        calls = []

        def flaky(argv, timeout):
            calls.append(argv)
            if len(calls) == 1:
                raise RuntimeError("boom")
            return subprocess.CompletedProcess(argv, 0, LINUX_PING_SUMMARY, "")

        config = {"enabled": True, "interval_seconds": 60}  # auto pairs: (a,b), (b,c)
        collector = NetworkMatrixCollector(self.db, lambda: devices, config, runner=flaky,
                                           clock=lambda: 0.0)
        collector.collect()
        self.assertEqual(len(calls), 2)
        rows = self.db.rows("SELECT * FROM network_matrix_samples ORDER BY id")
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["ok"], 0)
        self.assertEqual(rows[1]["ok"], 1)

    def test_reset_pair_forces_resample_before_the_interval(self):
        devices = [local_device(), remote_device("b")]
        calls = []

        def runner(argv, timeout):
            calls.append(argv)
            return subprocess.CompletedProcess(argv, 0, LINUX_PING_SUMMARY, "")

        config = {"enabled": True, "pairs": [["pinoc", "b"]], "interval_seconds": 3600}
        collector = NetworkMatrixCollector(self.db, lambda: devices, config, runner=runner,
                                           clock=lambda: 0.0)
        collector.collect()
        collector.collect()
        self.assertEqual(len(calls), 1)
        collector.reset_pair("pinoc", "b")
        collector.collect()
        self.assertEqual(len(calls), 2)


if __name__ == "__main__":
    unittest.main()
