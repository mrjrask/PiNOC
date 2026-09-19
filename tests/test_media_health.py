"""Coverage for storage-media (SD card / eMMC / disk) wear and I/O-error health."""
import os
import subprocess
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from pinoc.collectors.fleet import SCRIPT, FleetCollector, parse_media, sections
from pinoc.database import Database
from pinoc.device_config import DeviceConfig
from pinoc.health import evaluate
from pinoc.history import HistoryManager
from pinoc.models import DeviceState
from pinoc.state import PiNOCState

DISKSTATS = """\
 259       0 mmcblk0 100 0 50000 1200 200 0 300000 5000 0 2000 0
 259       1 mmcblk0p1 10 0 1000 50 5 0 5000 200 0 300 0
 259       2 mmcblk0p2 80 0 40000 900 190 0 290000 4500 0 1500 0
   8       0 sda 12 0 300 20 8 0 700 30 0 40 0
   8       1 sda1 10 0 200 15 5 0 500 25 0 30 0
"""

STORAGE = [
    {"device": "/dev/mmcblk0p2", "mount_point": "/", "filesystem": "ext4"},
    {"device": "/dev/sda1", "mount_point": "/data", "filesystem": "ext4"},
]

IO_ERRORS = """\
[ 123.456] sdhci-cqhci: Error -84 transferring command
[ 130.101] blk_update_request: I/O error, dev mmcblk0p2, sector 4096
[ 131.202] EXT4-fs (mmcblk0p2): I/O error while writing superblock
[ 140.000] blk_update_request: I/O error, dev sr0, sector 0
"""


def timestamp(seconds_ago: float = 0) -> str:
    return (datetime.now(timezone.utc) - timedelta(seconds=seconds_ago)).isoformat()


class ParseMediaTest(unittest.TestCase):
    def test_consolidates_partitions_and_maps_wear(self):
        media = parse_media(DISKSTATS, "", STORAGE)
        self.assertEqual([x["device"] for x in media], ["mmcblk0", "sda"])
        sd_card = media[0]
        self.assertEqual(sd_card["mount_points"], ["/"])
        self.assertEqual(sd_card["written_bytes"], 300000 * 512)
        self.assertEqual(sd_card["read_bytes"], 50000 * 512)
        self.assertFalse(sd_card["media_errors"])

    def test_matches_kernel_errors_with_aliases(self):
        media = parse_media(DISKSTATS, IO_ERRORS, STORAGE)
        sd_card = next(x for x in media if x["device"] == "mmcblk0")
        self.assertTrue(sd_card["media_errors"])
        self.assertEqual(sd_card["io_errors"], 2)  # the two mmcblk0* lines
        self.assertIn("superblock", sd_card["last_error"])
        disk = next(x for x in media if x["device"] == "sda")
        self.assertFalse(disk["media_errors"])  # the sr0 error belongs to another device

    def test_mmc_alias_matches_partition_only_errors(self):
        media = parse_media(DISKSTATS, IO_ERRORS, STORAGE)
        sd_card = next(x for x in media if x["device"] == "mmcblk0")
        self.assertEqual(sd_card["io_errors"], 2)

    def test_empty_when_no_diskstats(self):
        self.assertEqual(parse_media("", IO_ERRORS, STORAGE), [])
        self.assertEqual(parse_media(DISKSTATS, "", []), [])

    def test_pseudo_filesystems_are_ignored(self):
        storage = [{"device": "tmpfs", "mount_point": "/run"}]
        self.assertEqual(parse_media(DISKSTATS, "", storage), [])


class HealthTest(unittest.TestCase):
    def base(self):
        return {"last_seen": timestamp(), "cpu": {}, "memory": {}, "storage": [],
                "services": [], "integrations": {}}

    def test_media_errors_are_critical(self):
        device = self.base()
        device["media"] = [{"device": "mmcblk0", "media_errors": True, "io_errors": 3}]
        health, reasons, _ = evaluate(device)
        self.assertEqual(health, "critical")
        self.assertTrue(any("I/O errors" in reason for reason in reasons))

    def test_clean_media_keeps_health(self):
        device = self.base()
        device["media"] = [{"device": "mmcblk0", "media_errors": False, "io_errors": 0}]
        self.assertEqual(evaluate(device)[0], "healthy")


class FleetCollectionTest(unittest.TestCase):
    # The collection shell prints each marker on its own line, so tests must
    # use the same bare-marker format that sections() recognizes.
    SCRIPT_OUTPUT = f"""__OS__
PRETTY_NAME="Raspberry Pi OS"
__UNAME__
Linux 6.6 armv7l
__MODEL__
Raspberry Pi 5
__UPTIME__
1000 2000
__LOAD__
1.0 1.0 1.0
__CPU__
cpu 10 0 10 80 0 0 0 0 0 0
__FREQ__
__TEMP__
/sys/class/thermal/thermal_zone0/temp=50000
__THROTTLED__
throttled=0x0
__MEM__
MemTotal: 8000000 kB
MemAvailable: 4000000 kB
SwapTotal: 0 kB
SwapFree: 0 kB
__DF__
Filesystem Type 1024-blocks Used Available Capacity Mounted on
/dev/mmcblk0p2 ext4 100000 50000 50000 50% /
__MOUNTS__
/dev/mmcblk0p2 / ext4 rw 0 0
__DISKSTATS__
{DISKSTATS}
__IOERRORS__
{IO_ERRORS}
__IOERRORSTATUS__
available
__ROUTE__
__ADDR__
__NET__
iface |bytes
eth0: 1000 0 0 0 0 0 0 0 2000 0 0 0 0 0 0 0 0
__IW__
__SERVICES__
__UNITS__
ssh.service enabled
"""

    def test_journal_success_with_privilege_diagnostic_is_unavailable(self):
        with tempfile.TemporaryDirectory() as folder:
            commands = Path(folder)
            dmesg = commands / "dmesg"
            dmesg.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
            journalctl = commands / "journalctl"
            journalctl.write_text(
                "#!/bin/sh\n"
                "echo 'Hint: You are currently not seeing messages from other users.' >&2\n"
                "exit 0\n",
                encoding="utf-8",
            )
            dmesg.chmod(0o755)
            journalctl.chmod(0o755)
            env = os.environ.copy()
            env["PATH"] = f"{commands}:{env['PATH']}"

            result = subprocess.run(
                ["sh"], input=SCRIPT, text=True, capture_output=True, env=env, check=True
            )

        self.assertEqual(sections(result.stdout)["IOERRORSTATUS"], "unavailable")

    def test_media_is_collected_and_health_degrades(self):
        device = DeviceConfig(id="pi", hostname="pi", friendly_name="Pi",
                              address="192.168.1.10", collection_method="ssh")

        def runner(args, **kwargs):
            return subprocess.CompletedProcess(args, 0, self.SCRIPT_OUTPUT, "")

        collector = FleetCollector([device], runner=runner, timeout=1)
        snapshot = collector.collect_device(device)
        self.assertTrue(snapshot.online)
        self.assertTrue(snapshot.media)
        self.assertEqual(snapshot.media[0]["device"], "mmcblk0")
        self.assertTrue(snapshot.media[0]["media_errors"])
        self.assertEqual(snapshot.health, "critical")
        self.assertTrue(any("I/O errors" in reason for reason in snapshot.health_reasons))

    def test_media_degrades_gracefully_without_kernel_access(self):
        output = self.SCRIPT_OUTPUT.replace(DISKSTATS, "").replace(IO_ERRORS, "")
        device = DeviceConfig(id="pi", hostname="pi", friendly_name="Pi",
                              address="192.168.1.10", collection_method="ssh")

        def runner(args, **kwargs):
            return subprocess.CompletedProcess(args, 0, output, "")

        snapshot = FleetCollector([device], runner=runner, timeout=1).collect_device(device)
        self.assertEqual(snapshot.media, [])
        self.assertEqual(snapshot.health, "healthy")

    def test_unreadable_kernel_logs_are_unknown(self):
        output = self.SCRIPT_OUTPUT.replace(IO_ERRORS, "").replace(
            "__IOERRORSTATUS__\navailable", "__IOERRORSTATUS__\nunavailable")
        device = DeviceConfig(id="pi", hostname="pi", friendly_name="Pi",
                              address="192.168.1.10", collection_method="ssh")

        def runner(args, **kwargs):
            return subprocess.CompletedProcess(args, 0, output, "")

        snapshot = FleetCollector([device], runner=runner, timeout=1).collect_device(device)
        self.assertIsNone(snapshot.media[0]["media_errors"])
        self.assertIsNone(snapshot.media[0]["io_errors"])
        self.assertEqual(snapshot.media[0]["io_error_status"], "unknown")
        self.assertEqual(snapshot.collector_status["media_errors"]["status"], "unavailable")
        self.assertEqual(snapshot.health, "warning")


class HistoryTest(unittest.TestCase):
    def _device(self, stamp):
        return {"id": "pi", "online": True, "last_seen": stamp,
                "cpu": {}, "memory": {}, "hardware": {}, "storage": [], "services": [],
                "integrations": {}, "media": [
                    {"device": "mmcblk0", "mount_points": ["/"],
                     "read_bytes": 1024, "written_bytes": 2048,
                     "io_errors": 2, "media_errors": True, "last_error": "x"}]}

    def test_samples_and_alerts_and_resolves(self):
        with tempfile.TemporaryDirectory() as folder:
            db = Database(f"{folder}/db.sqlite")
            self.assertTrue(db.initialize())
            self.assertEqual(db.scalar("SELECT version FROM schema_version"), 7)
            history = HistoryManager(db, {})
            stamp = "2026-01-01T00:00:00+00:00"
            history._sample(self._device(stamp), stamp)
            self.assertEqual(db.scalar("SELECT COUNT(*) FROM media_metrics"), 1)
            row = db.rows("SELECT * FROM media_metrics")[0]
            self.assertEqual((row["block_device"], row["io_errors"], row["media_errors"]),
                             ("mmcblk0", 2, 1))
            history._alerts(self._device(stamp), stamp)
            self.assertEqual(db.scalar(
                "SELECT COUNT(*) FROM alerts WHERE alert_type='media_io_errors' AND resolved_at IS NULL"), 1)
            # Recovery clears the condition.
            recovered = self._device("2026-01-01T00:01:00+00:00")
            recovered["media"] = [{"device": "mmcblk0", "io_errors": 0, "media_errors": False}]
            history._alerts(recovered, "2026-01-01T00:01:00+00:00")
            self.assertEqual(db.scalar(
                "SELECT COUNT(*) FROM alerts WHERE resolved_at IS NULL"), 0)

    def test_unknown_observability_does_not_resolve_open_alert(self):
        with tempfile.TemporaryDirectory() as folder:
            db = Database(f"{folder}/db.sqlite")
            self.assertTrue(db.initialize())
            history = HistoryManager(db, {})
            stamp = "2026-01-01T00:00:00+00:00"
            history._alerts(self._device(stamp), stamp)
            unknown = self._device("2026-01-01T00:01:00+00:00")
            unknown["media"] = [{"device": "mmcblk0", "io_errors": None,
                                 "media_errors": None, "io_error_status": "unknown"}]
            history._sample(unknown, "2026-01-01T00:01:00+00:00")
            history._alerts(unknown, "2026-01-01T00:01:00+00:00")
            sample = db.rows("SELECT * FROM media_metrics")[0]
            self.assertIsNone(sample["io_errors"])
            self.assertIsNone(sample["media_errors"])
            self.assertEqual(db.scalar(
                "SELECT COUNT(*) FROM alerts WHERE alert_type='media_io_errors' AND resolved_at IS NULL"), 1)

    def test_retention_removes_old_media_samples(self):
        with tempfile.TemporaryDirectory() as folder:
            db = Database(f"{folder}/db.sqlite")
            self.assertTrue(db.initialize())
            db.execute("INSERT INTO media_metrics(timestamp,device_id,block_device,read_bytes,written_bytes,io_errors,media_errors) VALUES(?,?,?,?,?,?,?)",
                       ("2025-01-01T00:00:00+00:00", "pi", "mmcblk0", 1, 1, 0, 0))
            db.execute("INSERT INTO media_metrics(timestamp,device_id,block_device,read_bytes,written_bytes,io_errors,media_errors) VALUES(?,?,?,?,?,?,?)",
                       ("2026-01-01T00:00:00+00:00", "pi", "mmcblk0", 1, 1, 0, 0))
            history = HistoryManager(db, {})
            history.maintenance(datetime(2026, 1, 2, tzinfo=timezone.utc))
            rows = db.rows("SELECT * FROM media_metrics")
            self.assertEqual(len(rows), 1)
            self.assertGreater(rows[0]["timestamp"], "2025-12-01")


class WebSurfacingTest(unittest.TestCase):
    def test_media_reaches_the_device_api(self):
        from pinoc.web import create_app

        state = PiNOCState()
        state.publish([DeviceState(
            id="pi", hostname="pi", friendly_name="Pi", online=True,
            collection_method="local", media=[
                {"device": "mmcblk0", "mount_points": ["/"], "read_bytes": 10,
                 "written_bytes": 20, "io_errors": 1, "media_errors": True,
                 "last_error": "blk_update_request: I/O error"}])], replace=True)
        client = create_app(state, {"TESTING": True}).test_client()
        payload = client.get("/api/devices/pi").get_json()
        self.assertEqual(payload["media"][0]["device"], "mmcblk0")
        self.assertTrue(payload["media"][0]["media_errors"])


if __name__ == "__main__":
    unittest.main()
