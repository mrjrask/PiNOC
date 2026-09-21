import subprocess
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from pinoc.collectors.fleet import (FleetCollector, SCRIPT, parse_cpu, parse_memory, parse_network,
                                    parse_services, parse_storage, parse_throttled)
from pinoc.device_config import DeviceConfigError, load_devices, parse_device
from pinoc.health import evaluate


class ConfigTest(unittest.TestCase):
    def test_normalizes_and_derives_stable_hostname_id(self):
        d = parse_device({"hostname":"Pi A","address":"10.0.0.2","roles":["General","GENERAL"],"tags":["Upstairs"]},0)
        self.assertEqual((d.id,d.roles,d.tags),("pi-a",("general",),("upstairs",)))
    def test_duplicate_and_bad_optional_entry(self):
        with TemporaryDirectory() as folder:
            devices, errors=load_devices({"devices":[{"id":"x","hostname":"x"},{"id":"x","hostname":"y"},{"id":"bad","hostname":"z","ssh_port":0}]},Path(folder))
        self.assertEqual([d.id for d in devices],["x"]); self.assertEqual(len(errors),2)
    def test_legacy_migration_and_cockpit(self):
        with TemporaryDirectory() as folder:
            devices,errors=load_devices({"remote_host":"cm5.local","remote_user":"bob","remote_ssh_port":2222},Path(folder))
        self.assertFalse(errors); self.assertEqual((devices[0].id,devices[0].ssh_port),("cm5-file-server",2222))
        d=parse_device({"hostname":"pi","cockpit_enabled":True},0); self.assertEqual(d.cockpit_url,"https://pi:9090")

    def test_important_paths_must_be_a_list_of_strings(self):
        for value in ("/srv/data", None, 42, ["/srv/data", 42]):
            with self.subTest(value=value), self.assertRaisesRegex(
                    DeviceConfigError, "important_paths must be a list of strings"):
                parse_device({"hostname": "pi", "important_paths": value}, 0)


class ParsingTest(unittest.TestCase):
    def test_cpu_memory_storage_throttle_and_services(self):
        cpu,_=parse_cpu({"CPU":"cpu  10 0 10 80 0","LOAD":"1.0 2.0 3.0","TEMP":"x=50000","FREQ":"1200000"},(70,80))
        self.assertEqual(cpu["utilization_percent"],50.0); self.assertEqual(cpu["temperature_c"],50)
        mem=parse_memory("MemTotal: 100 kB\nMemAvailable: 25 kB\nSwapTotal: 10 kB\nSwapFree: 5 kB")
        self.assertEqual(mem["percent"],75.0)
        disks=parse_storage("Filesystem Type 1024-blocks Used Available Capacity Mounted on\n/dev/x ext4 100 90 10 90% /", "/dev/x / ext4 ro 0 0")
        self.assertTrue(disks[0]["read_only"])
        self.assertTrue(parse_throttled("throttled=0x50005")["undervoltage_now"])
        services=parse_services("Id=x.service\nLoadState=loaded\nActiveState=failed\nSubState=failed\nMainPID=0\nNRestarts=2",["x.service"])
        self.assertEqual((services[0]["state"],services[0]["critical"]),("failed",True))

    def test_cpu_uses_hottest_sensor_for_health_temperature(self):
        cpu,_=parse_cpu({"TEMP":"/sys/class/hwmon/hwmon0/temp1_input=42000\n"
                                "/sys/class/thermal/thermal_zone0/temp=81000"})
        self.assertEqual(cpu["temperature_c"],81)

    def test_services_treat_unset_numeric_properties_as_unavailable(self):
        services=parse_services("Id=x.service\nActiveState=inactive\nMainPID=[not set]\n"
                                "NRestarts=[not set]\nMemoryCurrent=[not set]",[])
        self.assertIsNone(services[0]["main_pid"])
        self.assertIsNone(services[0]["restart_count"])
        self.assertIsNone(services[0]["memory_bytes"])

    def test_wifi_channel_and_width_are_parsed_from_iw_info(self):
        # "iw dev <if> link" never prints a channel/width line at all; that
        # only appears in "iw dev <if> info"'s
        # "channel N (freq MHz), width: W MHz, ..." line.
        iw_text = (
            "Interface wlan0\n"
            "Connected to aa:bb:cc:dd:ee:ff (on wlan0)\n"
            "\tSSID: HomeWiFi\n"
            "\tsignal: -55 dBm\n"
            "Interface wlan0\n"
            "\tchannel 36 (5180 MHz), width: 80 MHz, center1: 5210 MHz\n"
        )
        net = parse_network({"ROUTE": "[]", "ADDR": "[]", "NET": "", "IW": iw_text})
        self.assertEqual(net["ssid"], "HomeWiFi")
        self.assertEqual(net["signal_dbm"], -55.0)
        self.assertEqual(net["channel"], 36)
        self.assertEqual(net["channel_width"], "80 MHz")

    def test_collection_script_actually_requests_iw_info(self):
        # The parser above only works if the remote-side script actually
        # runs "iw dev <if> info"; assert the script does, so the two
        # cannot silently drift apart again.
        self.assertIn("iw dev \"$ifc\" info", SCRIPT)


class HealthTest(unittest.TestCase):
    def base(self):
        now=datetime.now(timezone.utc).isoformat(); return {"last_seen":now,"cpu":{},"memory":{},"storage":[],"services":[]}
    def test_warning_degraded_critical_stale_offline(self):
        d=self.base(); d["cpu"]={"utilization_percent":71}; self.assertEqual(evaluate(d)[0],"warning")
        d["memory"]={"percent":81}; self.assertEqual(evaluate(d)[0],"degraded")
        d=self.base(); d["cpu"]={"temperature_c":81}; self.assertEqual(evaluate(d)[0],"critical")
        d=self.base(); d["last_seen"]=(datetime.now(timezone.utc)-timedelta(seconds=40)).isoformat(); self.assertEqual(evaluate(d)[0],"degraded")
        d["last_seen"]=(datetime.now(timezone.utc)-timedelta(seconds=121)).isoformat(); self.assertEqual(evaluate(d)[0],"offline")

    def test_read_only_mount_is_critical_only_when_it_contains_an_important_path(self):
        d=self.base(); d["storage"]=[{"mount_point":"/media/archive","read_only":True}]
        self.assertEqual(evaluate(d)[0],"healthy")
        d["important_paths"]=["/media/archive/backups"]
        self.assertEqual(evaluate(d)[0],"critical")

    def test_maintenance_requires_recent_successful_telemetry(self):
        self.assertEqual(evaluate({"maintenance": True})[0], "offline")
        d = self.base(); d["maintenance"] = True
        self.assertEqual(evaluate(d)[0], "maintenance")


class ConcurrencyTest(unittest.TestCase):
    def test_concurrent_collection_does_not_cross_contaminate_per_device_state(self):
        # previous_cpu/previous_net/snapshots/_last_jlogs are shared across
        # every collect_device() call, which collect() dispatches to a
        # ThreadPoolExecutor. With more devices than workers, the same
        # worker thread handles multiple different devices over time --
        # this stress-tests that each device's own prior CPU counters
        # (used to compute its utilization delta) are never read from or
        # overwritten by a different device's collection.
        n = 9
        devices = [parse_device({"id": f"d{i}", "hostname": f"d{i}"}, i) for i in range(n)]

        def output_for(i, cycle):
            if cycle == 1:
                idle, busy = 1000, i * 100
            else:
                idle, busy = 2000 - 100 * (i + 1), 200 * i + 100
            return (f"__UPTIME__\n1 1\n__LOAD__\n0 0 0\n"
                   f"__CPU__\ncpu {busy} 0 0 {idle} 0\n"
                   f"__MEM__\nMemTotal: 10 kB\nMemAvailable: 5 kB\n")

        state = {"cycle": 1}
        def runner(cmd, **kwargs):
            host = " ".join(cmd)
            i = next(idx for idx, d in enumerate(devices) if d.address in host)
            return subprocess.CompletedProcess(cmd, 0, output_for(i, state["cycle"]), "")

        collector = FleetCollector(devices, max_workers=6, runner=runner)
        collector.collect()
        state["cycle"] = 2
        result = collector.collect()
        by_id = {d.id: d for d in result}
        for i in range(n):
            # Each device's expected utilization is uniquely derived from
            # its own prior counters (10%, 20%, ..., 90%); a wrong/shared
            # previous value from another device would compute a different
            # number here.
            self.assertAlmostEqual(by_id[f"d{i}"].cpu["utilization_percent"], 10.0 * (i + 1), places=1)

    def test_failed_first_collection_keeps_maintenance_device_offline(self):
        device = parse_device({"hostname": "pi", "maintenance": True}, 0)
        def runner(*_args, **_kwargs):
            raise subprocess.TimeoutExpired("ssh", 1)
        result = FleetCollector([device], runner=runner).collect_device(device)
        self.assertEqual((result.health, result.online), ("offline", False))

    def test_empty_uptime_section_falls_back_instead_of_raising(self):
        # A present-but-empty UPTIME section (data.get("UPTIME","0") returns
        # "" rather than the "0" default) must not raise IndexError from
        # "".split()[0]; it should fall back to zero uptime like a missing
        # section would.
        device = parse_device({"id": "pi", "hostname": "pi"}, 0)
        def runner(cmd, **kwargs):
            return subprocess.CompletedProcess(
                cmd, 0,
                "__UPTIME__\n__LOAD__\n0 0 0\n__CPU__\ncpu 1 0 1 8\n"
                "__MEM__\nMemTotal: 10 kB\nMemAvailable: 5 kB\n", "")
        result = FleetCollector([device], runner=runner).collect_device(device)
        self.assertEqual(result.uptime_seconds, 0)
        self.assertEqual(result.error, "")

    def test_slow_failure_does_not_prevent_healthy_result(self):
        devices=[parse_device({"id":x,"hostname":x},i) for i,x in enumerate(("slow","good"))]
        def runner(cmd,**kwargs):
            host=" ".join(cmd)
            if "slow" in host: time.sleep(.15); raise subprocess.TimeoutExpired(cmd,.1)
            return subprocess.CompletedProcess(cmd,0,"__UPTIME__\n1 1\n__LOAD__\n0 0 0\n__CPU__\ncpu 1 0 1 8\n__MEM__\nMemTotal: 10 kB\nMemAvailable: 5 kB\n","")
        started=time.monotonic(); result=FleetCollector(devices,max_workers=2,runner=runner).collect()
        self.assertLess(time.monotonic()-started,.3); self.assertEqual({x.id for x in result},{"slow","good"})

    def test_unexpected_bug_in_one_device_does_not_drop_it_or_abort_others(self):
        # collect_device()'s except clause only catches known transport
        # failures; a genuinely unexpected bug (a real parsing/logic error,
        # not simulated here as any exception the health evaluator might
        # raise) must not propagate out of future.result() in collect() and
        # abort the whole cycle, nor silently drop the failing device from
        # the returned list (state.publish(replace=True) would delete it).
        devices=[parse_device({"id":x,"hostname":x},i) for i,x in enumerate(("broken","good"))]
        def runner(cmd,**kwargs):
            return subprocess.CompletedProcess(
                cmd,0,"__UPTIME__\n1 1\n__LOAD__\n0 0 0\n__CPU__\ncpu 1 0 1 8\n"
                "__MEM__\nMemTotal: 10 kB\nMemAvailable: 5 kB\n","")
        collector=FleetCollector(devices,max_workers=2,runner=runner)
        real_evaluate=evaluate; calls={"broken":0}
        def flaky_evaluate(raw,thresholds):
            if raw.get("id")=="broken" and calls["broken"]==0:
                calls["broken"]+=1;raise ValueError("simulated unexpected bug")
            return real_evaluate(raw,thresholds)
        with mock.patch("pinoc.collectors.fleet.evaluate",side_effect=flaky_evaluate):
            result=collector.collect()
        by_id={d.id:d for d in result}
        self.assertEqual(set(by_id),{"broken","good"})
        self.assertIn("simulated unexpected bug",by_id["broken"].error)
        self.assertEqual(by_id["good"].error,"")


if __name__ == "__main__": unittest.main()
