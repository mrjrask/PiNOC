import subprocess
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

from pinoc.collectors.fleet import FleetCollector, parse_cpu, parse_memory, parse_services, parse_storage, parse_throttled
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


class ConcurrencyTest(unittest.TestCase):
    def test_slow_failure_does_not_prevent_healthy_result(self):
        devices=[parse_device({"id":x,"hostname":x},i) for i,x in enumerate(("slow","good"))]
        def runner(cmd,**kwargs):
            host=" ".join(cmd)
            if "slow" in host: time.sleep(.15); raise subprocess.TimeoutExpired(cmd,.1)
            return subprocess.CompletedProcess(cmd,0,"__UPTIME__\n1 1\n__LOAD__\n0 0 0\n__CPU__\ncpu 1 0 1 8\n__MEM__\nMemTotal: 10 kB\nMemAvailable: 5 kB\n","")
        started=time.monotonic(); result=FleetCollector(devices,max_workers=2,runner=runner).collect()
        self.assertLess(time.monotonic()-started,.3); self.assertEqual({x.id for x in result},{"slow","good"})


if __name__ == "__main__": unittest.main()
