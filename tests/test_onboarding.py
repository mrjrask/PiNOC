"""Coverage for the onboarding wizard (pinoc/onboarding.py + its web routes).

Three layers, matching the split other recent features (see
tests/test_rollout.py, tests/test_schedules.py) use:

* :class:`DiscoveryParsingTest` -- pure parsing/merging of fake ARP and mDNS
  data, no subprocess or file I/O.
* :class:`FingerprintAndSuggestTest` -- the bounded SSH fingerprint pass
  (against a faked ``runner``, mirroring FleetCollector's own tests) and the
  suggested-config derivation heuristics, plus :class:`OnboardingService`'s
  bounds (candidate/host caps, injected ARP/mDNS/SSH sources).
* :class:`SaveDevicesTest` -- ``pinoc.config_store.save_devices`` writes
  through the same validated device parsing ``load_devices`` uses, and a
  rejected write leaves the existing device store untouched.
* :class:`WebTest` -- the HTTP surface (admin-gated scan/fingerprint/confirm,
  token scopes, confirm's add/update-by-id merge and its rejection case)
  through ``create_app``, following tests/test_schedules.py's WebTest.

No test in this file makes a real network, mDNS, or SSH call -- every
boundary (ARP table text, mDNS browse text, SSH subprocess) is injected.
"""
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from pinoc.config_store import save_devices
from pinoc.device_config import load_devices
from pinoc.onboarding import (
    OnboardingService, fingerprint_host, merge_candidates, parse_arp_text,
    parse_mdns_text, suggest_config,
)
from pinoc.state import PiNOCState
from pinoc.web.app import create_app

ARP_TEXT = (
    "IP address       HW type     Flags       HW address            Mask     Device\n"
    "192.168.1.50     0x1         0x2         b8:27:eb:aa:bb:cc     *        eth0\n"
    "192.168.1.51     0x1         0x0         00:00:00:00:00:00     *        eth0\n"
    "192.168.1.52     0x1         0x2         dc:a6:32:11:22:33     *        eth0\n"
)

MDNS_TEXT = (
    "=;eth0;IPv4;piaware;_adsb._tcp;local;piaware.local;192.168.1.50;22;\n"
    "=;eth0;IPv4;piaware;_ssh._tcp;local;piaware.local;192.168.1.50;22;\n"
    "+;eth0;IPv4;something;_http._tcp;local\n"  # unresolved browse-only line: too short, ignored
    "=;eth0;IPv4;magicmirror;_http._tcp;local;mirror.local;192.168.1.52;80;\n"
)


def fp_output(hostname="pi-a", os_name="Raspbian GNU/Linux", os_version="12", uname="Linux 6.1.0-rpi arm64",
             model="Raspberry Pi 4 Model B", units=("piaware.service", "dump1090-fa.service"),
             listen=("0.0.0.0:22",)):
    return (
        f"__HOSTNAME__\n{hostname}\n"
        f"__OS__\nNAME=\"{os_name}\"\nVERSION_ID=\"{os_version}\"\n"
        f"__UNAME__\n{uname}\n"
        f"__MODEL__\n{model}\n"
        f"__UNITS__\n" + "\n".join(units) + "\n"
        f"__LISTEN__\n" + "\n".join(listen) + "\n"
    )


class DiscoveryParsingTest(unittest.TestCase):
    def test_arp_drops_incomplete_entries(self):
        rows = parse_arp_text(ARP_TEXT)
        self.assertEqual([r["ip"] for r in rows], ["192.168.1.50", "192.168.1.52"])
        self.assertEqual(rows[0]["mac"], "b8:27:eb:aa:bb:cc")
        self.assertEqual(rows[0]["iface"], "eth0")

    def test_arp_empty_and_malformed_text_is_no_rows(self):
        self.assertEqual(parse_arp_text(""), [])
        self.assertEqual(parse_arp_text("just a header line\nshort row\n"), [])

    def test_mdns_parses_resolved_lines_and_dedups_services_by_address(self):
        rows = parse_mdns_text(MDNS_TEXT)
        by_ip = {r["ip"]: r for r in rows}
        self.assertEqual(set(by_ip), {"192.168.1.50", "192.168.1.52"})
        self.assertEqual(by_ip["192.168.1.50"]["hostname"], "piaware.local")
        self.assertEqual(set(by_ip["192.168.1.50"]["services"]), {"_adsb._tcp", "_ssh._tcp"})
        self.assertEqual(by_ip["192.168.1.52"]["hostname"], "mirror.local")

    def test_mdns_ignores_unresolved_and_malformed_lines(self):
        self.assertEqual(parse_mdns_text("+;eth0;IPv4;x;_http._tcp;local\n"), [])
        self.assertEqual(parse_mdns_text("not a browse line at all\n"), [])

    def test_merge_candidates_combines_by_ip_and_sorts(self):
        arp = parse_arp_text(ARP_TEXT)
        mdns = parse_mdns_text(MDNS_TEXT)
        merged = merge_candidates(arp, mdns)
        self.assertEqual([c["ip"] for c in merged], ["192.168.1.50", "192.168.1.52"])
        first = merged[0]
        self.assertEqual(first["mac"], "b8:27:eb:aa:bb:cc")  # from ARP
        self.assertEqual(first["hostname"], "piaware.local")  # from mDNS
        self.assertEqual(set(first["sources"]), {"arp", "mdns"})
        # Second candidate is in both sources too (ARP MAC + mDNS hostname).
        second = merged[1]
        self.assertEqual(second["mac"], "dc:a6:32:11:22:33")
        self.assertEqual(second["hostname"], "mirror.local")
        self.assertEqual(set(second["sources"]), {"arp", "mdns"})

    def test_merge_candidates_handles_no_overlap(self):
        merged = merge_candidates([{"ip": "10.0.0.1", "mac": "aa:aa:aa:aa:aa:aa"}], [])
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0]["sources"], ["arp"])


class FingerprintAndSuggestTest(unittest.TestCase):
    def test_fingerprint_host_parses_successful_session(self):
        def runner(cmd, **kwargs):
            self.assertIn("ssh", cmd[0])
            self.assertIn("192.168.1.50", " ".join(cmd))
            self.assertIn("__HOSTNAME__", kwargs.get("input", ""))
            return subprocess.CompletedProcess(cmd, 0, fp_output(), "")
        result = fingerprint_host("192.168.1.50", runner=runner)
        self.assertTrue(result["ok"])
        self.assertEqual(result["hostname"], "pi-a")
        self.assertEqual(result["os"], "Raspbian GNU/Linux")
        self.assertEqual(result["os_version"], "12")
        self.assertEqual(result["kernel"], "6.1.0-rpi")
        self.assertEqual(result["architecture"], "arm64")
        self.assertIn("piaware.service", result["units"])
        self.assertEqual(result["listening_ports"], ["0.0.0.0:22"])

    def test_fingerprint_host_uses_sshpass_when_password_given(self):
        seen = {}
        def runner(cmd, **kwargs):
            seen["cmd"] = cmd
            seen["env"] = kwargs.get("env")
            return subprocess.CompletedProcess(cmd, 0, fp_output(), "")
        fingerprint_host("192.168.1.50", password="hunter2", runner=runner)
        self.assertEqual(seen["cmd"][0], "sshpass")
        self.assertEqual(seen["env"]["SSHPASS"], "hunter2")

    def test_fingerprint_host_reports_nonzero_exit_as_failure(self):
        def runner(cmd, **kwargs):
            return subprocess.CompletedProcess(cmd, 255, "", "Permission denied (publickey).")
        result = fingerprint_host("192.168.1.50", runner=runner)
        self.assertFalse(result["ok"])
        self.assertIn("Permission denied", result["error"])

    def test_fingerprint_host_reports_timeout_as_failure(self):
        def runner(cmd, **kwargs):
            raise subprocess.TimeoutExpired(cmd, kwargs.get("timeout", 6))
        result = fingerprint_host("192.168.1.50", runner=runner)
        self.assertFalse(result["ok"])
        self.assertIn("timed out", result["error"])

    def test_fingerprint_host_reports_os_error_as_failure(self):
        def runner(cmd, **kwargs):
            raise OSError("ssh binary not found")
        result = fingerprint_host("192.168.1.50", runner=runner)
        self.assertFalse(result["ok"])
        self.assertIn("not found", result["error"])

    def test_suggest_config_adsb_receiver(self):
        fp = fingerprint_host("1.2.3.4", runner=lambda cmd, **kw: subprocess.CompletedProcess(
            cmd, 0, fp_output(hostname="piawaren", units=("piaware.service", "dump1090-fa.service", "ssh.service")), ""))
        suggested = suggest_config("1.2.3.4", fp)
        self.assertEqual(suggested["id"], "piawaren")
        self.assertEqual(suggested["roles"], ["adsb_receiver"])
        self.assertEqual(suggested["tags"], ["adsb"])
        self.assertIn("piaware.service", suggested["critical_services"])
        self.assertIn("dump1090-fa.service", suggested["critical_services"])
        self.assertEqual(suggested["collection_method"], "ssh")

    def test_suggest_config_file_server_and_cockpit(self):
        fp = fingerprint_host("1.2.3.5", runner=lambda cmd, **kw: subprocess.CompletedProcess(
            cmd, 0, fp_output(hostname="filer", units=("smbd.service", "nmbd.service", "cockpit.socket")), ""))
        suggested = suggest_config("1.2.3.5", fp)
        self.assertEqual(suggested["roles"], ["file_server"])
        self.assertEqual(suggested["tags"], ["storage"])
        self.assertTrue(suggested["cockpit_enabled"])
        self.assertIn("cockpit.socket", suggested["monitored_services"])
        # cockpit/service-name detection must not itself mark anything critical
        self.assertEqual(suggested["critical_services"], [])

    def test_suggest_config_falls_back_to_general_role(self):
        fp = fingerprint_host("1.2.3.6", runner=lambda cmd, **kw: subprocess.CompletedProcess(
            cmd, 0, fp_output(hostname="plain-pi", units=("ssh.service",)), ""))
        suggested = suggest_config("1.2.3.6", fp)
        self.assertEqual(suggested["roles"], ["general"])
        self.assertEqual(suggested["monitored_services"], [])

    def test_suggest_config_falls_back_hostname_to_ip_when_missing(self):
        suggested = suggest_config("10.0.0.9", {"units": []})
        self.assertEqual(suggested["hostname"], "10-0-0-9")
        self.assertEqual(suggested["id"], "10-0-0-9")

    def test_service_scan_bounds_candidate_count_and_uses_injected_sources(self):
        def arp_reader(path):
            return [{"ip": f"10.0.0.{i}", "mac": f"aa:bb:cc:dd:ee:{i:02x}"} for i in range(1, 6)]
        service = OnboardingService(arp_reader=arp_reader, mdns_runner=lambda *a, **k: subprocess.CompletedProcess([], 0, "", ""),
                                    max_candidates=3)
        candidates = service.scan()
        self.assertEqual(len(candidates), 3)
        self.assertEqual([c["ip"] for c in candidates], ["10.0.0.1", "10.0.0.2", "10.0.0.3"])

    def test_service_scan_tolerates_arp_reader_failure(self):
        def broken_reader(path):
            raise OSError("no permission")
        service = OnboardingService(arp_reader=broken_reader, mdns_runner=lambda *a, **k: subprocess.CompletedProcess([], 0, "", ""))
        self.assertEqual(service.scan(), [])

    def test_service_fingerprint_bounds_host_count_and_is_deterministically_ordered(self):
        calls = []
        def ssh_runner(cmd, **kwargs):
            ip = cmd[-4].split("@")[1]
            calls.append(ip)
            return subprocess.CompletedProcess(cmd, 0, fp_output(hostname=f"host-{ip}"), "")
        service = OnboardingService(ssh_runner=ssh_runner, max_fingerprint_hosts=2, fingerprint_workers=2)
        hosts = [{"ip": f"10.0.0.{i}"} for i in (5, 3, 1, 4)]
        results = service.fingerprint(hosts)
        self.assertEqual(len(results), 2)  # bounded, even though 4 hosts were passed in
        self.assertEqual(len(calls), 2)
        self.assertEqual([r["ip"] for r in results], sorted(r["ip"] for r in results))
        for r in results:
            self.assertTrue(r["ok"])
            self.assertIsNotNone(r["suggested"])

    def test_service_fingerprint_keeps_failures_isolated_per_host(self):
        def ssh_runner(cmd, **kwargs):
            ip = cmd[-4].split("@")[1]
            if ip.endswith(".2"):
                return subprocess.CompletedProcess(cmd, 255, "", "connection refused")
            return subprocess.CompletedProcess(cmd, 0, fp_output(), "")
        service = OnboardingService(ssh_runner=ssh_runner)
        results = service.fingerprint([{"ip": "10.0.0.1"}, {"ip": "10.0.0.2"}])
        by_ip = {r["ip"]: r for r in results}
        self.assertTrue(by_ip["10.0.0.1"]["ok"])
        self.assertFalse(by_ip["10.0.0.2"]["ok"])
        self.assertIsNone(by_ip["10.0.0.2"]["suggested"])
        self.assertIn("connection refused", by_ip["10.0.0.2"]["fingerprint"]["error"])


class SaveDevicesTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.base = Path(self._tmp.name)
        self.config = {"devices_file": "config/devices.json"}

    def _suggested(self, **overrides):
        base = {"id": "piaware", "hostname": "piaware", "friendly_name": "piaware",
                "address": "192.168.1.50", "collection_method": "ssh", "ssh_user": "pi",
                "ssh_port": 22, "roles": ["adsb_receiver"], "tags": ["adsb"],
                "monitored_services": ["piaware.service"], "critical_services": ["piaware.service"],
                "cockpit_enabled": False, "notes": "discovered"}
        base.update(overrides)
        return base

    def test_valid_confirm_writes_through_the_same_validated_path(self):
        path = save_devices(self.config, self.base, {"devices": [self._suggested()]})
        self.assertTrue(path.exists())
        devices, errors = load_devices(self.config, self.base)
        self.assertEqual(errors, [])
        self.assertEqual([d.id for d in devices], ["piaware"])
        self.assertEqual(devices[0].roles, ("adsb_receiver",))

    def test_invalid_confirm_raises_and_does_not_touch_existing_store(self):
        save_devices(self.config, self.base, {"devices": [self._suggested()]})
        devices_path = self.base / "config" / "devices.json"
        before = devices_path.read_text()
        with self.assertRaises(ValueError):
            save_devices(self.config, self.base,
                        {"devices": [self._suggested(id="bad", collection_method="not-a-method")]})
        self.assertEqual(devices_path.read_text(), before)  # untouched -- validation ran before any write

    def test_confirm_rejects_duplicate_ids_within_the_same_payload(self):
        with self.assertRaises(ValueError):
            save_devices(self.config, self.base,
                        {"devices": [self._suggested(), self._suggested()]})
        self.assertFalse((self.base / "config" / "devices.json").exists())

    def test_confirm_rejects_malformed_payload_shape(self):
        with self.assertRaises(ValueError):
            save_devices(self.config, self.base, {"devices": "not-a-list"})
        with self.assertRaises(ValueError):
            save_devices(self.config, self.base, ["not", "a", "dict"])


class WebTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.app_dir = Path(self._tmp.name)
        (self.app_dir / "config").mkdir(parents=True, exist_ok=True)
        from pinoc.database import Database
        from pinoc.history import HistoryManager
        from pinoc.security import SecurityManager
        self.db = Database(f"{self._tmp.name}/db.sqlite")
        self.assertTrue(self.db.initialize())
        self.history = HistoryManager(self.db, {})
        self.state = PiNOCState()
        self.app = create_app(
            self.state, {"TESTING": True, "AUTH_ENABLED": True, "SECRET_KEY": "test-secret",
                        "DATABASE": self.db, "APP_DIR": str(self.app_dir),
                        "PINOC_CONFIG": {"devices_file": "config/devices.json"}},
            self.history)
        self.security: SecurityManager = self.app.extensions["pinoc_security"]
        self.security.create_user("boss", "pw12345678", "administrator")
        self.security.create_user("op", "pw12345678", "operator")
        self.security.create_user("watch", "pw12345678", "viewer")
        self.client = self.app.test_client()
        self.fake_candidates = [{"ip": "192.168.1.50", "mac": "b8:27:eb:aa:bb:cc",
                                 "hostname": None, "mdns_services": [], "sources": ["arp"]}]
        service = self.app.extensions["pinoc_onboarding"]
        service.arp_reader = lambda path: [{"ip": "192.168.1.50", "mac": "b8:27:eb:aa:bb:cc"}]
        service.mdns_runner = lambda *a, **k: subprocess.CompletedProcess([], 0, "", "")
        service.ssh_runner = lambda cmd, **kw: subprocess.CompletedProcess(
            cmd, 0, fp_output(hostname="piawaren"), "")

    def tearDown(self):
        self.app.extensions["pinoc_actions"].stop()

    def _login(self, username):
        self.client.get("/login")
        with self.client.session_transaction() as session:
            csrf = session["csrf_token"]
        return self.client.post("/login", data={"username": username,
                                                "password": "pw12345678", "csrf_token": csrf})

    def _csrf(self):
        with self.client.session_transaction() as session:
            return session["csrf_token"]

    def _post(self, path, body=None):
        return self.client.post(path, json=body if body is not None else {},
                                headers={"X-CSRF-Token": self._csrf()})

    def test_onboarding_page_requires_admin(self):
        self.assertEqual(self._login("watch").status_code, 302)
        self.assertEqual(self.client.get("/onboarding").status_code, 403)

    def test_full_wizard_flow_as_administrator(self):
        self.assertEqual(self._login("boss").status_code, 302)
        self.assertEqual(self.client.get("/onboarding").status_code, 200)

        scanned = self._post("/api/onboarding/scan")
        self.assertEqual(scanned.status_code, 200)
        candidates = scanned.get_json()["candidates"]
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0]["ip"], "192.168.1.50")

        fingerprinted = self._post("/api/onboarding/fingerprint", {"hosts": candidates})
        self.assertEqual(fingerprinted.status_code, 200)
        results = fingerprinted.get_json()["results"]
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0]["ok"])
        suggested = results[0]["suggested"]
        self.assertEqual(suggested["address"], "192.168.1.50")

        confirmed = self._post("/api/onboarding/confirm", {"devices": [suggested]})
        self.assertEqual(confirmed.status_code, 201)
        body = confirmed.get_json()
        self.assertEqual(body["added"], [suggested["id"]])
        self.assertEqual(body["updated"], [])

        stored = json.loads((self.app_dir / "config" / "devices.json").read_text())
        self.assertEqual([d["id"] for d in stored["devices"]], [suggested["id"]])

        # Confirming the *same* id again is an update, not a duplicate.
        suggested["notes"] = "edited by operator"
        confirmed_again = self._post("/api/onboarding/confirm", {"devices": [suggested]})
        self.assertEqual(confirmed_again.status_code, 201)
        self.assertEqual(confirmed_again.get_json()["updated"], [suggested["id"]])
        stored_again = json.loads((self.app_dir / "config" / "devices.json").read_text())
        self.assertEqual(len(stored_again["devices"]), 1)
        self.assertEqual(stored_again["devices"][0]["notes"], "edited by operator")

    def test_confirm_rejects_invalid_device_without_corrupting_store(self):
        self.assertEqual(self._login("boss").status_code, 302)
        good = {"id": "good-one", "hostname": "good-one", "friendly_name": "Good", "address": "10.0.0.5",
               "collection_method": "ssh", "roles": ["general"]}
        first = self._post("/api/onboarding/confirm", {"devices": [good]})
        self.assertEqual(first.status_code, 201)
        devices_path = self.app_dir / "config" / "devices.json"
        before = devices_path.read_text()

        bad = {"id": "bad-one", "hostname": "bad-one", "friendly_name": "Bad", "address": "10.0.0.6",
              "collection_method": "not-a-real-method", "roles": ["general"]}
        rejected = self._post("/api/onboarding/confirm", {"devices": [bad]})
        self.assertEqual(rejected.status_code, 400)
        self.assertIn("collection_method", rejected.get_json()["error"])
        self.assertEqual(devices_path.read_text(), before)  # untouched by the rejected write

    def test_confirm_requires_devices_list(self):
        self.assertEqual(self._login("boss").status_code, 302)
        self.assertEqual(self._post("/api/onboarding/confirm", {"devices": []}).status_code, 400)
        self.assertEqual(self._post("/api/onboarding/confirm", {}).status_code, 400)

    def test_confirm_requires_every_device_to_carry_an_id(self):
        self.assertEqual(self._login("boss").status_code, 302)
        response = self._post("/api/onboarding/confirm", {"devices": [{"hostname": "no-id"}]})
        self.assertEqual(response.status_code, 400)

    def test_fingerprint_requires_hosts_list(self):
        self.assertEqual(self._login("boss").status_code, 302)
        self.assertEqual(self._post("/api/onboarding/fingerprint", {"hosts": []}).status_code, 400)

    def test_operator_denied(self):
        self.assertEqual(self._login("op").status_code, 302)
        self.assertEqual(self.client.get("/onboarding").status_code, 403)
        self.assertEqual(self._post("/api/onboarding/scan").status_code, 403)
        self.assertEqual(self._post("/api/onboarding/confirm", {"devices": [{"id": "x"}]}).status_code, 403)

    def test_viewer_denied(self):
        self.assertEqual(self._login("watch").status_code, 302)
        self.assertEqual(self._post("/api/onboarding/scan").status_code, 403)

    def test_unauthenticated_is_401(self):
        self.assertEqual(self.client.post("/api/onboarding/scan").status_code, 401)

    def test_token_scopes(self):
        admin_token = self.security.create_token("boss", ["admin:config"])
        read_token = self.security.create_token("boss", ["read:fleet"])
        ok = self.client.post("/api/onboarding/scan", headers={"Authorization": "Bearer " + admin_token})
        self.assertEqual(ok.status_code, 200)
        denied = self.client.post("/api/onboarding/scan", headers={"Authorization": "Bearer " + read_token})
        self.assertEqual(denied.status_code, 403)


if __name__ == "__main__":
    unittest.main()
