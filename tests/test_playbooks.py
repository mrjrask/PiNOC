"""Coverage for alert playbooks: validation, web surfacing, and runbook XSS safety."""
import json
import shutil
import subprocess
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from pinoc.config_store import validate_config
from pinoc.database import Database
from pinoc.history import HistoryManager
from pinoc.models import DeviceState
from pinoc.playbooks import load_playbooks, match, validate_playbooks
from pinoc.state import PiNOCState
from pinoc.web.app import create_app


def iso(seconds_ago: float = 0) -> str:
    return (datetime.now(timezone.utc) - timedelta(seconds=seconds_ago)).isoformat()


def sample_playbook(**overrides):
    entry = {"id": "service-failed", "alert_type": "service_failed", "title": "Service failed",
             "markdown": "## Triage\n- Check logs", "actions": ["service.restart"], "links": ["/alerts"]}
    entry.update(overrides)
    return entry


class PlaybookValidationTest(unittest.TestCase):
    def test_loads_valid_and_drops_invalid(self):
        config = {"playbooks": [
            sample_playbook(),
            sample_playbook(id="bad-action", alert_type="device_offline", title="X", actions=["device.panic"]),
            sample_playbook(id="bad-link", alert_type="raid_degraded", title="X", links=["javascript:alert(1)"]),
            sample_playbook(id="no-title", alert_type="probe_failed", title="  "),
            sample_playbook(id="big", alert_type="media_io_errors", title="X", markdown="x" * 20001),
            "not-a-dict",
        ]}
        playbooks = load_playbooks(config)
        self.assertEqual([p["id"] for p in playbooks], ["service-failed"])
        self.assertEqual(playbooks[0]["actions"], ["service.restart"])

    def test_known_actions_override(self):
        config = {"playbooks": [sample_playbook(actions=["custom.thing", "service.restart"])]}
        self.assertEqual(load_playbooks(config, known_actions={"custom.thing"}), [])
        self.assertEqual(load_playbooks(config, known_actions={"custom.thing", "service.restart"})[0]["actions"],
                         ["custom.thing", "service.restart"])

    def test_limits(self):
        self.assertEqual(load_playbooks({"playbooks": "nope"}), [])
        self.assertEqual(load_playbooks({}), [])
        self.assertEqual(len(load_playbooks({"playbooks": [sample_playbook(id=f"p{i}") for i in range(60)]})), 50)
        self.assertEqual(len(load_playbooks({"playbooks": [sample_playbook(actions=["service.restart"] * 11)]})), 0)
        self.assertEqual(len(load_playbooks({"playbooks": [sample_playbook(links=["https://a.com"] * 11)]})), 0)

    def test_validate_raises(self):
        with self.assertRaises(ValueError):
            validate_playbooks([sample_playbook(actions=["nope.nope"])])
        with self.assertRaises(ValueError):
            validate_playbooks([sample_playbook(), sample_playbook()])
        with self.assertRaises(ValueError):
            validate_playbooks("nope")
        validate_playbooks(None)  # group omitted is fine

    def test_match_exact_then_prefix(self):
        playbooks = load_playbooks({"playbooks": [
            sample_playbook(),
            {"id": "critical-prefix", "alert_type": "critical", "title": "Crit", "markdown": "x"},
        ]})
        self.assertEqual(match(playbooks, "service_failed")["id"], "service-failed")
        self.assertEqual(match(playbooks, "critical_disk_usage")["id"], "critical-prefix")
        self.assertIsNone(match(playbooks, "probe_failed"))
        self.assertIsNone(match(playbooks, None))

    def test_validate_config_accepts_playbooks(self):
        validate_config({"polling": {"fleet_seconds": 10}, "devices": [], "playbooks": [sample_playbook()]}, Path("."))


class PlaybookApiTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db = Database(f"{self._tmp.name}/db.sqlite")
        assert self.db.initialize()
        self.history = HistoryManager(self.db, {})
        self.state = PiNOCState()
        self.state.publish([DeviceState(id="pi", hostname="pi", friendly_name="Pi", online=True,
                                        collection_method="ssh")], replace=True)
        self.config = {
            "TESTING": True, "SECRET_KEY": "test-secret", "DATABASE": self.db,
            "PINOC_CONFIG": {
                "playbooks": [
                    sample_playbook(),
                    {"id": "critical-prefix", "alert_type": "critical", "title": "Critical prefix",
                     "markdown": "Prefix runbook"},
                ],
            },
        }
        self.app = create_app(self.state, self.config, self.history, None)
        self.client = self.app.test_client()

    def tearDown(self):
        actions = self.app.extensions.get("pinoc_actions")
        if actions:
            actions.stop()
        self._tmp.cleanup()

    def seed_alert(self, alert_type, resource="", state="active"):
        self.db.execute(
            "INSERT INTO alerts(device_id,alert_type,severity,message,fingerprint,opened_at,last_seen_at,state,metadata_json) "
            "VALUES(?,?,?,?,?,?,?,?,?)",
            ("pi", alert_type, "warning", f"{alert_type} happened", f"pi:{alert_type}:{resource}",
             iso(60), iso(30), state, json.dumps({"resource": resource})))

    def test_api_playbooks(self):
        payload = self.client.get("/api/playbooks").get_json()
        self.assertEqual([p["id"] for p in payload["playbooks"]], ["service-failed", "critical-prefix"])

    def test_alerts_attach_matching_playbook(self):
        self.seed_alert("service_failed", "ssh.service")
        self.seed_alert("critical_disk_usage", "/")
        self.seed_alert("probe_failed")
        rows = self.client.get("/api/alerts").get_json()["alerts"]
        by_type = {r["alert_type"]: r for r in rows}
        self.assertEqual(by_type["service_failed"]["playbook"]["id"], "service-failed")
        self.assertEqual(by_type["critical_disk_usage"]["playbook"]["id"], "critical-prefix")
        self.assertIsNone(by_type["probe_failed"]["playbook"])
        detail = self.client.get(f"/api/alerts/{by_type['service_failed']['alert_id']}").get_json()
        self.assertEqual(detail["playbook"]["id"], "service-failed")

    def test_token_scope_gating(self):
        security = self.app.extensions["pinoc_security"]
        security.create_user("person", "correct horse battery", "administrator")
        fleet = security.create_token("person", ["read:fleet"])
        alerts_only = security.create_token("person", ["read:alerts"])
        self.assertEqual(self.client.get("/api/playbooks", headers={"Authorization": "Bearer " + fleet}).status_code, 200)
        self.assertEqual(self.client.get("/api/playbooks", headers={"Authorization": "Bearer " + alerts_only}).status_code, 403)


class RunbookMarkdownXssTest(unittest.TestCase):
    @unittest.skipUnless(shutil.which("node"), "node not available")
    def test_markup_is_escaped_and_links_restricted(self):
        js_path = Path(__file__).resolve().parents[1] / "pinoc" / "web" / "static" / "app.js"
        probe = r"""const fs=require('fs');
eval(fs.readFileSync(PROBE_PATH,'utf8')+';globalThis.__P=PiNOC;');
const cases=JSON.parse(process.argv[1]);
let fail=0;
for(const input of cases){
 const out=globalThis.__P.runbookMarkdown(input);
 const problems=[];
 if(/<script/i.test(out)) problems.push('raw script');
 if(/<[^>]*on\w+=/.test(out.replace(/&lt;[\s\S]*?&gt;/g,'').replace(/<\/?(?:h4|p|ul|li|strong|a)[^>]*>/g,''))) problems.push('raw handler tag');
 for(const m of out.matchAll(/href="([^"]*)"/g)){
   if(!/^(?:https?:|\/(?!\/))/.test(m[1])) problems.push('bad scheme: '+m[1]);
   if(m[1].includes('"')) problems.push('quote in href');
 }
 if(problems.length){fail++;console.log('UNSAFE',JSON.stringify(input),problems.join(';'))}
 else console.log('SAFE',JSON.stringify(input));
}
process.exit(fail?1:0);
""".replace("PROBE_PATH", repr(str(js_path)))
        cases = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<a href='https://x' onclick='alert(1)'>c</a>",
            "## Head\n- item **bold** [ok](https://a.com/x) [bad](javascript:alert(2)) [rel](/page) [proto](//evil.com)",
            '[x](https://a.com" onclick="alert(1))',
            "[y](data:text/html,evil)",
            'text with "quotes" and backslash \\ and new\nlines',
            "a ** b ** c and [z](https://ok.example/path?x=1#frag)",
        ]
        result = subprocess.run(["node", "-e", probe, json.dumps(cases)], capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.count("SAFE"), len(cases))


if __name__ == "__main__":
    unittest.main()
