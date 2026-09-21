"""Coverage for uninstall_agent.sh's server-side credential revocation.

uninstall_agent.sh previously only removed local files/the agent user and
disabled the systemd unit -- it never revoked the agent's credential
server-side (DELETE /api/v1/dev/agents/<agent_id>/credential), so a
decommissioned device's extracted /etc/pinoc-agent/config.json credential
remained valid indefinitely, and the script's own success message implied
removal was complete.

The full script requires root and performs real systemctl/userdel/rm
operations, so it isn't executed end-to-end here (matching this repo's
existing installer test style in test_installer_dependencies.py, which
checks script content rather than running it). The one genuinely new,
side-effect-free piece of logic -- extracting agent_id from the agent's
config.json -- is exercised directly as a subprocess, since that's easy to
get subtly wrong (a bad JSON file, a missing key) without it being obvious.
"""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = (Path(__file__).parents[1] / "uninstall_agent.sh").read_text(encoding="utf-8")


def extract_agent_id(config_path) -> str:
    """Run the exact Python one-liner uninstall_agent.sh uses, against a
    real file, to prove it behaves as the script assumes."""
    snippet = (
        "import json,sys\n"
        "try:\n"
        f"    print(json.load(open({str(config_path)!r})).get('agent_id') or '')\n"
        "except Exception:\n"
        "    pass\n"
    )
    result = subprocess.run([sys.executable, "-c", snippet], capture_output=True, text=True, timeout=10)
    return result.stdout.strip()


class AgentIdExtractionTest(unittest.TestCase):
    def test_reads_agent_id_from_a_real_enrolled_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            path.write_text(json.dumps({"server": "https://pinoc.example", "agent_id": "a-123",
                                        "credential": "secret"}))
            self.assertEqual(extract_agent_id(path), "a-123")

    def test_missing_or_malformed_config_yields_empty_not_a_crash(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "nope.json"
            self.assertEqual(extract_agent_id(missing), "")
            malformed = Path(tmp) / "bad.json"
            malformed.write_text("{not json")
            self.assertEqual(extract_agent_id(malformed), "")

    def test_config_without_agent_id_yields_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            path.write_text(json.dumps({"server": "https://pinoc.example"}))
            self.assertEqual(extract_agent_id(path), "")


class ScriptContentTest(unittest.TestCase):
    def test_calls_the_credential_revoke_endpoint(self):
        self.assertIn("/api/v1/dev/agents/$AGENT_ID/credential", SCRIPT)
        self.assertIn("-X DELETE", SCRIPT)
        self.assertIn("Authorization: Bearer $TOKEN", SCRIPT)

    def test_warns_loudly_when_revocation_did_not_happen(self):
        # The previous success message implied removal was complete with
        # no mention of the still-valid server-side credential.
        self.assertIn("IMPORTANT", SCRIPT)
        self.assertIn("NOT revoked", SCRIPT)

    def test_confirms_revocation_when_it_did_happen(self):
        self.assertIn("revoked server-side", SCRIPT)


if __name__ == "__main__":
    unittest.main()
