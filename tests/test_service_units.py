"""Coverage for the shipped systemd unit files' sandboxing directives.

pi-noc.service (the primary, network-facing, higher-privilege process -- it
holds SSH keys, a WireGuard sudoers rule, and serves authentication) used to
set no sandboxing directives at all, unlike pinoc-agent.service. It must not
set NoNewPrivileges=yes: ActionDispatcher's rescue/service/wireguard.restart
handlers and the legacy collect_vpn_status() VPN monitor both shell out to
"sudo -n ..." on this host, and NoNewPrivileges would silently break every
one of those (sudo cannot elevate under it).
"""
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def parse_unit(name: str) -> dict:
    directives: dict = {}
    for line in (REPO_ROOT / name).read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("["):
            continue
        if "=" in line:
            key, value = line.split("=", 1)
            directives[key.strip()] = value.strip()
    return directives


class PiNocServiceHardeningTest(unittest.TestCase):
    def setUp(self):
        self.directives = parse_unit("pi-noc.service")

    def test_gains_the_same_baseline_sandboxing_as_the_agent_service(self):
        self.assertEqual(self.directives.get("PrivateTmp"), "yes")
        self.assertEqual(self.directives.get("ProtectSystem"), "full")
        self.assertEqual(self.directives.get("LockPersonality"), "yes")
        self.assertEqual(self.directives.get("RestrictSUIDSGID"), "yes")

    def test_protect_home_stays_disabled_for_its_own_working_directory_and_ssh_keys(self):
        self.assertEqual(self.directives.get("ProtectHome"), "false")

    def test_no_new_privileges_stays_disabled_so_local_sudo_actions_keep_working(self):
        # Unlike pinoc-agent.service, this must never be "yes": it would
        # silently break every sudo -n ... local action/VPN-status call.
        self.assertEqual(self.directives.get("NoNewPrivileges"), "no")


class AgentServiceUnaffectedTest(unittest.TestCase):
    def test_still_hardened_as_before(self):
        directives = parse_unit("pinoc-agent.service")
        self.assertEqual(directives.get("NoNewPrivileges"), "yes")
        self.assertEqual(directives.get("PrivateTmp"), "yes")
        self.assertEqual(directives.get("ProtectSystem"), "full")


if __name__ == "__main__":
    unittest.main()
