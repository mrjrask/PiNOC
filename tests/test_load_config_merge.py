"""load_config() must deep-merge config.json over DEFAULT_CONFIG so a
partial nested override doesn't drop its sibling defaults entirely."""
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import pi_noc


class LoadConfigDeepMergeTest(unittest.TestCase):
    def test_partial_nested_override_keeps_sibling_defaults(self):
        defaults = {
            "web_port": 8088,
            "polling": {"fleet_seconds": 10, "local_seconds": 10, "network_seconds": 10},
        }
        with TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "config.json"
            config_path.write_text(json.dumps({"polling": {"fleet_seconds": 5}}))
            with patch.object(pi_noc, "DEFAULT_CONFIG", defaults), \
                 patch.object(pi_noc, "CONFIG_FILE", config_path):
                config = pi_noc.load_config()
        self.assertEqual(config["polling"],
                         {"fleet_seconds": 5, "local_seconds": 10, "network_seconds": 10})
        self.assertEqual(config["web_port"], 8088)

    def test_top_level_override_still_works(self):
        defaults = {"web_port": 8088, "polling": {"fleet_seconds": 10}}
        with TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "config.json"
            config_path.write_text(json.dumps({"web_port": 9999}))
            with patch.object(pi_noc, "DEFAULT_CONFIG", defaults), \
                 patch.object(pi_noc, "CONFIG_FILE", config_path):
                config = pi_noc.load_config()
        self.assertEqual(config["web_port"], 9999)
        self.assertEqual(config["polling"], {"fleet_seconds": 10})

    def test_doubly_nested_override_still_merges_correctly(self):
        defaults = {"remote_temp_monitor": {"enabled": True, "poll_seconds": 10, "timeout_seconds": 3}}
        with TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "config.json"
            config_path.write_text(json.dumps({"remote_temp_monitor": {"poll_seconds": 30}}))
            with patch.object(pi_noc, "DEFAULT_CONFIG", defaults), \
                 patch.object(pi_noc, "CONFIG_FILE", config_path):
                config = pi_noc.load_config()
        self.assertEqual(config["remote_temp_monitor"],
                         {"enabled": True, "poll_seconds": 30, "timeout_seconds": 3})


if __name__ == "__main__":
    unittest.main()
