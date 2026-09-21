"""atomic_save() must validate config/devices.json against the directory
that actually contains config.json, not its parent."""
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from pinoc.config_store import atomic_save


class AtomicSaveDeviceValidationTest(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.instance_dir = Path(self.tmp.name)
        (self.instance_dir / "config").mkdir()
        self.config_path = self.instance_dir / "config.json"

    def test_invalid_devices_file_is_rejected(self):
        # Missing hostname/address on an "ssh" device is invalid.
        (self.instance_dir / "config" / "devices.json").write_text(
            json.dumps({"devices": [{"collection_method": "ssh"}]}))
        with self.assertRaises(ValueError):
            atomic_save(self.config_path, {"devices": [], "polling": {"fleet_seconds": 10}})
        self.assertFalse(self.config_path.exists())

    def test_valid_devices_file_is_accepted_and_saved(self):
        (self.instance_dir / "config" / "devices.json").write_text(
            json.dumps({"devices": [{"id": "pi", "hostname": "pi.local",
                                       "collection_method": "ssh"}]}))
        atomic_save(self.config_path, {"devices": [], "polling": {"fleet_seconds": 10}})
        self.assertTrue(self.config_path.exists())


if __name__ == "__main__":
    unittest.main()
