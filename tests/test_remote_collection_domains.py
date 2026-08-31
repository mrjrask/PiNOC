import os
import unittest

os.environ["PINOC_DISPLAY_ENABLED"] = "0"

from pi_noc import build_remote_script


class RemoteCollectionDomainsTest(unittest.TestCase):
    def test_health_script_does_not_execute_storage_or_smb_checks(self):
        script = build_remote_script(False, False, False)
        self.assertNotIn("disk_status D0", script)
        self.assertNotIn("MDSTAT_B64", script)
        self.assertNotIn("SMB_BIN", script)

    def test_storage_script_includes_disks_and_raid_only(self):
        script = build_remote_script(True, True, False)
        self.assertIn("disk_status D0", script)
        self.assertIn("MDSTAT_B64", script)
        self.assertNotIn("SMB_BIN", script)

    def test_service_script_includes_smb_only(self):
        script = build_remote_script(False, False, True)
        self.assertNotIn("disk_status D0", script)
        self.assertNotIn("MDSTAT_B64", script)
        self.assertIn("SMB_BIN", script)


if __name__ == "__main__":
    unittest.main()
