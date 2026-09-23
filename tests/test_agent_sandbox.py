import unittest
from pathlib import Path
from unittest import mock

from pinoc_agent import Executor


class AgentSandboxTest(unittest.TestCase):
    def test_workspace_jobs_are_wrapped_with_bubblewrap(self):
        root = Path("/tmp/pi-noc-test-workspace")
        with mock.patch("pinoc_agent.shutil.which", return_value="/usr/bin/bwrap"):
            argv = Executor.sandbox_argv(["python3", "-c", "print('ok')"], root, True)
        self.assertEqual(argv[0], "/usr/bin/bwrap")
        self.assertIn("--bind", argv)
        self.assertIn(str(root), argv)
        self.assertIn("/workspace", argv)
        self.assertIn("--cap-drop", argv)
        self.assertEqual(argv[-4:], ["--", "python3", "-c", "print('ok')"])

    def test_production_sandbox_fails_closed_when_bubblewrap_is_missing(self):
        with mock.patch("pinoc_agent.shutil.which", return_value=None):
            with self.assertRaisesRegex(ValueError, "bubblewrap"):
                Executor.sandbox_argv(["git", "status"], Path("/tmp/workspace"), True)

    def test_read_only_system_queries_can_run_without_workspace_sandbox(self):
        argv = ["systemctl", "show", "demo.service"]
        self.assertEqual(Executor.sandbox_argv(argv, Path("/tmp/workspace"), False), argv)


if __name__ == "__main__":
    unittest.main()
