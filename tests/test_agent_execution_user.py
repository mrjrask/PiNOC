"""A workspace's execution_user must actually be enforced, not silently
ignored -- this unprivileged agent cannot switch OS users, so a mismatch
must fail the job loudly instead of running it under the agent's own
identity."""
import os
import pwd
import unittest

from pinoc_agent import Executor


def base_job(job_id, root, execution_user=None):
    ws = {"path": str(root), "artifact_patterns": [], "services": []}
    if execution_user is not None:
        ws["execution_user"] = execution_user
    return {"job_id": job_id, "job_type": "command", "workspace": ws,
            "argv": ["python3", "-c", "print('ran')"], "environment": {}, "request": {},
            "timeout_seconds": 5, "output_limit_bytes": 1024, "file_limit_bytes": 1024,
            "artifact_limits": {"count": 1, "file_bytes": 10, "total_bytes": 10}}


class ExecutionUserTest(unittest.TestCase):
    def setUp(self):
        self.current_user = pwd.getpwuid(os.getuid()).pw_name

    def test_mismatched_execution_user_fails_without_running_anything(self, tmp_path=None):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            job = base_job("mismatch", tmp, execution_user="definitely-not-" + self.current_user)
            result = Executor().execute(job)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["error_type"], "invalid_request")
        self.assertIn("execution_user", result["stderr"])
        self.assertEqual(result["stdout"], "")  # the command never ran

    def test_matching_execution_user_runs_normally(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            job = base_job("match", tmp, execution_user=self.current_user)
            result = Executor().execute(job)
        self.assertEqual(result["status"], "succeeded")
        self.assertIn("ran", result["stdout"])

    def test_unset_execution_user_runs_normally(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            job = base_job("unset", tmp)
            result = Executor().execute(job)
        self.assertEqual(result["status"], "succeeded")
        self.assertIn("ran", result["stdout"])


if __name__ == "__main__":
    unittest.main()
