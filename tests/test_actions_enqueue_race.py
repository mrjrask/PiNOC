"""enqueue()'s "one pending action per device" check must be atomic with
the INSERT that follows it -- two concurrent requests must not both pass
the check before either has recorded its job."""
import subprocess
import threading
import time
import unittest
from tempfile import TemporaryDirectory

from pinoc.actions import ActionDispatcher, ActionError
from pinoc.database import Database
from pinoc.models import DeviceState
from pinoc.state import PiNOCState


def fake_runner(args, **kwargs):
    return subprocess.CompletedProcess(args, 0, "ok", "")


class EnqueueRaceTest(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = Database(self.tmp.name + "/pinoc.db")
        self.assertTrue(self.db.initialize())
        self.state = PiNOCState()
        self.state.publish([DeviceState(id="pi", hostname="pi", friendly_name="Pi", online=True,
                                        address="host", collection_method="ssh")], replace=True)
        self.dispatcher = ActionDispatcher(self.db, self.state, runner=fake_runner)
        self.addCleanup(self.dispatcher.stop)

    def test_concurrent_enqueue_cannot_both_pass_the_conflict_check(self):
        # Widen the window between validate()'s conflict-check SELECT and
        # enqueue()'s INSERT so the race manifests reliably in a test
        # instead of depending on unlucky thread scheduling.
        real_scalar = self.db.scalar
        def slow_scalar(sql, params=()):
            result = real_scalar(sql, params)
            if "action_jobs" in sql and "status IN" in sql:
                time.sleep(0.05)
            return result
        self.db.scalar = slow_scalar

        results = {}
        def run(name, action):
            try:
                self.dispatcher.enqueue(action, "pi", None, "op", "operator")
                results[name] = "ok"
            except ActionError as exc:
                results[name] = str(exc)

        t1 = threading.Thread(target=run, args=("a", "device.reboot"))
        t2 = threading.Thread(target=run, args=("b", "device.shutdown"))
        t1.start()
        time.sleep(0.01)
        t2.start()
        t1.join(5)
        t2.join(5)

        outcomes = list(results.values())
        self.assertEqual(len(outcomes), 2)
        self.assertEqual(outcomes.count("ok"), 1)
        self.assertEqual(sum("conflicting" in o for o in outcomes if o != "ok"), 1)
        # Exactly one job was ever recorded for this device -- the rejected
        # enqueue() call never inserted a row at all. (Checking *pending*
        # rows here would itself race against the background worker, which
        # can finish the fake, instant "succeeded" job before this runs.)
        total = real_scalar("SELECT COUNT(*) FROM action_jobs WHERE device_id='pi'")
        self.assertEqual(total, 1)


if __name__ == "__main__":
    unittest.main()
