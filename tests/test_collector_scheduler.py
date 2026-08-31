import threading
import time
import unittest

from pinoc.collectors.scheduler import CollectionScheduler, CollectionTask


class CollectorSchedulerTest(unittest.TestCase):
    def test_one_failed_task_does_not_block_another(self):
        completed = threading.Event()

        def fail():
            raise RuntimeError("expected failure")

        scheduler = CollectionScheduler([
            CollectionTask("failed", 60, fail),
            CollectionTask("healthy", 60, completed.set),
        ])
        scheduler.start()
        try:
            self.assertTrue(completed.wait(2))
        finally:
            scheduler.stop()

    def test_refresh_runs_task_before_interval_expires(self):
        calls = []
        second_call = threading.Event()

        def collect():
            calls.append(time.monotonic())
            if len(calls) >= 2:
                second_call.set()

        scheduler = CollectionScheduler([CollectionTask("refreshable", 60, collect)])
        scheduler.start()
        try:
            deadline = time.monotonic() + 2
            while not calls and time.monotonic() < deadline:
                time.sleep(0.01)
            scheduler.refresh()
            self.assertTrue(second_call.wait(2))
        finally:
            scheduler.stop()


if __name__ == "__main__":
    unittest.main()
