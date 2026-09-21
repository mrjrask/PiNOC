"""Coverage for SharedSnapshotCoordinator._publish()'s copy strategy.

_publish() runs after every one of the coordinator's 9 independently
polled collectors, so a full copy.deepcopy() of the whole snapshot tree
on every call is wasteful. It only needs to decouple the one field a
*later* collector could mutate in place on the *same* object a previous
publish just handed off (`remote`); every other field is always
reassigned wholesale by its own collect_* method, so sharing it by
reference is safe.
"""
import unittest
from unittest.mock import patch

import pi_noc
from pinoc.state import PiNOCState


def make_coordinator():
    with patch.object(pi_noc, "load_devices", return_value=([], [])), \
         patch.object(pi_noc, "read_env_value", return_value=""):
        return pi_noc.SharedSnapshotCoordinator(PiNOCState())


class PublishCopyStrategyTest(unittest.TestCase):
    def test_fields_that_are_always_reassigned_are_shared_not_copied(self):
        coordinator = make_coordinator()
        coordinator._publish()
        published = coordinator.state._legacy_snapshot
        self.assertIs(published.local, coordinator.snapshot.local)
        self.assertIs(published.vpn, coordinator.snapshot.vpn)
        self.assertIs(published.sensor, coordinator.snapshot.sensor)
        self.assertIs(published.temp_devices, coordinator.snapshot.temp_devices)

    def test_remote_mutated_in_place_after_publish_does_not_corrupt_it(self):
        # collect_remote_health/services/storage mutate
        # self.snapshot.remote's attributes in place rather than
        # reassigning it, so a previously published copy must stay
        # decoupled from that later mutation.
        coordinator = make_coordinator()
        coordinator.snapshot.remote.online = True
        coordinator.snapshot.remote.error = ""
        coordinator._publish()
        published = coordinator.state._legacy_snapshot

        coordinator.snapshot.remote.online = False
        coordinator.snapshot.remote.error = "boom"

        self.assertTrue(published.remote.online)
        self.assertEqual(published.remote.error, "")
        self.assertIsNot(published.remote, coordinator.snapshot.remote)

    def test_public_legacy_snapshot_reader_reflects_the_published_remote_state(self):
        coordinator = make_coordinator()
        coordinator.snapshot.remote.online = True
        coordinator._publish()
        self.assertTrue(coordinator.state.legacy_snapshot().remote.online)


if __name__ == "__main__":
    unittest.main()
