"""A leaked agents.credential_hash value must not be directly usable as an
HMAC signing key -- the whole point of encrypting agent credentials at rest
instead of hashing them (a hash used directly as the verification key gives
a database-only leak everything needed to forge signed agent requests)."""
import hashlib
import hmac
import time
import unittest
from tempfile import TemporaryDirectory

from pinoc.database import Database
from pinoc.development import DevelopmentGateway, DevError, PROTOCOL_VERSION, hash_token


class CredentialAtRestTest(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = Database(self.tmp.name + "/pinoc.db")
        self.assertTrue(self.db.initialize())
        self.gw = DevelopmentGateway(self.db, self.tmp.name + "/jobs", {}, "the-app-secret-key")

    def _enroll(self):
        code = self.gw.enrollment_code("pi", "admin")
        return self.gw.enroll({
            "enrollment_code": code, "hostname": "mock", "model": "Pi",
            "architecture": "aarch64", "agent_version": "1.0.0",
            "protocol_version": PROTOCOL_VERSION, "capabilities": {},
        })

    def test_stored_credential_hash_is_not_the_raw_hmac_key(self):
        answer = self._enroll()
        stored = self.db.scalar(
            "SELECT credential_hash FROM agents WHERE agent_id=?", (answer["agent_id"],))
        # The old bug: hash_token(raw_secret) was stored *and* used directly
        # as the HMAC key. Using the raw stored column value as that key must
        # no longer produce a valid signature.
        body = b"{}"
        stamp = str(int(time.time()))
        nonce = "attacker-nonce"
        digest = hashlib.sha256(body).hexdigest()
        message = f"{answer['agent_id']}\n{stamp}\n{nonce}\n{digest}".encode()
        try:
            forged_key = bytes.fromhex(stored)
        except ValueError:
            forged_key = stored.encode()  # not even valid hex anymore
        forged_signature = hmac.new(forged_key, message, hashlib.sha256).hexdigest()
        with self.assertRaises(DevError):
            self.gw.authenticate_agent(answer["agent_id"], stamp, nonce, body, forged_signature)

    def test_stored_credential_hash_is_not_plain_sha256_of_the_secret(self):
        answer = self._enroll()
        stored = self.db.scalar(
            "SELECT credential_hash FROM agents WHERE agent_id=?", (answer["agent_id"],))
        self.assertNotEqual(stored, hash_token(answer["credential"]))

    def test_enroll_sign_and_authenticate_round_trip_still_works(self):
        answer = self._enroll()
        body = b"{}"
        stamp = str(int(time.time()))
        nonce = "legit-nonce"
        signature = DevelopmentGateway.sign(answer["agent_id"], answer["credential"], stamp, nonce, body)
        row = self.gw.authenticate_agent(answer["agent_id"], stamp, nonce, body, signature)
        self.assertEqual(row["device_id"], "pi")

    def test_rotate_reencrypts_and_invalidates_the_old_credential(self):
        answer = self._enroll()
        new_credential = self.gw.rotate(answer["agent_id"])
        self.assertNotEqual(new_credential, answer["credential"])
        body = b"{}"
        stamp = str(int(time.time()))
        old_sig = DevelopmentGateway.sign(answer["agent_id"], answer["credential"], stamp, "n1", body)
        with self.assertRaises(DevError):
            self.gw.authenticate_agent(answer["agent_id"], stamp, "n1", body, old_sig)
        new_sig = DevelopmentGateway.sign(answer["agent_id"], new_credential, stamp, "n2", body)
        self.gw.authenticate_agent(answer["agent_id"], stamp, "n2", body, new_sig)

    def test_garbage_credential_hash_is_rejected_cleanly_not_a_crash(self):
        answer = self._enroll()
        self.db.execute("UPDATE agents SET credential_hash='not-a-fernet-token' WHERE agent_id=?",
                        (answer["agent_id"],))
        body = b"{}"
        stamp = str(int(time.time()))
        signature = DevelopmentGateway.sign(answer["agent_id"], answer["credential"], stamp, "n3", body)
        with self.assertRaises(DevError):
            self.gw.authenticate_agent(answer["agent_id"], stamp, "n3", body, signature)


if __name__ == "__main__":
    unittest.main()
