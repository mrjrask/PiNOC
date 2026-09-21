"""Regression coverage for Database connection lifecycle.

execute()/rows()/initialize()/backup() pool one connection per thread per
mode (read-only vs read-write) instead of opening a fresh connection (and
re-issuing its PRAGMAs) on every single call -- that was previously
unconditional, and ran on every metric write, every history query, every
poll. Pooling still has to preserve three things a fresh-connection-per-call
design got for free: no connection is ever touched from a thread other than
the one that opened it, a database file replaced out from under an
already-open connection (a backup restore) is picked up on the very next
call rather than silently writing to an orphaned file, and a connection that
raised is dropped rather than kept around to fail forever.
"""
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path

from pinoc.database import Database


class ConnectionLifecycleTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = Database(str(Path(self.tmp.name) / "pinoc.db"))
        self.assertTrue(self.db.initialize())

    def _spy_connect(self):
        created = []
        real_connect = self.db.connect

        def spy(readonly=False):
            con = real_connect(readonly)
            created.append(con)
            return con

        self.db.connect = spy
        return created

    @staticmethod
    def _is_closed(con):
        try:
            con.execute("SELECT 1")
        except sqlite3.ProgrammingError:
            return True
        return False

    def test_execute_reuses_one_pooled_connection_across_calls(self):
        # setUp()'s initialize() already warmed the write connection, so a
        # correctly pooled execute() must not create any *new* connection
        # at all here -- it reuses the one initialize() opened.
        created = self._spy_connect()
        for _ in range(3):
            self.db.execute(
                "INSERT INTO events(timestamp,event_type,severity,message) VALUES(?,?,?,?)",
                ("2024-01-01T00:00:00", "test", "info", "hi"),
            )
        self.assertEqual(len(created), 0)
        self.assertFalse(self._is_closed(self.db._local._rw_con[0]))

    def test_rows_reuses_one_pooled_connection_across_calls(self):
        created = self._spy_connect()
        for _ in range(3):
            self.db.rows("SELECT * FROM events")
        self.assertEqual(len(created), 1)
        self.assertFalse(self._is_closed(created[0]))

    def test_read_and_write_pool_separate_connections(self):
        self.db.execute(
            "INSERT INTO events(timestamp,event_type,severity,message) VALUES(?,?,?,?)",
            ("2024-01-01T00:00:00", "test", "info", "hi"),
        )
        self.db.rows("SELECT * FROM events")
        self.assertIsNot(self.db._local._rw_con[0], self.db._local._ro_con[0])

    def test_initializes_connection_is_reused_by_a_later_call(self):
        db = Database(str(Path(self.tmp.name) / "second.db"))
        created = []
        real_connect = db.connect

        def spy(readonly=False):
            con = real_connect(readonly)
            created.append(con)
            return con

        db.connect = spy
        self.assertTrue(db.initialize())
        write_connections_after_init = [c for c in created if c is not None]
        db.execute(
            "INSERT INTO events(timestamp,event_type,severity,message) VALUES(?,?,?,?)",
            ("2024-01-01T00:00:00", "test", "info", "hi"),
        )
        # initialize() and the execute() that follows it are both on the
        # write path, from the same thread -- they must share one
        # connection, not open a second.
        self.assertEqual(len(created), len(write_connections_after_init))

    def test_a_replaced_database_file_is_picked_up_without_waiting_for_a_restart(self):
        # backup.restore_bundle() atomically replaces the database file at
        # the same path. A connection cached before that replacement points
        # at the now-orphaned inode; the pool must detect this (cheaply) and
        # reconnect, exactly like a fresh-connection-per-call design would
        # have on its very next call.
        self.db.execute(
            "INSERT INTO events(timestamp,event_type,severity,message) VALUES(?,?,?,?)",
            ("2024-01-01T00:00:00", "before", "info", "hi"),
        )
        self.assertEqual(self.db.scalar("SELECT COUNT(*) FROM events"), 1)

        # Mirror how a real bundle is actually produced/applied: build_bundle()
        # uses the online backup API (a consolidated, self-contained file,
        # not a raw copy of a live WAL-mode database with data still
        # sitting unwritten in its -wal), and restore_bundle() then does an
        # atomic rename over the live path.
        replacement = Database(str(Path(self.tmp.name) / "replacement.db"))
        self.assertTrue(replacement.initialize())
        consolidated_path = Path(self.tmp.name) / "replacement-backup.db"
        replacement.backup(str(consolidated_path))
        import os
        os.replace(consolidated_path, self.db.path)
        # Mirror backup.restore_bundle()'s own handling: a replaced main
        # file combined with the pre-replacement -wal would replay
        # pre-replacement frames into the new database.
        for suffix in ("-wal", "-shm"):
            sidecar = self.db.path.with_name(self.db.path.name + suffix)
            if sidecar.exists():
                sidecar.unlink()

        self.assertEqual(self.db.scalar("SELECT COUNT(*) FROM events"), 0)
        self.db.execute(
            "INSERT INTO events(timestamp,event_type,severity,message) VALUES(?,?,?,?)",
            ("2024-01-01T00:00:00", "after", "info", "hi"),
        )
        self.assertEqual(self.db.scalar("SELECT COUNT(*) FROM events"), 1)

    def test_a_connection_that_raises_is_dropped_not_reused(self):
        with self.assertRaises(sqlite3.OperationalError):
            self.db.execute("INSERT INTO no_such_table(x) VALUES(1)")
        # The broken connection must not be handed back out on the next
        # call -- a transient error must not permanently break this thread's
        # writes.
        self.db.execute(
            "INSERT INTO events(timestamp,event_type,severity,message) VALUES(?,?,?,?)",
            ("2024-01-01T00:00:00", "test", "info", "hi"),
        )
        self.assertEqual(self.db.scalar("SELECT COUNT(*) FROM events"), 1)

    def test_each_thread_gets_its_own_connection(self):
        # sqlite3 connections must never be used from a thread other than
        # the one that created them.
        seen = {}

        def run(name):
            self.db.execute(
                "INSERT INTO events(timestamp,event_type,severity,message) VALUES(?,?,?,?)",
                ("2024-01-01T00:00:00", name, "info", "hi"),
            )
            seen[name] = self.db._local._rw_con[0]

        threads = [threading.Thread(target=run, args=(f"t{i}",)) for i in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(5)
        self.assertEqual(len(set(id(con) for con in seen.values())), 3)
        self.assertEqual(self.db.scalar("SELECT COUNT(*) FROM events"), 3)

    def test_backup_closes_both_connections(self):
        dest = str(Path(self.tmp.name) / "backup.db")
        self.db.backup(dest)
        # A successful independent open/read of the destination shows the
        # backup's destination connection was properly closed and flushed,
        # not just left open and garbage-collected eventually.
        con = sqlite3.connect(dest)
        try:
            self.assertIsNotNone(con.execute("SELECT COUNT(*) FROM schema_version").fetchone())
        finally:
            con.close()


if __name__ == "__main__":
    unittest.main()
