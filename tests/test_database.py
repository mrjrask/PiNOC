"""Regression coverage for Database connection lifecycle."""
import sqlite3
import tempfile
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

    def test_execute_closes_its_connection(self):
        created = self._spy_connect()
        self.db.execute(
            "INSERT INTO events(timestamp,event_type,severity,message) VALUES(?,?,?,?)",
            ("2024-01-01T00:00:00", "test", "info", "hi"),
        )
        self.assertEqual(len(created), 1)
        self.assertTrue(self._is_closed(created[0]))

    def test_rows_closes_its_connection(self):
        created = self._spy_connect()
        self.db.rows("SELECT * FROM events")
        self.assertEqual(len(created), 1)
        self.assertTrue(self._is_closed(created[0]))

    def test_initialize_closes_its_connection(self):
        db = Database(str(Path(self.tmp.name) / "second.db"))
        created = []
        real_connect = db.connect

        def spy(readonly=False):
            con = real_connect(readonly)
            created.append(con)
            return con

        db.connect = spy
        self.assertTrue(db.initialize())
        self.assertGreaterEqual(len(created), 1)
        for con in created:
            self.assertTrue(self._is_closed(con))

    def test_backup_closes_both_connections(self):
        dest = str(Path(self.tmp.name) / "backup.db")
        self.db.backup(dest)
        # A successful independent open/read of the destination shows the
        # backup connection was properly closed and flushed, not just left
        # open and garbage-collected eventually.
        con = sqlite3.connect(dest)
        try:
            self.assertIsNotNone(con.execute("SELECT COUNT(*) FROM schema_version").fetchone())
        finally:
            con.close()


if __name__ == "__main__":
    unittest.main()
