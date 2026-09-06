from __future__ import annotations

import sqlite3
import unittest

from syz_sage.database import Database
from tests.database.support import DatabaseFixture
from tests.support import (
    ALPHA_HASH,
)


class DatabaseLifecycleTests(DatabaseFixture, unittest.TestCase):
    def test_initialize_creates_parent_and_database(self) -> None:
        with Database(self.database_path) as database:
            database.initialize()

        self.assertTrue(self.database_path.is_file())
        self.assertGreater(self.database_path.stat().st_size, 0)

    def test_database_persists_after_reopening(self) -> None:
        with Database(self.database_path) as database:
            self.import_fixture(database)

        with Database(self.database_path) as database:
            database.initialize()
            bug = database.get_bug("extid-alpha123")
            status = database.status()

        self.assertEqual(status["bugs"], 2)
        self.assertEqual(bug["fixes"][0]["hash"], ALPHA_HASH)

    def test_initialize_rejects_non_pristine_or_incomplete_schema(self) -> None:
        non_pristine = self.root / "non-pristine.sqlite3"
        connection = sqlite3.connect(non_pristine)
        connection.execute("CREATE TABLE existing(value TEXT)")
        connection.close()
        database = Database(non_pristine)
        with self.assertRaisesRegex(RuntimeError, "non-pristine"):
            database.initialize()
        database.close()

        incomplete = self.root / "incomplete.sqlite3"
        connection = sqlite3.connect(incomplete)
        connection.execute("PRAGMA user_version = 1")
        connection.close()
        database = Database(incomplete)
        with self.assertRaisesRegex(RuntimeError, "incomplete or incompatible"):
            database.initialize()
        database.close()


if __name__ == "__main__":
    unittest.main()
