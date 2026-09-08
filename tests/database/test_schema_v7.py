from __future__ import annotations

import contextlib
import shutil
import sqlite3
import unittest
from unittest import mock

from syz_sage.database import SCHEMA_VERSION, Database, schema_v7
from tests.database.support import DatabaseFixture


class SchemaV7Tests(DatabaseFixture, unittest.TestCase):
    def make_schema6(self) -> None:
        with Database(self.database_path) as database:
            self.import_fixture(database)
            report = self.legacy / "artifacts/reports/extid-alpha123.txt"
            report.write_text(
                "BUG: KASAN: out-of-bounds in alpha\nWrite of size 4 at addr 0xffff\n"
            )
            database.ingest_files(self.legacy)
            database.connection.execute("DROP VIEW current_bug_patch_metrics")
            database.connection.execute("DROP TABLE snapshot_bug_characteristics")
            database.connection.execute("DROP TABLE patch_metric_coverage")
            database.connection.execute("PRAGMA user_version=6")

    def stored_rows(self) -> dict[str, list[tuple]]:
        with contextlib.closing(sqlite3.connect(self.database_path)) as connection:
            tables = [
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' "
                    "AND name NOT LIKE 'sqlite_%' "
                    "AND name NOT IN ('snapshot_bug_characteristics','patch_metric_coverage')"
                )
            ]
            return {
                table: connection.execute(f'SELECT * FROM "{table}" ORDER BY rowid').fetchall()
                for table in tables
            }

    def test_migration_classifies_all_retained_evidence_without_source_files(self) -> None:
        self.make_schema6()
        before = self.stored_rows()
        shutil.rmtree(self.legacy)
        with Database(self.database_path) as database:
            rows = database.connection.execute(
                "SELECT ch.family,ch.access_mode FROM snapshot_bug_characteristics ch "
                "JOIN bugs b ON b.id=ch.bug_id WHERE b.key='extid-alpha123' "
                "ORDER BY ch.snapshot_id"
            ).fetchall()
            self.assertEqual(
                [tuple(row) for row in rows],
                [("use-after-free", "read"), ("out-of-bounds", "write")],
            )
            bug = database.get_bug("extid-alpha123")
            self.assertEqual(bug["family"], "out-of-bounds")
            self.assertEqual(bug["bug_type"], "kasan")
            self.assertEqual(database.status()["schema_version"], SCHEMA_VERSION)
            self.assertTrue(database.health_check()["ok"])
            changes = database.connection.total_changes
            database.initialize()
            self.assertEqual(database.connection.total_changes, changes)
        self.assertEqual(self.stored_rows(), before)

    def test_failed_classification_rolls_back_schema_and_prior_snapshot_rows(self) -> None:
        self.make_schema6()
        before = self.stored_rows()
        original = schema_v7.index_snapshot
        calls = 0

        def fail_second(*args: object, **kwargs: object) -> None:
            nonlocal calls
            calls += 1
            if calls == 2:
                raise RuntimeError("planned classifier failure")
            original(*args, **kwargs)

        with (
            mock.patch.object(schema_v7, "index_snapshot", side_effect=fail_second),
            self.assertRaisesRegex(RuntimeError, "planned classifier failure"),
            Database(self.database_path),
        ):
            pass
        with contextlib.closing(sqlite3.connect(self.database_path)) as connection:
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 6)
            self.assertEqual(
                connection.execute(
                    "SELECT name FROM sqlite_master WHERE name IN "
                    "('snapshot_bug_characteristics','current_bug_patch_metrics',"
                    "'patch_metric_coverage')"
                ).fetchall(),
                [],
            )
        self.assertEqual(self.stored_rows(), before)

    def test_read_only_old_schema_does_not_migrate(self) -> None:
        self.make_schema6()
        before = self.database_path.read_bytes(), self.database_path.stat().st_mtime_ns
        with (
            self.assertRaisesRegex(RuntimeError, "ss migrate"),
            Database(self.database_path, read_only=True),
        ):
            pass
        self.assertEqual(
            (self.database_path.read_bytes(), self.database_path.stat().st_mtime_ns), before
        )

    def test_check_detects_missing_classification_without_repairing_it(self) -> None:
        with Database(self.database_path) as database:
            self.import_fixture(database)
            database.connection.execute(
                "DELETE FROM snapshot_bug_characteristics WHERE bug_id="
                "(SELECT id FROM bugs WHERE key='id-beta456')"
            )
            changes = database.connection.total_changes
            result = database.health_check()
            self.assertFalse(result["ok"])
            self.assertIn("missing or stale bug characteristics: 1", result["snapshot_errors"])
            self.assertEqual(database.connection.total_changes, changes)


if __name__ == "__main__":
    unittest.main()
