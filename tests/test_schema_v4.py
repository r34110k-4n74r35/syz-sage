from __future__ import annotations

import contextlib
import hashlib
import sqlite3
import unittest
from pathlib import Path
from unittest import mock

from syz_sage import location_store, schema_v3, schema_v4
from syz_sage.database import _SCHEMA_V1, Database
from syz_sage.storage import temporary_directory


class SchemaV4Tests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = temporary_directory()
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name) / "schema3.sqlite3"
        with contextlib.closing(sqlite3.connect(self.path)) as connection:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            connection.executescript(_SCHEMA_V1)
            location_store.migrate_v2(connection)
            schema_v3.migrate(connection)
            self.seed_history(connection)

    @staticmethod
    def seed_history(connection: sqlite3.Connection) -> None:
        content = b'{"version":1,"title":"original raw evidence","crashes":[]}'
        digest = hashlib.sha256(content).hexdigest()
        connection.execute(
            "INSERT INTO blobs(sha256, media_type, size_bytes, content, created_at) "
            "VALUES (?, 'application/json', ?, ?, '2026-09-01')",
            (digest, len(content), content),
        )
        for number in (1, 2):
            connection.execute(
                """INSERT INTO sync_runs(id, source_url, started_at, completed_at, status,
                       listing_json_sha256, error_count, summary_json)
                   VALUES (?, 'https://syzkaller.appspot.com/upstream/fixed?json=1',
                           '2026-09-01', '2026-09-01', 'completed', ?, 0, '{}')""",
                (number, digest),
            )
            count = 2 if number == 1 else 1
            connection.execute(
                """INSERT INTO snapshots(id, run_id, source_url, source_version, captured_at,
                       listing_json_sha256, source_record_count, record_count, status, is_current)
                   VALUES (?, ?, 'https://syzkaller.appspot.com/upstream/fixed?json=1', 1,
                           '2026-09-01', ?, ?, ?, 'completed', ?)""",
                (number, number, digest, count, count, int(number == 2)),
            )
            connection.execute(
                """INSERT INTO bugs(id, key, title, first_seen_at, last_seen_at,
                       first_seen_run_id, last_seen_run_id)
                   VALUES (?, ?, 'latest global title', '2026-09-01', '2026-09-01', 1, 1)""",
                (number, f"id-bug{number}"),
            )
            connection.execute(
                """INSERT INTO bug_versions(id, bug_id, raw_sha256, payload_kind, fetched_at,
                       title, status) VALUES (?, ?, ?, 'bug-json', '2026-09-01',
                                            'detail title differs', 'fixed on 2026/09/01')""",
                (number, number, digest),
            )
            connection.execute("UPDATE bugs SET current_version_id=? WHERE id=?", (number, number))
        connection.executemany(
            """INSERT INTO snapshot_bugs(snapshot_id, bug_id, bug_version_id, position, title,
                   bug_url, json_url, listing_record_sha256) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            [
                (
                    1,
                    1,
                    1,
                    0,
                    "KASAN: old alpha",
                    "https://syzkaller.appspot.com/bug?id=bug1",
                    "",
                    digest,
                ),
                (
                    1,
                    2,
                    2,
                    1,
                    "INFO: retained beta",
                    "https://syzkaller.appspot.com/bug?id=bug2",
                    "",
                    digest,
                ),
                (
                    2,
                    1,
                    1,
                    0,
                    "WARNING in current alpha",
                    "https://syzkaller.appspot.com/bug?id=bug1",
                    "",
                    digest,
                ),
            ],
        )
        connection.execute("INSERT INTO app_state VALUES ('preserved', 'same value')")
        connection.commit()

    def preserved_rows(self) -> dict[str, list[tuple]]:
        with contextlib.closing(sqlite3.connect(self.path)) as connection:
            return {
                table: connection.execute(f"SELECT * FROM {table}").fetchall()
                for table in (
                    "blobs",
                    "sync_runs",
                    "snapshots",
                    "bugs",
                    "bug_versions",
                    "app_state",
                )
            }

    def test_migration_classifies_each_historical_title_without_reading_source_blobs(self) -> None:
        before = self.preserved_rows()
        with contextlib.closing(Database(self.path)) as database:
            connection = database.connection

            def authorize(operation: int, table: str, column: str, *_: object) -> int:
                if operation == sqlite3.SQLITE_READ and table == "blobs" and column == "content":
                    return sqlite3.SQLITE_DENY
                return sqlite3.SQLITE_OK

            connection.set_authorizer(authorize)
            with mock.patch.object(Path, "read_bytes", side_effect=AssertionError("source read")):
                database.initialize()
            connection.set_authorizer(None)
            self.assertEqual(database.status()["schema_version"], 4)
            self.assertEqual(
                [
                    tuple(row)
                    for row in connection.execute(
                        "SELECT snapshot_id, bug_id, bug_type FROM snapshot_bugs "
                        "ORDER BY snapshot_id, bug_id"
                    )
                ],
                [(1, 1, "kasan"), (1, 2, "info"), (2, 1, "warning")],
            )
            self.assertEqual(database.get_bug("id-bug1")["bug_type"], "warning")
            self.assertTrue(database.health_check()["ok"])
            changes = connection.total_changes
            database.initialize()
            self.assertEqual(connection.total_changes, changes)
        self.assertEqual(self.preserved_rows(), before)

    def test_old_read_only_database_requires_explicit_migration_and_is_unchanged(self) -> None:
        before = self.path.read_bytes(), self.path.stat().st_mtime_ns
        with (
            self.assertRaisesRegex(RuntimeError, "ss migrate"),
            Database(self.path, read_only=True),
        ):
            pass
        self.assertEqual((self.path.read_bytes(), self.path.stat().st_mtime_ns), before)

    def test_classification_failure_rolls_back_column_index_view_and_version(self) -> None:
        before = self.preserved_rows()
        original = schema_v4.classify_bug_type
        calls = 0

        def classify(title: str) -> str:
            nonlocal calls
            calls += 1
            if calls == 2:
                raise RuntimeError("planned classifier failure")
            return original(title)

        with (
            mock.patch.object(schema_v4, "classify_bug_type", side_effect=classify),
            self.assertRaisesRegex(RuntimeError, "planned classifier failure"),
            Database(self.path),
        ):
            pass
        with contextlib.closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 3)
            self.assertNotIn(
                "bug_type",
                [row[1] for row in connection.execute("PRAGMA table_info(snapshot_bugs)")],
            )
            self.assertNotIn(
                "bug_type",
                [row[1] for row in connection.execute("PRAGMA table_info(current_bug_rows)")],
            )
            self.assertEqual(
                connection.execute(f"PRAGMA index_info({schema_v4.INDEX_NAME})").fetchall(), []
            )
        self.assertEqual(self.preserved_rows(), before)
        with Database(self.path) as database:
            self.assertEqual(database.get_bug("id-bug1")["bug_type"], "warning")

    def test_invalid_type_is_rejected_and_wrong_valid_type_is_detected_without_repair(self) -> None:
        with Database(self.path) as database:
            with self.assertRaises(sqlite3.IntegrityError):
                database.connection.execute("UPDATE snapshot_bugs SET bug_type='not-a-type'")
            database.connection.execute(
                "UPDATE snapshot_bugs SET bug_type='other' WHERE snapshot_id=1 AND bug_id=1"
            )
            changes = database.connection.total_changes
            result = database.health_check()
            self.assertFalse(result["ok"])
            self.assertIn("snapshot bug type mismatch: 1", result["snapshot_errors"])
            self.assertEqual(database.connection.total_changes, changes)

    def test_incomplete_schema4_index_or_view_is_rejected(self) -> None:
        with Database(self.path):
            pass
        with contextlib.closing(sqlite3.connect(self.path)) as connection:
            connection.execute(f"DROP INDEX {schema_v4.INDEX_NAME}")
        with (
            self.assertRaisesRegex(RuntimeError, "schema version 4 is incomplete"),
            Database(self.path, read_only=True),
        ):
            pass
        with contextlib.closing(sqlite3.connect(self.path)) as connection:
            connection.execute(
                f"CREATE INDEX {schema_v4.INDEX_NAME} ON snapshot_bugs(snapshot_id, bug_type)"
            )
            connection.execute("DROP VIEW current_bug_rows")
            connection.execute(schema_v4.CURRENT_BUG_ROWS_V3)
        with (
            self.assertRaisesRegex(RuntimeError, "current_bug_rows.bug_type"),
            Database(self.path, read_only=True),
        ):
            pass


if __name__ == "__main__":
    unittest.main()
