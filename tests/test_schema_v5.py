from __future__ import annotations

import contextlib
import json
import shutil
import sqlite3
import unittest
from pathlib import Path
from unittest import mock

from syz_sage import location_store
from syz_sage.database import SCHEMA_VERSION, Database
from syz_sage.storage import temporary_directory

FIXTURES = Path(__file__).parent / "fixtures/legacy_data"
REPORT = """BUG: KMSAN: uninit-value in access
 access+0x1/0x2
Uninit was stored to memory at:
 access+0x5/0x9 drivers/example.c:42
Uninit was created at:
 allocate+0x1/0x2 mm/slab.c:100
"""


class SchemaV5Tests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = temporary_directory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.data = self.root / "data"
        self.path = self.root / "store.sqlite3"
        shutil.copytree(FIXTURES, self.data)
        detail_path = self.data / "raw/bugs/extid-alpha123.json"
        detail = json.loads(detail_path.read_bytes())
        detail["title"] = detail["crashes"][0]["title"] = "KMSAN: uninit-value in access"
        detail_path.write_text(json.dumps(detail))
        report_path = self.data / "artifacts/reports/extid-alpha123.txt"
        with Database(self.path) as database:
            for line in (42, 43):
                report_path.write_text(REPORT.replace(":42", f":{line}"))
                self.assertEqual(database.ingest_files(self.data)["status"], "completed")
            # Recreate v4's bad derived data without changing any source blobs.
            database.connection.execute(
                "UPDATE crash_locations SET parser_version=2, "
                "file_path='drivers/example.c', line_number=42"
            )
            database.connection.execute(
                "UPDATE crash_stack_frames SET parser_version=2, section='manifestation'"
            )
            database.connection.execute("PRAGMA user_version=4")

    def preserved_rows(self) -> dict[str, list[tuple]]:
        with contextlib.closing(sqlite3.connect(self.path)) as connection:
            return {
                table: connection.execute(f"SELECT * FROM {table} ORDER BY rowid").fetchall()
                for table in (
                    "blobs",
                    "sync_runs",
                    "snapshots",
                    "bugs",
                    "bug_versions",
                    "snapshot_bugs",
                    "snapshot_reports",
                    "snapshot_patches",
                    "fix_locations",
                    "app_state",
                )
            }

    def test_migration_repairs_history_from_sqlite_and_preserves_sources_and_membership(
        self,
    ) -> None:
        preserved = self.preserved_rows()
        shutil.rmtree(self.data)
        with Database(self.path) as database:
            locations = database.connection.execute("SELECT * FROM crash_locations").fetchall()
            self.assertEqual(len(locations), 2)
            self.assertTrue(all(row["line_number"] is None for row in locations))
            self.assertTrue(all(row["parser_version"] == 3 for row in locations))
            frames = database.connection.execute(
                "SELECT section FROM crash_stack_frames WHERE report_line=4"
            ).fetchall()
            self.assertEqual([row[0] for row in frames], ["origin", "origin"])
            self.assertEqual(database.status()["schema_version"], SCHEMA_VERSION)
            self.assertTrue(database.health_check()["ok"])
            changes = database.connection.total_changes
            database.initialize()
            self.assertEqual(database.connection.total_changes, changes)
        self.assertEqual(self.preserved_rows(), preserved)

    def test_read_only_requires_explicit_migration_without_writing(self) -> None:
        before = self.path.read_bytes(), self.path.stat().st_mtime_ns
        with (
            self.assertRaisesRegex(RuntimeError, "ss migrate"),
            Database(self.path, read_only=True),
        ):
            pass
        self.assertEqual((self.path.read_bytes(), self.path.stat().st_mtime_ns), before)

    def test_failed_reparse_rolls_back_all_derived_rows_and_schema_version(self) -> None:
        with contextlib.closing(sqlite3.connect(self.path)) as connection:
            before = connection.execute("SELECT * FROM crash_locations ORDER BY id").fetchall()
            frames = connection.execute(
                "SELECT * FROM crash_stack_frames ORDER BY rowid"
            ).fetchall()
        original = location_store.index_report
        calls = 0

        def fail_second(connection: sqlite3.Connection, report: int, crash: int) -> None:
            nonlocal calls
            calls += 1
            if calls == 2:
                raise RuntimeError("planned parser failure")
            original(connection, report, crash)

        with (
            mock.patch.object(location_store, "index_report", side_effect=fail_second),
            self.assertRaisesRegex(RuntimeError, "planned parser failure"),
            Database(self.path),
        ):
            pass
        with contextlib.closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 4)
            self.assertEqual(
                connection.execute("SELECT * FROM crash_locations ORDER BY id").fetchall(), before
            )
            self.assertEqual(
                connection.execute("SELECT * FROM crash_stack_frames ORDER BY rowid").fetchall(),
                frames,
            )


if __name__ == "__main__":
    unittest.main()
