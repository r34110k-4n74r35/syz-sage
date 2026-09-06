from __future__ import annotations

import contextlib
import json
import shutil
import sqlite3
import unittest
from pathlib import Path
from unittest import mock

from syz_sage.database import SCHEMA_VERSION, Database, location_store
from syz_sage.project.storage import temporary_directory
from tests.support import FIXTURES

REPORT = """BUG: KASAN: use-after-free in victim
Call Trace:
 victim+0x10/0x20
Backtrace of CPU 1:
 victim+0x20/0x40 drivers/example.c:200
"""


class SchemaV6Tests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = temporary_directory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.data = self.root / "data"
        self.path = self.root / "store.sqlite3"
        shutil.copytree(FIXTURES, self.data)
        detail_path = self.data / "raw/bugs/extid-alpha123.json"
        detail = json.loads(detail_path.read_bytes())
        detail["title"] = detail["crashes"][0]["title"] = "KASAN: use-after-free in victim"
        detail_path.write_text(json.dumps(detail))
        report_path = self.data / "artifacts/reports/extid-alpha123.txt"
        with Database(self.path) as database:
            for line in (200, 201):
                report_path.write_text(REPORT.replace(":200", f":{line}"))
                self.assertEqual(database.ingest_files(self.data)["status"], "completed")
            # Recreate schema5's wrong extraction; source blobs/associations remain intact.
            database.connection.execute(
                "UPDATE crash_locations SET parser_version=3, "
                "file_path='drivers/example.c', line_number=200"
            )
            database.connection.execute("UPDATE crash_stack_frames SET parser_version=3")
            database.connection.execute("PRAGMA user_version=5")

    def preserved_tables(self) -> dict[str, list[tuple]]:
        with contextlib.closing(sqlite3.connect(self.path)) as connection:
            tables = [
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
                )
                if row[0] not in {"crash_locations", "crash_stack_frames"}
            ]
            return {
                table: connection.execute(f'SELECT * FROM "{table}" ORDER BY rowid').fetchall()
                for table in tables
            }

    def test_migration_repairs_current_and_historical_locations_without_touching_evidence(
        self,
    ) -> None:
        preserved = self.preserved_tables()
        shutil.rmtree(self.data)
        with Database(self.path) as database:
            locations = database.connection.execute("SELECT * FROM crash_locations").fetchall()
            self.assertEqual(len(locations), 2)
            self.assertTrue(all(row["line_number"] is None for row in locations))
            self.assertTrue(all(row["file_path"] is None for row in locations))
            self.assertTrue(all(row["parser_version"] == 4 for row in locations))
            frames = database.connection.execute(
                "SELECT section, line_number FROM crash_stack_frames WHERE report_line=5 "
                "ORDER BY line_number"
            ).fetchall()
            self.assertEqual(
                [tuple(row) for row in frames], [("other-task", 200), ("other-task", 201)]
            )
            bug = database.get_bug("extid-alpha123")
            self.assertIn("drivers/example.c:201", bug["report"]["text"])
            self.assertIsNone(bug["crash_locations"][0]["line_number"])
            self.assertEqual(database.status()["schema_version"], SCHEMA_VERSION)
            self.assertTrue(database.health_check()["ok"])
            changes = database.connection.total_changes
            database.initialize()
            self.assertEqual(database.connection.total_changes, changes)
        self.assertEqual(self.preserved_tables(), preserved)

    def test_read_only_requires_migration_without_writing(self) -> None:
        before = self.path.read_bytes(), self.path.stat().st_mtime_ns
        with (
            self.assertRaisesRegex(RuntimeError, "ss migrate"),
            Database(self.path, read_only=True),
        ):
            pass
        self.assertEqual((self.path.read_bytes(), self.path.stat().st_mtime_ns), before)

    def test_failed_reparse_rolls_back_locations_stacks_and_schema_version(self) -> None:
        with contextlib.closing(sqlite3.connect(self.path)) as connection:
            before = connection.execute("SELECT * FROM crash_locations ORDER BY rowid").fetchall()
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
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 5)
            self.assertEqual(
                connection.execute("SELECT * FROM crash_locations ORDER BY rowid").fetchall(),
                before,
            )
            self.assertEqual(
                connection.execute("SELECT * FROM crash_stack_frames ORDER BY rowid").fetchall(),
                frames,
            )


if __name__ == "__main__":
    unittest.main()
