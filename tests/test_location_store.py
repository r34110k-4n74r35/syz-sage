from __future__ import annotations

import contextlib
import hashlib
import io
import json
import shutil
import sqlite3
import unittest
from pathlib import Path
from unittest import mock

from syz_sage import location_store, schema_v3, schema_v4
from syz_sage.cli import main
from syz_sage.database import Database
from syz_sage.storage import temporary_directory

FIXTURES = Path(__file__).parent / "fixtures" / "legacy_data"
HTML = b"""<!doctype html><html><body><table>
<tr><td><a href="/bug?extid=alpha123">alpha</a>
<a href="/upstream/fixed?label=subsystems%3Anet">net</a>
<a href="/upstream/fixed?label=subsystems%3Amm">mm</a></td></tr>
<tr><td><a href="/bug?id=beta456">beta</a></td></tr>
</table></body></html>"""
REPORT = """BUG: KASAN: use-after-free in alpha
Call Trace:
 alpha+0x10/0x20 net/alpha.c:42 [inline]
 caller+0x1/0x2 net/alpha.c:60
Allocated by task 1:
 allocate+0x1/0x2 mm/slab.c:100
Freed by task 2:
 release+0x1/0x2 mm/slab.c:200
"""


class LocationStorageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = temporary_directory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.data = self.root / "data"
        shutil.copytree(FIXTURES, self.data)
        (self.data / "raw/upstream_fixed.html").write_bytes(HTML)
        self.report_path = self.data / "artifacts/reports/extid-alpha123.txt"
        self.report_path.write_text(REPORT)
        self.path = self.root / "db.sqlite3"

    def import_data(self) -> None:
        with Database(self.path) as db:
            self.assertEqual(db.import_legacy(self.data)["status"], "completed")

    def make_v1(self) -> None:
        self.import_data()
        with contextlib.closing(sqlite3.connect(self.path)) as connection:
            connection.execute("DROP VIEW current_bug_rows")
            connection.execute(schema_v4.CURRENT_BUG_ROWS_V3)
            connection.execute(f"DROP INDEX {schema_v4.INDEX_NAME}")
            connection.execute("ALTER TABLE snapshot_bugs DROP COLUMN bug_type")
            for view in (
                "current_bug_subsystems",
                "current_crash_locations",
                "current_crash_stack_frames",
                "current_fix_locations",
            ):
                connection.execute(f"DROP VIEW {view}")
            for table in location_store.REQUIRED_COLUMNS:
                connection.execute(f"DROP TABLE {table}")
            for table in schema_v3.REQUIRED_COLUMNS:
                connection.execute(f"DROP TABLE {table}")
            connection.execute("PRAGMA user_version = 1")
            connection.commit()

    def test_import_records_tags_locations_stack_and_source_versions(self) -> None:
        self.import_data()
        with Database(self.path, read_only=True) as db:
            bug = db.get_bug("extid-alpha123")
            self.assertEqual(bug["subsystems"], ["mm", "net"])
            location = bug["crash_locations"][0]
            self.assertEqual((location["function_name"], location["line_number"]), ("alpha", 42))
            self.assertEqual(location["report_sha256"], hashlib.sha256(REPORT.encode()).hexdigest())
            self.assertEqual(
                location["kernel_source_commit"], bug["crashes"][0]["kernel_source_commit"]
            )
            self.assertEqual(len(bug["crash_stack"]), 4)
            self.assertEqual(bug["crash_stack"][-1]["section"], "free")
            fix = bug["fix_locations"][0]
            self.assertEqual(fix["commit_hash"], "a" * 40)
            self.assertEqual((fix["old_start"], fix["old_count"]), (2, 0))
            self.assertEqual((fix["new_start"], fix["new_count"]), (3, 1))
            self.assertEqual(fix["function_name"], "alpha_read")
            self.assertEqual(fix["function_basis"], "inferred from definition context")
            self.assertEqual(db.list_bugs()[0]["subsystems"], ["mm", "net"])
            self.assertEqual(db.get_bug("id-beta456")["subsystems"], [])
            self.assertTrue(db.health_check()["ok"])

    def test_migration_backfills_from_blobs_and_preserves_sync_history(self) -> None:
        self.make_v1()
        # Prove migration is independent of the filesystem mirror.
        shutil.rmtree(self.data)
        with contextlib.closing(sqlite3.connect(self.path)) as connection:
            original = {
                table: connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                for table in ("bugs", "blobs", "snapshots", "sync_runs")
            }
        with (
            self.assertRaisesRegex(RuntimeError, "ss migrate"),
            Database(self.path, read_only=True),
        ):
            pass
        with contextlib.closing(Database(self.path, read_only=True)) as db:
            self.assertIsNone(db.check_files_current(self.data))
        with Database(self.path) as db:
            self.assertEqual(db.status()["schema_version"], 4)
            bug = db.get_bug("extid-alpha123")
            self.assertEqual(bug["subsystems"], ["mm", "net"])
            self.assertEqual(bug["crash_locations"][0]["line_number"], 42)
            self.assertEqual(len(bug["crash_stack"]), 4)
            for table, count in original.items():
                self.assertEqual(db.status()["counts"][table], count)
            changes = db.connection.total_changes
            db.initialize()
            self.assertEqual(db.connection.total_changes, changes)
            self.assertTrue(db.health_check()["ok"])

    def test_migration_is_atomic_on_parser_failure(self) -> None:
        self.make_v1()
        with (
            mock.patch.object(
                location_store, "index_patch", side_effect=RuntimeError("test failure")
            ),
            self.assertRaisesRegex(RuntimeError, "test failure"),
            Database(self.path),
        ):
            pass
        with contextlib.closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 1)
            self.assertIsNone(
                connection.execute(
                    "SELECT name FROM sqlite_master WHERE name = 'crash_locations'",
                ).fetchone()
            )
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM bugs").fetchone()[0], 2)
        with Database(self.path) as db:
            self.assertEqual(db.get_bug("extid-alpha123")["subsystems"], ["mm", "net"])

    def test_partial_ingestion_retains_active_tags_report_and_locations(self) -> None:
        self.import_data()
        with Database(self.path) as db:
            before = db.get_bug("extid-alpha123")
            self.report_path.write_text(REPORT.replace(":42", ":77"))
            (self.data / "raw/upstream_fixed.html").write_bytes(HTML.replace(b"%3Amm", b"%3Afs"))
            result = db.ingest_files(self.data, errors=["incomplete fetch"])
            self.assertEqual(result["status"], "partial")
            after = db.get_bug("extid-alpha123")
            for key in ("subsystems", "crash_locations", "crash_stack", "fix_locations"):
                self.assertEqual(after[key], before[key])
            result = db.ingest_files(self.data)
            self.assertEqual(result["status"], "completed")
            after = db.get_bug("extid-alpha123")
            self.assertEqual(after["subsystems"], ["fs", "net"])
            self.assertEqual(after["crash_locations"][0]["line_number"], 77)
            counts = db.status()["counts"]
            changes = db.connection.total_changes
            self.assertEqual(db.ingest_files(self.data)["status"], "unchanged")
            self.assertEqual(db.connection.total_changes, changes)
            self.assertEqual(db.status()["counts"], counts)

    def test_kcsan_keeps_both_conflicting_accesses(self) -> None:
        payload = self.data / "raw/bugs/extid-alpha123.json"
        data = json.loads(payload.read_text())
        data["title"] = data["crashes"][0]["title"] = "KCSAN: data-race in alpha / beta"
        payload.write_text(json.dumps(data))
        self.report_path.write_text("""BUG: KCSAN: data-race in alpha / beta
write to 0x123 by task 1:
 alpha+0x1/0x2 net/alpha.c:42
read to 0x123 by task 2:
 beta+0x1/0x2 net/beta.c:99
""")
        self.import_data()
        with Database(self.path, read_only=True) as db:
            locations = db.get_bug("extid-alpha123")["crash_locations"]
            self.assertEqual(
                [(loc["function_name"], loc["line_number"]) for loc in locations],
                [("alpha", 42), ("beta", 99)],
            )

    def test_cli_exposes_tags_locations_and_full_stack_without_writes(self) -> None:
        self.import_data()
        digest = hashlib.sha256(self.path.read_bytes()).hexdigest()
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(["--database", str(self.path), "show", "extid-alpha123", "--stack"])
        self.assertEqual(code, 0)
        rendered = " ".join(output.getvalue().split())
        for text in ("Subsystems: mm, net", "net/alpha.c:42", "release+0x1/0x2", "mm/slab.c:100"):
            self.assertIn(text, rendered)
        self.assertEqual(hashlib.sha256(self.path.read_bytes()).hexdigest(), digest)


if __name__ == "__main__":
    unittest.main()
