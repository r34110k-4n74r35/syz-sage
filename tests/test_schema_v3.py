from __future__ import annotations

import contextlib
import json
import shutil
import sqlite3
import unittest
from pathlib import Path
from unittest import mock

from syz_sage import location_store, schema_v3, schema_v4
from syz_sage.database import SCHEMA_VERSION, Database
from syz_sage.storage import temporary_directory

FIXTURES = Path(__file__).parent / "fixtures/legacy_data"
WARNING = """WARNING: CPU: 0 at include/linux/test.h:42 inner include/linux/test.h:42 [inline]
WARNING: CPU: 0 at include/linux/test.h:42 outer+0x1/0x2 net/example.c:99
"""


class SchemaV3Tests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = temporary_directory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.data = self.root / "data"
        shutil.copytree(FIXTURES, self.data)
        self.path = self.root / "store.sqlite3"
        self.report = self.data / "artifacts/reports/extid-alpha123.txt"
        self.report.write_text(WARNING)

    def import_data(self) -> None:
        with Database(self.path) as db:
            result = db.import_legacy(self.data)
            self.assertEqual(result["status"], "completed", result)

    def make_v2(self) -> None:
        self.import_data()
        with contextlib.closing(sqlite3.connect(self.path)) as connection:
            connection.execute("DROP VIEW current_bug_rows")
            connection.execute(schema_v4.CURRENT_BUG_ROWS_V3)
            connection.execute(f"DROP INDEX {schema_v4.INDEX_NAME}")
            connection.execute("ALTER TABLE snapshot_bugs DROP COLUMN bug_type")
            for view in (
                "current_crash_locations",
                "current_crash_stack_frames",
                "current_fix_locations",
            ):
                connection.execute(f"DROP VIEW {view}")
            for table in schema_v3.REQUIRED_COLUMNS:
                connection.execute(f"DROP TABLE {table}")
            for statement in location_store.SCHEMA_V2.split(";"):
                if statement.strip().startswith(
                    (
                        "CREATE VIEW current_crash_locations",
                        "CREATE VIEW current_crash_stack_frames",
                        "CREATE VIEW current_fix_locations",
                    )
                ):
                    connection.execute(statement)
            for table in ("crash_locations", "crash_stack_frames", "fix_locations"):
                connection.execute(f"UPDATE {table} SET parser_version = 1")
            connection.execute("UPDATE crash_locations SET function_name = 'outer'")
            connection.execute("PRAGMA user_version = 2")
            connection.commit()

    def test_v2_migration_repairs_coordinates_and_preserves_sources(self) -> None:
        self.make_v2()
        shutil.rmtree(self.data)
        with contextlib.closing(sqlite3.connect(self.path)) as connection:
            before = connection.execute("SELECT sha256 FROM blobs ORDER BY sha256").fetchall()
            runs = connection.execute("SELECT * FROM sync_runs ORDER BY id").fetchall()
        with Database(self.path) as db:
            location = db.get_bug("extid-alpha123")["crash_locations"][0]
            self.assertEqual(
                (location["function_name"], location["file_path"], location["line_number"]),
                ("inner", "include/linux/test.h", 42),
            )
            self.assertEqual(location["parser_version"], location_store.REPORT_PARSER_VERSION)
            self.assertEqual(db.status()["schema_version"], SCHEMA_VERSION)
            self.assertEqual(
                [
                    tuple(r)
                    for r in db.connection.execute("SELECT sha256 FROM blobs ORDER BY sha256")
                ],
                before,
            )
            self.assertEqual(
                [tuple(r) for r in db.connection.execute("SELECT * FROM sync_runs ORDER BY id")],
                runs,
            )
            self.assertTrue(db.health_check()["ok"])
            changes = db.connection.total_changes
            db.initialize()
            self.assertEqual(changes, db.connection.total_changes)

    def test_v2_migration_failure_rolls_back_schema_and_derived_rows(self) -> None:
        self.make_v2()
        with (
            mock.patch.object(
                location_store, "index_report", side_effect=RuntimeError("parser failed")
            ),
            self.assertRaisesRegex(RuntimeError, "parser failed"),
            Database(self.path),
        ):
            pass
        with contextlib.closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 2)
            self.assertIsNone(
                connection.execute(
                    "SELECT 1 FROM sqlite_master WHERE name = 'snapshot_reports'",
                ).fetchone()
            )
            self.assertEqual(
                connection.execute("SELECT function_name FROM crash_locations").fetchone()[0],
                "outer",
            )

    def test_snapshots_keep_their_own_report_and_patch_versions(self) -> None:
        self.import_data()
        patch_path = self.data / f"artifacts/patches/{'a' * 40}.diff"
        old_patch = patch_path.read_bytes()
        with Database(self.path) as db:
            first = db.status()["current_snapshot"]["id"]
            self.report.write_text(WARNING.replace(":42", ":43"))
            patch_path.write_bytes(old_patch.replace(b"return 0", b"return 1"))
            result = db.import_legacy(self.data)
            self.assertEqual(result["status"], "completed", result)
            second = result["snapshot_id"]
            versions = db.connection.execute(
                "SELECT report_version_id FROM snapshot_reports ORDER BY snapshot_id",
            ).fetchall()
            self.assertNotEqual(versions[0][0], versions[1][0])
            old_report = db.connection.execute(
                """
                SELECT b.content FROM snapshot_reports sr JOIN report_versions rv
                ON rv.id = sr.report_version_id JOIN blobs b ON b.sha256 = rv.blob_sha256
                WHERE sr.snapshot_id = ?
            """,
                (first,),
            ).fetchone()[0]
            self.assertEqual(old_report, WARNING.encode())
            old_patch_stored = db.connection.execute(
                """
                SELECT b.content FROM snapshot_patches sp JOIN patch_versions pv
                ON pv.id = sp.patch_version_id JOIN blobs b ON b.sha256 = pv.blob_sha256
                WHERE sp.snapshot_id = ?
            """,
                (first,),
            ).fetchone()[0]
            self.assertEqual(old_patch_stored, old_patch)
            self.assertEqual(db.get_bug("extid-alpha123")["snapshot_id"], second)
            self.assertEqual(db.get_bug("extid-alpha123")["crash_locations"][0]["line_number"], 43)

    def test_reparse_with_no_locations_removes_stale_coordinates_and_is_idempotent(self) -> None:
        self.import_data()
        with Database(self.path) as db:
            patch_id = db.connection.execute("SELECT id FROM patch_versions").fetchone()[0]
            db.connection.execute("UPDATE fix_locations SET parser_version = 1")
            with mock.patch.object(
                location_store, "extract_fix_locations", return_value=[]
            ) as parse:
                with db._transaction() as connection:
                    location_store.index_patch(connection, patch_id)
                rows = db.connection.execute("SELECT * FROM fix_locations").fetchall()
                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0]["kind"], "unparsed")
                self.assertIsNone(rows[0]["old_start"])
                changes = db.connection.total_changes
                location_store.index_patch(db.connection, patch_id)
                self.assertEqual(changes, db.connection.total_changes)
                self.assertEqual(parse.call_count, 1)

    def test_active_artifact_reads_use_snapshot_instead_of_compatibility_pointers(self) -> None:
        self.import_data()
        with Database(self.path) as db:
            original = db.get_bug("extid-alpha123")
            db.connection.execute("UPDATE reports SET current_blob_sha256 = NULL, source_url = ''")
            db.connection.execute("UPDATE patches SET current_blob_sha256 = NULL, source_url = ''")

            bug = db.get_bug("extid-alpha123")
            self.assertEqual(bug["report"], original["report"])
            self.assertTrue(bug["fixes"][0]["patch_available"])
            listed = {item["key"]: item for item in db.list_bugs()}
            self.assertTrue(listed["extid-alpha123"]["has_report"])
            self.assertEqual(db.status()["reports"], 1)
            self.assertEqual(db.status()["patches"], 1)

    def test_partial_report_and_patch_versions_do_not_change_active_reads(self) -> None:
        self.import_data()
        patch_path = self.data / f"artifacts/patches/{'a' * 40}.diff"
        detail_path = self.data / "raw/bugs/extid-alpha123.json"
        with Database(self.path) as db:
            original = db.get_bug("extid-alpha123")
            first_snapshot = original["snapshot_id"]
            detail = json.loads(detail_path.read_bytes())
            detail["crashes"][0]["crash-report-link"] = "/text?tag=CrashReport&x=alpha-new"
            detail_path.write_text(json.dumps(detail))
            self.report.write_text(WARNING.replace(":42", ":43"))
            patch_path.write_bytes(patch_path.read_bytes().replace(b"return 0", b"return 1"))

            partial = db.ingest_files(
                self.data, source_kind="legacy", errors=["unfinished retrieval elsewhere"]
            )
            self.assertEqual(partial["status"], "partial")
            self.assertEqual(db.get_bug("extid-alpha123")["report"], original["report"])
            self.assertEqual(
                db.get_bug("extid-alpha123")["fix_locations"], original["fix_locations"]
            )
            self.assertEqual(db.status()["current_snapshot"]["id"], first_snapshot)
            self.assertEqual(db.status()["reports"], 1)
            self.assertEqual(db.status()["patches"], 1)
            candidate = db.connection.execute(
                "SELECT source_url FROM snapshot_reports WHERE snapshot_id = ?",
                (partial["snapshot_id"],),
            ).fetchone()
            self.assertTrue(candidate["source_url"].endswith("alpha-new"))

            completed = db.import_legacy(self.data)
            self.assertEqual(completed["status"], "completed")
            bug = db.get_bug("extid-alpha123")
            self.assertTrue(bug["report"]["source_url"].endswith("alpha-new"))
            self.assertIn("test.h:43", bug["report"]["text"])
            self.assertTrue(bug["fixes"][0]["patch_available"])

    def test_identical_report_bytes_at_new_url_use_snapshot_source(self) -> None:
        self.import_data()
        detail_path = self.data / "raw/bugs/extid-alpha123.json"
        with Database(self.path) as db:
            old_report = db.get_bug("extid-alpha123")["report"]
            detail = json.loads(detail_path.read_bytes())
            detail["crashes"][0]["crash-report-link"] = "/text?tag=CrashReport&x=alpha-new"
            detail_path.write_text(json.dumps(detail))
            self.assertEqual(db.import_legacy(self.data)["status"], "completed")
            report = db.get_bug("extid-alpha123")["report"]
            self.assertEqual(report["sha256"], old_report["sha256"])
            self.assertTrue(report["source_url"].endswith("alpha-new"))
            version = db.connection.execute("SELECT source_url FROM report_versions").fetchone()
            self.assertEqual(version["source_url"], old_report["source_url"])

    def test_health_check_reports_missing_active_patch_extraction(self) -> None:
        self.import_data()
        with Database(self.path) as db:
            db.connection.execute("DELETE FROM fix_locations")
            health = db.health_check()
            self.assertFalse(health["ok"])
            self.assertTrue(
                any("active patch" in error for error in health["snapshot_errors"]), health
            )

    def test_snapshot_report_cannot_reference_another_bug(self) -> None:
        self.import_data()
        with Database(self.path) as db:
            row = db.connection.execute("SELECT * FROM snapshot_reports").fetchone()
            beta = db.connection.execute("SELECT id FROM bugs WHERE key = 'id-beta456'").fetchone()[
                0
            ]
            with self.assertRaisesRegex(sqlite3.IntegrityError, "different bug"):
                db.connection.execute(
                    "INSERT INTO snapshot_reports VALUES (?, ?, ?, ?, ?)",
                    (
                        row["snapshot_id"],
                        beta,
                        row["report_version_id"],
                        row["crash_id"],
                        row["source_url"],
                    ),
                )
            with self.assertRaisesRegex(sqlite3.IntegrityError, "different bug"):
                db.connection.execute(
                    "UPDATE snapshot_reports SET bug_id = ? WHERE snapshot_id = ? AND bug_id = ?",
                    (beta, row["snapshot_id"], row["bug_id"]),
                )


if __name__ == "__main__":
    unittest.main()
