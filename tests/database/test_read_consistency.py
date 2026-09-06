from __future__ import annotations

import json
import unittest
from unittest import mock

from syz_sage.database import Database
from syz_sage.project.progress_events import ProgressEvent
from tests.database.support import DatabaseFixture


class ReadConsistencyTests(DatabaseFixture, unittest.TestCase):
    def activate_smaller_snapshot(self, database: Database) -> dict:
        catalog, _ = self.direct_inputs()
        listing = json.loads((self.legacy / "raw/upstream_fixed.json").read_bytes())
        listing["Bugs"] = listing["Bugs"][:1]
        result = self.ingest_direct(
            database,
            records=catalog["bugs"][:1],
            listing_json=json.dumps(listing).encode(),
            listing_html=b'<html><a href="/bug?extid=alpha123">alpha</a></html>',
        )
        self.assertEqual(result["status"], "completed", result)
        return result

    def test_status_counts_and_metadata_share_snapshot_while_writer_commits(self) -> None:
        with Database(self.database_path) as writer:
            self.import_fixture(writer)
            with Database(self.database_path, read_only=True) as reader:
                before = reader.status()
                original = reader._current_effective_fixes

                def activate_after_count() -> dict:
                    self.activate_smaller_snapshot(writer)
                    return original()

                with mock.patch.object(
                    reader, "_current_effective_fixes", side_effect=activate_after_count
                ):
                    during = reader.status()
                self.assertEqual(during, before)
                latest = reader.status()
                self.assertEqual((latest["bugs"], latest["fixes"], latest["crashes"]), (1, 1, 1))
                self.assertNotEqual(
                    latest["current_snapshot"]["id"], before["current_snapshot"]["id"]
                )
                self.assertEqual(reader.connection.total_changes, 0)

    def test_noop_marker_and_coverage_share_snapshot_while_writer_commits(self) -> None:
        with Database(self.database_path) as writer:
            self.import_fixture(writer)
            with Database(self.database_path, read_only=True) as reader:
                before = reader.check_files_current(self.legacy, source_kind="legacy")
                self.assertIsNotNone(before)
                original = reader.status

                def activate_before_coverage() -> dict:
                    self.activate_smaller_snapshot(writer)
                    return original()

                with mock.patch.object(reader, "status", side_effect=activate_before_coverage):
                    during = reader.check_files_current(self.legacy, source_kind="legacy")
                self.assertEqual(during, before)
                self.assertIsNone(reader.check_files_current(self.legacy, source_kind="legacy"))
                self.assertEqual(reader.connection.total_changes, 0)

    def test_health_checks_same_database_version_from_sqlite_checks_through_blob_scan(self) -> None:
        with Database(self.database_path) as writer:
            self.import_fixture(writer)
            with Database(self.database_path, read_only=True) as reader:
                before = reader.health_check()
                activated: list[dict] = []

                def activate_after_sqlite(event: ProgressEvent) -> None:
                    if event.phase == "check-sqlite" and event.completed == 2:
                        activated.append(self.activate_smaller_snapshot(writer))

                reader._on_progress = activate_after_sqlite
                during = reader.health_check()
                reader._on_progress = None
                self.assertEqual(len(activated), 1)
                self.assertEqual(during, before)
                latest = reader.health_check()
                self.assertTrue(latest["ok"])
                self.assertGreater(latest["blob_count"], before["blob_count"])
                self.assertEqual(reader.connection.total_changes, 0)

    def test_statistics_checks_and_noop_reuse_existing_read_transaction(self) -> None:
        with Database(self.database_path) as database:
            self.import_fixture(database)
            with database._read_transaction():
                self.assertEqual(database.status()["bugs"], 2)
                self.assertTrue(database.health_check()["ok"])
                self.assertIsNotNone(
                    database.check_files_current(self.legacy, source_kind="legacy")
                )
                self.assertTrue(database.connection.in_transaction)


if __name__ == "__main__":
    unittest.main()
