from __future__ import annotations

import json
import unittest

from syz_sage.database import Database
from tests.database.support import DatabaseFixture
from tests.support import (
    ALPHA_HASH,
)


class DatabaseSnapshotsTests(DatabaseFixture, unittest.TestCase):
    def test_file_deltas_use_active_snapshot_even_when_candidate_is_partial(self) -> None:
        listing_path = self.legacy / "raw" / "upstream_fixed.json"
        catalog_path = self.legacy / "processed" / "catalog.json"
        original_listing = listing_path.read_bytes()
        original_catalog = catalog_path.read_bytes()

        with Database(self.database_path) as database:
            initial = database.import_legacy(self.legacy)
            initial_checked = initial["last_checked_at"]

            listing = json.loads(original_listing)
            listing["Bugs"] = [
                listing["Bugs"][0],
                {
                    "title": "newly fixed gamma",
                    "link": "/bug?extid=gamma789",
                    "fix-commits": [],
                },
            ]
            listing_path.write_text(json.dumps(listing))
            catalog = json.loads(original_catalog)
            catalog["bugs"] = [
                catalog["bugs"][0],
                {
                    "key": "extid-gamma789",
                    "title": "newly fixed gamma",
                    "bug_url": "https://syzkaller.appspot.com/bug?extid=gamma789",
                    "json_url": "https://syzkaller.appspot.com/bug?extid=gamma789&json=1",
                    "fix_commits": [],
                },
            ]
            catalog_path.write_text(json.dumps(catalog))
            (self.legacy / "raw" / "bugs" / "extid-gamma789.json").write_text(
                json.dumps(
                    {
                        "id": "gamma789",
                        "title": "newly fixed gamma",
                        "fix-commits": [],
                        "crashes": [],
                    }
                )
            )

            partial = database.ingest_files(
                self.legacy,
                errors=("one resource could not be refreshed",),
                source_kind="legacy",
            )
            partial_status = database.status()

            self.assertEqual(partial["status"], "partial")
            self.assertFalse(partial["activated"])
            self.assertEqual(partial["known_fixed_bugs"], 1)
            self.assertEqual(partial["new_fixed_bugs"], 1)
            self.assertEqual(partial["new_fixed_bug_keys"], ["extid-gamma789"])
            self.assertEqual(partial["no_longer_listed_bugs"], 1)
            self.assertEqual(partial["no_longer_listed_bug_keys"], ["id-beta456"])
            self.assertEqual(partial_status["bugs"], 2)
            self.assertIsNotNone(database.get_bug("id-beta456"))
            self.assertIsNone(database.get_bug("extid-gamma789"))
            self.assertEqual(partial["last_checked_at"], partial_status["last_checked_at"])
            self.assertGreaterEqual(partial["last_checked_at"], initial_checked)

            listing_path.write_bytes(original_listing)
            catalog_path.write_bytes(original_catalog)
            recovered = database.ingest_files(self.legacy, source_kind="legacy")
            unchanged = database.ingest_files(self.legacy, source_kind="legacy")
            final_status = database.status()

            self.assertEqual(recovered["status"], "completed")
            self.assertEqual(recovered["known_fixed_bugs"], 2)
            self.assertEqual(recovered["new_fixed_bugs"], 0)
            self.assertEqual(recovered["no_longer_listed_bugs"], 0)
            self.assertEqual(unchanged["status"], "unchanged")
            self.assertEqual(unchanged["new_fixed_bugs"], 0)
            self.assertEqual(unchanged["no_longer_listed_bugs"], 0)
            self.assertEqual(unchanged["bugs"], final_status["bugs"])
            self.assertEqual(unchanged["reports"], final_status["reports"])
            self.assertEqual(unchanged["patches"], final_status["patches"])
            self.assertEqual(unchanged["last_checked_at"], final_status["last_checked_at"])
            self.assertGreater(
                database.connection.execute("SELECT COUNT(*) FROM bugs").fetchone()[0],
                unchanged["bugs"],
            )

    def test_empty_listing_cannot_replace_current_snapshot(self) -> None:
        with Database(self.database_path) as database:
            self.import_fixture(database)
            current_id = database.status()["current_snapshot"]["id"]

            result = self.ingest_direct(
                database,
                records=[],
                listing_json=b'{"version": 2, "Bugs": []}',
            )

            self.assertEqual(result["status"], "failed")
            self.assertEqual(database.status()["current_snapshot"]["id"], current_id)

    def test_partial_run_preserves_active_membership_and_metadata(self) -> None:
        with Database(self.database_path) as database:
            self.import_fixture(database)
            before_status = database.status()
            before_bug = database.get_bug("extid-alpha123")
            catalog, payloads = self.direct_inputs()
            changed = json.loads(payloads["extid-alpha123"])
            changed["title"] = "candidate title must stay inactive"
            payloads["extid-alpha123"] = json.dumps(changed).encode()

            result = database.ingest_snapshot(
                listing_json=(self.legacy / "raw" / "upstream_fixed.json").read_bytes(),
                listing_html=b"not an HTML document",
                records=catalog["bugs"],
                bug_payloads=payloads,
                reports_dir=self.legacy / "artifacts" / "reports",
                patches_dir=self.legacy / "artifacts" / "patches",
                source_url=str(catalog["source"]),
                errors=("simulated resource failure",),
            )

            after_status = database.status()
            after_bug = database.get_bug("extid-alpha123")
            self.assertEqual(result["status"], "partial")
            self.assertFalse(result["activated"])
            self.assertTrue(any("listing HTML" in item for item in result["failures"]))
            self.assertEqual(
                after_status["current_snapshot"]["id"],
                before_status["current_snapshot"]["id"],
            )
            self.assertEqual(after_bug["title"], before_bug["title"])
            self.assertEqual(after_bug["raw_sha256"], before_bug["raw_sha256"])

    def test_invalid_artifacts_do_not_replace_current_metadata(self) -> None:
        with Database(self.database_path) as database:
            self.import_fixture(database)
            report_before = tuple(
                database.connection.execute(
                    """
                    SELECT crash_id, source_url, current_blob_sha256
                    FROM reports JOIN bugs ON bugs.id = reports.bug_id
                    WHERE bugs.key = 'extid-alpha123'
                    """
                ).fetchone()
            )
            patch_before = tuple(
                database.connection.execute(
                    """
                    SELECT source_url, current_blob_sha256
                    FROM patches WHERE commit_hash = ?
                    """,
                    (ALPHA_HASH,),
                ).fetchone()
            )
            (self.legacy / "artifacts" / "reports" / "extid-alpha123.txt").write_bytes(
                b"\xef\xbb\xbf<?xml version='1.0'?><error>temporary upstream error</error>"
            )
            (self.legacy / "artifacts" / "patches" / f"{ALPHA_HASH}.diff").write_bytes(
                b"\xef\xbb\xbf<?xml version='1.0'?><error>"
                b"temporary upstream error diff --git a/a b/a</error>"
            )

            result = self.ingest_direct(database)

            report_after = tuple(
                database.connection.execute(
                    """
                    SELECT crash_id, source_url, current_blob_sha256
                    FROM reports JOIN bugs ON bugs.id = reports.bug_id
                    WHERE bugs.key = 'extid-alpha123'
                    """
                ).fetchone()
            )
            patch_after = tuple(
                database.connection.execute(
                    """
                    SELECT source_url, current_blob_sha256
                    FROM patches WHERE commit_hash = ?
                    """,
                    (ALPHA_HASH,),
                ).fetchone()
            )
            self.assertEqual(result["status"], "partial")
            self.assertEqual(report_after, report_before)
            self.assertEqual(patch_after, patch_before)

    def test_complete_payload_without_report_clears_only_current_pointer(self) -> None:
        with Database(self.database_path) as database:
            self.import_fixture(database)
            catalog, payloads = self.direct_inputs()
            alpha = json.loads(payloads["extid-alpha123"])
            alpha["crashes"][0].pop("crash-report-link")
            payloads["extid-alpha123"] = json.dumps(alpha).encode()
            historical_digest = database.get_bug("extid-alpha123")["report"]["sha256"]

            result = database.ingest_snapshot(
                listing_json=(self.legacy / "raw" / "upstream_fixed.json").read_bytes(),
                listing_html=(self.legacy / "raw" / "upstream_fixed.html").read_bytes(),
                records=catalog["bugs"],
                bug_payloads=payloads,
                reports_dir=self.legacy / "artifacts" / "reports",
                patches_dir=self.legacy / "artifacts" / "patches",
                source_url=str(catalog["source"]),
            )

            bug = database.get_bug("extid-alpha123")
            listed = {item["key"]: item for item in database.list_bugs(limit=10)}
            self.assertEqual(result["status"], "completed")
            self.assertFalse(bug["report"]["available"])
            self.assertFalse(listed["extid-alpha123"]["has_report"])
            self.assertEqual(database.status()["reports"], 0)
            self.assertIsNotNone(
                database.connection.execute(
                    """
                    SELECT id FROM report_versions WHERE blob_sha256 = ?
                    """,
                    (historical_digest,),
                ).fetchone()
            )


if __name__ == "__main__":
    unittest.main()
