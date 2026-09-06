from __future__ import annotations

import json
import unittest

from syz_sage.database import Database
from tests.database.support import DatabaseFixture


class SnapshotIngestionTests(DatabaseFixture, unittest.TestCase):
    def test_import_is_idempotent(self) -> None:
        with Database(self.database_path) as database:
            self.import_fixture(database)
            first = database.status()
            result = database.import_legacy(self.legacy)
            second = database.status()

        self.assertEqual(result["status"], "unchanged")
        self.assertEqual(result["known_fixed_bugs"], first["bugs"])
        self.assertEqual(result["new_fixed_bugs"], 0)
        self.assertEqual(result["new_fixed_bug_keys"], [])
        self.assertEqual(result["no_longer_listed_bugs"], 0)
        self.assertEqual(result["no_longer_listed_bug_keys"], [])
        self.assertEqual(result["bugs"], first["bugs"])
        self.assertEqual(result["reports"], first["reports"])
        self.assertEqual(result["patches"], first["patches"])
        self.assertEqual(result["last_checked_at"], second["last_checked_at"])
        self.assertGreaterEqual(second["last_checked_at"], first["last_checked_at"])
        first["last_checked_at"] = second["last_checked_at"]
        self.assertEqual(first, second)

    def test_listing_and_prepared_keys_must_match_exact_order(self) -> None:
        with Database(self.database_path) as database:
            self.import_fixture(database)
            current_id = database.status()["current_snapshot"]["id"]
            catalog, _ = self.direct_inputs()

            result = self.ingest_direct(database, records=list(reversed(catalog["bugs"])))

            self.assertEqual(result["status"], "failed")
            self.assertFalse(result.get("activated", False))
            self.assertEqual(database.status()["current_snapshot"]["id"], current_id)

    def test_blob_additions_are_the_exact_committed_delta(self) -> None:
        with Database(self.database_path) as database:
            database.initialize()
            before = database.status()["counts"]["blobs"]
            result = database.import_legacy(self.legacy)
            after = database.status()["counts"]["blobs"]

            self.assertEqual(result["blobs_added"], after - before)

    def test_json_object_without_bug_shape_cannot_activate(self) -> None:
        with Database(self.database_path) as database:
            self.import_fixture(database)
            before = database.status()["current_snapshot"]["id"]
            catalog, payloads = self.direct_inputs()
            payloads["extid-alpha123"] = b'{"error": "temporary"}'

            result = database.ingest_snapshot(
                listing_json=(self.legacy / "raw" / "upstream_fixed.json").read_bytes(),
                listing_html=(self.legacy / "raw" / "upstream_fixed.html").read_bytes(),
                records=catalog["bugs"],
                bug_payloads=payloads,
                reports_dir=self.legacy / "artifacts" / "reports",
                patches_dir=self.legacy / "artifacts" / "patches",
                source_url=str(catalog["source"]),
            )

            self.assertEqual(result["status"], "partial")
            self.assertEqual(database.status()["current_snapshot"]["id"], before)
            self.assertTrue(any("does not look like" in item for item in result["failures"]))

    def test_malformed_bug_collections_cannot_activate(self) -> None:
        with Database(self.database_path) as database:
            self.import_fixture(database)
            before = database.status()["current_snapshot"]["id"]
            malformed_values = {
                "fix-commits": ["not an object"],
                "crashes": [1],
                "discussions": [123],
            }

            for field, malformed in malformed_values.items():
                catalog, payloads = self.direct_inputs()
                alpha = json.loads(payloads["extid-alpha123"])
                alpha[field] = malformed
                payloads["extid-alpha123"] = json.dumps(alpha).encode()

                result = database.ingest_snapshot(
                    listing_json=(self.legacy / "raw" / "upstream_fixed.json").read_bytes(),
                    listing_html=(self.legacy / "raw" / "upstream_fixed.html").read_bytes(),
                    records=catalog["bugs"],
                    bug_payloads=payloads,
                    reports_dir=self.legacy / "artifacts" / "reports",
                    patches_dir=self.legacy / "artifacts" / "patches",
                    source_url=str(catalog["source"]),
                )

                with self.subTest(field=field):
                    self.assertEqual(result["status"], "partial")
                    self.assertFalse(result["activated"])
                    self.assertEqual(database.status()["current_snapshot"]["id"], before)
                    self.assertTrue(any(field in failure for failure in result["failures"]))


if __name__ == "__main__":
    unittest.main()
