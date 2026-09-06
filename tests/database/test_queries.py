from __future__ import annotations

import json
import sqlite3
import unittest
from unittest import mock

from syz_sage.database import Database, location_store
from tests.database.support import DatabaseFixture
from tests.support import (
    ALPHA_HASH,
    BETA_HASH,
    tree_digests,
)


class DatabaseQueriesTests(DatabaseFixture, unittest.TestCase):
    def test_legacy_import_is_lossless_and_queryable(self) -> None:
        before = tree_digests(self.legacy)

        with Database(self.database_path) as database:
            result = self.import_fixture(database)
            status = database.status()
            alpha = database.get_bug("extid-alpha123")
            beta = database.get_bug("id-beta456")

        self.assertIsNotNone(result)
        self.assertEqual(before, tree_digests(self.legacy))
        self.assertEqual(status["bugs"], 2)
        self.assertEqual(status["fixes"], 2)
        self.assertEqual(status["crashes"], 2)
        self.assertEqual(status["reports"], 1)
        self.assertEqual(status["patches"], 1)

        self.assertIsNotNone(alpha)
        self.assertEqual(alpha["key"], "extid-alpha123")
        self.assertEqual(alpha["title"], "KASAN: use-after-free in alpha")
        self.assertEqual(alpha["fixes"][0]["hash"], ALPHA_HASH)
        self.assertEqual(len(alpha["crashes"]), 1)
        self.assertIn("text", alpha["report"])
        self.assertNotIn("content", alpha["report"])

        self.assertIsNotNone(beta)
        self.assertEqual(beta["key"], "id-beta456")
        self.assertEqual(beta["title"], "WARNING in beta")
        self.assertIn(beta["fixes"][0].get("hash"), {None, ""})

    def test_list_bugs_supports_case_insensitive_search_and_limit(self) -> None:
        with Database(self.database_path) as database:
            self.import_fixture(database)
            matches = database.list_bugs(query="kasan", limit=10)
            limited = database.list_bugs(limit=1)

        self.assertEqual([bug["key"] for bug in matches], ["extid-alpha123"])
        self.assertEqual(len(limited), 1)

    def test_get_bug_returns_none_for_unknown_key(self) -> None:
        with Database(self.database_path) as database:
            database.initialize()
            self.assertIsNone(database.get_bug("extid-does-not-exist"))

    def test_get_bug_keeps_one_snapshot_while_an_updater_activates(self) -> None:
        with Database(self.database_path) as writer:
            self.import_fixture(writer)
            with Database(self.database_path, read_only=True) as reader:
                before = reader.get_bug("extid-alpha123")
                original = location_store.bug_locations

                def activate_before_locations(connection: sqlite3.Connection, bug_id: int) -> dict:
                    report = self.legacy / "artifacts" / "reports" / "extid-alpha123.txt"
                    report.write_text(report.read_text().replace("alpha.c:42", "alpha.c:77"))
                    listing = self.legacy / "raw" / "upstream_fixed.html"
                    listing.write_text(
                        "<html><body><table><tr><td>"
                        '<a href="/bug?extid=alpha123">alpha</a></td><td>'
                        '<a href="/upstream/fixed?label=subsystems%3Ausb">usb</a></td></tr>'
                        '<tr><td><a href="/bug?id=beta456">beta</a></td></tr></table></body></html>'
                    )
                    result = writer.import_legacy(self.legacy)
                    self.assertEqual(result["status"], "completed", result)
                    return original(connection, bug_id)

                with mock.patch.object(
                    location_store, "bug_locations", side_effect=activate_before_locations
                ):
                    during = reader.get_bug("extid-alpha123")
                self.assertEqual(during, before)
                latest = reader.get_bug("extid-alpha123")
                self.assertNotEqual(latest["snapshot_id"], before["snapshot_id"])
                self.assertIn("alpha.c:77", latest["report"]["text"])
                self.assertEqual(latest["crash_locations"][0]["line_number"], 77)
                self.assertIn("usb", latest["subsystems"])
                self.assertEqual(reader.connection.total_changes, 0)
                with reader._transaction("DEFERRED"):
                    self.assertEqual(reader.get_bug("extid-alpha123"), latest)
                    self.assertTrue(reader.connection.in_transaction)

    def test_database_contains_artifact_bytes_not_only_legacy_paths(self) -> None:
        with Database(self.database_path) as database:
            self.import_fixture(database)

        database_bytes = self.database_path.read_bytes()
        self.assertIn(b"BUG: KASAN: use-after-free in alpha", database_bytes)
        self.assertIn(b"diff --git a/net/alpha.c b/net/alpha.c", database_bytes)

    def test_listing_only_fix_is_queryable_and_associated_with_patch(self) -> None:
        beta_path = self.legacy / "raw" / "bugs" / "id-beta456.json"
        beta = json.loads(beta_path.read_text())
        beta["fix-commits"] = []
        beta_path.write_text(json.dumps(beta))
        for path, container_name in (
            (self.legacy / "raw" / "upstream_fixed.json", "Bugs"),
            (self.legacy / "processed" / "catalog.json", "bugs"),
        ):
            payload = json.loads(path.read_text())
            fixes_name = "fix-commits" if container_name == "Bugs" else "fix_commits"
            payload[container_name][1][fixes_name][0]["hash"] = BETA_HASH
            path.write_text(json.dumps(payload))
        (self.legacy / "artifacts" / "patches" / f"{BETA_HASH}.diff").write_bytes(
            b"From beta\n\ndiff --git a/fs/beta.c b/fs/beta.c\n"
            b"--- a/fs/beta.c\n+++ b/fs/beta.c\n@@ -1 +1 @@\n-old\n+new\n"
        )

        with Database(self.database_path) as database:
            result = database.import_legacy(self.legacy)
            bug = database.get_bug("id-beta456")
            listed = {item["key"]: item for item in database.list_bugs(limit=10)}
            status = database.status()

        self.assertEqual(result["status"], "completed")
        self.assertEqual(bug["fixes"][0]["hash"], BETA_HASH)
        self.assertEqual(bug["fixes"][0]["sources"], ["listing"])
        self.assertTrue(bug["fixes"][0]["patch_available"])
        self.assertEqual(listed["id-beta456"]["fix_count"], 1)
        self.assertEqual(status["fixes"], 2)
        self.assertEqual(status["patches"], 2)

    def test_distinct_fix_hashes_with_same_subject_remain_queryable(self) -> None:
        alpha_path = self.legacy / "raw" / "bugs" / "extid-alpha123.json"
        alpha = json.loads(alpha_path.read_text())
        alpha["fix-commits"][0]["hash"] = BETA_HASH
        alpha_path.write_text(json.dumps(alpha))
        (self.legacy / "artifacts" / "patches" / f"{BETA_HASH}.diff").write_bytes(
            b"diff --git a/net/backport.c b/net/backport.c\n"
            b"--- a/net/backport.c\n+++ b/net/backport.c\n@@ -1 +1 @@\n-old\n+new\n"
        )

        with Database(self.database_path) as database:
            result = database.import_legacy(self.legacy)
            bug = database.get_bug("extid-alpha123")
            listed = database.list_bugs()
            status = database.status()

        self.assertEqual(result["status"], "completed")
        self.assertEqual([fix["hash"] for fix in bug["fixes"]], [ALPHA_HASH, BETA_HASH])
        self.assertEqual([fix["sources"] for fix in bug["fixes"]], [["listing"], ["bug-json"]])
        self.assertEqual(listed[0]["fix_count"], 2)
        self.assertEqual(status["fixes"], 3)
        self.assertEqual(
            {location["commit_hash"] for location in bug["fix_locations"]}, {ALPHA_HASH, BETA_HASH}
        )

    def test_fix_merging_does_not_borrow_another_commits_patch(self) -> None:
        rows = [
            {
                "source_kind": "listing",
                "normalized_title": "same subject",
                "repo": "same repo",
                "reported_hash": ALPHA_HASH,
                "patch_sha256": None,
            },
            {
                "source_kind": "bug-json",
                "normalized_title": "same subject",
                "repo": "same repo",
                "reported_hash": BETA_HASH,
                "patch_sha256": "downloaded",
            },
        ]
        fixes = Database._merge_fix_rows(rows)
        self.assertEqual(
            [(fix["hash"], fix["patch_available"]) for fix in fixes],
            [(ALPHA_HASH, False), (BETA_HASH, True)],
        )

    def test_ambiguous_title_only_fix_is_not_assigned_an_arbitrary_hash(self) -> None:
        base = {"normalized_title": "same subject", "repo": "same repo"}
        unknown = {**base, "source_kind": "listing", "reported_hash": None}
        alpha = {**base, "source_kind": "bug-json", "reported_hash": ALPHA_HASH}
        beta = {**base, "source_kind": "bug-json", "reported_hash": BETA_HASH}
        for rows in ([unknown, alpha, beta], [alpha, unknown, beta], [beta, alpha, unknown]):
            with self.subTest(rows=rows):
                fixes = Database._merge_fix_rows(rows)
                self.assertEqual({fix["hash"] for fix in fixes}, {None, ALPHA_HASH, BETA_HASH})
                self.assertEqual(len(fixes), 3)

        fixes = Database._merge_fix_rows([unknown, alpha])
        self.assertEqual(len(fixes), 1)
        self.assertEqual(fixes[0]["hash"], ALPHA_HASH)
        self.assertEqual(set(fixes[0]["sources"]), {"listing", "bug-json"})

    def test_partial_only_bug_is_not_exposed_by_active_inspection(self) -> None:
        with Database(self.database_path) as database:
            self.import_fixture(database)
            catalog, payloads = self.direct_inputs()
            listing = json.loads((self.legacy / "raw" / "upstream_fixed.json").read_text())
            listing["Bugs"].append(
                {
                    "title": "partial-only bug",
                    "link": "/bug?extid=partial789",
                    "fix-commits": [],
                }
            )
            catalog["bugs"].append(
                {
                    "key": "extid-partial789",
                    "title": "partial-only bug",
                    "bug_url": "https://syzkaller.appspot.com/bug?extid=partial789",
                    "json_url": ("https://syzkaller.appspot.com/bug?extid=partial789&json=1"),
                    "fix_commits": [],
                }
            )
            payloads["extid-partial789"] = json.dumps(
                {
                    "id": "partial789",
                    "title": "partial-only bug",
                    "fix-commits": [],
                    "crashes": [],
                }
            ).encode()

            result = database.ingest_snapshot(
                listing_json=json.dumps(listing).encode(),
                listing_html=(self.legacy / "raw" / "upstream_fixed.html").read_bytes(),
                records=catalog["bugs"],
                bug_payloads=payloads,
                reports_dir=self.legacy / "artifacts" / "reports",
                patches_dir=self.legacy / "artifacts" / "patches",
                source_url=str(catalog["source"]),
                errors=("candidate is intentionally incomplete",),
            )

            self.assertEqual(result["status"], "partial")
            self.assertIsNone(database.get_bug("extid-partial789"))
            self.assertNotIn(
                "extid-partial789",
                {item["key"] for item in database.list_bugs(limit=10)},
            )
            self.assertIsNotNone(
                database.connection.execute(
                    "SELECT id FROM bugs WHERE key = 'extid-partial789'"
                ).fetchone()
            )

    def test_keys_and_text_queries_are_literal_and_filesystem_safe(self) -> None:
        prepared, errors = Database._prepare_records(
            [{"key": "extid-alpha:beta", "title": "unsafe"}]
        )
        self.assertEqual(prepared, [])
        self.assertTrue(any("unsafe bug key" in error for error in errors))

        with Database(self.database_path) as database:
            self.import_fixture(database)
            self.assertEqual(database.list_bugs(query="%", limit=10), [])
            self.assertEqual(database.list_bugs(query="_", limit=10), [])


if __name__ == "__main__":
    unittest.main()
