from __future__ import annotations

import hashlib
import json
import shutil
import sqlite3
import unittest
from pathlib import Path

from syz_sage.database import Database
from syz_sage.storage import temporary_directory

FIXTURES = Path(__file__).parent / "fixtures" / "legacy_data"
ALPHA_HASH = "a" * 40
BETA_HASH = "b" * 40


def tree_digests(root: Path) -> dict[str, str]:
    return {
        str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


class DatabaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = temporary_directory()
        self.root = Path(self.temporary.name)
        self.legacy = self.root / "legacy"
        shutil.copytree(FIXTURES, self.legacy)
        self.database_path = self.root / "store" / "syz-sage.sqlite3"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def import_fixture(self, database: Database) -> object:
        database.initialize()
        return database.import_legacy(self.legacy)

    def direct_inputs(self) -> tuple[dict[str, object], dict[str, bytes]]:
        catalog = json.loads((self.legacy / "processed" / "catalog.json").read_text())
        payloads = {
            path.stem: path.read_bytes() for path in (self.legacy / "raw" / "bugs").glob("*.json")
        }
        return catalog, payloads

    def ingest_direct(
        self,
        database: Database,
        *,
        records: object | None = None,
        listing_json: bytes | None = None,
        listing_html: bytes | None = None,
        errors: tuple[str, ...] = (),
    ) -> dict[str, object]:
        catalog, payloads = self.direct_inputs()
        selected_records = catalog["bugs"] if records is None else records
        return database.ingest_snapshot(
            listing_json=(
                (self.legacy / "raw" / "upstream_fixed.json").read_bytes()
                if listing_json is None
                else listing_json
            ),
            listing_html=(
                (self.legacy / "raw" / "upstream_fixed.html").read_bytes()
                if listing_html is None
                else listing_html
            ),
            records=selected_records,
            bug_payloads=payloads,
            reports_dir=self.legacy / "artifacts" / "reports",
            patches_dir=self.legacy / "artifacts" / "patches",
            source_url=str(catalog["source"]),
            errors=errors,
        )

    def test_initialize_creates_parent_and_database(self) -> None:
        with Database(self.database_path) as database:
            database.initialize()

        self.assertTrue(self.database_path.is_file())
        self.assertGreater(self.database_path.stat().st_size, 0)

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

    def test_database_persists_after_reopening(self) -> None:
        with Database(self.database_path) as database:
            self.import_fixture(database)

        with Database(self.database_path) as database:
            database.initialize()
            bug = database.get_bug("extid-alpha123")
            status = database.status()

        self.assertEqual(status["bugs"], 2)
        self.assertEqual(bug["fixes"][0]["hash"], ALPHA_HASH)

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

    def test_database_contains_artifact_bytes_not_only_legacy_paths(self) -> None:
        with Database(self.database_path) as database:
            self.import_fixture(database)

        database_bytes = self.database_path.read_bytes()
        self.assertIn(b"BUG: KASAN: use-after-free in alpha", database_bytes)
        self.assertIn(b"diff --git a/net/alpha.c b/net/alpha.c", database_bytes)

    def test_stored_resolution_applies_to_a_new_matching_bug_version(self) -> None:
        resolution_path = self.legacy / "processed" / "resolved_fix_hashes.json"
        resolution_payload = json.loads(resolution_path.read_text())
        resolution_payload["resolutions"][0].update(
            {
                "status": "resolved",
                "hash": BETA_HASH,
                "commit_url": f"https://example.test/commit/{BETA_HASH}",
            }
        )
        resolution_path.write_text(json.dumps(resolution_payload))
        (self.legacy / "artifacts" / "patches" / f"{BETA_HASH}.diff").write_bytes(
            b"From beta\n\ndiff --git a/fs/beta.c b/fs/beta.c\n"
            b"--- a/fs/beta.c\n+++ b/fs/beta.c\n@@ -1 +1 @@\n-old\n+new\n"
        )

        with Database(self.database_path) as database:
            self.import_fixture(database)
            self.assertEqual(database.get_bug("id-beta456")["fixes"][0]["hash"], BETA_HASH)

            catalog = json.loads((self.legacy / "processed" / "catalog.json").read_text())
            bug_payloads = {
                path.stem: path.read_bytes()
                for path in (self.legacy / "raw" / "bugs").glob("*.json")
            }
            changed_beta = json.loads(bug_payloads["id-beta456"])
            changed_beta["last-crash"] = "2026/09/01 10:00"
            bug_payloads["id-beta456"] = json.dumps(changed_beta).encode()

            database.ingest_snapshot(
                listing_json=(self.legacy / "raw" / "upstream_fixed.json").read_bytes(),
                listing_html=(self.legacy / "raw" / "upstream_fixed.html").read_bytes(),
                records=catalog["bugs"],
                bug_payloads=bug_payloads,
                reports_dir=self.legacy / "artifacts" / "reports",
                patches_dir=self.legacy / "artifacts" / "patches",
                source_url=catalog["source"],
            )

            beta = database.get_bug("id-beta456")
            self.assertEqual(beta["last_crash"], "2026/09/01 10:00")
            self.assertEqual(beta["fixes"][0]["hash"], BETA_HASH)

    def test_partial_resolution_does_not_leak_into_a_later_complete_snapshot(self) -> None:
        resolution_path = self.legacy / "processed" / "resolved_fix_hashes.json"
        payload = json.loads(resolution_path.read_text())
        with Database(self.database_path) as database:
            self.import_fixture(database)
            before = tuple(database.connection.execute("SELECT * FROM fix_resolutions").fetchone())
            payload["resolutions"][0].update(status="resolved", hash=ALPHA_HASH)
            resolution_path.write_text(json.dumps(payload))

            partial = database.ingest_files(self.legacy, errors=["incomplete test candidate"])
            self.assertEqual(partial["status"], "partial")
            self.assertEqual(
                tuple(database.connection.execute("SELECT * FROM fix_resolutions").fetchone()),
                before,
            )
            self.assertIsNone(database.get_bug("id-beta456")["fixes"][0]["hash"])
            evidence = database.connection.execute(
                """SELECT b.content FROM documents d JOIN blobs b ON b.sha256 = d.blob_sha256
                   WHERE d.kind = 'fix-resolution' AND d.last_seen_run_id = ?""",
                (partial["run_id"],),
            ).fetchone()
            self.assertEqual(json.loads(evidence["content"])["hash"], ALPHA_HASH)

            # A new complete candidate with no resolutions must not reuse
            # resolution evidence retained from the partial candidate.
            complete = self.ingest_direct(database)
            self.assertEqual(complete["status"], "completed")
            self.assertIsNone(database.get_bug("id-beta456")["fixes"][0]["hash"])

            # Retrying the actual candidate accepts its newly supplied hash.
            accepted = database.ingest_files(self.legacy)
            self.assertEqual(accepted["status"], "completed")
            self.assertEqual(database.get_bug("id-beta456")["fixes"][0]["hash"], ALPHA_HASH)

    def test_partial_resolution_cannot_overwrite_an_accepted_resolution(self) -> None:
        resolution_path = self.legacy / "processed" / "resolved_fix_hashes.json"
        payload = json.loads(resolution_path.read_text())
        payload["resolutions"][0].update(status="resolved", hash=ALPHA_HASH)
        resolution_path.write_text(json.dumps(payload))
        with Database(self.database_path) as database:
            self.import_fixture(database)
            before = tuple(database.connection.execute("SELECT * FROM fix_resolutions").fetchone())
            payload["resolutions"][0]["hash"] = BETA_HASH
            resolution_path.write_text(json.dumps(payload))
            # Missing BETA_HASH patch makes the resolution candidate incomplete.
            partial = database.ingest_files(self.legacy)
            self.assertEqual(partial["status"], "partial")
            self.assertEqual(
                tuple(database.connection.execute("SELECT * FROM fix_resolutions").fetchone()),
                before,
            )
            self.assertEqual(self.ingest_direct(database)["status"], "completed")
            self.assertEqual(database.get_bug("id-beta456")["fixes"][0]["hash"], ALPHA_HASH)

    def test_legacy_partial_resolution_is_not_reused_or_preserved_by_an_unresolved_result(
        self,
    ) -> None:
        with Database(self.database_path) as database:
            self.import_fixture(database)
            partial = self.ingest_direct(database, errors=("incomplete test candidate",))
            # Reproduce a fix_resolutions row written by an older implementation.
            database.connection.execute(
                "UPDATE fix_resolutions SET resolved_hash = ?, last_seen_run_id = ?",
                (ALPHA_HASH, partial["run_id"]),
            )
            self.assertEqual(self.ingest_direct(database)["status"], "completed")
            self.assertIsNone(database.get_bug("id-beta456")["fixes"][0]["hash"])
            self.assertEqual(database.import_legacy(self.legacy)["status"], "completed")
            self.assertIsNone(database.get_bug("id-beta456")["fixes"][0]["hash"])
            self.assertIsNone(
                database.connection.execute("SELECT resolved_hash FROM fix_resolutions").fetchone()[
                    0
                ]
            )

    def test_retained_removed_resolution_and_invalid_orphan_patch_do_not_block(self) -> None:
        resolution_path = self.legacy / "processed" / "resolved_fix_hashes.json"
        orphan_patch = self.legacy / "artifacts" / "patches" / "retained-orphan.diff"

        with Database(self.database_path) as database:
            self.import_fixture(database)

            listing_path = self.legacy / "raw" / "upstream_fixed.json"
            listing = json.loads(listing_path.read_text())
            listing["Bugs"] = listing["Bugs"][:1]
            listing_path.write_text(json.dumps(listing))
            html_path = self.legacy / "raw" / "upstream_fixed.html"
            html_path.write_text(
                html_path.read_text().replace('<a href="/bug?id=beta456">WARNING in beta</a>\n', "")
            )

            catalog_path = self.legacy / "processed" / "catalog.json"
            catalog = json.loads(catalog_path.read_text())
            catalog["bugs"] = catalog["bugs"][:1]
            catalog_path.write_text(json.dumps(catalog))

            orphan_patch.write_bytes(b"retained historical artifact, not a valid patch")
            resolution_before = resolution_path.read_bytes()
            orphan_before = orphan_patch.read_bytes()
            tree_before = tree_digests(self.legacy)

            result = database.import_legacy(self.legacy)
            status = database.status()
            invalid_document = database.connection.execute(
                """
                SELECT is_valid, validation_error
                FROM documents
                WHERE kind = 'patch' AND natural_key = 'retained-orphan'
                """
            ).fetchone()
            retained_resolution_document = database.connection.execute(
                """
                SELECT is_valid
                FROM documents
                WHERE kind = 'legacy-resolutions' AND natural_key = ?
                """,
                (str(resolution_path),),
            ).fetchone()
            historical_resolution = database.connection.execute(
                """
                SELECT COUNT(*)
                FROM fix_resolutions AS r
                JOIN bugs AS b ON b.id = r.bug_id
                WHERE b.key = 'id-beta456'
                """
            ).fetchone()[0]

        self.assertEqual(result["status"], "completed")
        self.assertTrue(result["activated"])
        self.assertEqual(result["failure_count"], 0)
        self.assertEqual(result["no_longer_listed_bug_keys"], ["id-beta456"])
        self.assertEqual(result["patch_details"]["orphan_files"], 1)
        self.assertEqual(result["patch_details"]["invalid"], 1)
        self.assertEqual(status["bugs"], 1)
        self.assertEqual(
            tuple(invalid_document), (0, "patch filename is not a hexadecimal commit hash")
        )
        self.assertEqual(tuple(retained_resolution_document), (1,))
        self.assertEqual(historical_resolution, 1)
        self.assertEqual(resolution_path.read_bytes(), resolution_before)
        self.assertEqual(orphan_patch.read_bytes(), orphan_before)
        self.assertEqual(tree_digests(self.legacy), tree_before)

    def test_listing_and_prepared_keys_must_match_exact_order(self) -> None:
        with Database(self.database_path) as database:
            self.import_fixture(database)
            current_id = database.status()["current_snapshot"]["id"]
            catalog, _ = self.direct_inputs()

            result = self.ingest_direct(database, records=list(reversed(catalog["bugs"])))

            self.assertEqual(result["status"], "failed")
            self.assertFalse(result.get("activated", False))
            self.assertEqual(database.status()["current_snapshot"]["id"], current_id)

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

    def test_blob_additions_are_the_exact_committed_delta(self) -> None:
        with Database(self.database_path) as database:
            database.initialize()
            before = database.status()["counts"]["blobs"]
            result = database.import_legacy(self.legacy)
            after = database.status()["counts"]["blobs"]

            self.assertEqual(result["blobs_added"], after - before)

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

    def test_initialize_rejects_non_pristine_or_incomplete_schema(self) -> None:
        non_pristine = self.root / "non-pristine.sqlite3"
        connection = sqlite3.connect(non_pristine)
        connection.execute("CREATE TABLE existing(value TEXT)")
        connection.close()
        database = Database(non_pristine)
        with self.assertRaisesRegex(RuntimeError, "non-pristine"):
            database.initialize()
        database.close()

        incomplete = self.root / "incomplete.sqlite3"
        connection = sqlite3.connect(incomplete)
        connection.execute("PRAGMA user_version = 1")
        connection.close()
        database = Database(incomplete)
        with self.assertRaisesRegex(RuntimeError, "incomplete or incompatible"):
            database.initialize()
        database.close()

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
