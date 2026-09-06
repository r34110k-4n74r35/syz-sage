from __future__ import annotations

import json
import unittest

from syz_sage.database import Database
from syz_sage.retrieval.resolutions import resolution_targets
from tests.database.support import DatabaseFixture
from tests.support import (
    ALPHA_HASH,
    BETA_HASH,
    tree_digests,
)


class DatabaseResolutionsTests(DatabaseFixture, unittest.TestCase):
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

    def test_accepted_resolution_still_requires_patch_when_source_hash_is_removed(self) -> None:
        resolution_path = self.legacy / "processed" / "resolved_fix_hashes.json"
        original = resolution_path.read_bytes()
        payload = json.loads(original)
        payload["resolutions"][0].update(status="resolved", hash=BETA_HASH)
        resolution_path.write_text(json.dumps(payload))
        patch_path = self.legacy / "artifacts" / "patches" / f"{BETA_HASH}.diff"
        patch = (patch_path.parent / f"{ALPHA_HASH}.diff").read_bytes()
        patch_path.write_bytes(patch)
        with Database(self.database_path) as database:
            first = database.import_legacy(self.legacy)
            self.assertEqual(first["status"], "completed", first)
            resolution_path.write_bytes(original)
            patch_path.unlink()
            partial = database.import_legacy(self.legacy)
            self.assertEqual(partial["status"], "partial", partial)
            self.assertTrue(any("patch(es) missing" in item for item in partial["failures"]))
            beta = database.get_bug("id-beta456")
            self.assertEqual(beta["snapshot_id"], first["snapshot_id"])
            self.assertEqual(beta["fixes"][0]["hash"], BETA_HASH)
            self.assertTrue(beta["fixes"][0]["patch_available"])
            patch_path.write_bytes(patch)
            self.assertEqual(database.import_legacy(self.legacy)["status"], "completed")

    def test_obsolete_resolution_and_pending_patch_do_not_block_a_current_fix(self) -> None:
        resolution_path = self.legacy / "processed" / "resolved_fix_hashes.json"
        payload = json.loads(resolution_path.read_bytes())
        payload["resolutions"][0].update(status="resolved", hash=BETA_HASH)
        resolution_path.write_text(json.dumps(payload))
        patch_path = self.legacy / "artifacts" / "patches" / f"{BETA_HASH}.diff"
        patch_path.write_bytes((patch_path.parent / f"{ALPHA_HASH}.diff").read_bytes())
        with Database(self.database_path) as database:
            self.assertEqual(database.import_legacy(self.legacy)["status"], "completed")
            patch_path.unlink()
            for path, collection, field in (
                (self.legacy / "raw" / "upstream_fixed.json", "Bugs", "fix-commits"),
                (self.legacy / "processed" / "catalog.json", "bugs", "fix_commits"),
            ):
                document = json.loads(path.read_bytes())
                document[collection][1][field][0].update(
                    title="fs: current beta fix", hash=ALPHA_HASH
                )
                path.write_text(json.dumps(document))
            detail = self.legacy / "raw" / "bugs" / "id-beta456.json"
            document = json.loads(detail.read_bytes())
            document["fix-commits"][0].update(title="fs: current beta fix", hash=ALPHA_HASH)
            detail.write_text(json.dumps(document))
            (self.legacy / "processed" / "sync_state.json").write_text(
                json.dumps(
                    {
                        "version": 2,
                        "pending_details": [],
                        "pending_reports": [],
                        "pending_patches": [BETA_HASH],
                    }
                )
            )
            result = database.import_legacy(self.legacy)
            self.assertEqual(result["status"], "completed", result)
            self.assertEqual(database.get_bug("id-beta456")["fixes"][0]["hash"], ALPHA_HASH)
            self.assertEqual(
                database.connection.execute("SELECT resolved_hash FROM fix_resolutions").fetchone()[
                    0
                ],
                BETA_HASH,
            )

    def test_matching_new_resolution_replaces_old_patch_dependency(self) -> None:
        resolution_path = self.legacy / "processed" / "resolved_fix_hashes.json"
        payload = json.loads(resolution_path.read_bytes())
        payload["resolutions"][0].update(status="resolved", hash=BETA_HASH)
        resolution_path.write_text(json.dumps(payload))
        patch_path = self.legacy / "artifacts" / "patches" / f"{BETA_HASH}.diff"
        patch_path.write_bytes((patch_path.parent / f"{ALPHA_HASH}.diff").read_bytes())
        with Database(self.database_path) as database:
            self.assertEqual(database.import_legacy(self.legacy)["status"], "completed")
            catalog, details = self.direct_inputs()
            targets = resolution_targets(
                catalog["bugs"], {k: json.loads(v) for k, v in details.items()}
            )
            self.assertEqual(database.accepted_resolutions(targets)[0]["hash"], BETA_HASH)
            self.assertEqual(database.accepted_resolutions({"id-beta456": {("other", "")}}), [])
            patch_path.unlink()
            payload["resolutions"][0]["hash"] = ALPHA_HASH
            resolution_path.write_text(json.dumps(payload))
            result = database.import_legacy(self.legacy)
            self.assertEqual(result["status"], "completed", result)
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


if __name__ == "__main__":
    unittest.main()
