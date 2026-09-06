from __future__ import annotations

import json
import unittest
from unittest import mock

from syz_sage.database import SCHEMA_VERSION, Database
from syz_sage.retrieval.sync import (
    UpdateOptions,
    Updater,
)
from tests.retrieval.support import (
    FakeClient,
    ResolutionPatchClient,
    RewrittenHashClient,
    UpdaterFixture,
)
from tests.support import (
    BETA_HASH,
    GAMMA_HASH,
)


class UpdateResolutionsTests(UpdaterFixture, unittest.TestCase):
    def test_resolution_hash_repairs_missing_patch_using_resolution_repo(self) -> None:
        Updater(self.paths, self.database_path, client=FakeClient()).run(UpdateOptions(workers=2))
        repo = "git://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git"
        self.paths.resolutions.write_text(
            json.dumps(
                {
                    "resolutions": [
                        {
                            "bug_key": "id-beta456",
                            "title": "fs: guard beta state",
                            "repo": repo,
                            "status": "resolved",
                            "hash": BETA_HASH,
                            "commit_url": "https://provenance.example.invalid/not-a-repo",
                        }
                    ]
                }
            )
        )
        client = ResolutionPatchClient()

        summary = Updater(self.paths, self.database_path, client=client).run(
            UpdateOptions(workers=2)
        )

        self.assertTrue(summary.ok, summary.failures)
        self.assertEqual(summary.database["status"], "completed")
        self.assertTrue(summary.database["activated"])
        self.assertEqual(client.bug_calls, [])
        self.assertEqual(client.patch_calls, [BETA_HASH])
        self.assertEqual(client.patch_repos, [repo])
        self.assertTrue((self.paths.patches / f"{BETA_HASH}.diff").is_file())
        with Database(self.database_path) as database:
            beta = database.get_bug("id-beta456")
        beta_fix = next(fix for fix in beta["fixes"] if fix["title"] == "fs: guard beta state")
        self.assertEqual(beta_fix["hash"], BETA_HASH)
        self.assertTrue(beta_fix["patch_available"])

    def test_invalid_current_resolution_hash_is_a_partial_failure(self) -> None:
        Updater(self.paths, self.database_path, client=FakeClient()).run(UpdateOptions(workers=2))
        self.paths.resolutions.write_text(
            json.dumps(
                {
                    "resolutions": [
                        {
                            "bug_key": "id-beta456",
                            "title": "fs: guard beta state",
                            "repo": "git://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git",
                            "hash": ["not", "a", "hash"],
                        }
                    ]
                }
            )
        )
        client = ResolutionPatchClient()

        summary = Updater(self.paths, self.database_path, client=client).run(
            UpdateOptions(workers=2)
        )

        self.assertFalse(summary.ok)
        self.assertEqual(summary.database["status"], "partial")
        self.assertEqual(client.patch_calls, [])
        self.assertIn(
            "invalid commit hash",
            next(
                failure["error"]
                for failure in summary.failures
                if failure["kind"] == "resolution-metadata"
            ),
        )

    def test_malformed_hash_for_historical_resolution_is_ignored(self) -> None:
        Updater(self.paths, self.database_path, client=FakeClient()).run(UpdateOptions(workers=2))
        self.paths.resolutions.write_text(
            json.dumps(
                {
                    "resolutions": [
                        {
                            "bug_key": "id-gamma789",
                            "title": "historical gamma fix",
                            "hash": ["retained", "historical", "value"],
                        }
                    ]
                }
            )
        )
        client = ResolutionPatchClient()

        summary = Updater(self.paths, self.database_path, client=client).run(
            UpdateOptions(workers=2)
        )

        self.assertTrue(summary.ok, summary.failures)
        self.assertEqual(client.patch_calls, [])

    def test_obsolete_resolution_of_current_bug_does_not_require_its_patch(self) -> None:
        Updater(self.paths, self.database_path, client=FakeClient()).run()
        self.paths.resolutions.write_text(
            json.dumps(
                {
                    "resolutions": [
                        {
                            "bug_key": "id-beta456",
                            "title": "obsolete fix no longer referenced",
                            "repo": "git://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git",
                            "status": "resolved",
                            "hash": GAMMA_HASH,
                        }
                    ]
                }
            )
        )
        client = FakeClient()
        completed = Updater(self.paths, self.database_path, client=client).run()
        self.assertTrue(completed.ok, completed.failures)
        self.assertEqual(completed.database["status"], "completed")
        self.assertEqual(client.patch_calls, [])
        self.assertFalse((self.paths.patches / f"{GAMMA_HASH}.diff").exists())

    def test_accepted_resolution_repairs_patch_after_file_loses_its_hash(self) -> None:
        Updater(self.paths, self.database_path, client=FakeClient()).run()
        resolution = {
            "bug_key": "id-beta456",
            "title": "fs: guard beta state",
            "repo": "git://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git",
            "status": "resolved",
            "hash": BETA_HASH,
        }
        self.paths.resolutions.write_text(json.dumps({"resolutions": [resolution]}))
        first = Updater(self.paths, self.database_path, client=ResolutionPatchClient()).run()
        self.assertTrue(first.ok, first.failures)
        (self.paths.patches / f"{BETA_HASH}.diff").unlink()
        resolution.pop("hash")
        resolution["status"] = "unresolved"
        self.paths.resolutions.write_text(json.dumps({"resolutions": [resolution]}))

        client = ResolutionPatchClient()
        repaired = Updater(self.paths, self.database_path, client=client).run()
        self.assertTrue(repaired.ok, repaired.failures)
        self.assertEqual(client.patch_calls, [BETA_HASH])
        with Database(self.database_path, read_only=True) as database:
            self.assertEqual(database.get_bug("id-beta456")["fixes"][0]["hash"], BETA_HASH)

    def test_schema4_update_reads_accepted_resolution_before_automatic_migration(self) -> None:
        Updater(self.paths, self.database_path, client=FakeClient()).run()
        resolution = {
            "bug_key": "id-beta456",
            "title": "fs: guard beta state",
            "repo": "git://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git",
            "status": "resolved",
            "hash": BETA_HASH,
        }
        self.paths.resolutions.write_text(json.dumps({"resolutions": [resolution]}))
        first = Updater(self.paths, self.database_path, client=ResolutionPatchClient()).run()
        self.assertTrue(first.ok, first.failures)
        with Database(self.database_path) as database:
            old_snapshot = database.status()["current_snapshot"]["id"]
            source_hashes = {
                row[0] for row in database.connection.execute("SELECT sha256 FROM blobs")
            }
            # Schema 5 changes report parsing; reconstruct the schema 4 marker
            # and parser versions while retaining its accepted fix resolution.
            database.connection.execute("UPDATE crash_locations SET parser_version=2")
            database.connection.execute("UPDATE crash_stack_frames SET parser_version=2")
            database.connection.execute("PRAGMA user_version=4")
        (self.paths.patches / f"{BETA_HASH}.diff").unlink()
        resolution.pop("hash")
        resolution["status"] = "unresolved"
        self.paths.resolutions.write_text(json.dumps({"resolutions": [resolution]}))
        original_accepted = Database.accepted_resolutions
        read_only_versions: list[int] = []

        def accepted(database, targets):
            if database._read_only:
                read_only_versions.append(
                    database.connection.execute("PRAGMA user_version").fetchone()[0]
                )
                with mock.patch.object(
                    database, "initialize", side_effect=AssertionError("read-only migration")
                ):
                    return original_accepted(database, targets)
            return original_accepted(database, targets)

        client = ResolutionPatchClient()
        with mock.patch.object(Database, "accepted_resolutions", new=accepted):
            completed = Updater(self.paths, self.database_path, client=client).run()
        self.assertTrue(completed.ok, completed.failures)
        self.assertEqual(read_only_versions, [4])
        self.assertEqual(client.patch_calls, [BETA_HASH])
        self.assertEqual(client.bug_calls, [])
        self.assertEqual(client.report_calls, [])
        with Database(self.database_path, read_only=True) as database:
            self.assertEqual(database.status()["schema_version"], SCHEMA_VERSION)
            self.assertEqual(database.get_bug("id-beta456")["fixes"][0]["hash"], BETA_HASH)
            self.assertTrue(database.get_bug("id-beta456")["fixes"][0]["patch_available"])
            self.assertTrue(database.health_check()["ok"])
            self.assertIsNotNone(
                database.connection.execute(
                    "SELECT id FROM snapshots WHERE id=?", (old_snapshot,)
                ).fetchone()
            )
            self.assertTrue(
                source_hashes
                <= {row[0] for row in database.connection.execute("SELECT sha256 FROM blobs")}
            )

    def test_matching_file_resolution_overrides_accepted_hash_for_downloads(self) -> None:
        Updater(self.paths, self.database_path, client=FakeClient()).run()
        resolution = {
            "bug_key": "id-beta456",
            "title": "fs: guard beta state",
            "repo": "git://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git",
            "status": "resolved",
            "hash": BETA_HASH,
        }
        self.paths.resolutions.write_text(json.dumps({"resolutions": [resolution]}))
        first = Updater(self.paths, self.database_path, client=ResolutionPatchClient()).run()
        self.assertTrue(first.ok, first.failures)
        (self.paths.patches / f"{BETA_HASH}.diff").unlink()
        resolution["hash"] = GAMMA_HASH
        self.paths.resolutions.write_text(json.dumps({"resolutions": [resolution]}))

        client = ResolutionPatchClient()
        completed = Updater(self.paths, self.database_path, client=client).run()
        self.assertTrue(completed.ok, completed.failures)
        self.assertEqual(client.patch_calls, [GAMMA_HASH])

    def test_invalid_commit_hash_never_reaches_patch_client_or_filesystem(self) -> None:
        unsafe_hash = "../escaped-" + "a" * 29
        client = RewrittenHashClient(unsafe_hash)

        summary = Updater(self.paths, self.database_path, client=client).run(
            UpdateOptions(workers=2)
        )

        self.assertFalse(summary.ok)
        self.assertEqual(client.patch_calls, [])
        self.assertIn("patch-metadata", {failure["kind"] for failure in summary.failures})
        self.assertFalse((self.paths.artifacts / f"escaped-{'a' * 29}.diff").exists())
        self.assertEqual(summary.database["status"], "partial")
        self.assertFalse(summary.database["activated"])


if __name__ == "__main__":
    unittest.main()
