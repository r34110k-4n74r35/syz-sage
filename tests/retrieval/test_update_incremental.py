from __future__ import annotations

import unittest
from unittest import mock

from syz_sage.database import Database
from syz_sage.retrieval.sync import (
    UpdateOptions,
    Updater,
)
from tests.retrieval.support import (
    ExpandedListingClient,
    FakeClient,
    UpdaterFixture,
)
from tests.support import (
    ALPHA_HASH,
    GAMMA_HASH,
    digest,
)


class UpdateIncrementalTests(UpdaterFixture, unittest.TestCase):
    def test_identical_update_makes_no_detail_or_artifact_requests(self) -> None:
        Updater(self.paths, self.database_path, client=FakeClient()).run(UpdateOptions(workers=2))
        catalog_before = self.paths.catalog.read_bytes()
        database_before = digest(self.database_path)
        database_mtime = self.database_path.stat().st_mtime_ns
        mirror_mtimes = {
            path: path.stat().st_mtime_ns
            for path in (
                self.paths.listing_json,
                self.paths.listing_html,
                self.paths.catalog,
                self.paths.sync_state,
            )
        }
        client = FakeClient()

        with mock.patch.object(Database, "ingest_files", side_effect=AssertionError("must skip")):
            summary = Updater(self.paths, self.database_path, client=client).run(
                UpdateOptions(workers=2)
            )

        self.assertTrue(summary.ok, summary.failures)
        self.assertEqual(summary.database["status"], "unchanged")
        self.assertTrue(summary.database["skipped"])
        self.assertEqual(digest(self.database_path), database_before)
        self.assertEqual(self.database_path.stat().st_mtime_ns, database_mtime)
        self.assertEqual(summary.known_fixed_bugs, 2)
        self.assertEqual(summary.new_fixed_bugs, 0)
        self.assertEqual(summary.new_fixed_bug_keys, [])
        self.assertEqual(summary.changed_bugs, 0)
        self.assertEqual(summary.changed_bug_keys, [])
        self.assertEqual(summary.no_longer_listed_bugs, 0)
        self.assertEqual(summary.details_downloaded, 0)
        self.assertEqual(summary.details_reused, 2)
        self.assertEqual(summary.reports_downloaded, 0)
        self.assertEqual(summary.reports_reused, 1)
        self.assertEqual(summary.patches_downloaded, 0)
        self.assertEqual(summary.patches_reused, 1)
        self.assertEqual(client.bug_calls, [])
        self.assertEqual(client.report_calls, [])
        self.assertEqual(client.patch_calls, [])
        self.assertEqual(self.paths.catalog.read_bytes(), catalog_before)
        self.assertEqual({path: path.stat().st_mtime_ns for path in mirror_mtimes}, mirror_mtimes)

    def test_cached_files_initialize_a_missing_or_empty_database(self) -> None:
        Updater(self.paths, self.database_path, client=FakeClient()).run()
        for name in ("missing.sqlite3", "empty.sqlite3"):
            with self.subTest(name=name):
                target = self.paths.root / name
                if name == "empty.sqlite3":
                    target.touch()
                client = FakeClient()
                summary = Updater(self.paths, target, client=client).run()
                self.assertTrue(summary.ok, summary.failures)
                self.assertEqual(summary.database["status"], "completed")
                self.assertFalse(summary.database["skipped"])
                self.assertEqual(client.bug_calls, [])
                self.assertEqual(client.report_calls, [])
                self.assertEqual(client.patch_calls, [])
                with Database(target) as database:
                    self.assertEqual(database.status()["bugs"], 2)

    def test_downloaded_but_unindexed_files_are_ingested_on_next_update(self) -> None:
        Updater(self.paths, self.database_path, client=FakeClient()).run()
        with (
            mock.patch.object(Database, "ingest_files", side_effect=RuntimeError("interrupted")),
            self.assertRaisesRegex(RuntimeError, "interrupted"),
        ):
            Updater(self.paths, self.database_path, client=ExpandedListingClient()).run()

        client = ExpandedListingClient()
        summary = Updater(self.paths, self.database_path, client=client).run()
        self.assertTrue(summary.ok, summary.failures)
        self.assertFalse(summary.database["skipped"])
        self.assertEqual(summary.new_fixed_bug_keys, ["id-gamma789"])
        self.assertEqual(client.bug_calls, [])
        self.assertEqual(client.report_calls, [])
        self.assertEqual(client.patch_calls, [])
        with Database(self.database_path) as database:
            self.assertEqual(database.status()["bugs"], 3)

    def test_new_fixed_bug_fetches_only_its_missing_files(self) -> None:
        Updater(self.paths, self.database_path, client=FakeClient()).run(UpdateOptions(workers=2))
        client = ExpandedListingClient()

        summary = Updater(self.paths, self.database_path, client=client).run(
            UpdateOptions(workers=2)
        )

        self.assertTrue(summary.ok, summary.failures)
        self.assertEqual(summary.database["status"], "completed")
        self.assertTrue(summary.database["activated"])
        self.assertEqual(summary.known_fixed_bugs, 2)
        self.assertEqual(summary.new_fixed_bugs, 1)
        self.assertEqual(summary.new_fixed_bug_keys, ["id-gamma789"])
        self.assertEqual(summary.changed_bug_keys, [])
        self.assertEqual(client.bug_calls, ["id-gamma789"])
        self.assertEqual(
            client.report_calls,
            ["https://syzkaller.appspot.com/text?tag=CrashReport&x=gamma"],
        )
        self.assertEqual(client.patch_calls, [GAMMA_HASH])
        self.assertEqual(summary.details_downloaded, 1)
        self.assertEqual(summary.details_reused, 2)
        self.assertEqual(summary.reports_downloaded, 1)
        self.assertEqual(summary.reports_reused, 1)
        self.assertEqual(summary.patches_downloaded, 1)
        self.assertEqual(summary.patches_reused, 1)
        self.assertTrue((self.paths.bugs / "id-gamma789.json").is_file())
        self.assertTrue((self.paths.reports / "id-gamma789.txt").is_file())
        self.assertTrue((self.paths.patches / f"{GAMMA_HASH}.diff").is_file())
        with Database(self.database_path) as database:
            self.assertEqual(database.status()["bugs"], 3)

    def test_missing_known_files_are_repaired_without_listing_changes(self) -> None:
        Updater(self.paths, self.database_path, client=FakeClient()).run(UpdateOptions(workers=2))
        (self.paths.bugs / "id-beta456.json").unlink()
        (self.paths.reports / "extid-alpha123.txt").unlink()
        (self.paths.patches / f"{ALPHA_HASH}.diff").unlink()
        client = FakeClient()

        summary = Updater(self.paths, self.database_path, client=client).run(
            UpdateOptions(workers=2)
        )

        self.assertTrue(summary.ok, summary.failures)
        self.assertEqual(summary.database["status"], "unchanged")
        self.assertEqual(summary.new_fixed_bugs, 0)
        self.assertEqual(summary.changed_bugs, 0)
        self.assertEqual(client.bug_calls, ["id-beta456"])
        self.assertEqual(
            client.report_calls,
            ["https://syzkaller.appspot.com/text?tag=CrashReport&x=alpha"],
        )
        self.assertEqual(client.patch_calls, [ALPHA_HASH])
        self.assertEqual(summary.details_downloaded, 1)
        self.assertEqual(summary.reports_downloaded, 1)
        self.assertEqual(summary.patches_downloaded, 1)

    def test_readded_bug_reuses_all_retained_files(self) -> None:
        Updater(self.paths, self.database_path, client=ExpandedListingClient()).run()
        Updater(self.paths, self.database_path, client=FakeClient()).run()
        client = ExpandedListingClient(fail_new_bug=True)

        summary = Updater(self.paths, self.database_path, client=client).run()

        self.assertTrue(summary.ok, summary.failures)
        self.assertEqual(client.bug_calls, [])
        self.assertEqual(client.report_calls, [])
        self.assertEqual(client.patch_calls, [])
        self.assertEqual(summary.details_reused, 3)
        with Database(self.database_path) as database:
            self.assertEqual(database.status()["bugs"], 3)

    def test_missing_listing_does_not_redownload_saved_bugs(self) -> None:
        Updater(self.paths, self.database_path, client=FakeClient()).run()
        self.paths.listing_json.unlink()
        client = FakeClient()

        summary = Updater(self.paths, self.database_path, client=client).run()

        self.assertTrue(summary.ok, summary.failures)
        self.assertEqual(client.bug_calls, [])
        self.assertEqual(client.report_calls, [])
        self.assertEqual(client.patch_calls, [])
        self.assertTrue(summary.database["skipped"])

    def test_no_longer_listed_bug_leaves_retained_files_in_place(self) -> None:
        Updater(
            self.paths,
            self.database_path,
            client=ExpandedListingClient(),
        ).run(UpdateOptions(workers=2))
        gamma_files = [
            self.paths.bugs / "id-gamma789.json",
            self.paths.reports / "id-gamma789.txt",
            self.paths.patches / f"{GAMMA_HASH}.diff",
        ]
        self.assertTrue(all(path.is_file() for path in gamma_files))

        summary = Updater(self.paths, self.database_path, client=FakeClient()).run(
            UpdateOptions(workers=2)
        )

        self.assertTrue(summary.ok, summary.failures)
        self.assertEqual(summary.no_longer_listed_bugs, 1)
        self.assertEqual(summary.no_longer_listed_bug_keys, ["id-gamma789"])
        self.assertTrue(all(path.is_file() for path in gamma_files))
        with Database(self.database_path) as database:
            self.assertEqual(database.status()["bugs"], 2)

    def test_limited_update_reuses_files_but_remains_non_current(self) -> None:
        Updater(self.paths, self.database_path, client=FakeClient()).run(UpdateOptions(workers=2))
        with Database(self.database_path) as database:
            prior_snapshot = database.status()["current_snapshot"]["id"]
        before = {
            "bug": digest(self.paths.bugs / "extid-alpha123.json"),
            "report": digest(self.paths.reports / "extid-alpha123.txt"),
            "patch": digest(self.paths.patches / f"{ALPHA_HASH}.diff"),
        }
        client = FakeClient()

        summary = Updater(self.paths, self.database_path, client=client).run(
            UpdateOptions(workers=2, limit=1)
        )

        self.assertFalse(summary.ok)
        self.assertEqual(summary.database["status"], "partial")
        self.assertFalse(summary.database["activated"])
        self.assertEqual(summary.failures[0]["kind"], "selection")
        self.assertEqual(summary.details_downloaded, 0)
        self.assertEqual(summary.details_reused, 1)
        self.assertEqual(summary.reports_downloaded, 0)
        self.assertEqual(summary.reports_reused, 1)
        self.assertEqual(summary.patches_downloaded, 0)
        self.assertEqual(summary.patches_reused, 1)
        self.assertEqual(client.bug_calls, [])
        self.assertEqual(client.report_calls, [])
        self.assertEqual(client.patch_calls, [])
        self.assertEqual(
            before,
            {
                "bug": digest(self.paths.bugs / "extid-alpha123.json"),
                "report": digest(self.paths.reports / "extid-alpha123.txt"),
                "patch": digest(self.paths.patches / f"{ALPHA_HASH}.diff"),
            },
        )
        with Database(self.database_path) as database:
            status = database.status()
        self.assertEqual(status["bugs"], 2)
        self.assertEqual(status["current_snapshot"]["id"], prior_snapshot)


if __name__ == "__main__":
    unittest.main()
