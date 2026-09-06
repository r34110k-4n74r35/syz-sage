from __future__ import annotations

import unittest
from unittest import mock

from syz_sage.database import Database
from syz_sage.parsing.listing import PayloadError
from syz_sage.retrieval.sync import (
    UpdateOptions,
    Updater,
)
from tests.retrieval.support import (
    ChangedListingTitleClient,
    EmptyListingClient,
    FakeClient,
    InvalidHtmlClient,
    RewrittenHashClient,
    UpdaterFixture,
)
from tests.support import (
    ALPHA_HASH,
    BETA_HASH,
    FIXTURES,
    digest,
)


class UpdateListingTests(UpdaterFixture, unittest.TestCase):
    def test_navigation_only_html_changes_do_not_write_database(self) -> None:
        first = FakeClient()
        listing_html = first.listing_html("upstream", "fixed")
        first.listing_html = mock.Mock(
            return_value=listing_html.replace(b"<body>", b"<body><nav>Open [42]</nav>")
        )
        Updater(self.paths, self.database_path, client=first).run()
        html_before = self.paths.listing_html.read_bytes()
        database_before = digest(self.database_path)
        database_mtime = self.database_path.stat().st_mtime_ns
        changed_navigation = FakeClient()
        changed_navigation.listing_html = mock.Mock(
            return_value=listing_html.replace(b"<body>", b"<body><nav>Open [43]</nav>")
        )

        with mock.patch.object(Database, "ingest_files", side_effect=AssertionError("must skip")):
            summary = Updater(self.paths, self.database_path, client=changed_navigation).run()

        self.assertTrue(summary.ok, summary.failures)
        self.assertTrue(summary.database["skipped"])
        self.assertEqual(self.paths.listing_html.read_bytes(), html_before)
        self.assertEqual(digest(self.database_path), database_before)
        self.assertEqual(self.database_path.stat().st_mtime_ns, database_mtime)
        self.assertEqual(changed_navigation.bug_calls, [])
        self.assertEqual(changed_navigation.report_calls, [])
        self.assertEqual(changed_navigation.patch_calls, [])

    def test_subsystem_tag_changes_are_indexed_without_refetching_bug_details(self) -> None:
        listing_html = b"""<!doctype html><html><body><table>
            <tr><td><a href="/bug?extid=alpha123">alpha</a>
            <a href="/upstream?label=subsystems:net">net</a></td></tr>
            <tr><td><a href="/bug?id=beta456">beta</a></td></tr>
            </table></body></html>"""
        first = FakeClient()
        first.listing_html = mock.Mock(return_value=listing_html)
        Updater(self.paths, self.database_path, client=first).run()
        changed_tags = FakeClient()
        changed_tags.listing_html = mock.Mock(
            return_value=listing_html.replace(b"subsystems:net", b"subsystems:wireless")
        )

        summary = Updater(self.paths, self.database_path, client=changed_tags).run()

        self.assertTrue(summary.ok, summary.failures)
        self.assertFalse(summary.database["skipped"])
        self.assertEqual(summary.changed_bug_keys, ["extid-alpha123"])
        self.assertEqual(summary.changed_bugs, 1)
        self.assertEqual(changed_tags.bug_calls, [])
        self.assertEqual(changed_tags.report_calls, [])
        self.assertEqual(changed_tags.patch_calls, [])
        with Database(self.database_path) as database:
            self.assertEqual(database.get_bug("extid-alpha123")["subsystems"], ["wireless"])

    def test_error_page_or_mismatched_html_cannot_replace_listing_or_tags(self) -> None:
        Updater(self.paths, self.database_path, client=FakeClient()).run()
        html_before = self.paths.listing_html.read_bytes()
        with Database(self.database_path) as database:
            prior_snapshot = database.status()["current_snapshot"]["id"]

        for html in (
            b"<!doctype html><html><body>Temporarily unavailable</body></html>",
            b'<!doctype html><html><body><a href="/bug?extid=alpha123">alpha</a></body></html>',
        ):
            with self.subTest(html=html):
                client = FakeClient()
                client.listing_html = mock.Mock(return_value=html)

                summary = Updater(self.paths, self.database_path, client=client).run()

                self.assertFalse(summary.ok)
                self.assertEqual(summary.failures[0]["kind"], "listing-html")
                self.assertEqual(self.paths.listing_html.read_bytes(), html_before)
                with Database(self.database_path) as database:
                    self.assertEqual(database.status()["current_snapshot"]["id"], prior_snapshot)

    def test_empty_live_listing_cannot_replace_files_or_active_snapshot(self) -> None:
        Updater(self.paths, self.database_path, client=FakeClient()).run(UpdateOptions(workers=2))
        listing_before = self.paths.listing_json.read_bytes()
        with Database(self.database_path) as database:
            prior_snapshot = database.status()["current_snapshot"]["id"]

        with self.assertRaisesRegex(PayloadError, "no bug records"):
            Updater(self.paths, self.database_path, client=EmptyListingClient()).run()

        self.assertEqual(self.paths.listing_json.read_bytes(), listing_before)
        with Database(self.database_path) as database:
            status = database.status()
        self.assertEqual(status["current_snapshot"]["id"], prior_snapshot)

    def test_listing_fix_change_reuses_details_and_fetches_only_new_patch(self) -> None:
        Updater(self.paths, self.database_path, client=FakeClient()).run(UpdateOptions(workers=2))
        client = RewrittenHashClient(BETA_HASH)

        summary = Updater(self.paths, self.database_path, client=client).run(
            UpdateOptions(workers=2)
        )

        self.assertTrue(summary.ok, summary.failures)
        self.assertEqual(client.bug_calls, [])
        self.assertEqual(client.report_calls, [])
        self.assertEqual(summary.changed_bugs, 1)
        self.assertEqual(summary.changed_bug_keys, ["extid-alpha123"])
        self.assertEqual(client.patch_calls, [BETA_HASH])
        with Database(self.database_path) as database:
            alpha = database.get_bug("extid-alpha123")
        self.assertEqual(alpha["raw"]["fix-commits"][0]["hash"], ALPHA_HASH)
        self.assertIn(
            BETA_HASH,
            {fix["hash"] for fix in alpha["fixes"] if fix.get("hash")},
        )

    def test_changed_listing_reuses_saved_details_and_report(self) -> None:
        Updater(self.paths, self.database_path, client=FakeClient()).run(UpdateOptions(workers=2))
        client = ChangedListingTitleClient()

        summary = Updater(self.paths, self.database_path, client=client).run(
            UpdateOptions(workers=2)
        )

        self.assertTrue(summary.ok, summary.failures)
        self.assertFalse(summary.database["skipped"])
        self.assertEqual(summary.new_fixed_bugs, 0)
        self.assertEqual(summary.changed_bugs, 1)
        self.assertEqual(summary.changed_bug_keys, ["extid-alpha123"])
        self.assertEqual(client.bug_calls, [])
        self.assertEqual(client.report_calls, [])
        self.assertEqual(client.patch_calls, [])
        with Database(self.database_path) as database:
            bug = database.get_bug("extid-alpha123")
            listed = {row["key"]: row for row in database.list_bugs(limit=10)}
            version_title = database.connection.execute(
                """
                SELECT v.title
                FROM current_bug_rows AS c
                JOIN bug_versions AS v ON v.id = c.bug_version_id
                WHERE c.key = 'extid-alpha123'
                """
            ).fetchone()[0]

        self.assertEqual(bug["title"], ChangedListingTitleClient.title)
        self.assertEqual(listed["extid-alpha123"]["title"], ChangedListingTitleClient.title)
        self.assertEqual(bug["raw"]["title"], "KASAN: use-after-free in alpha")
        self.assertEqual(version_title, "KASAN: use-after-free in alpha")
        self.assertEqual(
            bug["report"]["text"],
            (FIXTURES / "artifacts" / "reports" / "extid-alpha123.txt").read_text(),
        )
        self.assertEqual(
            bug["report"]["source_url"],
            "https://syzkaller.appspot.com/text?tag=CrashReport&x=alpha",
        )

    def test_invalid_html_response_does_not_replace_prior_valid_listing(self) -> None:
        Updater(self.paths, self.database_path, client=FakeClient()).run(UpdateOptions(workers=2))
        html_before = self.paths.listing_html.read_bytes()
        with Database(self.database_path) as database:
            prior_snapshot = database.status()["current_snapshot"]["id"]

        summary = Updater(self.paths, self.database_path, client=InvalidHtmlClient()).run(
            UpdateOptions(workers=2)
        )

        self.assertFalse(summary.ok)
        self.assertIn("listing-html", {failure["kind"] for failure in summary.failures})
        self.assertEqual(self.paths.listing_html.read_bytes(), html_before)
        self.assertEqual(summary.database["status"], "partial")
        with Database(self.database_path) as database:
            current_snapshot = database.status()["current_snapshot"]["id"]
        self.assertEqual(current_snapshot, prior_snapshot)


if __name__ == "__main__":
    unittest.main()
