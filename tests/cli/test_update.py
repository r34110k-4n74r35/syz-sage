from __future__ import annotations

import json
import unittest
from unittest import mock

from syz_sage.parsing.listing import key_from_link
from syz_sage.retrieval.sync import UpdateSummary
from tests.cli.support import CliFixture, compact, invoke
from tests.support import (
    FIXTURES,
)


class CliUpdateTests(CliFixture, unittest.TestCase):
    def test_human_update_distinguishes_retention_from_activation(self) -> None:
        data_dir = self.root / "application-data"
        summary = UpdateSummary(
            namespace="upstream",
            status="fixed",
            listing_bugs=2,
            details_downloaded=1,
            failures=[
                {
                    "kind": "selection",
                    "key": "",
                    "error": "candidate snapshot is incomplete",
                }
            ],
            database={
                "status": "partial",
                "activated": False,
                "failure_count": 1,
                "failures": ["candidate snapshot is incomplete"],
            },
        )

        with mock.patch("syz_sage.cli.commands.Updater") as updater:
            updater.return_value.run.return_value = summary
            code, stdout, stderr = invoke(
                ["--data-dir", str(data_dir), "update", "--allow-partial"]
            )

        self.assertEqual(code, 0, stderr)
        content = compact(stdout)
        self.assertIn("Update incomplete", content)
        self.assertIn("Fixed bugs: 2 live", content)
        self.assertIn("Changes: 0 new; 0 changed; 0 no longer listed", content)
        self.assertIn("Bug details 1 0 -", content)
        self.assertIn("Result: partial; no snapshot activated", content)
        self.assertIn("Issues (1)", content)
        self.assertIn("Any previously active snapshot is unchanged", content)
        self.assertIn("selection: candidate snapshot is incomplete", stdout)
        self.assertNotIn("the previous current snapshot remains active", stdout)
        self.assertNotIn("No new fixed bugs; local files and database are already current.", stdout)
        self.assertNotIn("Indexed 2 bugs", stdout)

    def test_update_progress_and_json_output_with_real_ingestion(self) -> None:
        data_dir = self.root / "application-data"
        with mock.patch("syz_sage.retrieval.sync.SyzbotClient") as client_factory:
            client = client_factory.return_value
            client.dashboard = "https://syzkaller.appspot.com"
            client.listing_json.return_value = (
                FIXTURES / "raw" / "upstream_fixed.json"
            ).read_bytes()
            client.listing_html.return_value = (
                FIXTURES / "raw" / "upstream_fixed.html"
            ).read_bytes()
            client.bug.side_effect = lambda url: (
                FIXTURES / "raw" / "bugs" / f"{key_from_link(url)}.json"
            ).read_bytes()
            client.report.return_value = (
                FIXTURES / "artifacts" / "reports" / "extid-alpha123.txt"
            ).read_bytes()
            client.patch.return_value = (
                (FIXTURES / "artifacts" / "patches" / f"{'a' * 40}.diff").read_bytes(),
                "https://example.invalid/patch",
            )

            code, stdout, stderr = invoke(["--data-dir", str(data_dir), "update"])
            self.assertEqual(code, 0, stderr or stdout)
            self.assertIn("Checking fixed bugs on syzbot", stderr)
            self.assertIn("Bug details: downloading 2", stderr)
            self.assertIn("Crash reports: downloading 1", stderr)
            self.assertIn("Fix patches: downloading 1", stderr)
            self.assertIn("Updating SQLite", stderr)
            self.assertNotIn("\r", stderr)
            self.assertNotIn("\x1b", stderr)
            self.assertIn("snapshot activated", stdout)

            client.bug.reset_mock()
            client.report.reset_mock()
            client.patch.reset_mock()
            code, stdout, stderr = invoke(["--data-dir", str(data_dir), "update", "--json"])
            self.assertEqual(code, 0, stderr or stdout)
            self.assertEqual(stderr, "")
            self.assertEqual(json.loads(stdout)["database"]["status"], "unchanged")
            self.assertTrue(json.loads(stdout)["database"]["skipped"])
            client.bug.assert_not_called()
            self.assertEqual(json.loads(stdout)["details_downloaded"], 0)
            self.assertEqual(json.loads(stdout)["details_reused"], 2)
            client.report.assert_not_called()
            client.patch.assert_not_called()

            code, stdout, stderr = invoke(
                ["--data-dir", str(data_dir), "update", "--recheck-fixes"]
            )
            self.assertEqual(code, 0, stderr or stdout)
            client.bug.assert_called_once_with(
                "https://syzkaller.appspot.com/bug?id=beta456&json=1"
            )
            self.assertIn("skipping SQLite update", stderr)
            self.assertIn("1 fix rechecks", stderr)
            self.assertIn("Bug details: rechecking 1", stderr)
            self.assertIn(
                "Fix rechecks: 1 checked; 0 resolved; 1 awaiting hashes; 0 failed",
                stderr,
            )
            self.assertNotIn("updating SQLite from retained files", stderr)
            self.assertIn("SQLite write skipped", stdout)

            client.bug.reset_mock()
            code, stdout, stderr = invoke(["--data-dir", str(data_dir), "update"])
            self.assertEqual(code, 0, stderr or stdout)
            client.bug.assert_not_called()
            self.assertNotIn("Fix rechecks:", stderr)
            self.assertIn("SQLite write skipped", stdout)

    def test_human_update_reports_new_changed_removed_and_activation(self) -> None:
        data_dir = self.root / "application-data"
        summary = UpdateSummary(
            namespace="upstream",
            status="fixed",
            listing_bugs=4,
            known_fixed_bugs=3,
            new_fixed_bugs=1,
            new_fixed_bug_keys=["extid-new"],
            changed_bugs=1,
            changed_bug_keys=["extid-changed"],
            no_longer_listed_bugs=1,
            no_longer_listed_bug_keys=["extid-old"],
            details_downloaded=2,
            details_reused=2,
            reports_downloaded=1,
            reports_reused=2,
            reports_unavailable=1,
            patches_downloaded=1,
            patches_reused=3,
            database={
                "status": "completed",
                "activated": True,
                "failure_count": 0,
                "failures": [],
            },
        )

        with mock.patch("syz_sage.cli.commands.Updater") as updater:
            updater.return_value.run.return_value = summary
            code, stdout, stderr = invoke(["--data-dir", str(data_dir), "update"])

        self.assertEqual(code, 0, stderr)
        content = compact(stdout)
        self.assertIn("Update complete", content)
        self.assertIn("Fixed bugs: 4 live", content)
        self.assertIn("Changes: 1 new; 1 changed; 1 no longer listed", content)
        self.assertIn("New keys: extid-new", content)
        self.assertIn("Changed keys: extid-changed", content)
        self.assertIn("No longer listed: extid-old", content)
        self.assertIn("Bug details 2 2 -", content)
        self.assertIn("Reports 1 2 1", content)
        self.assertIn("Patches 1 3 -", content)
        self.assertIn("Result: complete; snapshot activated", content)
        self.assertNotIn("No new fixed bugs; local files and database are already current.", stdout)

    def test_quiet_update_keeps_summary_and_failure_details(self) -> None:
        summary = UpdateSummary(
            namespace="upstream",
            status="fixed",
            listing_bugs=2,
            failures=[{"kind": "report", "key": "extid-alpha123", "error": "timed out"}],
            database={"status": "partial", "activated": False, "failures": ["timed out"]},
        )
        with mock.patch("syz_sage.cli.commands.Updater") as updater:
            updater.return_value.run.return_value = summary
            code, stdout, stderr = invoke(
                ["--data-dir", str(self.root / "data"), "update", "--quiet"]
            )

        self.assertEqual(code, 1)
        self.assertIsNone(updater.call_args.kwargs["progress"])
        self.assertIsNone(updater.call_args.kwargs["on_progress"])
        self.assertEqual(stderr, "")
        self.assertIn("Fixed bugs: 2 live", compact(stdout))
        self.assertIn("report extid-alpha123: timed out", stdout)
        self.assertIn("Issues (1)", stdout)

    def test_update_interrupt_cleans_progress_before_error(self) -> None:
        with mock.patch("syz_sage.cli.commands.Updater") as updater:
            updater.return_value.run.side_effect = KeyboardInterrupt
            code, stdout, stderr = invoke(["--data-dir", str(self.root / "data"), "update"])
        self.assertEqual(code, 130)
        self.assertEqual(stdout, "")
        self.assertIn("Interrupted", stderr)
        self.assertNotIn("\r", stderr)
        self.assertNotIn("\x1b", stderr)

    def test_update_limits_human_issues_but_preserves_all_in_json(self) -> None:
        failures = [
            {"kind": "report", "key": f"extid-bug{i}", "error": "timed out\x1b[2J"}
            for i in range(8)
        ]
        summary = UpdateSummary(
            namespace="upstream",
            status="fixed",
            failures=failures,
            database={"status": "partial", "activated": False},
        )
        with mock.patch("syz_sage.cli.commands.Updater") as updater:
            updater.return_value.run.return_value = summary
            args = ["--data-dir", str(self.root / "data"), "update"]
            code, stdout, _stderr = invoke(args)
            self.assertEqual(code, 1)
            self.assertEqual(stdout.count("timed out"), 5)
            self.assertIn("3 more; use --json", stdout)
            self.assertNotIn("\x1b", stdout)
            self.assertIn(r"\x1b[2J", stdout)

            code, stdout, stderr = invoke([*args, "--json"])
            self.assertEqual(code, 1)
            self.assertEqual(stderr, "")
            self.assertEqual(json.loads(stdout)["failures"], failures)

    def test_human_update_prints_exact_no_change_message(self) -> None:
        data_dir = self.root / "application-data"
        summary = UpdateSummary(
            namespace="upstream",
            status="fixed",
            listing_bugs=4,
            known_fixed_bugs=4,
            details_reused=4,
            reports_reused=3,
            reports_unavailable=1,
            patches_reused=2,
            database={
                "status": "unchanged",
                "activated": False,
                "failure_count": 0,
                "failures": [],
            },
        )

        with mock.patch("syz_sage.cli.commands.Updater") as updater:
            updater.return_value.run.return_value = summary
            code, stdout, stderr = invoke(["--data-dir", str(data_dir), "update"])

        self.assertEqual(code, 0, stderr)
        content = compact(stdout)
        self.assertIn("Already up to date", content)
        self.assertIn("Fixed bugs: 4 live", content)
        self.assertIn("Changes: 0 new; 0 changed; 0 no longer listed", content)
        self.assertIn("Bug details 0 4 -", content)
        self.assertIn("Result: unchanged; SQLite write skipped", content)
        self.assertEqual(
            stdout.count("No new fixed bugs; local files and database are already current.\n"),
            1,
        )

    def test_allow_partial_does_not_mask_failed_database_ingestion(self) -> None:
        summary = UpdateSummary(
            namespace="upstream",
            status="fixed",
            listing_bugs=2,
            database={
                "status": "failed",
                "activated": False,
                "failure_count": 1,
                "failures": ["snapshot transaction failed"],
            },
        )

        with mock.patch("syz_sage.cli.commands.Updater") as updater:
            updater.return_value.run.return_value = summary
            code, _stdout, stderr = invoke(
                ["--data-dir", str(self.root / "data"), "update", "--allow-partial"]
            )

        self.assertEqual(code, 1, stderr)


if __name__ == "__main__":
    unittest.main()
