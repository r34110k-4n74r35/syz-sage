from __future__ import annotations

import json
import unittest

from syz_sage.database import Database
from syz_sage.retrieval.sync import (
    UpdateOptions,
    Updater,
)
from tests.retrieval.support import (
    ChangedReportClient,
    CustomDashboardClient,
    FakeClient,
    InvalidArtifactsClient,
    OffOriginReportClient,
    UpdaterFixture,
)
from tests.support import (
    ALPHA_HASH,
)


class UpdateReportsTests(UpdaterFixture, unittest.TestCase):
    def test_relative_report_url_uses_the_clients_dashboard(self) -> None:
        client = CustomDashboardClient()

        summary = Updater(self.paths, self.database_path, client=client).run(
            UpdateOptions(workers=2)
        )

        self.assertTrue(summary.ok, summary.failures)
        self.assertEqual(
            client.report_calls,
            ["https://mirror.example.invalid/syzbot/text?tag=CrashReport&x=alpha"],
        )
        with Database(self.database_path) as database:
            report = database.get_bug("extid-alpha123")["report"]
        self.assertEqual(
            report["source_url"],
            "https://mirror.example.invalid/syzbot/text?tag=CrashReport&x=alpha",
        )

    def test_refreshed_detail_forces_its_report_to_refresh(self) -> None:
        Updater(self.paths, self.database_path, client=FakeClient()).run(UpdateOptions(workers=2))
        client = ChangedReportClient()

        summary = Updater(self.paths, self.database_path, client=client).run(
            UpdateOptions(workers=2, refresh_details=True)
        )

        self.assertTrue(summary.ok, summary.failures)
        self.assertEqual(summary.reports_downloaded, 1)
        self.assertEqual(
            client.report_calls,
            ["https://syzkaller.appspot.com/text?tag=CrashReport&x=alpha-new"],
        )

    def test_failed_changed_report_is_retried_from_durable_state(self) -> None:
        Updater(self.paths, self.database_path, client=FakeClient()).run(UpdateOptions(workers=2))
        report_path = self.paths.reports / "extid-alpha123.txt"
        old_report = report_path.read_bytes()
        new_report = b"BUG: KASAN: changed representative report\nnew report bytes\n"
        observed_prearmed_state: list[bool] = []

        def observe_report_start() -> None:
            state = json.loads(self.paths.sync_state.read_text())
            self.assertIn("extid-alpha123", state["pending_reports"])
            self.assertNotIn("extid-alpha123", state["pending_details"])
            observed_prearmed_state.append(True)

        partial = Updater(
            self.paths,
            self.database_path,
            client=ChangedReportClient(
                fail_report=True,
                report_payload=new_report,
                on_report=observe_report_start,
            ),
        ).run(UpdateOptions(workers=2, refresh_details=True))

        self.assertFalse(partial.ok)
        self.assertEqual(partial.database["status"], "partial")
        self.assertEqual(observed_prearmed_state, [True])
        self.assertEqual(report_path.read_bytes(), old_report)
        state = json.loads(self.paths.sync_state.read_text())
        self.assertIn("extid-alpha123", state["pending_reports"])

        client = ChangedReportClient(report_payload=new_report)
        completed = Updater(self.paths, self.database_path, client=client).run(
            UpdateOptions(workers=2)
        )

        self.assertTrue(completed.ok, completed.failures)
        self.assertEqual(client.bug_calls, [])
        self.assertEqual(
            client.report_calls,
            ["https://syzkaller.appspot.com/text?tag=CrashReport&x=alpha-new"],
        )
        self.assertEqual(report_path.read_bytes(), new_report)
        state = json.loads(self.paths.sync_state.read_text())
        self.assertNotIn("extid-alpha123", state["pending_reports"])
        with Database(self.database_path) as database:
            report = database.get_bug("extid-alpha123")["report"]
        self.assertEqual(report["text"], new_report.decode())
        self.assertEqual(
            report["source_url"],
            "https://syzkaller.appspot.com/text?tag=CrashReport&x=alpha-new",
        )

    def test_no_reports_transfers_refreshed_detail_to_pending_report(self) -> None:
        Updater(self.paths, self.database_path, client=FakeClient()).run(UpdateOptions(workers=2))
        new_report = b"BUG: KASAN: delayed representative report\ndelayed bytes\n"

        partial = Updater(
            self.paths,
            self.database_path,
            client=ChangedReportClient(report_payload=new_report),
        ).run(UpdateOptions(workers=2, refresh_details=True, reports=False))

        self.assertFalse(partial.ok)
        state = json.loads(self.paths.sync_state.read_text())
        self.assertNotIn("extid-alpha123", state["pending_details"])
        self.assertIn("extid-alpha123", state["pending_reports"])

        client = ChangedReportClient(report_payload=new_report)
        completed = Updater(self.paths, self.database_path, client=client).run(
            UpdateOptions(workers=2)
        )

        self.assertTrue(completed.ok, completed.failures)
        self.assertEqual(client.bug_calls, [])
        self.assertEqual(len(client.report_calls), 1)
        self.assertEqual(
            (self.paths.reports / "extid-alpha123.txt").read_bytes(),
            new_report,
        )

    def test_invalid_artifacts_do_not_replace_prior_valid_files(self) -> None:
        Updater(self.paths, self.database_path, client=FakeClient()).run(UpdateOptions(workers=2))
        report_path = self.paths.reports / "extid-alpha123.txt"
        patch_path = self.paths.patches / f"{ALPHA_HASH}.diff"
        report_before = report_path.read_bytes()
        patch_before = patch_path.read_bytes()
        with Database(self.database_path) as database:
            prior_snapshot = database.status()["current_snapshot"]["id"]

        summary = Updater(self.paths, self.database_path, client=InvalidArtifactsClient()).run(
            UpdateOptions(workers=2, refresh_artifacts=True)
        )

        self.assertFalse(summary.ok)
        self.assertEqual(
            {"report", "patch"},
            {failure["kind"] for failure in summary.failures},
        )
        self.assertEqual(report_path.read_bytes(), report_before)
        self.assertEqual(patch_path.read_bytes(), patch_before)
        self.assertEqual(summary.database["status"], "partial")
        self.assertFalse(summary.database["activated"])
        with Database(self.database_path) as database:
            self.assertEqual(database.status()["current_snapshot"]["id"], prior_snapshot)

    def test_untrusted_report_metadata_is_a_partial_resource_failure(self) -> None:
        Updater(self.paths, self.database_path, client=FakeClient()).run(UpdateOptions(workers=2))
        with Database(self.database_path) as database:
            prior_snapshot = database.status()["current_snapshot"]["id"]
        client = OffOriginReportClient()

        summary = Updater(self.paths, self.database_path, client=client).run(
            UpdateOptions(workers=2, refresh_details=True)
        )

        self.assertFalse(summary.ok)
        metadata_failures = [
            failure for failure in summary.failures if failure["kind"] == "report-metadata"
        ]
        self.assertEqual(len(metadata_failures), 1)
        self.assertEqual(metadata_failures[0]["key"], "extid-alpha123")
        self.assertEqual(client.report_calls, [])
        self.assertEqual(summary.database["status"], "partial")
        self.assertFalse(summary.database["activated"])
        with Database(self.database_path) as database:
            self.assertEqual(database.status()["current_snapshot"]["id"], prior_snapshot)


if __name__ == "__main__":
    unittest.main()
