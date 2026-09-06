from __future__ import annotations

import json
import threading
import unittest
from concurrent.futures import Future
from unittest import mock

from syz_sage.database import Database
from syz_sage.database.ingestion import FileInventory
from syz_sage.parsing.listing import PayloadError
from syz_sage.project.config import DataPaths
from syz_sage.retrieval.artifacts import DownloadJob, validate_artifact
from syz_sage.retrieval.client import FetchError
from syz_sage.retrieval.retry_state import SyncState, load_sync_state
from syz_sage.retrieval.sync import (
    UpdateOptions,
    Updater,
    UpdateSummary,
)
from tests.retrieval.support import (
    ChangedListingTitleClient,
    ChangedReportClient,
    ExpandedListingClient,
    FakeClient,
    UpdaterFixture,
)
from tests.support import (
    ALPHA_HASH,
    GAMMA_HASH,
)


class UpdateRetryTests(UpdaterFixture, unittest.TestCase):
    def test_completion_batches_and_interruption_preserve_retry_intent(self) -> None:
        self.paths.ensure()
        jobs = [
            DownloadJob("report", f"id-bug{number}", self.paths.reports / f"id-bug{number}.txt")
            for number in range(12)
        ]
        state = SyncState()
        summary = UpdateSummary("upstream", "fixed")
        updater = Updater(self.paths, self.database_path, client=FakeClient())
        persisted_before_interrupt = []

        def results(*args, **kwargs):
            for index, job in enumerate(jobs):
                if index == 9:
                    persisted, error = load_sync_state(self.paths.sync_state)
                    self.assertIsNone(error)
                    persisted_before_interrupt.append(persisted.pending_reports)
                    raise KeyboardInterrupt
                future = Future()
                future.set_result(validate_artifact(job, b"BUG: saved crash stack\n"))
                yield job, future

        with (
            mock.patch("syz_sage.retrieval.sync.bounded_results", side_effect=results),
            self.assertRaises(KeyboardInterrupt),
        ):
            updater._download(
                jobs,
                UpdateOptions(),
                summary,
                state,
                FileInventory(),
                {},
                label="Crash reports",
                pending=state.pending_reports,
                accept=lambda result: state.pending_reports.discard(result.job.key),
            )

        # The on-disk queue was advanced before the batch finished; an abrupt
        # kill could replay only the completion since the eighth saved result.
        self.assertEqual(persisted_before_interrupt, [{job.key for job in jobs[8:]}])
        persisted, error = load_sync_state(self.paths.sync_state)
        self.assertIsNone(error)
        self.assertEqual(persisted.pending_reports, {job.key for job in jobs[9:]})
        self.assertTrue(all(job.path.is_file() for job in jobs[:9]))
        self.assertTrue(all(not job.path.exists() for job in jobs[9:]))
        self.assertFalse(self.database_path.exists())

    def test_atomic_save_failure_retains_old_report_and_pending_download(self) -> None:
        self.paths.ensure()
        path = self.paths.reports / "id-existing.txt"
        path.write_bytes(b"previous valid report")
        job = DownloadJob(
            "report", "id-existing", path, source_url="https://example.invalid/report"
        )
        state = SyncState()
        summary = UpdateSummary("upstream", "fixed")
        updater = Updater(self.paths, self.database_path, client=FakeClient())

        with (
            mock.patch("syz_sage.retrieval.sync.atomic_write", side_effect=OSError("disk full")),
            mock.patch(
                "syz_sage.retrieval.sync.fetch_artifact",
                return_value=validate_artifact(job, b"new report"),
            ),
        ):
            updater._download(
                [job],
                UpdateOptions(),
                summary,
                state,
                FileInventory(),
                {},
                label="Crash reports",
                pending=state.pending_reports,
                accept=lambda result: state.pending_reports.discard(result.job.key),
            )

        self.assertEqual(path.read_bytes(), b"previous valid report")
        persisted, error = load_sync_state(self.paths.sync_state)
        self.assertIsNone(error)
        self.assertEqual(persisted.pending_reports, {job.key})
        self.assertEqual(
            summary.failures, [{"kind": "report", "key": job.key, "error": "disk full"}]
        )

    def test_partial_new_bug_is_retried_after_listing_was_retained(self) -> None:
        Updater(self.paths, self.database_path, client=FakeClient()).run(UpdateOptions(workers=2))

        partial = Updater(
            self.paths,
            self.database_path,
            client=ExpandedListingClient(fail_new_bug=True),
        ).run(UpdateOptions(workers=2))

        self.assertFalse(partial.ok)
        self.assertEqual(partial.database["status"], "partial")
        self.assertFalse(partial.database["activated"])
        self.assertEqual(partial.new_fixed_bug_keys, ["id-gamma789"])
        self.assertFalse((self.paths.bugs / "id-gamma789.json").exists())
        self.assertTrue((self.paths.patches / f"{GAMMA_HASH}.diff").is_file())

        client = ExpandedListingClient()
        completed = Updater(self.paths, self.database_path, client=client).run(
            UpdateOptions(workers=2)
        )

        self.assertTrue(completed.ok, completed.failures)
        self.assertEqual(completed.database["status"], "completed")
        self.assertTrue(completed.database["activated"])
        self.assertEqual(completed.new_fixed_bug_keys, ["id-gamma789"])
        self.assertEqual(client.bug_calls, ["id-gamma789"])
        self.assertEqual(client.patch_calls, [])
        self.assertTrue((self.paths.bugs / "id-gamma789.json").is_file())
        self.assertTrue((self.paths.reports / "id-gamma789.txt").is_file())

    def test_corrupt_retry_state_does_not_redownload_saved_bugs(self) -> None:
        Updater(self.paths, self.database_path, client=FakeClient()).run()
        self.paths.sync_state.write_text("invalid JSON")
        client = FakeClient()

        with self.assertRaisesRegex(PayloadError, "Cannot read sync state"):
            Updater(self.paths, self.database_path, client=client).run()

        self.assertEqual(self.paths.sync_state.read_text(), "invalid JSON")
        self.assertEqual(client.bug_calls, [])
        self.assertEqual(client.report_calls, [])
        self.assertEqual(client.patch_calls, [])

    def test_corrupted_refresh_state_cannot_activate_stale_report_on_repeated_runs(self) -> None:
        Updater(self.paths, self.database_path, client=FakeClient()).run()
        with Database(self.database_path, read_only=True) as database:
            original_snapshot = database.status()["current_snapshot"]["id"]
            original_report = database.get_bug("extid-alpha123")["report"]
        failed = Updater(
            self.paths, self.database_path, client=ChangedReportClient(fail_report=True)
        ).run(UpdateOptions(refresh_details=True))
        self.assertEqual(failed.database["status"], "partial")
        self.paths.sync_state.write_text("invalid JSON")
        original_database = self.database_path.read_bytes()
        for _ in range(2):
            client = ChangedReportClient()
            with self.assertRaisesRegex(PayloadError, "saved retry state was preserved"):
                Updater(self.paths, self.database_path, client=client).run()
            self.assertEqual(self.paths.sync_state.read_text(), "invalid JSON")
            self.assertEqual(client.report_calls, [])
            self.assertEqual(self.database_path.read_bytes(), original_database)
            with Database(self.database_path, read_only=True) as database:
                self.assertEqual(database.status()["current_snapshot"]["id"], original_snapshot)
                self.assertEqual(database.get_bug("extid-alpha123")["report"], original_report)

    def test_interrupt_flushes_saved_results_before_waiting_for_running_worker(self) -> None:
        self.paths.ensure()
        jobs = [
            DownloadJob("report", f"id-job{number}", self.paths.reports / f"id-job{number}.txt")
            for number in range(2)
        ]
        state = SyncState()
        waiting = threading.Event()
        stopped = threading.Event()
        worker_observed: list[set[str]] = []
        client = FakeClient()
        client.cancel = stopped.set
        updater = Updater(self.paths, self.database_path, client=client)

        def fetch(client, job):
            if job.key == "id-job0":
                if not waiting.wait(timeout=2):
                    raise RuntimeError("test worker did not start")
                return validate_artifact(job, b"BUG: saved report\n")
            waiting.set()
            if not stopped.wait(timeout=2):
                raise RuntimeError("test worker was not cancelled")
            # Cancellation is signalled just before the callback writes the
            # queue; wait for that atomic write without touching real data.
            for _ in range(200):
                persisted, error = load_sync_state(self.paths.sync_state)
                if error is None and persisted.pending_reports == {"id-job1"}:
                    worker_observed.append(persisted.pending_reports)
                    break
                threading.Event().wait(0.005)
            return validate_artifact(job, b"BUG: unsaved interrupted report\n")

        def accept(result):
            state.pending_reports.discard(result.job.key)
            raise KeyboardInterrupt

        with (
            mock.patch("syz_sage.retrieval.sync.fetch_artifact", side_effect=fetch),
            self.assertRaises(KeyboardInterrupt),
        ):
            updater._download(
                jobs,
                UpdateOptions(workers=2),
                UpdateSummary("upstream", "fixed"),
                state,
                FileInventory(),
                {},
                label="Reports",
                pending=state.pending_reports,
                accept=accept,
            )
        self.assertEqual(worker_observed, [{"id-job1"}])
        self.assertTrue(jobs[0].path.is_file())
        self.assertFalse(jobs[1].path.exists())

    def test_failed_refresh_keeps_prior_valid_detail_and_indexes_cached_copy(self) -> None:
        Updater(self.paths, self.database_path, client=FakeClient()).run(UpdateOptions(workers=2))
        detail_path = self.paths.bugs / "extid-alpha123.json"
        before = detail_path.read_bytes()
        with Database(self.database_path) as database:
            prior_snapshot = database.status()["current_snapshot"]["id"]

        summary = Updater(
            self.paths,
            self.database_path,
            client=FakeClient(fail_bug="extid-alpha123"),
        ).run(
            UpdateOptions(
                workers=1,
                refresh_details=True,
            )
        )

        self.assertFalse(summary.ok)
        self.assertEqual(summary.database["status"], "partial")
        self.assertFalse(summary.database["activated"])
        self.assertEqual(summary.failures[0]["kind"], "bug-json")
        self.assertEqual(summary.failures[0]["key"], "extid-alpha123")
        self.assertEqual(summary.details_reused, 1)
        self.assertEqual(detail_path.read_bytes(), before)
        with Database(self.database_path) as database:
            bug = database.get_bug("extid-alpha123")
            status = database.status()
        self.assertEqual(bug["title"], "KASAN: use-after-free in alpha")
        self.assertEqual(status["latest_run"]["status"], "partial")
        self.assertEqual(status["current_snapshot"]["id"], prior_snapshot)

    def test_explicit_refresh_failure_is_retried_after_listing_rollover(self) -> None:
        for failure_kind in ("detail", "report"):
            with self.subTest(failure_kind=failure_kind):
                paths = DataPaths.from_root(self.paths.root / failure_kind)
                Updater(paths, paths.database, client=FakeClient()).run()
                with Database(paths.database) as database:
                    previous_snapshot = database.status()["current_snapshot"]["id"]
                failing = ChangedListingTitleClient(
                    fail_bug="extid-alpha123" if failure_kind == "detail" else None,
                )
                if failure_kind == "report":
                    failing.report = mock.Mock(side_effect=FetchError("planned report failure"))

                partial = Updater(paths, paths.database, client=failing).run(
                    UpdateOptions(refresh_details=True)
                )

                self.assertFalse(partial.ok)
                self.assertEqual(partial.database["status"], "partial")
                with Database(paths.database) as database:
                    self.assertEqual(database.status()["current_snapshot"]["id"], previous_snapshot)
                    self.assertEqual(
                        database.get_bug("extid-alpha123")["title"],
                        "KASAN: use-after-free in alpha",
                    )

                client = ChangedListingTitleClient()
                completed = Updater(paths, paths.database, client=client).run()
                self.assertTrue(completed.ok, completed.failures)
                self.assertEqual(completed.changed_bugs, 0)
                self.assertEqual(
                    client.bug_calls, ["extid-alpha123"] if failure_kind == "detail" else []
                )
                self.assertEqual(client.report_calls, [client.report_url])
                self.assertEqual(client.patch_calls, [])
                with Database(paths.database) as database:
                    bug = database.get_bug("extid-alpha123")
                    self.assertEqual(bug["raw"]["title"], client.title)
                    self.assertEqual(bug["report"]["text"], client.report_bytes.decode())

                unchanged = ChangedListingTitleClient()
                final = Updater(paths, paths.database, client=unchanged).run()
                self.assertTrue(final.ok, final.failures)
                self.assertEqual(final.database["status"], "unchanged")
                self.assertEqual(unchanged.bug_calls, [])
                self.assertEqual(unchanged.report_calls, [])
                self.assertEqual(unchanged.patch_calls, [])

    def test_failed_patch_refresh_is_retried_even_with_valid_old_patch(self) -> None:
        Updater(self.paths, self.database_path, client=FakeClient()).run()
        patch_path = self.paths.patches / f"{ALPHA_HASH}.diff"
        old_patch = patch_path.read_bytes()
        observed_prearmed_state: list[bool] = []

        def fail_patch(commit_hash: str, repo: str | None = None) -> tuple[bytes, str]:
            state = json.loads(self.paths.sync_state.read_text())
            self.assertIn(commit_hash, state["pending_patches"])
            observed_prearmed_state.append(True)
            raise FetchError("planned patch refresh failure")

        failing = FakeClient()
        failing.patch = mock.Mock(side_effect=fail_patch)
        partial = Updater(self.paths, self.database_path, client=failing).run(
            UpdateOptions(refresh_artifacts=True)
        )

        self.assertFalse(partial.ok)
        self.assertEqual(observed_prearmed_state, [True])
        self.assertEqual(partial.database["status"], "partial")
        self.assertEqual(patch_path.read_bytes(), old_patch)
        state = json.loads(self.paths.sync_state.read_text())
        self.assertEqual(state["pending_patches"], [ALPHA_HASH])

        client = FakeClient()
        completed = Updater(self.paths, self.database_path, client=client).run()
        self.assertTrue(completed.ok, completed.failures)
        self.assertEqual(client.patch_calls, [ALPHA_HASH])
        self.assertEqual(client.bug_calls, [])
        self.assertEqual(client.report_calls, [])
        state = json.loads(self.paths.sync_state.read_text())
        self.assertEqual(state["pending_patches"], [])

        unchanged_client = FakeClient()
        unchanged = Updater(self.paths, self.database_path, client=unchanged_client).run()
        self.assertTrue(unchanged.ok)
        self.assertTrue(unchanged.database["skipped"])
        self.assertEqual(unchanged_client.patch_calls, [])

    def test_legacy_retry_state_preserves_pending_work_during_upgrade(self) -> None:
        Updater(self.paths, self.database_path, client=FakeClient()).run()
        self.paths.sync_state.write_text(
            json.dumps(
                {
                    "version": 1,
                    "pending_details": ["id-beta456"],
                    "pending_reports": ["extid-alpha123"],
                }
            )
        )
        client = FakeClient()

        summary = Updater(self.paths, self.database_path, client=client).run()

        self.assertTrue(summary.ok, summary.failures)
        self.assertEqual(client.bug_calls, ["id-beta456"])
        self.assertEqual(len(client.report_calls), 1)
        self.assertEqual(client.patch_calls, [])
        state = json.loads(self.paths.sync_state.read_text())
        self.assertEqual(state["version"], 2)
        self.assertEqual(state["pending_details"], [])
        self.assertEqual(state["pending_reports"], [])
        self.assertEqual(state["pending_patches"], [])

    def test_unsafe_pending_patch_hash_does_not_schedule_download(self) -> None:
        Updater(self.paths, self.database_path, client=FakeClient()).run()
        self.paths.sync_state.write_text(
            json.dumps(
                {
                    "version": 2,
                    "pending_details": [],
                    "pending_reports": [],
                    "pending_patches": ["../outside"],
                }
            )
        )
        client = FakeClient()
        before = self.paths.sync_state.read_bytes()

        with self.assertRaisesRegex(PayloadError, "invalid hash"):
            Updater(self.paths, self.database_path, client=client).run()

        self.assertEqual(client.patch_calls, [])
        self.assertEqual(self.paths.sync_state.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
