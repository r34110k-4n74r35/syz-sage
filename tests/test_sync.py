from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import threading
import unittest
from collections.abc import Callable
from concurrent.futures import Future
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from syz_sage.artifacts import DownloadJob, validate_artifact
from syz_sage.client import FetchError
from syz_sage.config import DataPaths
from syz_sage.database import SCHEMA_VERSION, Database
from syz_sage.ingestion import FileInventory
from syz_sage.parsing import PayloadError
from syz_sage.retry_state import SyncState, load_sync_state
from syz_sage.storage import temporary_directory
from syz_sage.sync import (
    UpdateOptions,
    Updater,
    UpdateSummary,
    _add_patch_job,
    _exclusive_update_lock,
    atomic_write,
)

FIXTURES = Path(__file__).parent / "fixtures" / "legacy_data"
ALPHA_HASH = "a" * 40
BETA_HASH = "b" * 40
GAMMA_HASH = "c" * 40


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class FakeClient:
    dashboard = "https://syzkaller.appspot.com"

    def __init__(
        self,
        fail_bug: str | None = None,
        on_listing: Callable[[], None] | None = None,
    ) -> None:
        self.fail_bug = fail_bug
        self.on_listing = on_listing
        self.bug_calls: list[str] = []
        self.report_calls: list[str] = []
        self.patch_calls: list[str] = []
        self.patch_repos: list[str | None] = []

    def listing_json(self, namespace: str, status: str) -> bytes:
        self._assert_scope(namespace, status)
        if self.on_listing is not None:
            self.on_listing()
        return (FIXTURES / "raw" / "upstream_fixed.json").read_bytes()

    def listing_html(self, namespace: str, status: str) -> bytes:
        self._assert_scope(namespace, status)
        return (FIXTURES / "raw" / "upstream_fixed.html").read_bytes()

    def bug(self, json_url: str) -> bytes:
        key = "extid-alpha123" if "extid=alpha123" in json_url else "id-beta456"
        self.bug_calls.append(key)
        if key == self.fail_bug:
            raise FetchError(f"planned detail failure for {key}")
        return (FIXTURES / "raw" / "bugs" / f"{key}.json").read_bytes()

    def report(self, url: str) -> bytes:
        self.report_calls.append(url)
        return (FIXTURES / "artifacts" / "reports" / "extid-alpha123.txt").read_bytes()

    def patch(self, commit_hash: str, repo: str | None = None) -> tuple[bytes, str]:
        self.patch_calls.append(commit_hash)
        self.patch_repos.append(repo)
        payload = (FIXTURES / "artifacts" / "patches" / f"{commit_hash}.diff").read_bytes()
        return payload, f"https://example.invalid/{commit_hash}.diff"

    @staticmethod
    def _assert_scope(namespace: str, status: str) -> None:
        if (namespace, status) != ("upstream", "fixed"):
            raise AssertionError(f"unexpected update scope: {namespace}/{status}")


class EmptyListingClient(FakeClient):
    def listing_json(self, namespace: str, status: str) -> bytes:
        self._assert_scope(namespace, status)
        return b'{"version": 1, "Bugs": []}'


class RewrittenHashClient(FakeClient):
    def __init__(self, commit_hash: str) -> None:
        super().__init__()
        self.commit_hash = commit_hash

    def listing_json(self, namespace: str, status: str) -> bytes:
        payload = json.loads(super().listing_json(namespace, status))
        payload["Bugs"][0]["fix-commits"][0]["hash"] = self.commit_hash
        return json.dumps(payload).encode("utf-8")

    def bug(self, json_url: str) -> bytes:
        payload = json.loads(super().bug(json_url))
        if "extid=alpha123" in json_url:
            payload["fix-commits"][0]["hash"] = self.commit_hash
        return json.dumps(payload).encode("utf-8")

    def patch(self, commit_hash: str, repo: str | None = None) -> tuple[bytes, str]:
        self.patch_calls.append(commit_hash)
        payload = (FIXTURES / "artifacts" / "patches" / f"{ALPHA_HASH}.diff").read_bytes()
        return payload, f"https://example.invalid/{commit_hash}.diff"


class ChangedListingTitleClient(FakeClient):
    title = "KASAN: updated live title for alpha"
    report_url = "https://syzkaller.appspot.com/text?tag=CrashReport&x=alpha-updated"
    report_bytes = b"BUG: KASAN: updated alpha crash\nupdated stack trace\n"

    def listing_json(self, namespace: str, status: str) -> bytes:
        payload = json.loads(super().listing_json(namespace, status))
        payload["Bugs"][0]["title"] = self.title
        return json.dumps(payload).encode("utf-8")

    def bug(self, json_url: str) -> bytes:
        payload = json.loads(super().bug(json_url))
        if "extid=alpha123" in json_url:
            payload["title"] = self.title
            payload["crashes"][0]["crash-report-link"] = self.report_url
        return json.dumps(payload).encode("utf-8")

    def report(self, url: str) -> bytes:
        self.report_calls.append(url)
        return self.report_bytes


class CustomDashboardClient(FakeClient):
    dashboard = "https://mirror.example.invalid/syzbot"


class InvalidHtmlClient(FakeClient):
    def listing_html(self, namespace: str, status: str) -> bytes:
        self._assert_scope(namespace, status)
        return b"<html><body>truncated upstream response"


class ChangedReportClient(FakeClient):
    def __init__(
        self,
        *,
        fail_report: bool = False,
        report_payload: bytes | None = None,
        on_report: Callable[[], None] | None = None,
    ) -> None:
        super().__init__()
        self.fail_report = fail_report
        self.report_payload = report_payload
        self.on_report = on_report

    def bug(self, json_url: str) -> bytes:
        payload = json.loads(super().bug(json_url))
        if "extid=alpha123" in json_url:
            payload["crashes"][0]["crash-report-link"] = "/text?tag=CrashReport&x=alpha-new"
        return json.dumps(payload).encode("utf-8")

    def report(self, url: str) -> bytes:
        self.report_calls.append(url)
        if self.on_report is not None:
            self.on_report()
        if self.fail_report:
            raise FetchError("planned changed report failure")
        if self.report_payload is not None:
            return self.report_payload
        return (FIXTURES / "artifacts" / "reports" / "extid-alpha123.txt").read_bytes()


class ResolutionPatchClient(FakeClient):
    def patch(self, commit_hash: str, repo: str | None = None) -> tuple[bytes, str]:
        self.patch_calls.append(commit_hash)
        self.patch_repos.append(repo)
        payload = (FIXTURES / "artifacts" / "patches" / f"{ALPHA_HASH}.diff").read_bytes()
        return payload, f"https://example.invalid/{commit_hash}.diff"


class ExpandedListingClient(FakeClient):
    def __init__(self, *, fail_new_bug: bool = False) -> None:
        super().__init__()
        self.fail_new_bug = fail_new_bug

    def listing_html(self, namespace: str, status: str) -> bytes:
        return (
            super()
            .listing_html(namespace, status)
            .replace(b"</body>", b'<a href="/bug?id=gamma789">gamma</a></body>')
        )

    def listing_json(self, namespace: str, status: str) -> bytes:
        payload = json.loads(super().listing_json(namespace, status))
        payload["Bugs"].append(
            {
                "title": "KMSAN: uninitialized value in gamma",
                "link": "/bug?id=gamma789",
                "fix-commits": [
                    {
                        "title": "net: initialize gamma state",
                        "hash": GAMMA_HASH,
                        "repo": (
                            "git://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git"
                        ),
                        "branch": "master",
                    }
                ],
            }
        )
        return json.dumps(payload).encode("utf-8")

    def bug(self, json_url: str) -> bytes:
        if "id=gamma789" not in json_url:
            return super().bug(json_url)
        self.bug_calls.append("id-gamma789")
        if self.fail_new_bug:
            raise FetchError("planned detail failure for id-gamma789")
        return json.dumps(
            {
                "version": 1,
                "id": "gamma789",
                "title": "KMSAN: uninitialized value in gamma",
                "status": "fixed on 2026/09/01 12:00",
                "fix-commits": [
                    {
                        "title": "net: initialize gamma state",
                        "hash": GAMMA_HASH,
                        "repo": (
                            "git://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git"
                        ),
                        "branch": "master",
                    }
                ],
                "crashes": [
                    {
                        "title": "KMSAN: uninitialized value in gamma",
                        "crash-report-link": "/text?tag=CrashReport&x=gamma",
                    }
                ],
                "discussions": [],
            }
        ).encode("utf-8")

    def patch(self, commit_hash: str, repo: str | None = None) -> tuple[bytes, str]:
        if commit_hash != GAMMA_HASH:
            return super().patch(commit_hash, repo)
        self.patch_calls.append(commit_hash)
        self.patch_repos.append(repo)
        payload = (FIXTURES / "artifacts" / "patches" / f"{ALPHA_HASH}.diff").read_bytes()
        return payload, f"https://example.invalid/{commit_hash}.diff"


class OffOriginReportClient(FakeClient):
    def bug(self, json_url: str) -> bytes:
        payload = json.loads(super().bug(json_url))
        if "extid=alpha123" in json_url:
            payload["crashes"][0]["crash-report-link"] = "https://attacker.example.invalid/report"
        return json.dumps(payload).encode("utf-8")


class InvalidArtifactsClient(FakeClient):
    def report(self, url: str) -> bytes:
        self.report_calls.append(url)
        return b"\xef\xbb\xbf<?xml version='1.0'?><error>temporary failure</error>"

    def patch(self, commit_hash: str, repo: str | None = None) -> tuple[bytes, str]:
        self.patch_calls.append(commit_hash)
        return (
            b"\xef\xbb\xbf<?xml version='1.0'?><error>temporary failure diff --git a/a b/a</error>",
            f"https://example.invalid/{commit_hash}.diff",
        )


class UpdaterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = temporary_directory()
        self.paths = DataPaths.from_root(Path(self.temporary.name) / "data")
        self.database_path = self.paths.database

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_patch_job_prefers_first_nonempty_repository(self) -> None:
        jobs: dict[str, str | None] = {}

        _add_patch_job(jobs, BETA_HASH, None)
        _add_patch_job(jobs, BETA_HASH, "https://git.kernel.org/example.git")
        _add_patch_job(jobs, BETA_HASH, "https://github.com/example/other")

        self.assertEqual(jobs, {BETA_HASH: "https://git.kernel.org/example.git"})

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
            mock.patch("syz_sage.sync.bounded_results", side_effect=results),
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
            mock.patch("syz_sage.sync.atomic_write", side_effect=OSError("disk full")),
            mock.patch(
                "syz_sage.sync.fetch_artifact", return_value=validate_artifact(job, b"new report")
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

    def test_end_to_end_update_writes_files_and_database_without_network(self) -> None:
        progress: list[str] = []

        def observe_network_start() -> None:
            self.assertTrue(progress[-1].startswith("Checking "))
            self.assertFalse(
                self.database_path.exists(),
                "the updater opened SQLite before it finished the filesystem phase",
            )

        client = FakeClient(on_listing=observe_network_start)
        original_ingest_files = Database.ingest_files
        ingestion_observed: list[bool] = []

        def observe_ingestion(
            database: Database,
            paths: DataPaths,
            **kwargs: object,
        ) -> dict[str, object]:
            expected_files = [
                paths.listing_json,
                paths.listing_html,
                paths.catalog,
                paths.bugs / "extid-alpha123.json",
                paths.bugs / "id-beta456.json",
                paths.reports / "extid-alpha123.txt",
                paths.patches / f"{ALPHA_HASH}.diff",
            ]
            self.assertTrue(all(path.is_file() for path in expected_files))
            self.assertIn("updating SQLite", progress[-1])
            ingestion_observed.append(True)
            return original_ingest_files(database, paths, **kwargs)

        with mock.patch.object(Database, "ingest_files", new=observe_ingestion):
            summary = Updater(
                self.paths, self.database_path, client=client, progress=progress.append
            ).run(UpdateOptions(workers=2))

        self.assertTrue(summary.ok, summary.failures)
        self.assertEqual(ingestion_observed, [True])
        self.assertEqual(summary.database["status"], "completed")
        self.assertTrue(summary.database["activated"])
        self.assertEqual(summary.listing_bugs, 2)
        self.assertEqual(summary.details_downloaded, 2)
        self.assertEqual(summary.reports_downloaded, 1)
        self.assertEqual(summary.reports_unavailable, 1)
        self.assertEqual(summary.patches_downloaded, 1)
        self.assertEqual(set(client.bug_calls), {"extid-alpha123", "id-beta456"})
        self.assertEqual(client.patch_calls, [ALPHA_HASH])

        self.assertEqual(
            self.paths.listing_json.read_bytes(),
            (FIXTURES / "raw" / "upstream_fixed.json").read_bytes(),
        )
        self.assertEqual(
            self.paths.bugs.joinpath("extid-alpha123.json").read_bytes(),
            (FIXTURES / "raw" / "bugs" / "extid-alpha123.json").read_bytes(),
        )
        self.assertEqual(
            self.paths.reports.joinpath("extid-alpha123.txt").read_bytes(),
            (FIXTURES / "artifacts" / "reports" / "extid-alpha123.txt").read_bytes(),
        )
        self.assertEqual(
            self.paths.patches.joinpath(f"{ALPHA_HASH}.diff").read_bytes(),
            (FIXTURES / "artifacts" / "patches" / f"{ALPHA_HASH}.diff").read_bytes(),
        )

        with Database(self.database_path) as database:
            status = database.status()
            alpha = database.get_bug("extid-alpha123")
            patch_source = database.connection.execute(
                "SELECT source_url FROM documents WHERE kind = 'patch' AND natural_key = ?",
                (ALPHA_HASH,),
            ).fetchone()[0]
        self.assertEqual(patch_source, f"https://example.invalid/{ALPHA_HASH}.diff")
        self.assertEqual(status["bugs"], 2)
        self.assertEqual(status["reports"], 1)
        self.assertEqual(status["patches"], 1)
        self.assertIn("BUG: KASAN", alpha["report"]["text"])
        self.assertTrue(alpha["fixes"][0]["patch_available"])
        self.assertEqual(summary.known_fixed_bugs, 0)
        self.assertEqual(summary.new_fixed_bugs, 2)
        self.assertEqual(summary.new_fixed_bug_keys, ["extid-alpha123", "id-beta456"])

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

    def test_external_edit_after_save_cannot_poison_inventory_or_active_report(self) -> None:
        Updater(self.paths, self.database_path, client=FakeClient()).run()
        report_path = self.paths.reports / "extid-alpha123.txt"
        old_report = report_path.read_bytes()
        with Database(self.database_path, read_only=True) as database:
            active = database.status()["current_snapshot"]["id"]

        def edited_write(path: Path, payload: bytes) -> None:
            atomic_write(path, payload)
            if path == report_path:
                # Ordinary same-size in-place edit between save and observation.
                path.write_bytes(b"X" + payload[1:])

        with mock.patch("syz_sage.sync.atomic_write", side_effect=edited_write):
            summary = Updater(self.paths, self.database_path, client=FakeClient()).run(
                UpdateOptions(refresh_artifacts=True)
            )

        self.assertFalse(summary.ok)
        self.assertEqual(summary.failures[0]["kind"], "report")
        self.assertIn("changed after save", summary.failures[0]["error"])
        self.assertEqual(report_path.read_bytes(), b"X" + old_report[1:])
        state, error = load_sync_state(self.paths.sync_state)
        self.assertIsNone(error)
        self.assertIn("extid-alpha123", state.pending_reports)
        with Database(self.database_path, read_only=True) as database:
            self.assertEqual(database.status()["current_snapshot"]["id"], active)
            self.assertEqual(
                database.get_bug("extid-alpha123")["report"]["text"], old_report.decode()
            )

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
            mock.patch("syz_sage.sync.fetch_artifact", side_effect=fetch),
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

    def test_unchanged_database_result_is_successful(self) -> None:
        summary = UpdateSummary(
            namespace="upstream",
            status="fixed",
            database={
                "status": "unchanged",
                "activated": False,
                "failure_count": 0,
                "failures": [],
            },
        )

        self.assertTrue(summary.ok)

    def test_missing_database_result_is_not_successful(self) -> None:
        summary = UpdateSummary(namespace="upstream", status="fixed")

        self.assertFalse(summary.ok)

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

    def test_existing_input_lock_preserves_read_only_file_and_directory(self) -> None:
        self.paths.root.mkdir()
        lock = self.paths.root / ".syz_sage.update.lock"
        lock.write_bytes(b"saved lock metadata\n")
        lock.chmod(0o444)
        self.paths.root.chmod(0o555)
        before = lock.read_bytes(), lock.stat().st_mtime_ns, lock.stat().st_mode
        try:
            with (
                mock.patch.object(Path, "mkdir", side_effect=AssertionError("created directory")),
                _exclusive_update_lock(self.paths.root, create=False),
            ):
                self.assertEqual(set(self.paths.root.iterdir()), {lock})
            self.assertEqual(
                (lock.read_bytes(), lock.stat().st_mtime_ns, lock.stat().st_mode), before
            )
        finally:
            self.paths.root.chmod(0o755)
            lock.chmod(0o644)

    def test_existing_input_lock_does_not_create_missing_paths(self) -> None:
        with (
            self.assertRaises(FileNotFoundError),
            _exclusive_update_lock(self.paths.root, create=False),
        ):
            self.fail("missing lock was acquired")
        self.assertFalse(self.paths.root.exists())
        self.paths.root.mkdir()
        with (
            self.assertRaises(FileNotFoundError),
            _exclusive_update_lock(self.paths.root, create=False),
        ):
            self.fail("missing lock was acquired")
        self.assertEqual(list(self.paths.root.iterdir()), [])

    def test_windows_existing_empty_lock_does_not_initialize_a_byte(self) -> None:
        self.paths.root.mkdir()
        lock = self.paths.root / ".syz_sage.update.lock"
        lock.write_bytes(b"")
        before = lock.stat().st_mtime_ns
        locking = SimpleNamespace(LK_NBLCK=2, LK_UNLCK=0, locking=mock.Mock())
        with (
            mock.patch("syz_sage.sync.os", SimpleNamespace(name="nt", SEEK_END=os.SEEK_END)),
            mock.patch("syz_sage.sync.importlib.import_module", return_value=locking),
            _exclusive_update_lock(self.paths.root, create=False),
        ):
            self.assertEqual(lock.read_bytes(), b"")
        self.assertEqual(lock.read_bytes(), b"")
        self.assertEqual(lock.stat().st_mtime_ns, before)
        self.assertEqual(
            [call.args[1:] for call in locking.locking.call_args_list], [(2, 1), (0, 1)]
        )

    def test_update_lock_is_exclusive_between_processes(self) -> None:
        source = Path(__file__).resolve().parents[1] / "src"
        environment = os.environ.copy()
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        environment["PYTHONPATH"] = os.pathsep.join(
            [str(source), environment.get("PYTHONPATH", "")]
        ).rstrip(os.pathsep)
        program = """
import sys
from pathlib import Path
from syz_sage.sync import _exclusive_update_lock

try:
    with _exclusive_update_lock(Path(sys.argv[1]), create=sys.argv[2] == "create"):
        pass
except RuntimeError:
    raise SystemExit(23)
"""

        for mode in ("create", "read-only"):
            with self.subTest(mode=mode):
                command = [sys.executable, "-c", program, str(self.paths.root), mode]
                with _exclusive_update_lock(self.paths.root):
                    blocked = subprocess.run(
                        command, check=False, capture_output=True, env=environment
                    )
                available = subprocess.run(
                    command, check=False, capture_output=True, env=environment
                )
                self.assertEqual(blocked.returncode, 23, blocked.stderr.decode())
                self.assertEqual(available.returncode, 0, available.stderr.decode())


if __name__ == "__main__":
    unittest.main()
