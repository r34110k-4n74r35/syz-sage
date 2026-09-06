from __future__ import annotations

import argparse
import contextlib
import io
import json
import shutil
import subprocess
import sys
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from scripts import (
    build_fixed_bug_workbook,
    common,
    download_listings,
    fetch_artifacts,
    resolve_title_only_fixes,
)
from syz_sage.parsing.listing import PayloadError
from syz_sage.project.config import DataPaths
from syz_sage.project.storage import temporary_directory
from syz_sage.retrieval.client import FetchError, SyzbotClient
from syz_sage.retrieval.retry_state import SyncState, load_sync_state, save_sync_state
from syz_sage.retrieval.sync import _exclusive_update_lock
from tests.support import ALPHA_HASH, FIXTURES, PROJECT_ROOT

ROOT = PROJECT_ROOT


class ScriptCommandTests(unittest.TestCase):
    def test_scripts_are_runnable_from_the_project_root(self) -> None:
        for name in (
            "analyze_fixed_bugs",
            "audit_snapshot",
            "build_catalog",
            "build_fixed_bug_report",
            "build_fixed_bug_workbook",
            "download_listings",
            "fetch_artifacts",
            "resolve_title_only_fixes",
        ):
            with self.subTest(name=name):
                result = subprocess.run(
                    [sys.executable, "-B", "-m", f"scripts.{name}", "--help"],
                    cwd=ROOT,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("usage:", result.stdout)

    def test_workbook_launcher_preserves_environment_and_explicit_destinations(self) -> None:
        with temporary_directory() as directory:
            root = Path(directory)
            analysis = root / "inputs" / "analysis.json"
            output = root / "exports" / "report.xlsx"
            previews = root / "exports" / "previews"
            with (
                mock.patch("syz_sage.project.storage.project_root", return_value=root / "checkout"),
                mock.patch.object(
                    sys, "argv", ["workbook", str(analysis), str(output), str(previews)]
                ),
                mock.patch.object(build_fixed_bug_workbook.shutil, "which", return_value="node"),
                mock.patch.object(
                    build_fixed_bug_workbook.subprocess,
                    "run",
                    return_value=SimpleNamespace(returncode=0),
                ) as run,
            ):
                self.assertEqual(build_fixed_bug_workbook.main(), 0)
            self.assertEqual(
                run.call_args.args[0][-3:], list(map(str, (analysis, output, previews)))
            )
            self.assertNotIn("env", run.call_args.kwargs)
            self.assertEqual(list(root.iterdir()), [])

    def test_common_writer_accepts_explicit_destination_outside_checkout(self) -> None:
        with temporary_directory() as directory:
            root = Path(directory)
            output = root / "exports" / "report.md"
            with mock.patch(
                "syz_sage.project.storage.project_root", return_value=root / "checkout"
            ):
                common.write_text(output, "User-selected report\n")
            self.assertEqual(output.read_text(), "User-selected report\n")


class ScriptRetrievalTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = temporary_directory()
        self.addCleanup(temporary.cleanup)
        self.paths = DataPaths.from_root(Path(temporary.name) / "data")
        shutil.copytree(FIXTURES, self.paths.root)
        replacements = {
            "DATA": self.paths.root,
            "RAW": self.paths.raw,
            "PROCESSED": self.paths.processed,
            "ARTIFACTS": self.paths.artifacts,
            "BUG_JSON": self.paths.bugs,
            "REPORTS": self.paths.reports,
            "PATCHES": self.paths.patches,
            "REPROS": self.paths.reproducers,
            "CONFIGS": self.paths.configs,
            "OUTPUT": self.paths.resolutions,
        }
        for module in (common, download_listings, fetch_artifacts, resolve_title_only_fixes):
            for name, value in replacements.items():
                if hasattr(module, name):
                    patcher = mock.patch.object(module, name, value)
                    patcher.start()
                    self.addCleanup(patcher.stop)
        self.client = mock.create_autospec(SyzbotClient, instance=True)
        self.client.limiter = SimpleNamespace(requests=6, window=15.0)
        self.client.bug.return_value = (self.paths.bugs / "extid-alpha123.json").read_bytes()
        self.client.report.return_value = (self.paths.reports / "extid-alpha123.txt").read_bytes()
        self.client.patch.return_value = (
            (self.paths.patches / f"{ALPHA_HASH}.diff").read_bytes(),
            f"https://github.com/torvalds/linux/commit/{ALPHA_HASH}.diff",
        )
        self.client.listing_json.return_value = self.paths.listing_json.read_bytes()
        self.client.listing_html.return_value = self.paths.listing_html.read_bytes()
        for module in (common, download_listings, fetch_artifacts):
            patcher = mock.patch.object(module, "CLIENT", self.client)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.record = json.loads(self.paths.catalog.read_bytes())["bugs"][0]
        quiet = contextlib.redirect_stdout(io.StringIO())
        quiet.__enter__()
        self.addCleanup(quiet.__exit__, None, None, None)

    def test_listing_pair_is_validated_before_replacing_either_source(self) -> None:
        before = (self.paths.listing_json.read_bytes(), self.paths.listing_html.read_bytes())
        self.client.listing_html.return_value = b"<html><body>server error</body></html>"
        with mock.patch.object(sys, "argv", ["download_listings"]), self.assertRaises(PayloadError):
            download_listings.main()
        self.assertEqual(self.paths.listing_json.read_bytes(), before[0])
        self.assertEqual(self.paths.listing_html.read_bytes(), before[1])
        self.assertEqual(list(self.paths.raw.glob("*.tmp")), [])

    def test_listing_writer_uses_the_same_update_lock(self) -> None:
        with (
            _exclusive_update_lock(self.paths.root),
            mock.patch.object(sys, "argv", ["download_listings"]),
            self.assertRaisesRegex(RuntimeError, "another update"),
        ):
            download_listings.main()
        self.client.listing_json.assert_not_called()

    def test_listing_writer_does_not_create_optional_artifact_directories(self) -> None:
        with mock.patch.object(sys, "argv", ["download_listings"]):
            download_listings.main()
        self.assertFalse(self.paths.reproducers.exists())
        self.assertFalse(self.paths.configs.exists())

    def test_fetch_progress_stays_on_console_and_retry_state_is_retained(self) -> None:
        (self.paths.bugs / "extid-alpha123.json").unlink()
        self.client.bug.side_effect = FetchError("planned detail failure")
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            fetch_artifacts.cmd_syzbot([self.record], None, False, False, 1, False)
        self.assertIn("syzbot 1/1", output.getvalue())
        self.assertIn("fail=1", output.getvalue())
        self.assertFalse((self.paths.processed / "fetch_status.json").exists())
        state, error = load_sync_state(self.paths.sync_state)
        self.assertIsNone(error)
        self.assertIn("extid-alpha123", state.pending_details)

    def test_invalid_detail_preserves_cached_bytes_and_retry_intent(self) -> None:
        path = self.paths.bugs / "extid-alpha123.json"
        before = path.read_bytes()
        self.client.bug.return_value = b'{"title":"bad metadata", "crashes":"not a list"}'
        self.assertIsNone(fetch_artifacts.fetch_bug_json(self.record, force=True))
        self.assertEqual(path.read_bytes(), before)
        state, error = load_sync_state(self.paths.sync_state)
        self.assertIsNone(error)
        self.assertIn("extid-alpha123", state.pending_details)

    def test_downloaded_identifiers_cannot_choose_arbitrary_paths(self) -> None:
        unsafe = ("../escaped", "extid-../escaped", "/tmp/escaped", r"..\escaped")
        for value in unsafe:
            with self.subTest(value=value):
                with self.assertRaisesRegex(PayloadError, "unsafe bug key"):
                    fetch_artifacts.fetch_bug_json({"key": value, "json_url": "unused"})
                with self.assertRaisesRegex(PayloadError, "invalid commit hash"):
                    fetch_artifacts.fetch_patch(value, None)
        self.client.bug.assert_not_called()
        self.client.patch.assert_not_called()
        self.assertFalse(self.paths.sync_state.exists())

    def test_changed_report_failure_retries_with_cached_new_details(self) -> None:
        detail = json.loads(self.client.bug.return_value)
        detail["crashes"][0]["crash-report-link"] = "/text?tag=CrashReport&x=alpha-new"
        self.client.bug.return_value = json.dumps(detail).encode()
        self.client.report.side_effect = FetchError("planned report failure")
        path = self.paths.reports / "extid-alpha123.txt"
        before = path.read_bytes()
        failed = fetch_artifacts.process_bug(self.record, False, False, force_json=True)
        self.assertEqual(failed["error"], "report")
        self.assertEqual(path.read_bytes(), before)
        state, _ = load_sync_state(self.paths.sync_state)
        self.assertIn("extid-alpha123", state.pending_reports)
        self.assertEqual(state.pending_details, set())

        self.client.report.side_effect = None
        self.client.report.return_value = b"BUG: new representative report\n alpha+0x1/0x2\n"
        completed = fetch_artifacts.process_bug(self.record, False, False)
        self.assertTrue(completed["report"])
        self.assertIsNone(completed["error"])
        self.assertEqual(self.client.bug.call_count, 1)
        self.client.report.assert_called_with(
            "https://syzkaller.appspot.com/text?tag=CrashReport&x=alpha-new"
        )
        state, _ = load_sync_state(self.paths.sync_state)
        self.assertEqual(state.pending_reports, set())

    def test_optional_reproducers_and_configs_are_fetched_for_complete_bug(self) -> None:
        self.assertFalse(self.paths.reproducers.exists())
        self.assertFalse(self.paths.configs.exists())
        self.client.get.return_value = b"# valid optional research text\n"
        fetch_artifacts.cmd_syzbot([self.record], None, True, True, 1, False)
        self.assertTrue((self.paths.reproducers / "extid-alpha123.c").is_file())
        self.assertTrue((self.paths.reproducers / "extid-alpha123.syz").is_file())
        self.assertTrue((self.paths.configs / "alpha.config").is_file())
        self.assertEqual(self.client.get.call_count, 3)
        self.client.bug.assert_not_called()
        self.client.report.assert_not_called()
        self.client.patch.assert_not_called()

    def test_config_url_token_cannot_escape_the_artifact_directory(self) -> None:
        for query in ("x=../../escaped", "x=%2Ftmp%2Fescaped", "x=alpha&x=beta", "x="):
            with self.subTest(query=query):
                detail = json.loads(self.client.bug.return_value)
                detail["crashes"][0]["kernel-config"] = f"/text?tag=KernelConfig&{query}"
                with (
                    mock.patch.object(fetch_artifacts, "fetch_bug_json", return_value=detail),
                    self.assertRaisesRegex(PayloadError, "safe artifact token"),
                ):
                    fetch_artifacts.process_bug(self.record, False, True)
        self.client.get.assert_not_called()
        self.assertFalse(self.paths.configs.exists())

    def test_config_filename_uses_just_the_decoded_query_token(self) -> None:
        self.assertEqual(
            fetch_artifacts._config_path(
                "https://syzkaller.appspot.com/text?x=alpha&tag=KernelConfig"
            ),
            self.paths.configs / "alpha.config",
        )

    def test_markup_optional_artifact_is_not_saved(self) -> None:
        self.client.get.return_value = b'\xef\xbb\xbf<?xml version="1.0"?><error>failure</error>'
        destination = self.paths.configs / "alpha.config"
        self.assertFalse(
            fetch_artifacts.fetch_text(
                "https://syzkaller.appspot.com/text?tag=KernelConfig&x=alpha", destination
            )
        )
        self.assertFalse(destination.exists())

    def test_patch_uses_core_client_and_normalizes_filename(self) -> None:
        (self.paths.patches / f"{ALPHA_HASH}.diff").unlink()
        repository = "https://github.com/example/linux.git"
        self.assertTrue(fetch_artifacts.fetch_patch(ALPHA_HASH.upper(), repository))
        self.client.patch.assert_called_once_with(ALPHA_HASH, repository)
        self.assertEqual(
            (self.paths.patches / f"{ALPHA_HASH}.diff").read_bytes(),
            self.client.patch.return_value[0],
        )

    def test_bug_worker_fetches_listing_and_detail_fixes(self) -> None:
        listing_hash = "b" * 40
        repository = "https://github.com/example/linux.git"
        record = {
            **self.record,
            "fix_commits": [{"hash": listing_hash, "repo": repository}],
        }
        result = fetch_artifacts.process_bug(record, False, False)
        self.assertEqual(result["patches"], 2)
        self.assertIsNone(result["error"])
        self.client.patch.assert_called_once_with(listing_hash, repository)
        self.client.bug.assert_not_called()
        self.assertTrue((self.paths.patches / f"{listing_hash}.diff").is_file())

    def test_duplicate_patch_workers_serialize_failure_and_retry(self) -> None:
        save_sync_state(self.paths.sync_state, SyncState(pending_patches={ALPHA_HASH}))
        first_fetch = threading.Event()
        second_waiting = threading.Event()
        release_first = threading.Event()
        payload_and_url = self.client.patch.return_value

        class ObservedLock:
            def __init__(self) -> None:
                self.lock = threading.Lock()

            def __enter__(self) -> None:
                if not self.lock.acquire(blocking=False):
                    second_waiting.set()
                    self.lock.acquire()

            def __exit__(self, *args: object) -> None:
                self.lock.release()

        def download(commit_hash: str, repo: str | None) -> tuple[bytes, str]:
            if not first_fetch.is_set():
                first_fetch.set()
                if not release_first.wait(timeout=5):
                    raise RuntimeError("timed out waiting for test worker")
                raise FetchError("planned first worker failure")
            return payload_and_url

        self.client.patch.side_effect = download
        with (
            mock.patch.dict(fetch_artifacts.PATCH_LOCKS, {ALPHA_HASH: ObservedLock()}),
            ThreadPoolExecutor(max_workers=2) as executor,
        ):
            failed = executor.submit(fetch_artifacts.fetch_patch, ALPHA_HASH, None)
            try:
                self.assertTrue(first_fetch.wait(timeout=5))
                retried = executor.submit(fetch_artifacts.fetch_patch, ALPHA_HASH, None)
                self.assertTrue(second_waiting.wait(timeout=5))
                self.assertEqual(self.client.patch.call_count, 1)
            finally:
                release_first.set()
            self.assertFalse(failed.result(timeout=5))
            self.assertTrue(retried.result(timeout=5))
        state, error = load_sync_state(self.paths.sync_state)
        self.assertIsNone(error)
        self.assertEqual(state.pending_patches, set())
        self.assertTrue(fetch_artifacts.fetch_patch(ALPHA_HASH, None))
        self.assertEqual(self.client.patch.call_count, 2)
        self.assertEqual(
            (self.paths.patches / f"{ALPHA_HASH}.diff").read_bytes(), payload_and_url[0]
        )

    def test_status_does_not_create_directories_or_download(self) -> None:
        with (
            mock.patch.object(sys, "argv", ["fetch_artifacts", "--status"]),
            mock.patch.object(fetch_artifacts, "ensure_dirs") as ensure,
            mock.patch.object(fetch_artifacts, "_exclusive_update_lock") as lock,
        ):
            fetch_artifacts.main()
        ensure.assert_not_called()
        lock.assert_not_called()
        self.client.get.assert_not_called()
        self.assertFalse(self.paths.sync_state.exists())

    def test_resolver_searches_through_core_client_and_rejects_untrusted_repo(self) -> None:
        self.client.get.return_value = (
            f'<html><a href="/repo/commit/?id={ALPHA_HASH}">net: fix alpha</a></html>'.encode()
        )
        repo = "git://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git"
        result = resolve_title_only_fixes.resolve_one(
            "extid-alpha123", {"title": "net: fix alpha", "repo": repo}
        )
        self.assertEqual(result["status"], "resolved")
        self.client.get.assert_called_once_with(
            "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/log/"
            "?qt=grep&q=net%3A+fix+alpha",
            timeout=90,
            dashboard_request=False,
        )
        self.client.get.reset_mock()
        result = resolve_title_only_fixes.resolve_one(
            "extid-alpha123", {"title": "net: fix alpha", "repo": "https://untrusted.invalid/git"}
        )
        self.assertEqual(result["status"], "unresolved")
        self.client.get.assert_not_called()

    def test_resolution_identity_preserves_distinct_repositories(self) -> None:
        old = json.loads(self.paths.resolutions.read_bytes())["resolutions"][0]
        new = {**old, "repo": "https://git.kernel.org/pub/scm/linux/kernel/git/other/linux.git"}
        with (
            mock.patch.object(
                resolve_title_only_fixes, "load_jobs", return_value=[("id-beta456", {})]
            ),
            mock.patch.object(resolve_title_only_fixes, "resolve_one", return_value=new),
        ):
            resolve_title_only_fixes._run(argparse.Namespace(limit=None, workers=1))
        results = json.loads(self.paths.resolutions.read_bytes())["resolutions"]
        self.assertEqual({result["repo"] for result in results}, {old["repo"], new["repo"]})


if __name__ == "__main__":
    unittest.main()
