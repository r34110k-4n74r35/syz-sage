from __future__ import annotations

import json
import unittest
from unittest import mock

from syz_sage.database import Database
from syz_sage.project.progress_events import ProgressEvent
from syz_sage.retrieval.client import FetchError
from syz_sage.retrieval.resolutions import unresolved_fix_keys
from syz_sage.retrieval.sync import UpdateOptions, Updater, UpdateSummary
from tests.retrieval.support import ResolutionPatchClient, UpdaterFixture
from tests.support import ALPHA_HASH, BETA_HASH, digest

BETA_KEY = "id-beta456"
BETA_REPORT = "https://syzkaller.appspot.com/text?tag=CrashReport&x=beta"
REPO = "git://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git"


class PatchDiscoveryClient(ResolutionPatchClient):
    """Keep the listing stable while publishing additional detail metadata."""

    def __init__(
        self,
        *,
        detail_hash: str | None = None,
        empty_listing_fixes: bool = False,
        empty_detail_fixes: bool = False,
        mixed_fixes: bool = False,
        report_url: str = BETA_REPORT,
        fail_detail: bool = False,
        fail_patch: str | None = None,
    ) -> None:
        super().__init__(fail_bug=BETA_KEY if fail_detail else None)
        self.detail_hash = detail_hash
        self.empty_listing_fixes = empty_listing_fixes
        self.empty_detail_fixes = empty_detail_fixes
        self.mixed_fixes = mixed_fixes
        self.report_url = report_url
        self.fail_patch = fail_patch

    def listing_json(self, namespace: str, status: str) -> bytes:
        payload = json.loads(super().listing_json(namespace, status))
        beta = payload["Bugs"][1]
        if self.empty_listing_fixes:
            beta["fix-commits"] = []
        elif self.mixed_fixes:
            beta["fix-commits"].append(dict(payload["Bugs"][0]["fix-commits"][0]))
        return json.dumps(payload).encode()

    def bug(self, json_url: str) -> bytes:
        payload = json.loads(super().bug(json_url))
        if "id=beta456" in json_url:
            if self.empty_detail_fixes:
                payload["fix-commits"] = []
            else:
                if self.detail_hash is not None:
                    payload["fix-commits"][0]["hash"] = self.detail_hash
                if self.mixed_fixes:
                    payload["fix-commits"].append(
                        {"title": "net: fix alpha lifetime", "hash": ALPHA_HASH, "repo": REPO}
                    )
            payload["crashes"][0]["crash-report-link"] = self.report_url
        return json.dumps(payload).encode()

    def patch(self, commit_hash: str, repo: str | None = None) -> tuple[bytes, str]:
        if commit_hash == self.fail_patch:
            self.patch_calls.append(commit_hash)
            self.patch_repos.append(repo)
            raise FetchError("patch is not published yet")
        return super().patch(commit_hash, repo)


class UpdatePatchDiscoveryTests(UpdaterFixture, unittest.TestCase):
    def test_anonymous_or_invalid_fix_is_not_hidden_by_a_usable_reference(self) -> None:
        for fixes in (
            [{"hash": ALPHA_HASH}, {}],
            [{"hash": ALPHA_HASH, "title": "fix"}, {"hash": "invalid", "title": "fix"}],
        ):
            with self.subTest(fixes=fixes):
                record = {"key": BETA_KEY, "fix_commits": fixes}
                self.assertEqual(unresolved_fix_keys([record], {}, {}), {BETA_KEY})

    def update(
        self,
        client: PatchDiscoveryClient,
        options: UpdateOptions | None = None,
        *,
        events: list[ProgressEvent] | None = None,
        messages: list[str] | None = None,
    ) -> UpdateSummary:
        return Updater(
            self.paths,
            self.database_path,
            client=client,
            on_progress=events.append if events is not None else None,
            progress=messages.append if messages is not None else None,
        ).run(options)

    def assert_fix_rechecks(
        self,
        events: list[ProgressEvent],
        *,
        checked: int,
        resolved: int,
        unresolved: int,
        failed: int,
    ) -> None:
        self.assertEqual(
            [event.message for event in events if event.phase == "fix-discovery-result"],
            [
                f"Fix rechecks: {checked} checked; {resolved} resolved; "
                f"{unresolved} awaiting hashes; {failed} failed"
            ],
        )

    def assert_beta_patch_available(self) -> None:
        self.assertTrue((self.paths.patches / f"{BETA_HASH}.diff").is_file())
        with Database(self.database_path, read_only=True) as database:
            beta = database.get_bug(BETA_KEY)
        matching = [fix for fix in beta["fixes"] if fix["hash"] == BETA_HASH]
        self.assertEqual(len(matching), 1)
        self.assertTrue(matching[0]["patch_available"])

    def test_default_updates_leave_cached_unresolved_fix_until_recheck_requested(self) -> None:
        self.assertTrue(self.update(PatchDiscoveryClient()).ok)
        observed_paths = (
            self.paths.bugs / f"{BETA_KEY}.json",
            self.paths.reports / f"{BETA_KEY}.txt",
            self.database_path,
        )
        before = {path: (digest(path), path.stat().st_mtime_ns) for path in observed_paths}

        for attempt in range(2):
            with self.subTest(attempt=attempt):
                client = PatchDiscoveryClient(detail_hash=BETA_HASH)
                events: list[ProgressEvent] = []
                with mock.patch.object(
                    Database, "ingest_files", side_effect=AssertionError("must skip")
                ):
                    result = self.update(client, events=events)

                self.assertTrue(result.ok, result.failures)
                self.assertEqual(client.bug_calls, [])
                self.assertEqual(client.patch_calls, [])
                self.assertEqual(client.report_calls, [])
                self.assertTrue(result.database["skipped"])
                self.assertEqual(result.details_downloaded, 0)
                self.assertEqual(result.details_reused, 2)
                self.assertEqual(
                    {path: (digest(path), path.stat().st_mtime_ns) for path in observed_paths},
                    before,
                )
                self.assertFalse(any(event.phase == "fix-discovery-result" for event in events))
                self.assertEqual(
                    json.loads(self.paths.sync_state.read_bytes())["pending_details"], []
                )

        rechecked = PatchDiscoveryClient(detail_hash=BETA_HASH)
        completed = self.update(rechecked, UpdateOptions(recheck_fixes=True))
        self.assertTrue(completed.ok, completed.failures)
        self.assertEqual(rechecked.bug_calls, [BETA_KEY])
        self.assertEqual(rechecked.patch_calls, [BETA_HASH])
        self.assertFalse(completed.database["skipped"])
        self.assert_beta_patch_available()

    def test_default_update_reuses_cached_detail_with_no_fix_entries(self) -> None:
        initial = PatchDiscoveryClient(empty_listing_fixes=True, empty_detail_fixes=True)
        self.assertTrue(self.update(initial).ok)
        client = PatchDiscoveryClient(empty_listing_fixes=True, detail_hash=BETA_HASH)

        result = self.update(client)

        self.assertTrue(result.ok, result.failures)
        self.assertEqual(client.bug_calls, [])
        self.assertEqual(client.patch_calls, [])
        self.assertEqual(client.report_calls, [])
        self.assertTrue(result.database["skipped"])

    def test_default_update_recovers_missing_or_invalid_unresolved_detail(self) -> None:
        self.assertTrue(self.update(PatchDiscoveryClient()).ok)
        detail_path = self.paths.bugs / f"{BETA_KEY}.json"
        for content in (None, b"not valid JSON"):
            with self.subTest(content=content):
                if content is None:
                    detail_path.unlink()
                else:
                    detail_path.write_bytes(content)
                client = PatchDiscoveryClient()

                result = self.update(client)

                self.assertTrue(result.ok, result.failures)
                self.assertEqual(client.bug_calls, [BETA_KEY])
                self.assertEqual(client.patch_calls, [])
                self.assertEqual(result.details_downloaded, 1)
                self.assertEqual(result.details_reused, 1)
                self.assertEqual(json.loads(detail_path.read_bytes())["id"], "beta456")

    def test_title_only_fix_discovers_later_hash_without_listing_change(self) -> None:
        self.assertTrue(self.update(PatchDiscoveryClient()).ok)
        listing_before = self.paths.listing_json.read_bytes()
        client = PatchDiscoveryClient(detail_hash=BETA_HASH)
        events: list[ProgressEvent] = []

        result = self.update(client, UpdateOptions(recheck_fixes=True), events=events)

        self.assertTrue(result.ok, result.failures)
        self.assertEqual(self.paths.listing_json.read_bytes(), listing_before)
        self.assertEqual(result.changed_bugs, 0)
        self.assertEqual(result.new_fixed_bugs, 0)
        self.assertEqual(client.bug_calls, [BETA_KEY])
        self.assertEqual(client.patch_calls, [BETA_HASH])
        self.assertEqual(client.report_calls, [])
        self.assertFalse(result.database["skipped"])
        self.assert_beta_patch_available()
        self.assert_fix_rechecks(events, checked=1, resolved=1, unresolved=0, failed=0)

        # The retained listing still has a title-only reference. A matching
        # hashed detail reference satisfies it on subsequent requested rechecks.
        unchanged = PatchDiscoveryClient(detail_hash=BETA_HASH)
        events.clear()
        final = self.update(unchanged, UpdateOptions(recheck_fixes=True), events=events)
        self.assertTrue(final.ok, final.failures)
        self.assertTrue(final.database["skipped"])
        self.assertEqual(unchanged.bug_calls, [])
        self.assertEqual(unchanged.patch_calls, [])
        self.assertEqual(unchanged.report_calls, [])
        self.assertFalse(any(event.phase == "fix-discovery-result" for event in events))

    def test_absent_fix_entries_discover_a_later_detail_fix(self) -> None:
        initial = PatchDiscoveryClient(empty_listing_fixes=True, empty_detail_fixes=True)
        self.assertTrue(self.update(initial).ok)
        client = PatchDiscoveryClient(empty_listing_fixes=True, detail_hash=BETA_HASH)

        result = self.update(client, UpdateOptions(recheck_fixes=True))

        self.assertTrue(result.ok, result.failures)
        self.assertEqual(result.changed_bugs, 0)
        self.assertEqual(client.bug_calls, [BETA_KEY])
        self.assertEqual(client.patch_calls, [BETA_HASH])
        self.assertEqual(client.report_calls, [])
        self.assert_beta_patch_available()

    def test_new_detail_fix_identity_uses_saved_resolution_in_recheck_outcome(self) -> None:
        initial = PatchDiscoveryClient(empty_listing_fixes=True, empty_detail_fixes=True)
        self.assertTrue(self.update(initial).ok)
        self.paths.resolutions.write_text(
            json.dumps(
                {
                    "resolutions": [
                        {
                            "bug_key": BETA_KEY,
                            "title": "fs: guard beta state",
                            "repo": REPO,
                            "status": "resolved",
                            "hash": BETA_HASH,
                        }
                    ]
                }
            )
        )
        client = PatchDiscoveryClient(empty_listing_fixes=True)
        events: list[ProgressEvent] = []

        result = self.update(client, UpdateOptions(recheck_fixes=True), events=events)

        self.assertTrue(result.ok, result.failures)
        self.assertEqual(client.bug_calls, [BETA_KEY])
        self.assertEqual(client.patch_calls, [BETA_HASH])
        self.assertEqual(client.report_calls, [])
        self.assert_fix_rechecks(events, checked=1, resolved=1, unresolved=0, failed=0)
        self.assert_beta_patch_available()

        unchanged = PatchDiscoveryClient(empty_listing_fixes=True)
        final = self.update(unchanged, UpdateOptions(recheck_fixes=True))
        self.assertTrue(final.ok, final.failures)
        self.assertEqual(unchanged.bug_calls, [])
        self.assertEqual(unchanged.patch_calls, [])
        self.assertTrue(final.database["skipped"])

    def test_live_hash_satisfies_matching_stale_title_only_detail(self) -> None:
        self.assertTrue(self.update(PatchDiscoveryClient()).ok)
        detail_path = self.paths.bugs / f"{BETA_KEY}.json"
        stale_detail = detail_path.read_bytes()
        client = PatchDiscoveryClient()
        published_listing = json.loads(client.listing_json("upstream", "fixed"))
        published_listing["Bugs"][1]["fix-commits"][0]["hash"] = BETA_HASH
        client.listing_json = mock.Mock(return_value=json.dumps(published_listing).encode())

        result = self.update(client)

        self.assertTrue(result.ok, result.failures)
        self.assertEqual(client.bug_calls, [])
        self.assertEqual(client.report_calls, [])
        self.assertEqual(client.patch_calls, [BETA_HASH])
        self.assertEqual(detail_path.read_bytes(), stale_detail)
        self.assertEqual(result.changed_bug_keys, [BETA_KEY])
        self.assert_beta_patch_available()

    def test_unresolved_fix_is_checked_when_another_fix_already_has_a_patch(self) -> None:
        self.assertTrue(self.update(PatchDiscoveryClient(mixed_fixes=True)).ok)
        alpha_patch = self.paths.patches / f"{ALPHA_HASH}.diff"
        alpha_before = digest(alpha_patch)
        client = PatchDiscoveryClient(mixed_fixes=True, detail_hash=BETA_HASH)

        result = self.update(client, UpdateOptions(recheck_fixes=True))

        self.assertTrue(result.ok, result.failures)
        self.assertEqual(client.bug_calls, [BETA_KEY])
        self.assertEqual(client.patch_calls, [BETA_HASH])
        self.assertEqual(client.report_calls, [])
        self.assertEqual(digest(alpha_patch), alpha_before)
        self.assert_beta_patch_available()

    def test_unchanged_unresolved_detail_reuses_report_and_skips_database(self) -> None:
        self.assertTrue(self.update(PatchDiscoveryClient()).ok)
        detail_path = self.paths.bugs / f"{BETA_KEY}.json"
        report_path = self.paths.reports / f"{BETA_KEY}.txt"
        observed_paths = (detail_path, report_path, self.database_path)
        before = {path: (digest(path), path.stat().st_mtime_ns) for path in observed_paths}
        for attempt in range(2):
            with self.subTest(attempt=attempt):
                client = PatchDiscoveryClient()
                events: list[ProgressEvent] = []
                messages: list[str] = []
                with mock.patch.object(
                    Database, "ingest_files", side_effect=AssertionError("must skip")
                ):
                    result = self.update(
                        client, UpdateOptions(recheck_fixes=True), events=events, messages=messages
                    )

                self.assertTrue(result.ok, result.failures)
                self.assertEqual(client.bug_calls, [BETA_KEY])
                self.assertEqual(client.report_calls, [])
                self.assertEqual(client.patch_calls, [])
                self.assertTrue(result.database["skipped"])
                self.assertEqual(
                    {path: (digest(path), path.stat().st_mtime_ns) for path in observed_paths},
                    before,
                )
                state = json.loads(self.paths.sync_state.read_bytes())
                self.assertEqual(state["pending_details"], [])
                self.assertEqual(state["pending_reports"], [])
                self.assertEqual(state["pending_patches"], [])
                saved = [event.message for event in events if event.phase == "saved-details"][-1]
                for text in ("1 reused", "0 missing/invalid", "0 retries", "1 fix rechecks"):
                    self.assertIn(text, saved)
                phase_messages = [
                    event.message for event in events if event.phase == "download-bug-details"
                ]
                self.assertTrue(phase_messages)
                self.assertTrue(all("Bug details: rechecking 1" in text for text in phase_messages))
                self.assertFalse(any("Bug details: downloading" in text for text in messages))
                self.assert_fix_rechecks(events, checked=1, resolved=0, unresolved=1, failed=0)

    def test_discovery_refreshes_report_when_its_representative_url_changes(self) -> None:
        self.assertTrue(self.update(PatchDiscoveryClient()).ok)
        new_url = "https://syzkaller.appspot.com/text?tag=CrashReport&x=beta-new"
        client = PatchDiscoveryClient(detail_hash=BETA_HASH, report_url=new_url)

        result = self.update(client, UpdateOptions(recheck_fixes=True))

        self.assertTrue(result.ok, result.failures)
        self.assertEqual(client.bug_calls, [BETA_KEY])
        self.assertEqual(client.report_calls, [new_url])
        self.assertEqual(client.patch_calls, [BETA_HASH])
        with Database(self.database_path, read_only=True) as database:
            beta = database.get_bug(BETA_KEY)
        self.assertEqual(beta["report"]["source_url"], new_url)

    def test_failed_discovery_retains_valid_detail_and_retries_next_update(self) -> None:
        self.assertTrue(self.update(PatchDiscoveryClient()).ok)
        detail_path = self.paths.bugs / f"{BETA_KEY}.json"
        before = detail_path.read_bytes()
        with Database(self.database_path, read_only=True) as database:
            prior_snapshot = database.status()["current_snapshot"]["id"]
        failing = PatchDiscoveryClient(fail_detail=True)
        events: list[ProgressEvent] = []

        partial = self.update(failing, UpdateOptions(recheck_fixes=True), events=events)

        self.assertFalse(partial.ok)
        self.assertEqual(failing.bug_calls, [BETA_KEY])
        self.assertEqual(failing.report_calls, [])
        self.assertEqual(detail_path.read_bytes(), before)
        self.assertEqual(
            json.loads(self.paths.sync_state.read_bytes())["pending_details"], [BETA_KEY]
        )
        with Database(self.database_path, read_only=True) as database:
            self.assertEqual(database.status()["current_snapshot"]["id"], prior_snapshot)
        self.assert_fix_rechecks(events, checked=0, resolved=0, unresolved=0, failed=1)

        recovered = PatchDiscoveryClient(detail_hash=BETA_HASH)
        events.clear()
        complete = self.update(recovered, events=events)
        self.assertTrue(complete.ok, complete.failures)
        self.assertEqual(recovered.bug_calls, [BETA_KEY])
        self.assertEqual(recovered.patch_calls, [BETA_HASH])
        self.assert_beta_patch_available()
        self.assertEqual(json.loads(self.paths.sync_state.read_bytes())["pending_details"], [])
        self.assertFalse(any(event.phase == "fix-discovery-result" for event in events))
        saved = [event.message for event in events if event.phase == "saved-details"][-1]
        self.assertIn("1 retries", saved)

    def test_hash_discovery_does_not_clear_invalid_report_metadata_retry(self) -> None:
        self.assertTrue(self.update(PatchDiscoveryClient()).ok)
        events: list[ProgressEvent] = []
        client = PatchDiscoveryClient(
            detail_hash=BETA_HASH, report_url="https://example.com/untrusted-report"
        )

        result = self.update(client, UpdateOptions(recheck_fixes=True), events=events)

        self.assertFalse(result.ok)
        self.assertEqual(client.bug_calls, [BETA_KEY])
        self.assertEqual(client.report_calls, [])
        self.assertEqual(client.patch_calls, [BETA_HASH])
        self.assertTrue(any(failure["kind"] == "report-metadata" for failure in result.failures))
        self.assert_fix_rechecks(events, checked=1, resolved=1, unresolved=0, failed=0)
        state = json.loads(self.paths.sync_state.read_bytes())
        self.assertEqual(state["pending_details"], [BETA_KEY])

        recovered = PatchDiscoveryClient(detail_hash=BETA_HASH)
        completed = self.update(recovered)
        self.assertTrue(completed.ok, completed.failures)
        self.assertEqual(recovered.bug_calls, [BETA_KEY])
        self.assertEqual(json.loads(self.paths.sync_state.read_bytes())["pending_details"], [])
        self.assert_beta_patch_available()

    def test_no_patches_does_not_automatically_refresh_unresolved_details(self) -> None:
        self.assertTrue(self.update(PatchDiscoveryClient()).ok)
        client = PatchDiscoveryClient(detail_hash=BETA_HASH)

        result = self.update(client, UpdateOptions(patches=False, recheck_fixes=True))

        self.assertFalse(result.ok)
        self.assertEqual(client.bug_calls, [])
        self.assertEqual(client.patch_calls, [])
        self.assertEqual(client.report_calls, [])
        self.assertFalse((self.paths.patches / f"{BETA_HASH}.diff").exists())

    def test_limit_does_not_refresh_unselected_unresolved_bug(self) -> None:
        self.assertTrue(self.update(PatchDiscoveryClient()).ok)
        client = PatchDiscoveryClient(detail_hash=BETA_HASH)

        result = self.update(client, UpdateOptions(limit=1, recheck_fixes=True))

        self.assertFalse(result.ok)
        self.assertEqual(client.bug_calls, [])
        self.assertEqual(client.patch_calls, [])
        self.assertEqual(client.report_calls, [])
        self.assertFalse((self.paths.patches / f"{BETA_HASH}.diff").exists())

    def test_known_hash_retries_later_patch_without_refreshing_details(self) -> None:
        initial = PatchDiscoveryClient(detail_hash=BETA_HASH, fail_patch=BETA_HASH)
        partial = self.update(initial)
        self.assertFalse(partial.ok)
        self.assertFalse((self.paths.patches / f"{BETA_HASH}.diff").exists())
        self.assertEqual(
            json.loads(self.paths.sync_state.read_bytes())["pending_patches"], [BETA_HASH]
        )
        client = PatchDiscoveryClient(detail_hash=BETA_HASH)

        result = self.update(client)

        self.assertTrue(result.ok, result.failures)
        self.assertEqual(client.bug_calls, [])
        self.assertEqual(client.patch_calls, [BETA_HASH])
        self.assertEqual(client.report_calls, [])
        self.assert_beta_patch_available()

    def test_saved_and_accepted_resolutions_avoid_unnecessary_detail_refresh(self) -> None:
        self.assertTrue(self.update(PatchDiscoveryClient()).ok)
        resolution = {
            "bug_key": BETA_KEY,
            "title": "fs: guard beta state",
            "repo": REPO,
            "status": "resolved",
            "hash": BETA_HASH,
        }
        self.paths.resolutions.write_text(json.dumps({"resolutions": [resolution]}))
        client = PatchDiscoveryClient()

        result = self.update(client, UpdateOptions(recheck_fixes=True))

        self.assertTrue(result.ok, result.failures)
        self.assertEqual(client.bug_calls, [])
        self.assertEqual(client.patch_calls, [BETA_HASH])
        self.assertEqual(client.report_calls, [])
        self.assert_beta_patch_available()

        # A formerly accepted resolution remains usable if the local resolver
        # subsequently leaves that exact identity unresolved.
        resolution.pop("hash")
        resolution["status"] = "unresolved"
        self.paths.resolutions.write_text(json.dumps({"resolutions": [resolution]}))
        accepted = PatchDiscoveryClient()
        completed = self.update(accepted, UpdateOptions(recheck_fixes=True))
        self.assertTrue(completed.ok, completed.failures)
        self.assertEqual(accepted.bug_calls, [])
        self.assertEqual(accepted.patch_calls, [])
        self.assertEqual(accepted.report_calls, [])
        self.assert_beta_patch_available()

    def test_explicit_detail_refresh_still_refreshes_unchanged_reports(self) -> None:
        self.assertTrue(self.update(PatchDiscoveryClient(detail_hash=BETA_HASH)).ok)
        client = PatchDiscoveryClient(detail_hash=BETA_HASH)

        result = self.update(client, UpdateOptions(refresh_details=True))

        self.assertTrue(result.ok, result.failures)
        self.assertCountEqual(client.bug_calls, ["extid-alpha123", BETA_KEY])
        self.assertCountEqual(
            client.report_calls,
            ["https://syzkaller.appspot.com/text?tag=CrashReport&x=alpha", BETA_REPORT],
        )
        self.assertEqual(client.patch_calls, [])


if __name__ == "__main__":
    unittest.main()
