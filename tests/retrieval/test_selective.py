from __future__ import annotations

import copy
import hashlib
import shutil
import unittest
from concurrent.futures import CancelledError
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from syz_sage.database import Database
from syz_sage.parsing.listing import PayloadError
from syz_sage.project.config import DataPaths
from syz_sage.project.storage import exclusive_update_lock, temporary_directory
from syz_sage.retrieval.selective import fetch_evidence
from tests.support import FIXTURES, tree_digests


def artifact_url(tag: str, token: str) -> str:
    return f"https://syzkaller.appspot.com/text?tag={tag}&x={token}"


class EvidenceClient:
    dashboard = "https://syzkaller.appspot.com"

    def __init__(self) -> None:
        self.calls: list[str] = []
        self.cancelled = False
        self.resets = 0
        self.cancel_calls = 0
        self.responses: dict[str, bytes | BaseException] = {
            "ReproC": b"// saved C reproducer\nint main(void) { return 0; }\n",
            "ReproSyz": b"# saved syz reproducer\nr0 = openat$foo(0, 0, 0)\n",
            "KernelConfig": b"# kernel build configuration\nCONFIG_KASAN=y\n",
            "CrashReport": b"BUG: KASAN: sample\nCall Trace:\n sample+0x1/0x2\n",
        }

    def reset_cancellation(self) -> None:
        self.resets += 1
        self.cancelled = False

    def cancel(self) -> None:
        self.cancel_calls += 1
        self.cancelled = True

    def get(self, url: str, *, dashboard_request: bool = False) -> bytes:
        if not dashboard_request:
            raise AssertionError("evidence must use dashboard origin validation")
        if self.cancelled:
            raise CancelledError()
        self.calls.append(url)
        value = self.responses[parse_qs(urlsplit(url).query)["tag"][0]]
        if isinstance(value, BaseException):
            raise value
        return value


class SelectiveEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = temporary_directory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.paths = DataPaths.from_root(self.root / "data")
        self.client = EvidenceClient()
        self.bug = {
            "key": "extid-alpha123",
            "bug_url": "https://syzkaller.appspot.com/bug?extid=alpha123",
            "snapshot_id": 11,
            "in_current_snapshot": True,
            "crashes": [
                {
                    "ordinal": ordinal,
                    "title": f"crash {ordinal}",
                    "kernel_source_git": "git://git.kernel.org/example/linux.git",
                    "kernel_source_commit": str(ordinal) * 40,
                    "syzkaller_commit": "a" * 40,
                    "c_reproducer_url": artifact_url("ReproC", str(ordinal)),
                    "syz_reproducer_url": artifact_url("ReproSyz", str(ordinal)),
                    "kernel_config_url": artifact_url("KernelConfig", str(ordinal)),
                    "crash_report_url": artifact_url("CrashReport", str(ordinal)),
                }
                for ordinal in (0, 1)
            ],
            "report": {"source_url": artifact_url("CrashReport", "1"), "sha256": "unknown"},
        }

    def fetch(self, **options):
        return fetch_evidence(self.paths, self.bug, client=self.client, **options)

    def test_no_flags_has_no_filesystem_or_network_effects(self) -> None:
        with self.assertRaisesRegex(ValueError, "select at least one artifact"):
            self.fetch()
        self.assertFalse(self.paths.root.exists())
        self.assertEqual(self.client.calls, [])

    def test_default_selection_keeps_all_evidence_from_representative_crash(self) -> None:
        self.paths.reports.mkdir(parents=True)
        representative = self.paths.reports / "extid-alpha123.txt"
        representative.write_bytes(b"existing representative bytes")
        before = copy.deepcopy(self.bug)
        events = []
        result = self.fetch(
            c_repro=True, syz_repro=True, config=True, report=True, on_progress=events.append
        )
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["downloaded"], 4)
        self.assertEqual(result["selection"], "representative-report")
        self.assertEqual(result["crash"]["ordinal"], 1)
        self.assertEqual(result["crash"]["kernel_source_commit"], "1" * 40)
        self.assertEqual(result["reproduction_status"], "not_attempted")
        self.assertEqual(self.bug, before)
        self.assertTrue(
            all(parse_qs(urlsplit(url).query)["x"] == ["1"] for url in self.client.calls)
        )
        for entry in result["artifacts"]:
            path = Path(entry["path"])
            self.assertEqual(path.parent.name, "extid-alpha123")
            self.assertIn("crash-1-", path.name)
            self.assertIn(hashlib.sha256(entry["url"].encode()).hexdigest(), path.name)
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), entry["sha256"])
            self.assertEqual(path.stat().st_size, entry["size"])
        self.assertEqual(representative.read_bytes(), b"existing representative bytes")
        self.assertEqual(
            [(event.completed, event.total) for event in events], [(n, 4) for n in range(5)]
        )
        self.assertFalse(self.paths.database.exists())
        self.assertFalse(self.paths.sync_state.exists())

    def test_missing_selected_artifact_does_not_borrow_from_another_crash(self) -> None:
        self.bug["crashes"][0]["c_reproducer_url"] = ""
        result = self.fetch(c_repro=True, syz_repro=True, crash=0)
        self.assertFalse(result["ok"])
        self.assertEqual(result["crash"]["kernel_source_commit"], "0" * 40)
        self.assertEqual(result["unavailable"], 1)
        self.assertEqual(result["downloaded"], 1)
        self.assertEqual(self.client.calls, [artifact_url("ReproSyz", "0")])

    def test_default_selection_falls_back_to_first_report_then_first_crash(self) -> None:
        self.bug["report"] = None
        self.bug["crashes"][0]["crash_report_url"] = ""
        first_report = self.fetch(c_repro=True)
        self.assertEqual(first_report["selection"], "first-report")
        self.assertEqual(first_report["crash"]["ordinal"], 1)
        self.bug["crashes"][1]["crash_report_url"] = ""
        first_crash = self.fetch(config=True)
        self.assertEqual(first_crash["selection"], "first-crash")
        self.assertEqual(first_crash["crash"]["ordinal"], 0)

    def test_invalid_selection_and_bug_identity_fail_before_side_effects(self) -> None:
        for ordinal in (-1, 2, True):
            with self.subTest(ordinal=ordinal), self.assertRaises(ValueError):
                self.fetch(c_repro=True, crash=ordinal)
        self.bug["key"] = "../../outside"
        with self.assertRaises(PayloadError):
            self.fetch(c_repro=True)
        self.assertFalse(self.paths.root.exists())
        self.assertEqual(self.client.calls, [])

    def test_inactive_bug_and_missing_crashes_are_not_fetchable(self) -> None:
        self.bug["in_current_snapshot"] = False
        with self.assertRaisesRegex(ValueError, "active"):
            self.fetch(c_repro=True)
        self.bug["in_current_snapshot"] = True
        self.bug["crashes"] = []
        with self.assertRaisesRegex(ValueError, "no saved crash"):
            self.fetch(c_repro=True)
        self.assertFalse(self.paths.root.exists())

    def test_cache_reuse_is_stable_and_changed_url_gets_a_distinct_file(self) -> None:
        first = self.fetch(c_repro=True)
        path = Path(first["artifacts"][0]["path"])
        before = path.stat().st_mtime_ns
        second = self.fetch(c_repro=True)
        self.assertEqual(second["reused"], 1)
        self.assertEqual(len(self.client.calls), 1)
        self.assertEqual(path.stat().st_mtime_ns, before)
        self.bug["crashes"][1]["c_reproducer_url"] = artifact_url("ReproC", "new-build")
        third = self.fetch(c_repro=True)
        self.assertEqual(third["downloaded"], 1)
        self.assertNotEqual(third["artifacts"][0]["path"], str(path))
        self.assertTrue(path.is_file())

    def test_invalid_cached_bytes_are_repaired_without_refresh(self) -> None:
        first = self.fetch(config=True)
        path = Path(first["artifacts"][0]["path"])
        path.write_bytes(b"<html>temporary error</html>")
        second = self.fetch(config=True)
        self.assertEqual(second["downloaded"], 1)
        self.assertEqual(path.read_bytes(), self.client.responses["KernelConfig"])
        self.assertEqual(len(self.client.calls), 2)

    def test_failed_refresh_preserves_valid_prior_bytes_and_reports_retention(self) -> None:
        first = self.fetch(c_repro=True)
        path = Path(first["artifacts"][0]["path"])
        before = path.read_bytes()
        self.client.responses["ReproC"] = b"<html>temporary error</html>"
        result = self.fetch(c_repro=True, refresh=True)
        self.assertFalse(result["ok"])
        self.assertEqual(result["failed"], 1)
        self.assertTrue(result["artifacts"][0]["retained"])
        self.assertTrue(result["artifacts"][0]["available"])
        self.assertEqual(result["artifacts"][0]["sha256"], hashlib.sha256(before).hexdigest())
        self.assertEqual(path.read_bytes(), before)

    def test_invalid_payloads_are_never_saved_as_optional_evidence(self) -> None:
        self.client.responses.update(
            ReproC=b"temporarily unavailable",
            ReproSyz=b'{"error": "missing"}',
            KernelConfig=b"<html>temporary error</html>",
            CrashReport=b"",
        )
        result = self.fetch(c_repro=True, syz_repro=True, config=True, report=True)
        self.assertEqual(result["failed"], 4)
        self.assertFalse(result["ok"])
        self.assertTrue(all(not Path(entry["path"]).exists() for entry in result["artifacts"]))

    def test_matching_representative_cache_reuses_exact_raw_report_bytes(self) -> None:
        self.paths.reports.mkdir(parents=True)
        original = b"BUG: representative report\nraw-byte=\xff\n"
        (self.paths.reports / "extid-alpha123.txt").write_bytes(original)
        self.bug["report"]["sha256"] = hashlib.sha256(original).hexdigest()
        result = self.fetch(report=True)
        self.assertEqual(result["reused"], 1)
        self.assertEqual(result["artifacts"][0]["cache_source"], "representative-report")
        self.assertEqual(Path(result["artifacts"][0]["path"]).read_bytes(), original)
        self.assertEqual(self.client.calls, [])

    def test_url_validation_precedes_network_and_url_tokens_cannot_choose_paths(self) -> None:
        self.bug["crashes"][1]["crash_report_url"] = "https://other.example.invalid/report"
        self.bug["crashes"][1]["c_reproducer_url"] = artifact_url("ReproC", "../../escape")
        result = self.fetch(c_repro=True, report=True, crash=1)
        self.assertEqual(result["failed"], 1)
        self.assertEqual(result["downloaded"], 1)
        self.assertEqual(len(self.client.calls), 1)
        path = Path(result["artifacts"][0]["path"])
        self.assertEqual(path.parent, self.paths.reproducers / "extid-alpha123")
        self.assertNotIn("escape", path.name)

    def test_cancellation_stops_remaining_requests_releases_lock_and_allows_retry(self) -> None:
        for error in (KeyboardInterrupt(), CancelledError()):
            with self.subTest(error=type(error).__name__):
                self.client = EvidenceClient()
                original = self.client.responses["ReproC"]
                self.client.responses["ReproC"] = error
                with self.assertRaises(type(error)):
                    self.fetch(c_repro=True, config=True, refresh=True)
                self.assertEqual(len(self.client.calls), 1)
                self.assertEqual(self.client.cancel_calls, 1)
                with exclusive_update_lock(self.paths.root):
                    pass
                self.client.responses["ReproC"] = original
                result = self.fetch(c_repro=True, config=True, refresh=True)
                self.assertTrue(result["ok"], result)
                self.assertEqual(self.client.resets, 2)

    def test_unavailable_artifacts_do_not_create_directories_or_fetch(self) -> None:
        self.bug["crashes"][1]["c_reproducer_url"] = ""
        self.bug["crashes"][1]["kernel_config_url"] = None
        result = self.fetch(c_repro=True, config=True)
        self.assertEqual(result["unavailable"], 2)
        self.assertFalse(result["ok"])
        self.assertFalse(self.paths.root.exists())
        self.assertEqual(self.client.calls, [])

    def test_shared_update_lock_prevents_concurrent_evidence_writes(self) -> None:
        with (
            exclusive_update_lock(self.paths.root),
            self.assertRaisesRegex(RuntimeError, "another update"),
        ):
            self.fetch(c_repro=True)
        self.assertEqual(self.client.calls, [])
        self.assertFalse(self.paths.reproducers.exists())

    def test_optional_files_do_not_change_active_database_or_update_fingerprint(self) -> None:
        shutil.copytree(FIXTURES, self.paths.root)
        with Database(self.paths.database) as database:
            database.import_legacy(self.paths.root)
        with Database(self.paths.database, read_only=True) as database:
            bug = database.get_bug("extid-alpha123")
            before_status = database.status()
            before_current = database.check_files_current(self.paths)
        before = tree_digests(self.paths.database_dir)
        result = fetch_evidence(
            self.paths,
            bug,
            c_repro=True,
            syz_repro=True,
            config=True,
            report=True,
            client=self.client,
        )
        self.assertTrue(result["ok"], result)
        self.assertEqual(tree_digests(self.paths.database_dir), before)
        with Database(self.paths.database, read_only=True) as database:
            self.assertEqual(database.status(), before_status)
            self.assertEqual(database.get_bug("extid-alpha123"), bug)
            self.assertEqual(database.check_files_current(self.paths), before_current)


if __name__ == "__main__":
    unittest.main()
