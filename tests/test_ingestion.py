from __future__ import annotations

import hashlib
import json
import os
import shutil
import unittest
from collections import Counter
from pathlib import Path
from unittest import mock

from syz_sage import location_store
from syz_sage.database import Database
from syz_sage.ingestion import FileInventory, file_stamp
from syz_sage.storage import temporary_directory

FIXTURES = Path(__file__).parent / "fixtures" / "legacy_data"
ALPHA_HASH = "a" * 40


class FileIngestionTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = temporary_directory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.data = self.root / "data"
        shutil.copytree(FIXTURES, self.data)
        self.database_path = self.root / "store.sqlite3"
        self.layout = Database._legacy_layout(self.data)

    def source_files(self) -> list[Path]:
        return sorted(path for path in self.data.rglob("*") if path.is_file())

    def change_catalog(self) -> None:
        path = self.layout["catalog"]
        payload = json.loads(path.read_bytes())
        payload["generated_at"] = "2026-09-06T12:00:00Z"
        path.write_text(json.dumps(payload))

    def test_fingerprint_preserves_legacy_content_algorithm_and_reuses_scan(self) -> None:
        expected = hashlib.sha256()
        for path in self.source_files():
            expected.update(str(path.relative_to(self.data)).encode())
            expected.update(b"\0")
            expected.update(path.read_bytes())
            expected.update(b"\0")
        inventory = FileInventory(max_bytes=0)
        first = inventory.fingerprint(self.layout)
        self.assertEqual(first, (expected.hexdigest(), []))
        with mock.patch.object(Path, "read_bytes", side_effect=AssertionError("reread")):
            self.assertEqual(inventory.fingerprint(self.layout), first)

    def test_shared_current_check_and_ingestion_read_each_source_once(self) -> None:
        inventory = FileInventory()
        calls: Counter[Path] = Counter()
        original = Path.read_bytes
        sources = set(self.source_files())

        def read(path: Path) -> bytes:
            if path in sources:
                calls[path] += 1
            return original(path)

        with Database(self.database_path) as database:
            database.initialize()
            with mock.patch.object(Path, "read_bytes", autospec=True, side_effect=read):
                self.assertIsNone(database.check_files_current(self.data, inventory=inventory))
                result = database.ingest_files(self.data, inventory=inventory)
            self.assertEqual(result["status"], "completed", result)
            self.assertTrue(database.health_check()["ok"])
        self.assertEqual(calls, Counter({path: 1 for path in self.source_files()}))

    def test_read_only_noop_keeps_database_bytes_and_mtime(self) -> None:
        with Database(self.database_path) as database:
            database.ingest_files(self.data)
        before = self.database_path.read_bytes(), self.database_path.stat().st_mtime_ns
        inventory = FileInventory()
        original = Path.read_bytes

        def read(path: Path) -> bytes:
            if path == self.layout["sync_state"]:
                return original(path)
            raise AssertionError(f"reread: {path}")

        with Database(self.database_path, read_only=True) as database:
            result = database.check_files_current(self.data, inventory=inventory)
            self.assertIsNotNone(result)
            self.assertEqual(result["status"], "unchanged")
            with mock.patch.object(Path, "read_bytes", autospec=True, side_effect=read):
                self.assertEqual(database.ingest_files(self.data, inventory=inventory), result)
        self.assertEqual(
            (self.database_path.read_bytes(), self.database_path.stat().st_mtime_ns), before
        )

    def test_same_size_edit_with_preserved_mtime_invalidates_parsed_json(self) -> None:
        path = self.root / "value.json"
        path.write_bytes(b'{"value":1}')
        inventory = FileInventory()
        self.assertEqual(inventory.read_json(path), {"value": 1})
        stamp = path.stat()
        path.write_bytes(b'{"value":2}')
        os.utime(path, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
        self.assertEqual(inventory.read_json(path), {"value": 2})
        replacement = self.root / "replacement.json"
        replacement.write_bytes(b'{"value":3}')
        os.utime(replacement, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
        replacement.replace(path)
        self.assertEqual(inventory.read_json(path), {"value": 3})

    def test_fingerprint_detects_changed_and_added_files_with_evicted_bytes(self) -> None:
        inventory = FileInventory(max_bytes=0)
        before = inventory.fingerprint(self.layout)
        report = next(self.layout["reports"].glob("*.txt"))
        old = report.stat()
        report.write_bytes(report.read_bytes().replace(b"alpha", b"gamma"))
        os.utime(report, ns=(old.st_atime_ns, old.st_mtime_ns))
        changed = inventory.fingerprint(self.layout)
        self.assertNotEqual(changed, before)
        (self.layout["reports"] / "extid-new.txt").write_text("BUG: new report")
        self.assertNotEqual(inventory.fingerprint(self.layout), changed)
        self.assertEqual(inventory.cached_bytes, 0)

    def test_observation_and_json_annotation_reject_concurrent_changes(self) -> None:
        path = self.root / "value.json"
        original = b'{"value":1}'
        path.write_bytes(original)
        inventory = FileInventory()
        inventory.observe(path, original, digest=hashlib.sha256(original).hexdigest())
        stamp, digest = file_stamp(path), inventory.digest(path)
        path.write_bytes(b'{"value":2}')
        with self.assertRaisesRegex(OSError, "changed while parsing"):
            inventory.remember_json(path, {"value": 1}, digest=digest)
        with self.assertRaisesRegex(OSError, "changed while observing"):
            inventory.observe(path, original, expected_stamp=stamp)
        self.assertEqual(inventory.read_json(path), {"value": 2})
        self.assertEqual(inventory.read_json(path, payload=original), {"value": 1})

    def test_edit_during_fingerprint_does_not_cache_a_mixed_input_digest(self) -> None:
        inventory = FileInventory(max_bytes=0)
        path = self.layout["bugs"] / "extid-alpha123.json"
        original = inventory.read_bytes

        def read_then_change(source: Path) -> bytes:
            payload = original(source)
            if source == path:
                path.write_bytes(payload.replace(b"fixed on", b"changed!"))
            return payload

        with mock.patch.object(inventory, "read_bytes", side_effect=read_then_change):
            fingerprint, errors = inventory.fingerprint(self.layout)
        self.assertTrue(any("changed while fingerprinting" in error for error in errors))
        with self.assertRaisesRegex(OSError, "changed after fingerprinting"):
            inventory.assert_fingerprint_current(self.layout, fingerprint)
        self.assertEqual(
            inventory.fingerprint(self.layout), FileInventory().fingerprint(self.layout)
        )

    def test_edit_after_fingerprint_cannot_activate_or_save_a_false_noop_marker(self) -> None:
        path = self.layout["bugs"] / "extid-alpha123.json"
        original = path.read_bytes()
        inventory = FileInventory()
        fingerprint = inventory.fingerprint

        def change_after_fingerprint(layout: dict) -> tuple[str, list[str]]:
            result = fingerprint(layout)
            path.write_bytes(original.replace(b"fixed on", b"changed!"))
            return result

        with Database(self.database_path) as database:
            with mock.patch.object(inventory, "fingerprint", side_effect=change_after_fingerprint):
                result = database.ingest_files(self.data, inventory=inventory)
            self.assertEqual(result["status"], "failed", result)
            self.assertIsNone(database.get_bug("extid-alpha123"))
            self.assertIsNone(
                database.connection.execute(
                    "SELECT value FROM app_state WHERE key='file_import:snapshot'"
                ).fetchone()
            )
            path.write_bytes(original)
            retry = database.ingest_files(self.data)
            self.assertEqual(retry["status"], "completed", retry)
            self.assertEqual(database.get_bug("extid-alpha123")["raw"], json.loads(original))

    def test_edit_after_parsing_rolls_back_snapshot_and_preserves_prior_fingerprint(self) -> None:
        path = self.layout["bugs"] / "extid-alpha123.json"
        original = path.read_bytes()
        with Database(self.database_path) as database:
            first = database.ingest_files(self.data)
            state = tuple(
                database.connection.execute(
                    "SELECT * FROM app_state WHERE key='file_import:snapshot'"
                ).fetchone()
            )
            self.change_catalog()
            insert = database._insert_bug_children

            def change_after_parsing(*args: object) -> int:
                result = insert(*args)
                path.write_bytes(original.replace(b"fixed on", b"changed!"))
                return result

            with mock.patch.object(
                database, "_insert_bug_children", side_effect=change_after_parsing
            ):
                result = database.ingest_files(self.data)
            self.assertEqual(result["status"], "failed", result)
            self.assertTrue(
                any("changed after fingerprinting" in error for error in result["failures"])
            )
            self.assertEqual(
                database.get_bug("extid-alpha123")["snapshot_id"], first["snapshot_id"]
            )
            self.assertEqual(
                tuple(
                    database.connection.execute(
                        "SELECT * FROM app_state WHERE key='file_import:snapshot'"
                    ).fetchone()
                ),
                state,
            )
            self.assertTrue(database.health_check()["ok"])
            self.assertEqual(database.ingest_files(self.data)["status"], "completed")
            self.assertIn("changed!", database.get_bug("extid-alpha123")["status"])

    def test_late_artifact_addition_invalidates_read_only_noop_without_database_writes(
        self,
    ) -> None:
        with Database(self.database_path) as database:
            database.ingest_files(self.data)
        before = self.database_path.read_bytes(), self.database_path.stat().st_mtime_ns
        with Database(self.database_path, read_only=True) as reader:
            unchanged = reader._unchanged_files_result

            def add_after_comparison(*args: object) -> dict | None:
                result = unchanged(*args)
                (self.layout["reports"] / "extid-new.txt").write_text("BUG: newly retained report")
                return result

            with mock.patch.object(
                reader, "_unchanged_files_result", side_effect=add_after_comparison
            ):
                self.assertIsNone(reader.check_files_current(self.data))
        self.assertEqual(
            (self.database_path.read_bytes(), self.database_path.stat().st_mtime_ns), before
        )

    def test_streamed_and_cached_ingestion_have_identical_query_results(self) -> None:
        results = []
        for budget in (0, 128, 32 * 1024 * 1024):
            inventory = FileInventory(max_bytes=budget)
            with Database(self.root / f"{budget}.sqlite3") as database:
                result = database.ingest_files(self.data, inventory=inventory)
                self.assertEqual(result["status"], "completed", result)
                self.assertTrue(database.health_check()["ok"])
                results.append([database.get_bug(key) for key in ("extid-alpha123", "id-beta456")])
            self.assertLessEqual(inventory.cached_bytes, budget)
        self.assertEqual(results[0], results[1])
        self.assertEqual(results[0], results[2])

    def test_new_locations_parse_before_writer_and_existing_locations_are_reused(self) -> None:
        with Database(self.database_path) as database:
            report_parser = location_store.prepare_report
            patch_parser = location_store.prepare_patch

            def report(payload: bytes, title: str) -> location_store.PreparedReport:
                self.assertFalse(database.connection.in_transaction)
                return report_parser(payload, title)

            def patch(payload: bytes) -> location_store.PreparedPatch:
                self.assertFalse(database.connection.in_transaction)
                return patch_parser(payload)

            with (
                mock.patch.object(location_store, "prepare_report", side_effect=report) as reports,
                mock.patch.object(location_store, "prepare_patch", side_effect=patch) as patches,
            ):
                result = database.ingest_files(self.data)
                self.assertEqual(result["status"], "completed", result)
                self.assertEqual(reports.call_count, 1)
                self.assertEqual(patches.call_count, 1)
            self.change_catalog()
            with (
                mock.patch.object(location_store, "prepare_report", side_effect=AssertionError),
                mock.patch.object(location_store, "prepare_patch", side_effect=AssertionError),
            ):
                result = database.ingest_files(self.data)
            self.assertEqual(result["status"], "completed", result)

    def test_artifact_edit_after_preparation_fails_without_mismatched_blob_or_activation(
        self,
    ) -> None:
        report_path = self.layout["reports"] / "extid-alpha123.txt"
        with Database(self.database_path) as database:
            first = database.ingest_files(self.data)
            report_path.write_bytes(report_path.read_bytes() + b"\nnew evidence\n")
            original = location_store.prepare_report

            def mutate(payload: bytes, title: str) -> location_store.PreparedReport:
                prepared = original(payload, title)
                stamp = report_path.stat()
                report_path.write_bytes(payload.replace(b"alpha", b"gamma"))
                os.utime(report_path, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
                return prepared

            with mock.patch.object(location_store, "prepare_report", side_effect=mutate):
                result = database.ingest_files(self.data)
            self.assertEqual(result["status"], "failed", result)
            self.assertTrue(any("changed after preparation" in item for item in result["failures"]))
            self.assertEqual(database.status()["current_snapshot"]["id"], first["snapshot_id"])
            self.assertTrue(database.health_check()["ok"])

    def test_preparation_failure_is_recorded_and_keeps_active_snapshot(self) -> None:
        with Database(self.database_path) as database:
            first = database.ingest_files(self.data)
            report = self.layout["reports"] / "extid-alpha123.txt"
            report.write_bytes(report.read_bytes() + b"\nnew evidence\n")
            with mock.patch.object(
                location_store, "prepare_report", side_effect=RuntimeError("parser failed")
            ):
                result = database.ingest_files(self.data)
            self.assertEqual(result["status"], "failed", result)
            self.assertEqual(database.status()["latest_run"]["status"], "failed")
            self.assertEqual(database.status()["current_snapshot"]["id"], first["snapshot_id"])

    def test_successful_patch_endpoint_survives_later_offline_ingestion(self) -> None:
        path = self.layout["patches"] / f"{ALPHA_HASH}.diff"
        endpoint = f"https://example.invalid/fallback/{ALPHA_HASH}.patch"
        with Database(self.database_path) as database:
            first = database.ingest_files(self.data, source_urls={path: endpoint})
            self.assertEqual(first["status"], "completed", first)
            self.change_catalog()
            second = database.ingest_files(self.data)
            self.assertEqual(second["status"], "completed", second)
            self.assertEqual(
                database.connection.execute(
                    "SELECT source_url FROM documents WHERE kind='patch' AND natural_key=?",
                    (ALPHA_HASH,),
                ).fetchone()[0],
                endpoint,
            )
            self.assertEqual(
                database.connection.execute(
                    "SELECT source_url FROM patches WHERE commit_hash=?", (ALPHA_HASH,)
                ).fetchone()[0],
                endpoint,
            )


if __name__ == "__main__":
    unittest.main()
