from __future__ import annotations

import contextlib
import io
import shutil
import sqlite3
import unittest
from dataclasses import FrozenInstanceError
from pathlib import Path
from unittest import mock

from syz_sage import location_store
from syz_sage.database import SCHEMA_VERSION, Database
from syz_sage.progress_events import ProgressEvent, emit_progress
from syz_sage.storage import temporary_directory

FIXTURES = Path(__file__).parent / "fixtures/legacy_data"


class DatabaseProgressTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = temporary_directory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.data = self.root / "data"
        self.path = self.root / "store.sqlite3"
        shutil.copytree(FIXTURES, self.data)
        self.events: list[ProgressEvent] = []

    def phase(self, name: str) -> list[ProgressEvent]:
        return [event for event in self.events if event.phase == name]

    def test_new_database_has_one_creation_phase_completed_after_all_schema_work(self) -> None:
        versions: list[int] = []

        def observe(event: ProgressEvent) -> None:
            self.events.append(event)
            if event.completed == 1:
                with contextlib.closing(sqlite3.connect(self.path)) as reader:
                    versions.append(reader.execute("PRAGMA user_version").fetchone()[0])

        with Database(self.path, on_progress=observe):
            pass
        self.assertEqual([event.phase for event in self.events], ["initialize", "initialize"])
        self.assertEqual([event.completed for event in self.events], [None, 1])
        self.assertEqual(versions, [SCHEMA_VERSION])

    def test_failed_new_database_migration_does_not_report_creation_complete(self) -> None:
        with (
            mock.patch.object(location_store, "migrate_v2", side_effect=RuntimeError("migration")),
            self.assertRaisesRegex(RuntimeError, "migration"),
            Database(self.path, on_progress=self.events.append),
        ):
            pass
        self.assertEqual(self.events, [ProgressEvent("initialize", "Creating database schema")])

    def test_ingestion_counts_processed_items_and_reports_commit_after_transaction(self) -> None:
        with Database(self.path) as database:
            database._on_progress = self.events.append
            database.initialize()
            self.assertEqual(self.events, [])
            committed_states: list[tuple[bool, str]] = []

            def observe(event: ProgressEvent) -> None:
                self.events.append(event)
                if event.phase == "commit-snapshot" and event.completed == 1:
                    committed_states.append(
                        (
                            database.connection.in_transaction,
                            database.status()["latest_run"]["status"],
                        )
                    )

            database._on_progress = observe
            result = database.ingest_files(self.data)
            self.assertEqual(result["status"], "completed", result)
            self.assertEqual(committed_states, [(False, "completed")])
            self.assertTrue(all(event.message for event in self.events))
            for phase, total in (
                ("read-bugs", 2),
                ("prepare-bugs", 2),
                ("index-bugs", 2),
                ("prepare-reports", 1),
                ("prepare-patches", 1),
                ("index-reports", 1),
                ("index-patches", 1),
                ("commit-snapshot", 1),
            ):
                events = self.phase(phase)
                self.assertEqual([event.completed for event in events], list(range(total + 1)))
                self.assertTrue(all(event.total == total for event in events))
            count = len([path for path in self.data.rglob("*") if path.is_file()])
            self.assertEqual(self.phase("fingerprint")[-1].completed, count)

    def test_read_only_noop_emits_only_file_inspection_and_keeps_database_unchanged(self) -> None:
        with Database(self.path) as database:
            database.ingest_files(self.data)
        before = self.path.read_bytes(), self.path.stat().st_mtime_ns
        with Database(self.path, read_only=True, on_progress=self.events.append) as database:
            self.assertEqual(self.events, [])
            result = database.ingest_files(self.data)
            self.assertEqual(result["status"], "unchanged", result)
        self.assertEqual({event.phase for event in self.events}, {"fingerprint"})
        self.assertEqual((self.path.read_bytes(), self.path.stat().st_mtime_ns), before)

    def test_partial_candidate_counts_do_not_claim_activation(self) -> None:
        with Database(self.path) as database:
            first = database.ingest_files(self.data)
            database._on_progress = self.events.append
            result = database.ingest_files(self.data, errors=["planned incomplete candidate"])
            self.assertEqual(result["status"], "partial", result)
            self.assertFalse(result["activated"])
            self.assertEqual(database.status()["current_snapshot"]["id"], first["snapshot_id"])
            self.assertEqual(self.phase("index-bugs")[-1].completed, 2)
            self.assertEqual(self.phase("commit-snapshot")[-1].message, "Snapshot result committed")

    def test_migration_reparse_counts_and_completion_follow_actual_commit(self) -> None:
        with Database(self.path) as database:
            database.ingest_files(self.data)
            database.connection.execute("PRAGMA user_version=4")
        observed_versions: list[int] = []

        def observe(event: ProgressEvent) -> None:
            self.events.append(event)
            if event.phase == "migrate-v5" and event.completed == 1:
                with contextlib.closing(sqlite3.connect(self.path)) as reader:
                    observed_versions.append(reader.execute("PRAGMA user_version").fetchone()[0])

        with Database(self.path, on_progress=observe) as database:
            self.assertEqual(database.status()["schema_version"], SCHEMA_VERSION)
            self.assertEqual(observed_versions, [SCHEMA_VERSION])
            self.assertEqual(
                [(event.completed, event.total) for event in self.phase("migrate-v5-reports")],
                [(0, 1), (1, 1)],
            )
            self.events.clear()
            database.initialize()
            self.assertEqual(self.events, [])

    def test_failed_migration_has_no_committed_event_and_preserves_old_schema(self) -> None:
        with Database(self.path) as database:
            database.ingest_files(self.data)
            database.connection.execute("PRAGMA user_version=4")
        with (
            mock.patch.object(location_store, "index_report", side_effect=RuntimeError("parser")),
            self.assertRaisesRegex(RuntimeError, "parser"),
            Database(self.path, on_progress=self.events.append),
        ):
            pass
        self.assertEqual([event.completed for event in self.phase("migrate-v5")], [None])
        self.assertIsNone(self.phase("migrate-v5")[0].total)
        self.assertEqual([event.completed for event in self.phase("migrate-v5-reports")], [0])
        with contextlib.closing(sqlite3.connect(self.path)) as reader:
            self.assertEqual(reader.execute("PRAGMA user_version").fetchone()[0], 4)

    def test_broken_observer_does_not_change_ingestion_or_health_results(self) -> None:
        calls = 0

        def broken(event: ProgressEvent) -> None:
            nonlocal calls
            calls += 1
            raise RuntimeError("display failure")

        with Database(self.path, on_progress=broken) as database:
            result = database.ingest_files(self.data)
            self.assertEqual(result["status"], "completed", result)
            self.assertTrue(database.health_check()["ok"])
        self.assertGreater(calls, 10)

    def test_health_progress_streams_blob_counts_without_printing_or_mutation(self) -> None:
        with Database(self.path) as database:
            database.ingest_files(self.data)
            expected = database.health_check()
        before = self.path.read_bytes(), self.path.stat().st_mtime_ns
        output = io.StringIO()
        with (
            contextlib.redirect_stdout(output),
            contextlib.redirect_stderr(output),
            Database(self.path, read_only=True, on_progress=self.events.append) as database,
        ):
            result = database.health_check()
        self.assertEqual(result, expected)
        self.assertEqual(output.getvalue(), "")
        self.assertEqual(self.phase("check-blobs")[-1].completed, result["blob_count"])
        self.assertIsNone(self.phase("check-blobs")[-1].total)
        self.assertEqual(self.phase("check-snapshots")[-1].completed, 3)
        self.assertEqual((self.path.read_bytes(), self.path.stat().st_mtime_ns), before)

    def test_events_are_immutable_and_cancellation_is_not_swallowed(self) -> None:
        event = ProgressEvent("test", "Testing", 0, 1)
        with self.assertRaises(FrozenInstanceError):
            event.completed = 1  # type: ignore[misc]
        with self.assertRaises(KeyboardInterrupt):
            emit_progress(mock.Mock(side_effect=KeyboardInterrupt), event)


if __name__ == "__main__":
    unittest.main()
