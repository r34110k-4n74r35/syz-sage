from __future__ import annotations

import unittest
from pathlib import Path
from unittest import mock

from syz_sage.database import Database
from syz_sage.project.config import DataPaths
from syz_sage.retrieval.retry_state import load_sync_state
from syz_sage.retrieval.sync import (
    UpdateOptions,
    Updater,
    UpdateSummary,
    _add_patch_job,
    atomic_write,
)
from tests.retrieval.support import (
    FakeClient,
    UpdaterFixture,
)
from tests.support import (
    ALPHA_HASH,
    BETA_HASH,
    FIXTURES,
)


class UpdatePipelineTests(UpdaterFixture, unittest.TestCase):
    def test_patch_job_prefers_first_nonempty_repository(self) -> None:
        jobs: dict[str, str | None] = {}

        _add_patch_job(jobs, BETA_HASH, None)
        _add_patch_job(jobs, BETA_HASH, "https://git.kernel.org/example.git")
        _add_patch_job(jobs, BETA_HASH, "https://github.com/example/other")

        self.assertEqual(jobs, {BETA_HASH: "https://git.kernel.org/example.git"})

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

        with mock.patch("syz_sage.retrieval.sync.atomic_write", side_effect=edited_write):
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


if __name__ == "__main__":
    unittest.main()
