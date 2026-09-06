from __future__ import annotations

import hashlib
import json
import shutil
import unittest
from pathlib import Path

from syz_sage.config import DataPaths
from syz_sage.database import Database
from syz_sage.storage import temporary_directory

FIXTURES = Path(__file__).parent / "fixtures" / "legacy_data"
ALPHA_HASH = "a" * 40
BETA_HASH = "b" * 40


class IngestionRetryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = temporary_directory()
        self.root = Path(self.temporary.name)
        self.paths = DataPaths.from_root(self.root / "data")
        shutil.copytree(FIXTURES, self.paths.root)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_state(self, *, version: int = 2, **queues: list[str]) -> None:
        value: dict[str, object] = {
            "version": version,
            "pending_details": [],
            "pending_reports": [],
        }
        if version == 2:
            value["pending_patches"] = []
        value.update(queues)
        self.paths.sync_state.write_text(json.dumps(value))

    def test_pending_queues_prevent_unchanged_shortcut_and_offline_activation(self) -> None:
        for name, value in (
            ("pending_details", "extid-alpha123"),
            ("pending_reports", "extid-alpha123"),
            ("pending_patches", ALPHA_HASH),
        ):
            with self.subTest(queue=name):
                self.write_state()
                database_path = self.root / f"{name}.sqlite3"
                with Database(database_path) as database:
                    initial = database.import_legacy(self.paths)
                    self.assertEqual(initial["status"], "completed")
                    snapshot = database.status()["current_snapshot"]["id"]
                self.write_state(**{name: [value]})
                with Database(database_path, read_only=True) as database:
                    self.assertIsNone(
                        database.check_files_current(self.paths, source_kind="legacy")
                    )
                with Database(database_path) as database:
                    partial = database.import_legacy(self.paths)
                    self.assertEqual(partial["status"], "partial")
                    self.assertFalse(partial["activated"])
                    self.assertEqual(database.status()["current_snapshot"]["id"], snapshot)
                    self.assertTrue(any("pending" in error for error in partial["failures"]))

    def test_unfinished_refresh_never_pairs_old_report_with_new_crash(self) -> None:
        for version, queue in ((1, "pending_reports"), (2, "pending_details")):
            with self.subTest(version=version, queue=queue):
                paths = DataPaths.from_root(self.root / f"case-{version}")
                shutil.copytree(FIXTURES, paths.root)
                with Database(paths.database) as database:
                    initial = database.import_legacy(paths)
                    old_report = database.get_bug("extid-alpha123")["report"]
                    location_count = database.connection.execute(
                        "SELECT COUNT(*) FROM crash_locations"
                    ).fetchone()[0]
                detail_path = paths.bugs / "extid-alpha123.json"
                detail = json.loads(detail_path.read_bytes())
                detail["crashes"][0]["crash-report-link"] = "/text?tag=CrashReport&x=alpha-new"
                detail_path.write_text(json.dumps(detail))
                new_detail_hash = hashlib.sha256(detail_path.read_bytes()).hexdigest()
                state: dict[str, object] = {
                    "version": version,
                    "pending_details": [],
                    "pending_reports": [],
                }
                if version == 2:
                    state["pending_patches"] = []
                state[queue] = ["extid-alpha123"]
                paths.sync_state.write_text(json.dumps(state))

                with Database(paths.database) as database:
                    partial = database.import_legacy(paths)
                    self.assertEqual(partial["status"], "partial")
                    self.assertEqual(partial["report_details"]["pending_refresh"], 1)
                    self.assertEqual(
                        database.status()["current_snapshot"]["id"], initial["snapshot_id"]
                    )
                    self.assertEqual(database.get_bug("extid-alpha123")["report"], old_report)
                    self.assertEqual(
                        database.connection.execute(
                            "SELECT COUNT(*) FROM crash_locations"
                        ).fetchone()[0],
                        location_count,
                    )
                    self.assertEqual(
                        database.connection.execute(
                            "SELECT COUNT(*) FROM crash_locations l "
                            "JOIN crashes c ON c.id=l.crash_id "
                            "JOIN bug_versions v ON v.id=c.bug_version_id WHERE v.raw_sha256=?",
                            (new_detail_hash,),
                        ).fetchone()[0],
                        0,
                    )
                    self.assertEqual(
                        database.connection.execute(
                            "SELECT COUNT(*) FROM documents WHERE kind='crash-report' "
                            "AND source_url LIKE '%alpha-new'"
                        ).fetchone()[0],
                        0,
                    )

                state[queue] = []
                paths.sync_state.write_text(json.dumps(state))
                (paths.reports / "extid-alpha123.txt").write_text(
                    "BUG: KASAN: use-after-free in alpha\n alpha+0x1/0x20 net/alpha.c:99\n"
                )
                with Database(paths.database) as database:
                    completed = database.import_legacy(paths)
                    self.assertEqual(completed["status"], "completed")
                    report = database.get_bug("extid-alpha123")["report"]
                    self.assertTrue(report["source_url"].endswith("alpha-new"))
                    self.assertIn("net/alpha.c:99", report["text"])

    def test_only_historical_pending_work_keeps_unchanged_database(self) -> None:
        with Database(self.paths.database) as database:
            initial = database.import_legacy(self.paths)
        self.write_state(
            pending_details=["id-historical"],
            pending_reports=["id-historical"],
            pending_patches=[BETA_HASH],
        )
        with Database(self.paths.database, read_only=True) as database:
            unchanged = database.check_files_current(self.paths, source_kind="legacy")
            self.assertIsNotNone(unchanged)
        with Database(self.paths.database) as database:
            result = database.import_legacy(self.paths)
            self.assertEqual(result["status"], "unchanged")
            self.assertEqual(result["snapshot_id"], initial["snapshot_id"])

    def test_pending_resolved_patch_is_live_even_without_listing_hash(self) -> None:
        resolutions = json.loads(self.paths.resolutions.read_bytes())
        resolutions["resolutions"][0].update(hash=BETA_HASH, status="resolved")
        self.paths.resolutions.write_text(json.dumps(resolutions))
        shutil.copyfile(
            self.paths.patches / f"{ALPHA_HASH}.diff", self.paths.patches / f"{BETA_HASH}.diff"
        )
        with Database(self.paths.database) as database:
            self.assertEqual(database.import_legacy(self.paths)["status"], "completed")
        self.write_state(pending_patches=[BETA_HASH])
        with Database(self.paths.database) as database:
            result = database.import_legacy(self.paths)
            self.assertEqual(result["status"], "partial")
            self.assertTrue(any("live patch" in error for error in result["failures"]))

    def test_corrupt_retry_state_is_partial_and_preserves_raw_report(self) -> None:
        with Database(self.paths.database) as database:
            initial = database.import_legacy(self.paths)
            report = database.get_bug("extid-alpha123")["report"]
        self.paths.sync_state.write_text("invalid JSON")
        with Database(self.paths.database, read_only=True) as database:
            self.assertIsNone(database.check_files_current(self.paths, source_kind="legacy"))
        with Database(self.paths.database) as database:
            result = database.import_legacy(self.paths)
            self.assertEqual(result["status"], "partial")
            self.assertEqual(database.status()["current_snapshot"]["id"], initial["snapshot_id"])
            self.assertEqual(database.get_bug("extid-alpha123")["report"], report)
            self.assertEqual(result["report_details"]["pending_refresh"], 1)


if __name__ == "__main__":
    unittest.main()
