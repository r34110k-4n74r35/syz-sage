from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path

from syz_sage.cli.commands import _import_lock_root
from syz_sage.database import Database
from syz_sage.project.config import DataPaths
from syz_sage.retrieval.sync import _exclusive_update_lock
from tests.cli.support import CliFixture, compact, invoke


class CliMaintenanceTests(CliFixture, unittest.TestCase):
    def test_check_verifies_stored_data_without_database_writes(self) -> None:
        self.import_fixture()
        digest = hashlib.sha256(self.database.read_bytes()).hexdigest()
        modified_at = self.database.stat().st_mtime_ns

        code, stdout, stderr = invoke(["--database", str(self.database), "check", "--json"])
        self.assertEqual(code, 0, stderr)
        result = json.loads(stdout)
        self.assertTrue(result["ok"])
        self.assertGreater(result["blob_count"], 0)
        self.assertEqual(result["foreign_key_errors"], [])

        code, stdout, stderr = invoke(["--database", str(self.database), "check"])
        self.assertEqual(code, 0, stderr)
        self.assertIn("Database check: passed", stdout)
        self.assertIn("SQLite: ok", compact(stdout))
        self.assertEqual(hashlib.sha256(self.database.read_bytes()).hexdigest(), digest)
        self.assertEqual(self.database.stat().st_mtime_ns, modified_at)

    def test_check_reports_corrupted_blob_and_exits_unsuccessfully(self) -> None:
        self.import_fixture()
        with Database(self.database) as database:
            database.connection.execute(
                "UPDATE blobs SET content = ?, size_bytes = ? "
                "WHERE sha256 = (SELECT sha256 FROM blobs LIMIT 1)",
                (b"corrupted", len(b"corrupted")),
            )
            database.connection.commit()
        digest = hashlib.sha256(self.database.read_bytes()).hexdigest()

        code, stdout, stderr = invoke(["--database", str(self.database), "check", "--json"])
        self.assertEqual(code, 1, stderr)
        result = json.loads(stdout)
        self.assertFalse(result["ok"])
        self.assertEqual(len(result["blob_hash_mismatches"]), 1)

        code, stdout, stderr = invoke(["--database", str(self.database), "check"])
        self.assertEqual(code, 1, stderr)
        self.assertIn("Database check: failed", stdout)
        self.assertIn("Blob hashes: 1 errors", compact(stdout))
        self.assertEqual(hashlib.sha256(self.database.read_bytes()).hexdigest(), digest)

    def test_import_refuses_a_source_locked_by_update_before_creating_database(self) -> None:
        with _exclusive_update_lock(self.legacy):
            code, stdout, stderr = invoke(
                ["--database", str(self.database), "import-legacy", str(self.legacy)]
            )
        self.assertEqual(code, 1)
        self.assertEqual(stdout, "")
        self.assertIn("another update owns data root", stderr)
        self.assertFalse(self.database.exists())

    def test_import_locks_a_separate_archive_at_the_destination(self) -> None:
        source = DataPaths.from_root(Path(self.root.anchor) / "external-syz-sage-snapshot")
        destination = DataPaths.from_root(self.root / "data")
        self.assertEqual(_import_lock_root(source, destination), destination.root)

    def test_import_does_not_create_a_missing_source_or_database(self) -> None:
        source = self.root / "missing-source"
        code, stdout, stderr = invoke(
            ["--database", str(self.database), "import-legacy", str(source)]
        )
        self.assertEqual(code, 1)
        self.assertEqual(stdout, "")
        self.assertIn("Legacy source directory does not exist", stderr)
        self.assertFalse(source.exists())
        self.assertFalse(self.database.exists())

    def test_offline_progress_commands_support_plain_quiet_and_json_output(self) -> None:
        self.import_fixture()
        for arguments, title in (
            (["import-legacy", str(self.legacy)], "Importing saved data"),
            (["migrate"], "Migrating database"),
            (["check"], "Checking database"),
        ):
            base = ["--database", str(self.database), *arguments]
            with self.subTest(command=arguments[0]):
                code, stdout, stderr = invoke(base)
                self.assertEqual(code, 0, stderr or stdout)
                self.assertIn(title, stderr)
                self.assertTrue(stdout.strip())
                self.assertNotIn("\r", stderr)
                self.assertNotIn("\x1b", stderr)

                code, quiet_stdout, stderr = invoke([*base, "--quiet"])
                self.assertEqual(code, 0, stderr)
                self.assertEqual(stderr, "")
                self.assertTrue(quiet_stdout.strip())

                code, stdout, stderr = invoke([*base, "--json"])
                self.assertEqual(code, 0, stderr)
                self.assertEqual(stderr, "")
                self.assertIsInstance(json.loads(stdout), dict)

    def test_migrate_shows_the_original_schema_and_reparse_progress(self) -> None:
        self.import_fixture()
        with Database(self.database) as database:
            database.connection.execute("PRAGMA user_version=4")
        code, stdout, stderr = invoke(["--database", str(self.database), "migrate"])
        self.assertEqual(code, 0, stderr or stdout)
        self.assertIn("Migration: schema 4 -> 5", compact(stdout))
        self.assertIn("Reparsing stored crash reports", stderr)
        self.assertNotIn("\r", stderr)
        self.assertNotIn("\x1b", stderr)


if __name__ == "__main__":
    unittest.main()
