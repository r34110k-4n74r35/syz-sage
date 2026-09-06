from __future__ import annotations

import os
import unittest
from unittest import mock

from syz_sage.project.config import DATABASE_ENV, DataPaths
from tests.cli.support import CliFixture, invoke


class CliPathsTests(CliFixture, unittest.TestCase):
    def test_data_dir_selects_its_default_database(self) -> None:
        data_dir = self.root / "application-data"

        code, stdout, stderr = invoke(
            ["--data-dir", str(data_dir), "import-legacy", str(self.legacy)]
        )

        self.assertEqual(code, 0, stderr or stdout)
        self.assertTrue(DataPaths.from_root(data_dir).database.is_file())

    def test_explicit_data_dir_ignores_ambient_database_environment(self) -> None:
        data_dir = self.root / "application-data"
        ambient_database = self.root / "ambient.sqlite3"

        with mock.patch.dict(os.environ, {DATABASE_ENV: str(ambient_database)}):
            code, stdout, stderr = invoke(
                ["--data-dir", str(data_dir), "import-legacy", str(self.legacy)]
            )

        self.assertEqual(code, 0, stderr or stdout)
        self.assertTrue((data_dir / "db" / "syz_sage.sqlite3").is_file())
        self.assertFalse((data_dir / "syz_sage.sqlite3").exists())
        self.assertFalse(ambient_database.exists())

    def test_explicit_database_wins_over_data_dir_and_environment(self) -> None:
        data_dir = self.root / "application-data"
        ambient_database = self.root / "ambient.sqlite3"
        explicit_database = self.root / "explicit" / "selected.sqlite3"

        with mock.patch.dict(os.environ, {DATABASE_ENV: str(ambient_database)}):
            code, stdout, stderr = invoke(
                [
                    "--data-dir",
                    str(data_dir),
                    "--database",
                    str(explicit_database),
                    "import-legacy",
                    str(self.legacy),
                ]
            )

        self.assertEqual(code, 0, stderr or stdout)
        self.assertTrue(explicit_database.is_file())
        self.assertFalse((data_dir / "db" / "syz_sage.sqlite3").exists())
        self.assertFalse(ambient_database.exists())

    def test_corrupt_database_is_reported_without_a_traceback(self) -> None:
        self.database.parent.mkdir(parents=True)
        self.database.write_bytes(b"this is not a SQLite database")

        code, stdout, stderr = invoke(["--database", str(self.database), "status", "--json"])

        self.assertEqual(code, 1)
        self.assertEqual(stdout, "")
        self.assertIn("Error:", stderr)
        self.assertNotIn("Traceback", stderr)


if __name__ == "__main__":
    unittest.main()
