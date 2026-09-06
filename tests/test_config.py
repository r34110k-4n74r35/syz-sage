from __future__ import annotations

import os
import unittest
from pathlib import Path
from unittest import mock

from syz_sage.config import DATA_DIR_ENV, DATABASE_ENV, DataPaths
from syz_sage.storage import temporary_directory


class DataPathsTests(unittest.TestCase):
    def test_checkout_default_stays_in_project_from_any_working_directory(self) -> None:
        project = Path(__file__).resolve().parents[1]
        with (
            mock.patch.dict(os.environ, {}, clear=True),
            mock.patch("syz_sage.config.Path.cwd", return_value=project / "tests"),
        ):
            paths = DataPaths.default()

        self.assertEqual(paths.root, project / "data")
        self.assertEqual(paths.database, project / "data" / "db" / "syz_sage.sqlite3")

    def test_explicit_environment_data_directory_takes_precedence(self) -> None:
        with (
            temporary_directory() as directory,
            mock.patch.dict(os.environ, {DATA_DIR_ENV: directory}),
        ):
            self.assertEqual(DataPaths.default().root, Path(directory).resolve())

    def test_external_environment_path_does_not_require_a_checkout(self) -> None:
        destination = Path(__file__).resolve().parents[2] / "explicitly-selected-data"
        with (
            mock.patch.dict(os.environ, {DATA_DIR_ENV: str(destination)}),
            mock.patch("syz_sage.config.project_root", side_effect=AssertionError("no lookup")),
        ):
            self.assertEqual(DataPaths.default().root, destination)

    def test_missing_default_checkout_never_creates_an_external_app_data_directory(self) -> None:
        with temporary_directory() as directory:
            home = Path(directory) / "home"
            home.mkdir()
            with (
                mock.patch.dict(os.environ, {DATA_DIR_ENV: "", "HOME": str(home)}),
                mock.patch(
                    "syz_sage.config.project_root",
                    side_effect=ValueError("specify --data-dir"),
                ),
                self.assertRaisesRegex(ValueError, "--data-dir"),
            ):
                DataPaths.default()
            self.assertEqual(list(home.iterdir()), [])

    def test_standalone_install_requires_explicit_data_without_checkout(self) -> None:
        outside = Path(__file__).resolve().parents[2] / "unrecognized-installation"
        installed = outside / "site-packages" / "syz_sage" / "storage.py"
        with (
            mock.patch.dict(os.environ, {}, clear=True),
            mock.patch("syz_sage.storage.__file__", str(installed)),
            mock.patch("syz_sage.storage.Path.cwd", return_value=outside),
            self.assertRaisesRegex(ValueError, "source checkout"),
        ):
            DataPaths.default()

    def test_installed_package_under_project_finds_owning_checkout(self) -> None:
        project = Path(__file__).resolve().parents[1]
        installed = project / ".venv" / "lib" / "site-packages" / "syz_sage" / "storage.py"
        with (
            mock.patch.dict(os.environ, {}, clear=True),
            mock.patch("syz_sage.storage.__file__", str(installed)),
            mock.patch("syz_sage.storage.Path.cwd", return_value=project.parent),
        ):
            self.assertEqual(DataPaths.default().root, project / "data")

    def test_external_install_requires_a_recognized_working_checkout(self) -> None:
        project = Path(__file__).resolve().parents[1]
        installed = project.parent / "external-install" / "syz_sage" / "storage.py"
        with (
            mock.patch.dict(os.environ, {}, clear=True),
            mock.patch("syz_sage.storage.__file__", str(installed)),
            mock.patch("syz_sage.storage.Path.cwd", return_value=project / "tests"),
        ):
            self.assertEqual(DataPaths.default().root, project / "data")

    def test_from_root_builds_all_paths_beneath_the_requested_directory(self) -> None:
        with temporary_directory() as directory:
            root = Path(directory).resolve()
            paths = DataPaths.from_root(root)

            self.assertEqual(paths.raw, root / "raw")
            self.assertEqual(paths.processed, root / "processed")
            self.assertEqual(paths.artifacts, root / "artifacts")
            self.assertEqual(paths.bugs, root / "raw" / "bugs")
            self.assertEqual(paths.reports, root / "artifacts" / "reports")
            self.assertEqual(paths.patches, root / "artifacts" / "patches")
            self.assertEqual(paths.sync_state, root / "processed" / "sync_state.json")
            self.assertEqual(paths.database_dir, root / "db")
            self.assertEqual(paths.database.parent, paths.database_dir)
            self.assertIn(paths.database.suffix, {".db", ".sqlite", ".sqlite3"})

    def test_path_construction_does_not_create_directories(self) -> None:
        with temporary_directory() as directory:
            root = Path(directory) / "not-created"

            DataPaths.from_root(root)

            self.assertFalse(root.exists())

    def test_ensure_creates_required_directories_but_leaves_optional_artifacts_lazy(self) -> None:
        with temporary_directory() as directory:
            paths = DataPaths.from_root(Path(directory) / "data")

            paths.ensure()

            for required in (
                paths.database_dir,
                paths.raw,
                paths.processed,
                paths.bugs,
                paths.reports,
                paths.patches,
            ):
                with self.subTest(path=required):
                    self.assertTrue(required.is_dir())
            self.assertFalse(paths.reproducers.exists())
            self.assertFalse(paths.configs.exists())

    def test_explicit_root_database_is_independent_of_environment(self) -> None:
        with temporary_directory() as directory:
            root = Path(directory) / "data"
            with mock.patch.dict(os.environ, {DATABASE_ENV: str(Path(directory) / "other.db")}):
                paths = DataPaths.from_root(root)

            self.assertEqual(paths.database, root.resolve() / "db" / "syz_sage.sqlite3")


if __name__ == "__main__":
    unittest.main()
