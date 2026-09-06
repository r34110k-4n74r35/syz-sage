from __future__ import annotations

import contextlib
import hashlib
import importlib
import io
import os
import shutil
import sqlite3
import unittest
from pathlib import Path
from unittest import mock

from syz_sage.cli import main
from syz_sage.database import Database
from syz_sage.parsing.listing import PayloadError
from syz_sage.project.config import DATA_DIR_ENV, DATABASE_ENV, DataPaths
from syz_sage.project.storage import project_root, temporary_directory, writable_path, write_bytes
from syz_sage.retrieval.sync import UpdateSummary, atomic_write
from tests.support import FIXTURES


class StoragePathTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = temporary_directory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        # Model an external destination without touching the user's directories.
        self.checkout = self.root / "checkout"
        self.checkout.mkdir()
        self.external = self.root / "elsewhere"
        self.external.mkdir()
        self.source = self.external / "archive"
        shutil.copytree(FIXTURES, self.source)
        environment = mock.patch.dict(os.environ, {DATA_DIR_ENV: "", DATABASE_ENV: ""})
        environment.start()
        self.addCleanup(environment.stop)

    def invoke(self, *arguments: str) -> tuple[int, str]:
        output = io.StringIO()
        with contextlib.redirect_stderr(output), contextlib.redirect_stdout(output):
            code = main(list(arguments))
        return code, output.getvalue()

    def test_explicit_writes_work_outside_the_default_checkout(self) -> None:
        with mock.patch("syz_sage.project.storage.project_root", return_value=self.checkout):
            write_bytes(self.external / "nested" / "plain.txt", b"plain")
            atomic_write(self.external / "nested" / "atomic.txt", b"atomic")
            paths = DataPaths.from_root(self.external / "data")
            paths.ensure()
            with Database(paths.database) as database:
                database.import_legacy(self.source)
                self.assertIsNotNone(database.get_bug("extid-alpha123"))
        self.assertEqual((self.external / "nested" / "plain.txt").read_bytes(), b"plain")
        self.assertEqual((self.external / "nested" / "atomic.txt").read_bytes(), b"atomic")
        self.assertEqual(list(self.checkout.iterdir()), [])

    def test_normalizing_explicit_paths_does_not_need_checkout_or_create_files(self) -> None:
        target = self.external / "not-created" / "file"
        with mock.patch(
            "syz_sage.project.storage.project_root", side_effect=AssertionError("no lookup")
        ):
            self.assertEqual(writable_path(target), target)
        self.assertFalse(target.parent.exists())

    def test_explicit_symlinks_and_hardlinks_follow_normal_filesystem_behavior(self) -> None:
        directory_link = self.checkout / "linked-directory"
        directory_link.symlink_to(self.external, target_is_directory=True)
        file_link = self.checkout / "linked-file"
        file_link.symlink_to(self.external / "target.txt")
        with mock.patch("syz_sage.project.storage.project_root", return_value=self.checkout):
            atomic_write(directory_link / "target.txt", b"first")
            atomic_write(file_link, b"second")
            hardlink = self.checkout / "hardlink"
            os.link(self.external / "target.txt", hardlink)
            write_bytes(hardlink, b"third")
        self.assertTrue(file_link.is_symlink())
        self.assertEqual((self.external / "target.txt").read_bytes(), b"third")

    def test_explicit_cli_and_environment_paths_work_without_checkout(self) -> None:
        for selection in ("data-flag", "database-flag", "data-env", "database-env"):
            target = self.external / selection
            database_path = target / "db" / "syz_sage.sqlite3"
            arguments: list[str] = []
            environment: dict[str, str] = {}
            if selection == "data-flag":
                arguments = ["--data-dir", str(target)]
            elif selection == "database-flag":
                arguments = ["--database", str(database_path)]
            elif selection == "data-env":
                environment = {DATA_DIR_ENV: str(target)}
            else:
                environment = {DATABASE_ENV: str(database_path)}
            before = sorted(p.relative_to(self.source) for p in self.source.rglob("*"))
            with (
                self.subTest(selection=selection),
                mock.patch.dict(os.environ, environment),
                mock.patch(
                    "syz_sage.project.config.project_root", side_effect=ValueError("no checkout")
                ),
                mock.patch(
                    "syz_sage.project.storage.project_root", side_effect=ValueError("no checkout")
                ),
            ):
                code, output = self.invoke(*arguments, "import-legacy", str(self.source), "--json")
                self.assertEqual(code, 0, output)
                code, output = self.invoke(*arguments, "show", "extid-alpha123", "--json")
                self.assertEqual(code, 0, output)
                self.assertIn("extid-alpha123", output)
            self.assertTrue(database_path.is_file())
            self.assertEqual(
                sorted(p.relative_to(self.source) for p in self.source.rglob("*")), before
            )
        self.assertEqual(list(self.checkout.iterdir()), [])

    def test_update_uses_explicit_external_paths(self) -> None:
        target = self.external / "downloads"
        database_path = self.external / "database" / "selected.sqlite3"
        with (
            mock.patch(
                "syz_sage.project.config.project_root", side_effect=ValueError("no checkout")
            ),
            mock.patch("syz_sage.cli.commands.Updater") as updater,
        ):
            updater.return_value.run.return_value = UpdateSummary(
                namespace="upstream", status="fixed", database={"status": "unchanged"}
            )
            code, output = self.invoke(
                "--data-dir", str(target), "--database", str(database_path), "update", "--json"
            )
            self.assertEqual(code, 0, output)
            self.assertEqual(updater.call_args.args[0].root, target)
            self.assertEqual(updater.call_args.args[1], database_path)
            updater.return_value.run.assert_called_once()
        self.assertFalse(target.exists())

    def test_update_with_only_database_needs_a_default_or_explicit_data_root(self) -> None:
        with (
            mock.patch(
                "syz_sage.project.config.project_root", side_effect=ValueError("specify --data-dir")
            ),
            mock.patch("syz_sage.cli.commands.Updater") as updater,
        ):
            code, output = self.invoke("--database", str(self.external / "selected.db"), "update")
            self.assertEqual(code, 1)
            self.assertIn("--data-dir", output)
            updater.assert_not_called()
        self.assertFalse((self.external / "selected.db").exists())

    def test_inspection_and_migration_need_only_explicit_database(self) -> None:
        database_path = self.external / "store.sqlite3"
        with Database(database_path) as database:
            database.import_legacy(self.source)
        digest = hashlib.sha256(database_path.read_bytes()).hexdigest()
        with mock.patch(
            "syz_sage.project.config.project_root", side_effect=ValueError("no checkout")
        ):
            for arguments in (
                ("status",),
                ("list",),
                ("filter",),
                ("show", "extid-alpha123"),
                ("check",),
            ):
                with (
                    self.subTest(arguments=arguments),
                    mock.patch("syz_sage.cli.commands.Database", wraps=Database) as factory,
                ):
                    code, output = self.invoke("--database", str(database_path), *arguments)
                    self.assertEqual(code, 0, output)
                    self.assertTrue(factory.call_args.kwargs["read_only"])
            self.assertEqual(hashlib.sha256(database_path.read_bytes()).hexdigest(), digest)
            code, output = self.invoke("--database", str(database_path), "migrate")
            self.assertEqual(code, 0, output)
        with (
            Database(database_path, read_only=True) as database,
            self.assertRaises(sqlite3.OperationalError),
        ):
            database.connection.execute("DELETE FROM app_state")

    def test_sqlite_uses_its_default_temporary_storage_setting(self) -> None:
        with contextlib.closing(sqlite3.connect(":memory:")) as standard:
            expected = standard.execute("PRAGMA temp_store").fetchone()[0]
        with Database(self.external / "store.sqlite3") as database:
            self.assertEqual(
                database.connection.execute("PRAGMA temp_store").fetchone()[0], expected
            )

    def test_existing_read_only_source_lock_can_be_used_without_writing(self) -> None:
        lock = self.source / ".syz_sage.update.lock"
        lock.write_bytes(b"")
        lock.chmod(0o444)
        self.addCleanup(lock.chmod, 0o644)
        before = (lock.read_bytes(), lock.stat().st_mtime_ns)
        database_path = self.external / "destination" / "selected.sqlite3"
        code, output = self.invoke(
            "--database", str(database_path), "import-legacy", str(self.source)
        )
        self.assertEqual(code, 0, output)
        self.assertEqual((lock.read_bytes(), lock.stat().st_mtime_ns), before)
        self.assertTrue(database_path.is_file())

    def test_arbitrary_report_paths_do_not_relax_downloaded_identifier_validation(self) -> None:
        fetcher = importlib.import_module("scripts.fetch_artifacts")
        auditor = importlib.import_module("scripts.audit_snapshot")
        auditor.atomic_write(self.external / "reports" / "audit.json", "{}")
        self.assertEqual((self.external / "reports" / "audit.json").read_text(), "{}")
        with mock.patch.object(fetcher, "http_get") as fetch:
            with self.assertRaisesRegex(PayloadError, "unsafe bug key"):
                fetcher.fetch_bug_json({"key": "../escaped", "json_url": "unused"})
            with self.assertRaisesRegex(PayloadError, "invalid commit hash"):
                fetcher.fetch_patch("../escaped", None)
            fetch.assert_not_called()

    def test_status_does_not_initialize_an_empty_database(self) -> None:
        database_path = self.external / "empty.sqlite3"
        database_path.touch()
        code, output = self.invoke("--database", str(database_path), "status")
        self.assertEqual(code, 1)
        self.assertIn("read-only", output)
        self.assertEqual(database_path.read_bytes(), b"")

    def test_test_scratch_stays_local_without_changing_environment(self) -> None:
        environment = dict.fromkeys(("TMPDIR", "TEMP", "TMP"), str(self.external))
        with mock.patch.dict(os.environ, environment):
            with temporary_directory() as directory:
                scratch = Path(directory)
                self.assertEqual(scratch.parent, project_root())
                self.assertTrue(scratch.name.startswith(".syz-sage-tmp-"))
                (scratch / "file").write_bytes(b"temporary content")
                self.assertEqual({name: os.environ[name] for name in environment}, environment)
            self.assertFalse(scratch.exists())

    def test_temporary_files_clean_up_after_failure(self) -> None:
        with (
            self.assertRaisesRegex(RuntimeError, "interrupted operation"),
            temporary_directory() as directory,
        ):
            scratch = Path(directory)
            (scratch / "file").write_bytes(b"temporary content")
            raise RuntimeError("interrupted operation")
        self.assertFalse(scratch.exists())


if __name__ == "__main__":
    unittest.main()
