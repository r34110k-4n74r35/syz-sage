from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import re
import shutil
import unittest
from pathlib import Path
from unittest import mock

from syz_sage.cli import _human_bug, _human_list, _import_lock_root, main
from syz_sage.config import DATABASE_ENV, DataPaths
from syz_sage.database import Database
from syz_sage.display import progress
from syz_sage.parsing import key_from_link
from syz_sage.storage import temporary_directory
from syz_sage.sync import UpdateSummary, _exclusive_update_lock

FIXTURES = Path(__file__).parent / "fixtures" / "legacy_data"
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def compact(text: str) -> str:
    """Compare content without depending on presentation alignment or wrapping."""
    return " ".join(ANSI_RE.sub("", text).split())


def invoke(arguments: list[str]) -> tuple[int, str, str]:
    stdout = io.StringIO()
    stderr = io.StringIO()
    with (
        contextlib.redirect_stdout(stdout),
        contextlib.redirect_stderr(stderr),
        mock.patch(
            "syz_sage.terminal.shutil.get_terminal_size",
            return_value=os.terminal_size((96, 24)),
        ),
    ):
        code = main(arguments)
    return code, stdout.getvalue(), stderr.getvalue()


class CliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = temporary_directory()
        self.root = Path(self.temporary.name)
        self.legacy = self.root / "legacy"
        shutil.copytree(FIXTURES, self.legacy)
        self.database = self.root / "database" / "syz-sage.sqlite3"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def import_fixture(self) -> None:
        code, stdout, stderr = invoke(
            ["--database", str(self.database), "import-legacy", str(self.legacy)]
        )
        self.assertEqual(code, 0, stderr or stdout)

    def test_import_status_list_and_show_as_json(self) -> None:
        self.import_fixture()

        code, stdout, stderr = invoke(["--database", str(self.database), "status", "--json"])
        self.assertEqual(code, 0, stderr)
        status = json.loads(stdout)
        self.assertEqual(status["bugs"], 2)
        self.assertEqual(status["reports"], 1)
        self.assertEqual(status["patches"], 1)

        code, stdout, stderr = invoke(
            [
                "--database",
                str(self.database),
                "list",
                "--query",
                "alpha",
                "--json",
            ]
        )
        self.assertEqual(code, 0, stderr)
        bugs = json.loads(stdout)
        self.assertEqual([bug["key"] for bug in bugs], ["extid-alpha123"])

        code, stdout, stderr = invoke(
            [
                "--database",
                str(self.database),
                "show",
                "extid-alpha123",
                "--json",
            ]
        )
        self.assertEqual(code, 0, stderr)
        bug = json.loads(stdout)
        self.assertEqual(bug["key"], "extid-alpha123")
        self.assertEqual(bug["fixes"][0]["hash"], "a" * 40)
        self.assertNotIn("text", bug["report"])

        code, stdout, stderr = invoke(
            [
                "--database",
                str(self.database),
                "show",
                "extid-alpha123",
                "--report",
                "--json",
            ]
        )
        self.assertEqual(code, 0, stderr)
        bug_with_report = json.loads(stdout)
        self.assertIn("BUG: KASAN: use-after-free in alpha", bug_with_report["report"]["text"])

    def test_human_show_report_displays_its_body_and_size(self) -> None:
        self.import_fixture()

        code, stdout, stderr = invoke(
            [
                "--database",
                str(self.database),
                "show",
                "extid-alpha123",
                "--report",
            ]
        )

        self.assertEqual(code, 0, stderr)
        self.assertIn("Representative report: available (", compact(stdout))
        self.assertNotIn("available (0 bytes)", stdout)
        self.assertIn("BUG: KASAN: use-after-free in alpha", stdout)

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

    def test_show_accepts_a_syzbot_url_for_the_same_local_bug(self) -> None:
        self.import_fixture()
        arguments = ["--database", str(self.database), "show"]
        code, by_key, stderr = invoke([*arguments, "extid-alpha123", "--json"])
        self.assertEqual(code, 0, stderr)

        code, by_url, stderr = invoke(
            [*arguments, "https://syzkaller.appspot.com/bug?extid=alpha123", "--json"]
        )

        self.assertEqual(code, 0, stderr)
        self.assertEqual(json.loads(by_url), json.loads(by_key))

    def test_show_rejects_invalid_or_ambiguous_bug_references(self) -> None:
        self.import_fixture()
        for key in (
            "alpha123",
            "https://example.invalid/bug?extid=alpha123",
            "https://syzkaller.appspot.com/bug?extid=alpha123&id=beta456",
            "https://syzkaller.appspot.com/upstream/fixed?extid=alpha123",
        ):
            with self.subTest(key=key):
                code, stdout, stderr = invoke(["--database", str(self.database), "show", key])
                self.assertEqual(code, 1)
                self.assertEqual(stdout, "")
                self.assertIn("show expects", stderr)

    def test_human_show_preserves_location_precision_and_avoids_expanded_stack_hint(self) -> None:
        bug = {
            "key": "extid-alpha123",
            "title": "data-race in alpha",
            "subsystems": ["mm", "net"],
            "crash_locations": [
                {
                    "file_path": "net/alpha.c",
                    "line_number": 42,
                    "column_number": 7,
                    "function_name": "alpha",
                    "role": "read",
                    "confidence": "high",
                    "method": "access-site",
                    "kernel_source_commit": "b" * 40,
                }
            ],
            "fix_locations": [
                {
                    "commit_hash": "a" * 40,
                    "repo": "https://example.invalid/linux.git",
                    "old_file_path": None,
                    "old_start": 0,
                    "old_count": 0,
                    "new_file_path": "net/alpha.c",
                    "new_start": 1,
                    "new_count": 3,
                    "function_name": "alpha",
                    "function_basis": "hunk-header",
                }
            ],
            "crash_stack": [{"section": "stack", "raw_line": "alpha net/alpha.c:42"}],
            "report": {
                "available": True,
                "size": 25,
                "source_url": "https://syzkaller.appspot.com/text?tag=CrashReport&x=abc",
            },
        }
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            _human_bug(bug, include_report=False, include_stack=True)

        rendered = stdout.getvalue()
        content = compact(rendered)
        self.assertIn("Subsystems: mm, net", content)
        self.assertIn("net/alpha.c:42:7", content)
        self.assertIn("Function: alpha", content)
        self.assertIn("Role: read", content)
        self.assertIn("/dev/null -> net/alpha.c", content)
        self.assertIn("old /dev/null -> new 1-3", content)
        self.assertNotIn("/dev/null (after line", rendered)
        self.assertIn("Report URL: https://syzkaller.appspot.com/text?", content)
        self.assertIn("alpha net/alpha.c:42", rendered)
        self.assertNotIn("use --stack to display", rendered)

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

    def test_human_update_distinguishes_retention_from_activation(self) -> None:
        data_dir = self.root / "application-data"
        summary = UpdateSummary(
            namespace="upstream",
            status="fixed",
            listing_bugs=2,
            details_downloaded=1,
            failures=[
                {
                    "kind": "selection",
                    "key": "",
                    "error": "candidate snapshot is incomplete",
                }
            ],
            database={
                "status": "partial",
                "activated": False,
                "failure_count": 1,
                "failures": ["candidate snapshot is incomplete"],
            },
        )

        with mock.patch("syz_sage.cli.Updater") as updater:
            updater.return_value.run.return_value = summary
            code, stdout, stderr = invoke(
                ["--data-dir", str(data_dir), "update", "--allow-partial"]
            )

        self.assertEqual(code, 0, stderr)
        content = compact(stdout)
        self.assertIn("Update incomplete", content)
        self.assertIn("Fixed bugs: 2 live", content)
        self.assertIn("Changes: 0 new; 0 changed; 0 no longer listed", content)
        self.assertIn("Bug details 1 0 -", content)
        self.assertIn("Result: partial; no snapshot activated", content)
        self.assertIn("Issues (1)", content)
        self.assertIn("Any previously active snapshot is unchanged", content)
        self.assertIn("selection: candidate snapshot is incomplete", stdout)
        self.assertNotIn("the previous current snapshot remains active", stdout)
        self.assertNotIn("No new fixed bugs; local files and database are already current.", stdout)
        self.assertNotIn("Indexed 2 bugs", stdout)

    def test_update_progress_and_json_output_with_real_ingestion(self) -> None:
        data_dir = self.root / "application-data"
        with mock.patch("syz_sage.sync.SyzbotClient") as client_factory:
            client = client_factory.return_value
            client.dashboard = "https://syzkaller.appspot.com"
            client.listing_json.return_value = (
                FIXTURES / "raw" / "upstream_fixed.json"
            ).read_bytes()
            client.listing_html.return_value = (
                FIXTURES / "raw" / "upstream_fixed.html"
            ).read_bytes()
            client.bug.side_effect = lambda url: (
                FIXTURES / "raw" / "bugs" / f"{key_from_link(url)}.json"
            ).read_bytes()
            client.report.return_value = (
                FIXTURES / "artifacts" / "reports" / "extid-alpha123.txt"
            ).read_bytes()
            client.patch.return_value = (
                (FIXTURES / "artifacts" / "patches" / f"{'a' * 40}.diff").read_bytes(),
                "https://example.invalid/patch",
            )

            code, stdout, stderr = invoke(["--data-dir", str(data_dir), "update"])
            self.assertEqual(code, 0, stderr or stdout)
            self.assertIn("Checking https://syzkaller.appspot.com/upstream/fixed", stderr)
            self.assertIn("Bug details: downloading 2", stderr)
            self.assertIn("Crash reports: downloading 1", stderr)
            self.assertIn("Fix patches: downloading 1", stderr)
            self.assertIn("updating SQLite", stderr)
            self.assertIn("snapshot activated", stdout)

            client.bug.reset_mock()
            client.report.reset_mock()
            client.patch.reset_mock()
            code, stdout, stderr = invoke(["--data-dir", str(data_dir), "update", "--json"])
            self.assertEqual(code, 0, stderr or stdout)
            self.assertEqual(stderr, "")
            self.assertEqual(json.loads(stdout)["database"]["status"], "unchanged")
            self.assertTrue(json.loads(stdout)["database"]["skipped"])
            client.bug.assert_not_called()
            client.report.assert_not_called()
            client.patch.assert_not_called()

            code, stdout, stderr = invoke(["--data-dir", str(data_dir), "update"])
            self.assertEqual(code, 0, stderr or stdout)
            self.assertIn("skipping SQLite update", stderr)
            self.assertNotIn("updating SQLite from retained files", stderr)
            self.assertIn("SQLite write skipped", stdout)

    def test_human_update_reports_new_changed_removed_and_activation(self) -> None:
        data_dir = self.root / "application-data"
        summary = UpdateSummary(
            namespace="upstream",
            status="fixed",
            listing_bugs=4,
            known_fixed_bugs=3,
            new_fixed_bugs=1,
            new_fixed_bug_keys=["extid-new"],
            changed_bugs=1,
            changed_bug_keys=["extid-changed"],
            no_longer_listed_bugs=1,
            no_longer_listed_bug_keys=["extid-old"],
            details_downloaded=2,
            details_reused=2,
            reports_downloaded=1,
            reports_reused=2,
            reports_unavailable=1,
            patches_downloaded=1,
            patches_reused=3,
            database={
                "status": "completed",
                "activated": True,
                "failure_count": 0,
                "failures": [],
            },
        )

        with mock.patch("syz_sage.cli.Updater") as updater:
            updater.return_value.run.return_value = summary
            code, stdout, stderr = invoke(["--data-dir", str(data_dir), "update"])

        self.assertEqual(code, 0, stderr)
        content = compact(stdout)
        self.assertIn("Update complete", content)
        self.assertIn("Fixed bugs: 4 live", content)
        self.assertIn("Changes: 1 new; 1 changed; 1 no longer listed", content)
        self.assertIn("New keys: extid-new", content)
        self.assertIn("Changed keys: extid-changed", content)
        self.assertIn("No longer listed: extid-old", content)
        self.assertIn("Bug details 2 2 -", content)
        self.assertIn("Reports 1 2 1", content)
        self.assertIn("Patches 1 3 -", content)
        self.assertIn("Result: complete; snapshot activated", content)
        self.assertNotIn("No new fixed bugs; local files and database are already current.", stdout)

    def test_quiet_update_keeps_summary_and_failure_details(self) -> None:
        summary = UpdateSummary(
            namespace="upstream",
            status="fixed",
            listing_bugs=2,
            failures=[{"kind": "report", "key": "extid-alpha123", "error": "timed out"}],
            database={"status": "partial", "activated": False, "failures": ["timed out"]},
        )
        with mock.patch("syz_sage.cli.Updater") as updater:
            updater.return_value.run.return_value = summary
            code, stdout, stderr = invoke(
                ["--data-dir", str(self.root / "data"), "update", "--quiet"]
            )

        self.assertEqual(code, 1)
        self.assertIsNone(updater.call_args.kwargs["progress"])
        self.assertEqual(stderr, "")
        self.assertIn("Fixed bugs: 2 live", compact(stdout))
        self.assertIn("report extid-alpha123: timed out", stdout)
        self.assertIn("Issues (1)", stdout)

    def test_update_limits_human_issues_but_preserves_all_in_json(self) -> None:
        failures = [
            {"kind": "report", "key": f"extid-bug{i}", "error": "timed out\x1b[2J"}
            for i in range(8)
        ]
        summary = UpdateSummary(
            namespace="upstream",
            status="fixed",
            failures=failures,
            database={"status": "partial", "activated": False},
        )
        with mock.patch("syz_sage.cli.Updater") as updater:
            updater.return_value.run.return_value = summary
            args = ["--data-dir", str(self.root / "data"), "update"]
            code, stdout, _stderr = invoke(args)
            self.assertEqual(code, 1)
            self.assertEqual(stdout.count("timed out"), 5)
            self.assertIn("3 more; use --json", stdout)
            self.assertNotIn("\x1b", stdout)
            self.assertIn(r"\x1b[2J", stdout)

            code, stdout, stderr = invoke([*args, "--json"])
            self.assertEqual(code, 1)
            self.assertEqual(stderr, "")
            self.assertEqual(json.loads(stdout)["failures"], failures)

    def test_terminal_color_respects_no_color_dumb_term_and_json(self) -> None:
        self.import_fixture()
        args = ["--database", str(self.database), "show", "extid-alpha123"]
        for environment, use_json, colored in (
            ({"TERM": "xterm"}, False, True),
            ({"TERM": "xterm", "NO_COLOR": ""}, False, False),
            ({"TERM": "dumb"}, False, False),
            ({"TERM": "xterm"}, True, False),
        ):
            with self.subTest(environment=environment, json=use_json):
                stdout = io.StringIO()
                with (
                    contextlib.redirect_stdout(stdout),
                    mock.patch.object(stdout, "isatty", return_value=True),
                    mock.patch.dict(os.environ, environment, clear=True),
                ):
                    code = main([*args, "--json"] if use_json else args)
                self.assertEqual(code, 0)
                self.assertEqual("\x1b[" in stdout.getvalue(), colored)
                if use_json:
                    self.assertEqual(json.loads(stdout.getvalue())["key"], "extid-alpha123")

    def test_narrow_list_wraps_complete_titles_and_retains_full_keys(self) -> None:
        rows = [
            {
                "key": "extid-" + "a" * 40,
                "title": (
                    "KASAN: use-after-free in a_long_function with additional diagnostic detail"
                ),
                "subsystems": ["net", "mm"],
            },
            {
                "key": "id-" + "b" * 40,
                "title": "WARNING in another_function while processing a retained crash record",
                "subsystems": ["fs"],
            },
        ]
        stdout = io.StringIO()
        with (
            contextlib.redirect_stdout(stdout),
            mock.patch(
                "syz_sage.terminal.shutil.get_terminal_size",
                return_value=os.terminal_size((60, 24)),
            ),
        ):
            _human_list(rows, offset=10)
        rendered = stdout.getvalue()
        for row in rows:
            self.assertIn(row["key"], rendered)
            self.assertIn(row["title"], compact(rendered))
        self.assertTrue(all(len(line) <= 60 for line in rendered.splitlines()))
        self.assertIn("11. KASAN:", rendered)
        self.assertIn("12. WARNING", rendered)
        self.assertIn("ss list --offset 12", compact(rendered))

    def test_wide_list_alignment_is_independent_of_ansi_styling(self) -> None:
        rows = [
            {"key": "extid-alpha123", "title": "FIRST_TITLE", "subsystems": ["net", "mm"]},
            {"key": "id-beta456", "title": "SECOND_TITLE", "subsystems": ["fs"]},
        ]
        outputs = []
        for is_tty in (False, True):
            stdout = io.StringIO()
            with (
                contextlib.redirect_stdout(stdout),
                mock.patch.object(stdout, "isatty", return_value=is_tty),
                mock.patch.dict(os.environ, {"TERM": "xterm"}, clear=True),
                mock.patch(
                    "syz_sage.terminal.shutil.get_terminal_size",
                    return_value=os.terminal_size((110, 24)),
                ),
            ):
                _human_list(rows)
            outputs.append(stdout.getvalue())
        self.assertNotIn("\x1b", outputs[0])
        self.assertIn("\x1b[", outputs[1])
        self.assertEqual(ANSI_RE.sub("", outputs[1]), outputs[0])
        lines = outputs[0].splitlines()
        title_column = next(line for line in lines if line.startswith("KEY")).index("TITLE")
        for title in ("FIRST_TITLE", "SECOND_TITLE"):
            self.assertEqual(
                next(line for line in lines if title in line).index(title), title_column
            )

    def test_progress_color_uses_stderr_terminal_and_respects_no_color(self) -> None:
        for stdout_tty, stderr_tty, environment, expected_color in (
            (True, False, {"TERM": "xterm"}, False),
            (False, True, {"TERM": "xterm"}, True),
            (False, True, {"TERM": "xterm", "NO_COLOR": ""}, False),
            (False, True, {"TERM": "dumb"}, False),
        ):
            with self.subTest(stdout_tty=stdout_tty, stderr_tty=stderr_tty, env=environment):
                stdout, stderr = io.StringIO(), io.StringIO()
                with (
                    contextlib.redirect_stdout(stdout),
                    contextlib.redirect_stderr(stderr),
                    mock.patch.object(stdout, "isatty", return_value=stdout_tty),
                    mock.patch.object(stderr, "isatty", return_value=stderr_tty),
                    mock.patch.dict(os.environ, environment, clear=True),
                ):
                    progress("Bug details: downloading 2\x1b[2J")
                self.assertEqual(stdout.getvalue(), "")
                self.assertEqual(bool(ANSI_RE.search(stderr.getvalue())), expected_color)
                self.assertIn("Bug details: downloading 2", compact(stderr.getvalue()))
                self.assertIn(r"\x1b[2J", stderr.getvalue())
                self.assertNotIn("\x1b[2J", stderr.getvalue())

    def test_show_groups_each_commit_with_its_locations_once(self) -> None:
        fixes = [
            {
                "hash": "a" * 40,
                "title": "First fix subject",
                "repo": "kernel.git",
                "patch_available": True,
            },
            {
                "hash": "b" * 40,
                "title": "Second fix subject",
                "repo": "kernel.git",
                "patch_available": True,
            },
        ]
        locations = [
            {
                "commit_hash": fix["hash"],
                "repo": "kernel.git",
                "old_file_path": f"net/{filename}.c",
                "new_file_path": f"net/{filename}.c",
                "old_start": 10,
                "old_count": 1,
                "new_start": 10,
                "new_count": 2,
                "function_name": filename,
                "function_basis": "inferred from hunk heading",
            }
            for fix, filename in zip(fixes, ("first", "second"), strict=True)
        ]
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            _human_bug(
                {
                    "title": "Bug subject",
                    "key": "extid-alpha123",
                    "fixes": fixes,
                    "fix_locations": locations,
                },
                include_report=False,
            )
        rendered = stdout.getvalue()
        self.assertEqual(rendered.count("Fixes (2)"), 1)
        for fix in fixes:
            self.assertEqual(rendered.count(fix["title"]), 1)
            self.assertEqual(rendered.count(fix["hash"]), 1)
        self.assertLess(rendered.index("First fix subject"), rendered.index("net/first.c"))
        self.assertLess(rendered.index("net/first.c"), rendered.index("Second fix subject"))
        self.assertLess(rendered.index("Second fix subject"), rendered.index("net/second.c"))
        self.assertEqual(rendered.count("old 10 -> new 10-11"), 2)
        self.assertNotIn("Fix commits:", rendered)
        self.assertNotIn("Fix locations", rendered)

    def test_human_update_prints_exact_no_change_message(self) -> None:
        data_dir = self.root / "application-data"
        summary = UpdateSummary(
            namespace="upstream",
            status="fixed",
            listing_bugs=4,
            known_fixed_bugs=4,
            details_reused=4,
            reports_reused=3,
            reports_unavailable=1,
            patches_reused=2,
            database={
                "status": "unchanged",
                "activated": False,
                "failure_count": 0,
                "failures": [],
            },
        )

        with mock.patch("syz_sage.cli.Updater") as updater:
            updater.return_value.run.return_value = summary
            code, stdout, stderr = invoke(["--data-dir", str(data_dir), "update"])

        self.assertEqual(code, 0, stderr)
        content = compact(stdout)
        self.assertIn("Already up to date", content)
        self.assertIn("Fixed bugs: 4 live", content)
        self.assertIn("Changes: 0 new; 0 changed; 0 no longer listed", content)
        self.assertIn("Bug details 0 4 -", content)
        self.assertIn("Result: unchanged; SQLite write skipped", content)
        self.assertEqual(
            stdout.count("No new fixed bugs; local files and database are already current.\n"),
            1,
        )

    def test_allow_partial_does_not_mask_failed_database_ingestion(self) -> None:
        summary = UpdateSummary(
            namespace="upstream",
            status="fixed",
            listing_bugs=2,
            database={
                "status": "failed",
                "activated": False,
                "failure_count": 1,
                "failures": ["snapshot transaction failed"],
            },
        )

        with mock.patch("syz_sage.cli.Updater") as updater:
            updater.return_value.run.return_value = summary
            code, _stdout, stderr = invoke(
                ["--data-dir", str(self.root / "data"), "update", "--allow-partial"]
            )

        self.assertEqual(code, 1, stderr)

    def test_human_metadata_escapes_terminal_control_characters(self) -> None:
        stdout = io.StringIO()
        bug = {
            "key": "extid-safe\x1b[31m",
            "title": "title\r\n\t\u202ereversed",
            "status": "fixed\x7f",
            "fixes": [{"hash": "a" * 40, "title": "fix\x1b]0;owned\x07"}],
            "crashes": [],
            "report": {"text": "line one\nline two\x1b[2J\r", "size": 21},
        }

        with contextlib.redirect_stdout(stdout):
            _human_list([bug])
            _human_bug(bug, include_report=True)

        rendered = stdout.getvalue()
        self.assertNotIn("\x1b", rendered)
        self.assertNotIn("\r", rendered)
        self.assertNotIn("\t", rendered)
        self.assertNotIn("\u202e", rendered)
        self.assertIn(r"\x1b", rendered)
        self.assertIn(r"\u202e", rendered)
        self.assertIn("line one\nline two", rendered)

    def test_human_show_does_not_call_an_unavailable_report_available(self) -> None:
        stdout = io.StringIO()
        bug = {
            "key": "extid-safe",
            "title": "safe title",
            "fixes": [],
            "crashes": [],
            "report": {"available": False, "text": None, "size": 0},
        }

        with contextlib.redirect_stdout(stdout):
            _human_bug(bug, include_report=False)

        self.assertIn("Representative report: unavailable", compact(stdout.getvalue()))

    def test_unknown_bug_has_a_nonzero_exit_status(self) -> None:
        self.import_fixture()

        code, _stdout, _stderr = invoke(
            [
                "--database",
                str(self.database),
                "show",
                "extid-not-present",
                "--json",
            ]
        )

        self.assertNotEqual(code, 0)


if __name__ == "__main__":
    unittest.main()
