from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import re
import shutil
import sqlite3
import unittest
from pathlib import Path
from unittest import mock

from syz_sage.cli import main
from syz_sage.database import SCHEMA_VERSION, Database
from syz_sage.display import human_filter, human_filter_values
from syz_sage.storage import temporary_directory

FIXTURES = Path(__file__).parent / "fixtures" / "legacy_data"
ANSI = re.compile(r"\x1b\[[0-9;]*m")


class Output(io.StringIO):
    def __init__(self, tty: bool = False) -> None:
        super().__init__()
        self.tty = tty

    def isatty(self) -> bool:
        return self.tty


def invoke(
    arguments: list[str], *, tty: bool = False, no_color: bool = False
) -> tuple[int, str, str]:
    stdout, stderr = Output(tty), Output(tty)
    environment = {"TERM": "xterm", "COLUMNS": "96"}
    if no_color:
        environment["NO_COLOR"] = ""
    with (
        contextlib.redirect_stdout(stdout),
        contextlib.redirect_stderr(stderr),
        mock.patch.dict(os.environ, environment, clear=True),
    ):
        try:
            code = main(arguments)
        except SystemExit as exc:
            code = int(exc.code)
    return code, stdout.getvalue(), stderr.getvalue()


class FilterCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = temporary_directory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "mirror"
        self.database = self.root / "bugs.sqlite3"
        shutil.copytree(FIXTURES, self.source)
        (self.source / "raw" / "upstream_fixed.html").write_text(
            "<!doctype html><html><body><table><tr><td>"
            '<a href="/bug?extid=alpha123">alpha</a></td>'
            '<td><a href="/upstream?label=subsystems%3Afs">fs</a>'
            '<a href="/upstream?label=subsystems%3Anet">net</a></td></tr>'
            '<tr><td><a href="/bug?id=beta456">beta</a></td>'
            '<td><a href="/upstream?label=subsystems%3Aext4">ext4</a>'
            '<a href="/upstream?label=subsystems%3Amm">mm</a></td></tr></table></body></html>',
            encoding="utf-8",
        )
        with Database(self.database) as database:
            result = database.import_legacy(self.source)
        self.assertFalse(result.get("failures"), result)

    def run_filter(self, *arguments: str, **options: bool) -> tuple[int, str, str]:
        return invoke(["--database", str(self.database), "filter", *arguments], **options)

    def test_case_insensitive_multi_values_repeat_flags_and_combined_categories(self) -> None:
        code, output, error = self.run_filter(
            "--type",
            "KASAN",
            "warning",
            "--type",
            "kasan",
            "--subsystem",
            "FS",
            "mm",
            "--subsystem",
            "fs",
            "--json",
        )
        self.assertEqual(code, 0, error)
        result = json.loads(output)
        self.assertEqual(result["bug_types"], ["kasan", "warning"])
        self.assertEqual(result["subsystems"], ["fs", "mm"])
        self.assertEqual(result["total"], 2)
        self.assertEqual([row["bug_type"] for row in result["bugs"]], ["kasan", "warning"])
        code, output, error = self.run_filter("--type", "kasan", "--subsystem", "mm", "--json")
        self.assertEqual(code, 0, error)
        self.assertEqual(json.loads(output)["bugs"], [])

    def test_subsystems_are_exact_and_query_combines_with_filters(self) -> None:
        code, output, error = self.run_filter("--subsystem", "fs", "--json")
        self.assertEqual(code, 0, error)
        self.assertEqual([row["key"] for row in json.loads(output)["bugs"]], ["extid-alpha123"])
        code, output, error = self.run_filter("--bug-type", "KASAN", "--query", "ALPHA", "--json")
        self.assertEqual(code, 0, error)
        self.assertEqual(json.loads(output)["total"], 1)

    def test_browse_defaults_pagination_unlimited_and_offset_beyond_results(self) -> None:
        code, output, error = self.run_filter("--json")
        self.assertEqual(code, 0, error)
        result = json.loads(output)
        self.assertEqual((result["total"], result["limit"], result["offset"]), (2, 20, 0))
        code, output, error = self.run_filter("--limit", "1", "--offset", "1", "--json")
        self.assertEqual(code, 0, error)
        result = json.loads(output)
        self.assertEqual(result["total"], 2)
        self.assertEqual([row["key"] for row in result["bugs"]], ["id-beta456"])
        code, output, error = self.run_filter("--all", "--offset", "1", "--json")
        self.assertEqual(code, 0, error)
        self.assertIsNone(json.loads(output)["limit"])
        self.assertEqual(len(json.loads(output)["bugs"]), 1)
        code, output, error = self.run_filter("--offset", "9")
        self.assertEqual(code, 0, error)
        self.assertIn("Matching fixed bugs (2)", output)
        self.assertIn("No rows at offset 9", output)

    def test_human_cards_include_complete_evidence_summary_and_paging_hint(self) -> None:
        code, output, error = self.run_filter("--limit", "1")
        self.assertEqual(code, 0, error)
        compact = " ".join(output.split())
        for content in (
            "KASAN: use-after-free in alpha",
            "https://syzkaller.appspot.com/bug?extid=alpha123",
            "Matching fixed bugs (2)",
            "Showing: 1-1 of 2",
            "Bug type: KASAN",
            "Subsystems: fs, net",
            "Saved status: fixed",
            "Crashes: 1",
            "Fixes: 1",
            "Representative report: available",
            "--offset 1",
            "ss show KEY",
        ):
            self.assertIn(content, compact)
        self.assertNotIn("\x1b", output)

    def test_urls_only_is_uncolored_complete_lines_even_on_a_terminal(self) -> None:
        code, output, error = self.run_filter("--all", "--urls-only", tty=True)
        self.assertEqual(code, 0, error)
        self.assertEqual(
            output.splitlines(),
            [
                "https://syzkaller.appspot.com/bug?extid=alpha123",
                "https://syzkaller.appspot.com/bug?id=beta456",
            ],
        )
        self.assertEqual(error, "")
        code, output, error = self.run_filter("--query", "no such bug", "--urls-only")
        self.assertEqual((code, output, error), (0, "", ""))

    def test_filter_json_and_human_include_saved_patch_and_c_reproducer_links(self) -> None:
        code, output, error = self.run_filter("--query", "alpha", "--json")
        self.assertEqual(code, 0, error)
        bug = json.loads(output)["bugs"][0]
        self.assertTrue(bug["patch_urls"])
        self.assertEqual(bug["c_reproducer_status"], "available")
        self.assertEqual(
            bug["c_reproducer_urls"], ["https://syzkaller.appspot.com/text?tag=ReproC&x=alpha"]
        )
        code, output, error = self.run_filter("--query", "alpha")
        self.assertEqual(code, 0, error)
        self.assertIn("Patch / commit URLs:", output)
        self.assertIn("C reproducer: available (URL recorded)", " ".join(output.split()))
        for url in [*bug["patch_urls"], *bug["c_reproducer_urls"]]:
            self.assertIn(url, [line.strip() for line in output.splitlines()])

    def test_absent_links_and_reproducer_status_are_explicit(self) -> None:
        code, output, error = self.run_filter("--query", "beta", "--json")
        self.assertEqual(code, 0, error)
        bug = json.loads(output)["bugs"][0]
        self.assertEqual(bug["patch_urls"], [])
        self.assertEqual(bug["c_reproducer_urls"], [])
        self.assertEqual(bug["c_reproducer_status"], "not_provided")
        code, output, error = self.run_filter("--query", "beta")
        self.assertEqual(code, 0, error)
        compact = " ".join(output.split())
        self.assertIn("Patch / commit URLs: not recorded", compact)
        self.assertIn("C reproducer: not provided in saved crash metadata", compact)

    def test_no_matches_json_and_human_are_successful(self) -> None:
        code, output, error = self.run_filter("--subsystem", "nonexistent", "--json")
        self.assertEqual(code, 0, error)
        self.assertEqual(json.loads(output)["total"], 0)
        self.assertEqual(json.loads(output)["bugs"], [])
        code, output, error = self.run_filter("--query", "nonexistent")
        self.assertEqual(code, 0, error)
        self.assertIn("No bugs match these filters.", output)

    def test_urls_only_escapes_saved_controls_without_adding_output_lines(self) -> None:
        with mock.patch.object(
            Database,
            "filter_bugs",
            return_value={"bugs": [{"bug_url": "https://example.invalid/bug?x=1\n\x1b[2J"}]},
        ):
            code, output, error = self.run_filter("--urls-only", tty=True)
        self.assertEqual(code, 0, error)
        self.assertEqual(output.splitlines(), [r"https://example.invalid/bug?x=1\x0a\x1b[2J"])

    def test_list_values_reports_actual_types_and_tags_with_counts(self) -> None:
        code, output, error = self.run_filter("--list-values", "--json", tty=True)
        self.assertEqual(code, 0, error)
        values = json.loads(output)
        self.assertEqual(
            values["bug_types"],
            [
                {"value": "kasan", "count": 1},
                {"value": "warning", "count": 1},
            ],
        )
        self.assertEqual(
            {item["value"]: item["count"] for item in values["subsystems"]},
            {"fs": 1, "net": 1, "ext4": 1, "mm": 1},
        )
        code, output, error = self.run_filter("--list-values")
        self.assertEqual(code, 0, error)
        self.assertIn("Bug types", output)
        self.assertIn("Subsystem tags", output)
        self.assertIn("kasan", output)

    def test_filter_uses_read_only_database_without_network_or_data_changes(self) -> None:
        before = hashlib.sha256(self.database.read_bytes()).digest()
        modified = self.database.stat().st_mtime_ns
        with (
            mock.patch("syz_sage.cli.Updater", side_effect=AssertionError("unexpected retrieval")),
            mock.patch("syz_sage.cli.Database", wraps=Database) as opened,
        ):
            for arguments in (("--json",), ("--list-values", "--json"), ("--urls-only",), ()):
                code, _, error = self.run_filter(*arguments)
                self.assertEqual(code, 0, error)
            self.assertTrue(
                all(call.kwargs == {"read_only": True} for call in opened.call_args_list)
            )
        self.assertEqual(hashlib.sha256(self.database.read_bytes()).digest(), before)
        self.assertEqual(self.database.stat().st_mtime_ns, modified)

    def test_filter_refuses_older_database_without_migrating(self) -> None:
        with contextlib.closing(sqlite3.connect(self.database)) as connection:
            connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION - 1}")
        before = self.database.read_bytes()
        code, output, error = self.run_filter("--json")
        self.assertEqual(code, 1)
        self.assertEqual(output, "")
        self.assertIn("migrat", error.lower())
        self.assertEqual(self.database.read_bytes(), before)

    def test_color_respects_no_color_and_json_stays_uncolored(self) -> None:
        code, plain, error = self.run_filter("--limit", "1")
        self.assertEqual(code, 0, error)
        code, colored, error = self.run_filter("--limit", "1", tty=True)
        self.assertEqual(code, 0, error)
        self.assertIn("\x1b[", colored)
        self.assertEqual(ANSI.sub("", colored), plain)
        code, output, error = self.run_filter("--limit", "1", tty=True, no_color=True)
        self.assertEqual(code, 0, error)
        self.assertEqual(output, plain)
        code, output, error = self.run_filter("--json", tty=True)
        self.assertEqual(code, 0, error)
        self.assertNotIn("\x1b", output)

    def test_show_displays_the_bug_type(self) -> None:
        code, output, error = invoke(["--database", str(self.database), "show", "extid-alpha123"])
        self.assertEqual(code, 0, error)
        self.assertIn("Bug type: KASAN", " ".join(output.split()))


class FilterValidationTests(unittest.TestCase):
    def test_value_labels_escape_saved_terminal_controls(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            human_filter_values(
                {
                    "bug_types": [],
                    "subsystems": [{"value": "net\x1b[2J", "count": 1}],
                }
            )
        self.assertNotIn("\x1b", output.getvalue())
        self.assertIn(r"net\x1b[2J", output.getvalue())

    def test_invalid_criteria_and_contradictory_flags_fail_before_paths_or_database(self) -> None:
        invalid = [
            ["--type", "not-a-type"],
            ["--type", " "],
            ["--subsystem", ""],
            ["--query", "\t"],
            ["--limit", "0"],
            ["--offset", "-1"],
            ["--all", "--limit", "20"],
            ["--json", "--urls-only"],
            ["--list-values", "--type", "kasan"],
            ["--list-values", "--subsystem", "mm"],
            ["--list-values", "--query", "alpha"],
            ["--list-values", "--limit", "20"],
            ["--list-values", "--offset", "0"],
            ["--list-values", "--all"],
            ["--list-values", "--urls-only"],
        ]
        for arguments in invalid:
            with self.subTest(arguments=arguments), mock.patch("syz_sage.cli._paths") as paths:
                code, output, error = invoke(["filter", *arguments])
                self.assertEqual(code, 2, error)
                self.assertEqual(output, "")
                self.assertIn("error:", error)
                paths.assert_not_called()

    def test_narrow_human_output_preserves_long_titles_and_urls(self) -> None:
        title = "KASAN: " + "a long diagnostic title " * 10
        url = "https://syzkaller.appspot.com/bug?id=" + "a" * 40
        patch_urls = [f"https://git.kernel.org/example/patch/?id={digit * 40}" for digit in "ab"]
        c_urls = [f"https://syzkaller.appspot.com/text?tag=ReproC&x={index}" for index in range(5)]
        value = {
            "bugs": [
                {
                    "title": title,
                    "bug_url": url,
                    "bug_type": "kasan",
                    "patch_urls": patch_urls,
                    "c_reproducer_status": "available",
                    "c_reproducer_urls": c_urls,
                }
            ],
            "total": 1,
            "offset": 0,
            "limit": 20,
            "bug_types": [],
            "subsystems": [],
        }
        output = io.StringIO()
        with contextlib.redirect_stdout(output), mock.patch.dict(os.environ, {"COLUMNS": "40"}):
            human_filter(value)
        rendered = output.getvalue()
        self.assertIn(" ".join(title.split()), " ".join(rendered.split()))
        for expected in [url, *patch_urls, *c_urls]:
            self.assertIn(expected, [line.strip() for line in rendered.splitlines()])

    def test_filter_artifact_links_escape_controls_and_unknown_c_status(self) -> None:
        value = {
            "bugs": [
                {
                    "patch_urls": ["https://example.invalid/patch?x=1\x1b[2J"],
                    "c_reproducer_status": "unknown",
                    "c_reproducer_urls": ["https://example.invalid/repro?x=1\nnext"],
                }
            ],
            "total": 1,
            "offset": 0,
            "limit": 20,
            "bug_types": [],
            "subsystems": [],
        }
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            human_filter(value)
        rendered = output.getvalue()
        self.assertNotIn("\x1b", rendered)
        self.assertIn(r"https://example.invalid/patch?x=1\x1b[2J", rendered)
        self.assertIn(r"https://example.invalid/repro?x=1\x0anext", rendered)
        self.assertIn(
            "C reproducer: unknown (metadata missing or invalid)", " ".join(rendered.split())
        )


if __name__ == "__main__":
    unittest.main()
