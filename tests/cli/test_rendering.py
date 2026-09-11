from __future__ import annotations

import contextlib
import io
import json
import os
import unittest
from unittest import mock

from syz_sage.cli.commands import _human_bug, _human_list, main
from syz_sage.cli.display import progress
from tests.cli.support import ANSI_RE, CliFixture, compact


class CliRenderingTests(CliFixture, unittest.TestCase):
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
            _human_bug(bug, include_stack=True)

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
                "syz_sage.cli.terminal.shutil.get_terminal_size",
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
                    "syz_sage.cli.terminal.shutil.get_terminal_size",
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
            _human_bug(bug)

        rendered = stdout.getvalue()
        self.assertNotIn("\x1b", rendered)
        self.assertNotIn("\r", rendered)
        self.assertNotIn("\t", rendered)
        self.assertNotIn("\u202e", rendered)
        self.assertIn(r"\x1b", rendered)
        self.assertIn(r"\u202e", rendered)
        self.assertNotIn("line one", rendered)
        self.assertNotIn("Full representative report", rendered)

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
            _human_bug(bug)

        self.assertIn("Representative report: unavailable", compact(stdout.getvalue()))


if __name__ == "__main__":
    unittest.main()
