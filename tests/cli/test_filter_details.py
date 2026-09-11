from __future__ import annotations

import contextlib
import io
import os
import unittest
from unittest import mock

from syz_sage.cli.display import human_filter
from tests.cli.support import ANSI_RE, compact


class FilterDetailsDisplayTests(unittest.TestCase):
    def render(self, bug, *, width=96, tty=False, environment=None):
        output = io.StringIO()
        with (
            contextlib.redirect_stdout(output),
            mock.patch.object(output, "isatty", return_value=tty),
            mock.patch.dict(
                os.environ,
                {"TERM": "xterm", "COLUMNS": str(width), **(environment or {})},
                clear=True,
            ),
        ):
            human_filter(
                {"bugs": [bug], "total": 1, "offset": 0, "bug_types": [], "subsystems": []}
            )
        return output.getvalue()

    def test_fix_locations_stay_with_their_commit_and_repository(self):
        bug = {
            "fixes": [
                {"title": "First fix", "hash": "a" * 40, "repo": "repo-one"},
                {"title": "Second fix", "hash": "a" * 40, "repo": "repo-two"},
                {"title": "Third fix", "hash": "b" * 40, "repo": "repo-one"},
            ],
            "fix_locations": [
                {
                    "commit_hash": "a" * 40,
                    "repo": "repo-two",
                    "old_file_path": "old.c",
                    "new_file_path": "new.c",
                    "old_start": 4,
                    "old_count": 2,
                    "new_start": 4,
                    "new_count": 1,
                    "function_name": "second_fn",
                    "function_basis": "inferred from hunk header",
                },
                {
                    "commit_hash": "a" * 40,
                    "repo": "repo-one",
                    "old_file_path": "first.c",
                    "new_file_path": "first.c",
                    "old_start": 2,
                    "old_count": 0,
                    "new_start": 3,
                    "new_count": 1,
                    "function_name": "first_fn",
                    "function_basis": "inferred from definition context",
                },
            ],
        }
        output = compact(self.render(bug))
        first = output.split("1. First fix", 1)[1].split("2. Second fix", 1)[0]
        second = output.split("2. Second fix", 1)[1].split("3. Third fix", 1)[0]
        third = output.split("3. Third fix", 1)[1]
        self.assertIn("first_fn", first)
        self.assertIn("old after line 2 -> new 3", first)
        self.assertNotIn("second_fn", first)
        self.assertIn("old.c -> new.c", second)
        self.assertIn("second_fn", second)
        self.assertIn("old 4-5 -> new 4", second)
        self.assertNotIn("first_fn", second)
        self.assertIn("Changed locations unknown.", third)
        self.assertNotIn("first_fn", third)
        self.assertNotIn("second_fn", third)

    def test_rich_details_preserve_links_coordinates_and_colors_in_narrow_output(self):
        report_url = "https://syzkaller.appspot.com/text?tag=CrashReport&x=" + "a" * 60
        repo = "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git"
        coordinate = "drivers/example/really_long_filename.c:123:4"
        bug = {
            "title": "KASAN: diagnostic\x1b[2J",
            "bug_url": "https://example.invalid/bug",
            "first_crash": "2026-08-01T12:00:00Z",
            "crash_stack_count": 8,
            "crash_locations": [
                {
                    "file_path": coordinate.split(":")[0],
                    "line_number": 123,
                    "column_number": 4,
                    "function_name": "crash_fn\x1b[2J",
                    "role": "primary",
                    "confidence": "high",
                    "method": "explicit report site",
                    "kernel_source_commit": "c" * 40,
                }
            ],
            "fixes": [
                {
                    "title": "fix\x1b[2J",
                    "hash": "a" * 40,
                    "repo": repo,
                    "link": repo + "/commit/?id=" + "a" * 40,
                    "patch_available": True,
                }
            ],
            "fix_locations": [
                {
                    "commit_hash": "a" * 40,
                    "repo": repo,
                    "old_file_path": "x.c\x1b[2J",
                    "new_file_path": "x.c\x1b[2J",
                    "function_name": "fix_fn\x1b[2J",
                    "function_basis": "inferred from hunk header",
                    "old_start": 1,
                    "old_count": 1,
                    "new_start": 1,
                    "new_count": 2,
                }
            ],
            "report": {"available": True, "size": 1024, "source_url": report_url},
        }
        for width in (24, 40, 96):
            with self.subTest(width=width):
                plain = self.render(bug, width=width)
                colored = self.render(bug, width=width, tty=True)
                self.assertEqual(ANSI_RE.sub("", colored), plain)
                self.assertNotIn("\x1b[2J", colored)
                self.assertIn(r"fix_fn\x1b[2J", plain)
                self.assertIn(coordinate, plain)
                self.assertIn("a" * 40, plain)
                self.assertIn("c" * 40, plain)
                self.assertIn("2026-08-01 12:00:00 UTC", compact(plain))
                self.assertIn("Stack: 8 extracted frames", compact(plain))
                self.assertIn(report_url, [line.strip() for line in plain.splitlines()])
                self.assertTrue(
                    all(
                        len(line) <= width
                        for line in plain.splitlines()
                        if line.strip() == "Representative report:"
                    )
                )
                self.assertIn(
                    bug["fixes"][0]["link"], [line.strip() for line in plain.splitlines()]
                )
                for environment in ({"NO_COLOR": ""}, {"TERM": "dumb"}):
                    self.assertEqual(
                        self.render(bug, width=width, tty=True, environment=environment), plain
                    )

        bug["fixes"][0]["repo"] = "repo\x1b[2J"
        bug["report"]["source_url"] = report_url + "\n\x1b[2J"
        output = self.render(bug)
        self.assertNotIn("\x1b", output)
        self.assertIn(r"repo\x1b[2J", output)
        self.assertIn(report_url + r"\x0a\x1b[2J", output)

    def test_patch_download_urls_remain_visible_without_repeating_fix_links(self):
        commit = "https://example.invalid/commit?id=" + "a" * 40
        patch = "https://example.invalid/patch?id=" + "b" * 40
        output = self.render(
            {
                "fixes": [{"title": "Fix", "hash": "a" * 40, "link": commit}],
                "patch_urls": [commit, patch],
            }
        )
        lines = [line.strip() for line in output.splitlines()]
        self.assertEqual(lines.count(commit), 1)
        self.assertEqual(lines.count(patch), 1)
