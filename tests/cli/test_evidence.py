from __future__ import annotations

import contextlib
import io
import json
import os
import re
import unittest
from unittest import mock

from syz_sage.analysis.evidence import build_explanation
from syz_sage.cli import main
from syz_sage.cli.presentation.evidence import human_explanation, human_patch
from tests.cli.support import CliFixture, compact, invoke
from tests.support import ALPHA_HASH

ANSI = re.compile(r"\x1b\[[0-9;]*m")


class EvidenceDisplayTests(unittest.TestCase):
    def render(self, function, value, *, tty=False, width=96, environment=None):
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
            function(value)
        return output.getvalue()

    def patch(self):
        return {
            "key": "extid-alpha",
            "fix": {"title": "Repair alpha"},
            "commit_hash": ALPHA_HASH,
            "available": True,
            "source_url": "https://git.kernel.org/patch/?id=" + ALPHA_HASH,
            "sha256": "d" * 64,
            "size": 200,
            "files": [{}],
            "total_files": 2,
            "text": "diff --git a/x.c b/x.c\n--- a/x.c\n+++ b/x.c\n@@ -1 +1 @@ int x(void)\n-old\n+"
            + "a" * 150
            + "\n",
        }

    def test_diff_colors_do_not_modify_lines_and_respect_no_color(self):
        value = self.patch()
        plain = self.render(human_patch, value, width=24)
        colored = self.render(human_patch, value, tty=True, width=24)
        self.assertEqual(ANSI.sub("", colored), plain)
        self.assertIn("\x1b[32m+" + "a" * 150, colored)
        self.assertIn("\x1b[31m-old", colored)
        self.assertIn("+" + "a" * 150, plain.splitlines())
        self.assertIn(value["source_url"], [line.strip() for line in plain.splitlines()])
        for environment in ({"NO_COLOR": ""}, {"TERM": "dumb"}):
            self.assertEqual(
                self.render(human_patch, value, tty=True, width=24, environment=environment), plain
            )

    def test_diff_escapes_terminal_controls_and_keeps_tabs_as_source_indentation(self):
        value = self.patch()
        value["text"] = "+\ttext\x1b[2J\r\x00\u202e\n"
        output = self.render(human_patch, value, tty=True)
        self.assertNotIn("\x1b[2J", output)
        self.assertIn("+\ttext" + r"\x1b[2J\x0d\x00\u202e", output)
        self.assertEqual(value["text"], "+\ttext\x1b[2J\r\x00\u202e\n")

    def test_missing_patch_is_explicit_and_has_no_empty_diff_section(self):
        value = self.patch()
        value.update(available=False, text=None, files=[])
        output = self.render(human_patch, value)
        self.assertIn("No retained patch text", output)
        self.assertIn("not recorded", output)
        self.assertNotIn("\nDiff\n", output)

    def test_explanation_colors_and_unknown_evidence_remain_readable(self):
        value = build_explanation(
            {
                "key": "extid-alpha",
                "title": "KASAN: example\x1b[2J",
                "bug_url": "https://syzkaller.appspot.com/bug?extid=" + "a" * 70,
                "fixes": [{"title": "Unresolved fix"}],
            }
        )
        plain = self.render(human_explanation, value, width=40)
        colored = self.render(human_explanation, value, tty=True, width=40)
        self.assertEqual(ANSI.sub("", colored), plain)
        self.assertIn(value["bug_url"], [line.strip() for line in plain.splitlines()])
        self.assertIn("No crash source location is recorded", compact(plain))
        self.assertIn("No parsed changed regions are recorded", compact(plain))
        self.assertIn("are not compared", compact(plain))
        self.assertNotIn("\x1b[2J", colored)
        self.assertIn(r"\x1b[2J", plain)
        self.assertEqual(
            self.render(human_explanation, value, tty=True, width=40, environment={"NO_COLOR": ""}),
            plain,
        )


class EvidenceCommandTests(CliFixture, unittest.TestCase):
    def test_patch_and_explanation_json_are_complete_uncolored_and_read_only(self):
        self.import_fixture()
        before = self.database.read_bytes()
        code, stdout, stderr = invoke(
            [
                "--database",
                str(self.database),
                "show",
                "extid-alpha123",
                "--patch",
                ALPHA_HASH,
                "--file",
                "net/*",
                "--explain",
                "--json",
            ]
        )
        self.assertEqual(code, 0, stderr)
        self.assertEqual(stderr, "")
        value = json.loads(stdout)
        self.assertEqual(
            value["patch"]["text"],
            (self.legacy / f"artifacts/patches/{ALPHA_HASH}.diff").read_text(),
        )
        self.assertEqual(value["explanation"]["crash"]["operation"]["value"], "read")
        self.assertEqual(
            value["explanation"]["fixes"][0]["hunks"][0]["relationship"], "same-function"
        )
        self.assertEqual(
            value["explanation"]["crash"]["operation"]["report_lines"][0]["report_line"], 2
        )
        self.assertNotIn("text", value["report"])
        self.assertNotIn("\x1b", stdout)
        self.assertEqual(self.database.read_bytes(), before)

    def test_explanation_and_patch_human_display_supporting_evidence(self):
        self.import_fixture()
        code, stdout, stderr = invoke(
            [
                "--database",
                str(self.database),
                "show",
                "extid-alpha123",
                "--patch",
                ALPHA_HASH,
                "--explain",
            ]
        )
        self.assertEqual(code, 0, stderr)
        text = compact(stdout)
        for expected in (
            "Crash-to-fix evidence",
            "Operation: read",
            "Report line 2:",
            "Relationship: same-function",
            "inferred from definition context",
            "Matching manifestation frames",
            "confidence: inferred",
            "Saved patch",
            "return 0;",
        ):
            self.assertIn(expected, text)

    def test_file_requires_patch_and_wrong_commit_or_file_returns_clear_error(self):
        error_output = io.StringIO()
        with contextlib.redirect_stderr(error_output), self.assertRaises(SystemExit) as raised:
            main(["--database", str(self.database), "show", "extid-alpha123", "--file", "net/*"])
        self.assertEqual(raised.exception.code, 2)
        self.assertIn("--file requires --patch", error_output.getvalue())
        self.assertFalse(self.database.exists())
        self.import_fixture()
        for args, message in (
            (["--patch", ALPHA_HASH[:12]], "full 40"),
            (["--patch", "b" * 40], "not a recorded fix"),
            (["--patch", ALPHA_HASH, "--file", "absent/*"], "no saved patch file"),
        ):
            with self.subTest(args=args):
                code, _, stderr = invoke(
                    ["--database", str(self.database), "show", "extid-alpha123", *args]
                )
                self.assertEqual(code, 1, stderr)
                self.assertIn(message, stderr)
