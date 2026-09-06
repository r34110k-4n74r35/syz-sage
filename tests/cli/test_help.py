from __future__ import annotations

import argparse
import contextlib
import io
import os
import re
import unittest
from unittest import mock

from syz_sage.cli.commands import _parser
from syz_sage.parsing.bug_types import BUG_TYPES

ANSI = re.compile(r"\x1b\[[0-9;]*m")
COMMANDS = ("update", "show", "list", "filter", "status", "check", "import-legacy", "migrate")


class Output(io.StringIO):
    def __init__(self, *, tty: bool = False) -> None:
        super().__init__()
        self.tty = tty

    def isatty(self) -> bool:
        return self.tty


class HelpTests(unittest.TestCase):
    def render(
        self,
        arguments: list[str],
        *,
        stdout_tty: bool = False,
        stderr_tty: bool = False,
        environment: dict[str, str] | None = None,
    ) -> tuple[int, str, str]:
        stdout, stderr = Output(tty=stdout_tty), Output(tty=stderr_tty)
        with (
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
            mock.patch.dict(
                os.environ, {"TERM": "xterm", "COLUMNS": "80", **(environment or {})}, clear=True
            ),
            self.assertRaises(SystemExit) as raised,
        ):
            _parser().parse_args(arguments)
        return int(raised.exception.code), stdout.getvalue(), stderr.getvalue()

    def test_root_help_groups_paths_commands_and_examples(self) -> None:
        code, stdout, stderr = self.render(["--help"])

        self.assertEqual(code, 0)
        self.assertEqual(stderr, "")
        self.assertIn("usage: ss", stdout)
        for title in ("Options:", "Paths:", "Commands:", "Examples:"):
            self.assertIn(title, stdout)
        self.assertIn("Place these options before COMMAND.", stdout)
        self.assertIn("ss COMMAND --help", stdout)
        for command in COMMANDS:
            self.assertRegex(stdout, rf"(?m)^  {re.escape(command)}\s{{2,}}\S")
        self.assertNotIn("{update,", stdout)
        self.assertNotIn("\x1b", stdout)

    def test_each_command_has_local_usage_and_practical_examples(self) -> None:
        for command in COMMANDS:
            with self.subTest(command=command):
                code, stdout, stderr = self.render([command, "--help"])
                self.assertEqual(code, 0)
                self.assertEqual(stderr, "")
                self.assertIn(f"usage: ss {command}", stdout)
                self.assertIn("Examples:", stdout)
                self.assertIn("--json", stdout)
        _, update, _ = self.render(["update", "--help"])
        self.assertIn("first N listing entries", update)
        self.assertIn("default: 8", update)
        self.assertIn("Partial runs:", update)
        self.assertIn("--quiet", update)
        _, show, _ = self.render(["show", "--help"])
        self.assertIn("KEY_OR_URL", show)
        self.assertIn("looked up locally", show)
        self.assertIn("Report content:", show)
        _, filtering, _ = self.render(["filter", "--help"])
        for text in ("--type", "--subsystem", "--list-values", "--urls-only", "--all"):
            self.assertIn(text, filtering)
        self.assertIn("Subsystem tags match exactly", " ".join(filtering.split()))
        self.assertIn("OR within each category", " ".join(filtering.split()))
        self.assertIn("Supported types:", filtering)
        for bug_type in BUG_TYPES:
            self.assertIn(bug_type, filtering)

    def test_help_wraps_for_narrow_and_wide_terminals(self) -> None:
        for width in (60, 96):
            for command in (None, *COMMANDS):
                with self.subTest(width=width, command=command):
                    arguments = [command, "--help"] if command else ["--help"]
                    code, stdout, stderr = self.render(
                        arguments, environment={"COLUMNS": str(width)}
                    )
                    self.assertEqual(code, 0, stderr)
                    self.assertLessEqual(max(map(len, stdout.splitlines())), width)

    def test_color_changes_decoration_only_and_respects_terminal_preferences(self) -> None:
        _, plain, _ = self.render(["update", "--help"])
        _, colored, _ = self.render(["update", "--help"], stdout_tty=True)
        self.assertIn("\x1b[", colored)
        self.assertEqual(ANSI.sub("", colored), plain)
        for environment in ({"NO_COLOR": ""}, {"NO_COLOR": "1"}, {"TERM": "dumb"}):
            with self.subTest(environment=environment):
                _, stdout, _ = self.render(
                    ["update", "--help"], stdout_tty=True, environment=environment
                )
                self.assertEqual(stdout, plain)

    def test_usage_errors_use_stderr_terminal_capabilities(self) -> None:
        for stdout_tty, stderr_tty in ((False, True), (True, False)):
            with self.subTest(stdout_tty=stdout_tty, stderr_tty=stderr_tty):
                code, stdout, stderr = self.render(
                    ["update", "--workers", "invalid"],
                    stdout_tty=stdout_tty,
                    stderr_tty=stderr_tty,
                )
                self.assertEqual(code, 2)
                self.assertEqual(stdout, "")
                self.assertEqual("\x1b[" in stderr, stderr_tty)
                self.assertIn("usage: ss update", ANSI.sub("", stderr))
                self.assertIn("error:", ANSI.sub("", stderr))

    def test_format_help_stays_plain_and_explicit_output_stream_is_respected(self) -> None:
        stdout, destination = Output(tty=True), Output()
        with (
            contextlib.redirect_stdout(stdout),
            mock.patch.dict(os.environ, {"TERM": "xterm", "COLUMNS": "80"}, clear=True),
        ):
            parser = _parser()
            plain = parser.format_help()
            parser.print_help(destination)
        self.assertNotIn("\x1b", plain)
        self.assertEqual(destination.getvalue(), plain)
        self.assertEqual(stdout.getvalue(), "")

    def test_error_arguments_cannot_inject_terminal_controls(self) -> None:
        code, _, stderr = self.render(["status", "--unknown=\x1b[2J"])
        self.assertEqual(code, 2)
        self.assertNotIn("\x1b", stderr)
        self.assertIn(r"\x1b[2J", stderr)

    def test_grouped_options_preserve_argument_defaults_and_destinations(self) -> None:
        parser = _parser()
        update = parser.parse_args(["update"])
        self.assertIsInstance(update, argparse.Namespace)
        self.assertEqual(update.workers, 8)
        self.assertIsNone(update.limit)
        self.assertFalse(update.refresh_details)
        self.assertFalse(update.refresh_artifacts)
        self.assertFalse(update.no_reports)
        self.assertFalse(update.no_patches)
        self.assertFalse(update.allow_partial)
        self.assertFalse(update.json)
        self.assertFalse(update.quiet)
        listing = parser.parse_args(["list"])
        self.assertEqual((listing.limit, listing.offset), (20, 0))
        show = parser.parse_args(["show", "extid-alpha123", "--report", "--stack", "--json"])
        self.assertEqual(show.key, "extid-alpha123")
        self.assertTrue(show.report and show.stack and show.json)
        filtering = parser.parse_args(
            [
                "filter",
                "--type",
                "KASAN",
                "kmsan",
                "--type",
                "warning",
                "--subsystem",
                "fs",
                "mm",
                "--subsystem",
                "net",
                "--all",
                "--urls-only",
            ]
        )
        self.assertEqual(filtering.bug_types, ["kasan", "kmsan", "warning"])
        self.assertEqual(filtering.subsystems, ["fs", "mm", "net"])
        self.assertTrue(filtering.all and filtering.urls_only)


if __name__ == "__main__":
    unittest.main()
