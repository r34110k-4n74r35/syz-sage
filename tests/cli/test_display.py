from __future__ import annotations

import contextlib
import io
import os
import re
import unittest
from pathlib import Path
from unittest import mock

from syz_sage.cli import display
from syz_sage.cli.help import HelpParser
from syz_sage.cli.terminal import terminal_width
from syz_sage.retrieval.sync import UpdateSummary

ANSI = re.compile(r"\x1b\[[0-9;]*m")
DATABASE = Path("data/db/syz_sage.sqlite3")


class HumanDisplayTests(unittest.TestCase):
    def test_width_uses_the_output_stream_when_stdout_is_redirected(self):
        stream = io.StringIO()
        with (
            mock.patch.object(stream, "isatty", return_value=True),
            mock.patch.object(stream, "fileno", return_value=2),
            mock.patch.dict(os.environ, {"TERM": "xterm"}, clear=True),
            mock.patch(
                "syz_sage.cli.terminal.shutil.get_terminal_size",
                return_value=os.terminal_size((96, 24)),
            ),
            mock.patch(
                "syz_sage.cli.terminal.os.get_terminal_size",
                return_value=os.terminal_size((63, 24)),
            ) as size,
        ):
            self.assertEqual(terminal_width(stream), 63)
            size.assert_called_once_with(2)

    def render(self, function, *args, tty=False, width=96, environment=None, **kwargs):
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
            function(*args, **kwargs)
        return output.getvalue()

    @staticmethod
    def status():
        return {
            "database": str(DATABASE),
            "schema_version": 5,
            "bugs": 2,
            "fixes": 3,
            "reports": 1,
            "patches": 2,
            "crashes": 2,
            "current_snapshot": {"id": 7},
            "last_sync_status": "completed",
            "last_sync_at": "2026-09-07T10:00:00Z",
            "last_checked_at": "2026-09-07T12:00:00Z",
            "counts": {
                "bug_subsystems": 12,
                "crash_locations": 15,
                "crash_stack_frames": 100,
                "fix_locations": 30,
            },
        }

    @staticmethod
    def summary():
        return UpdateSummary(
            namespace="upstream",
            status="fixed",
            listing_bugs=2,
            new_fixed_bugs=1,
            new_fixed_bug_keys=["extid-alpha"],
            changed_bugs=1,
            changed_bug_keys=["id-beta"],
            details_downloaded=1,
            details_reused=1,
            reports_downloaded=1,
            reports_unavailable=1,
            patches_reused=2,
            database={"status": "completed", "activated": True, "snapshot_id": 7, "blobs_added": 3},
        )

    def test_color_only_adds_decoration_to_every_human_summary(self):
        calls = [
            (display.human_status, (self.status(),), {}),
            (display.human_migrate, (self.status(), DATABASE), {"prior_schema": 4}),
            (display.human_update, (self.summary(), Path("data"), DATABASE), {}),
            (
                display.human_import,
                (
                    {
                        "status": "completed",
                        "activated": True,
                        "bugs": 2,
                        "reports": 1,
                        "patches": 2,
                    },
                    DATABASE,
                ),
                {},
            ),
            (
                display.human_check,
                (
                    {"ok": True, "schema_version": 5, "quick_check": ["ok"], "blob_count": 9},
                    DATABASE,
                ),
                {},
            ),
        ]
        for function, args, kwargs in calls:
            with self.subTest(command=function.__name__):
                plain = self.render(function, *args, **kwargs)
                colored = self.render(function, *args, tty=True, **kwargs)
                self.assertNotIn("\x1b", plain)
                self.assertIn("\x1b[", colored)
                self.assertEqual(ANSI.sub("", colored), plain)
                for environment in ({"NO_COLOR": ""}, {"TERM": "dumb"}):
                    self.assertEqual(
                        self.render(function, *args, tty=True, environment=environment, **kwargs),
                        plain,
                    )

    def test_failed_import_accepts_early_nested_coverage_and_reports_failure(self):
        value = {
            "status": "failed",
            "records_imported": 2,
            "bug_payloads": {"valid": 1, "invalid": 1, "missing": 0},
            "reports": {"valid": 1, "expected": 2, "missing": 1},
            "patches": {"valid": 0, "expected": 1, "invalid": 1},
            "failures": ["invalid source metadata"],
        }
        output = self.render(display.human_import, value, DATABASE, tty=True)
        plain = " ".join(ANSI.sub("", output).split())
        self.assertIn("Import failed", plain)
        self.assertIn("Result: failed; no snapshot activated", plain)
        self.assertIn("Bugs: 2", plain)
        self.assertIn("Reports: 1 valid / 2 expected; 1 missing", plain)
        self.assertIn("Patches: 0 valid / 1 expected; 1 invalid", plain)
        self.assertIn("Issues (1)", plain)
        self.assertIn("\x1b[31mImport failed", output)
        self.assertIn("\x1b[33m1 valid / 2 expected; 1 missing", output)

    def test_completed_import_uses_coverage_details_and_does_not_claim_missing_artifacts(self):
        value = {
            "status": "completed",
            "activated": True,
            "bugs": 2,
            "reports": 1,
            "patches": 2,
            "report_details": {"valid": 1, "expected": 1, "missing": 0, "unavailable_upstream": 1},
            "patch_details": {"valid": 2, "expected": 2, "invalid": 0},
            "blobs_added": 7,
        }
        output = " ".join(self.render(display.human_import, value, DATABASE).split())
        self.assertIn("Import complete", output)
        self.assertIn("Result: complete; snapshot activated", output)
        self.assertIn("Reports: 1 valid / 1 expected; 1 not provided upstream", output)
        self.assertIn("New blobs: 7", output)
        self.assertNotIn("missing", output)

    def test_noop_and_partial_import_keep_activation_meaning(self):
        for state, expected in (
            ("unchanged", "unchanged; SQLite write skipped"),
            ("partial", "partial; no snapshot activated"),
            ("completed", "complete; snapshot not activated"),
        ):
            with self.subTest(state=state):
                output = " ".join(
                    self.render(
                        display.human_import,
                        {
                            "status": state,
                            "activated": False,
                            "bugs": 2,
                            "reports": 1,
                            "patches": 2,
                        },
                        DATABASE,
                    ).split()
                )
                self.assertIn(expected, output)
                if state == "partial":
                    self.assertIn("Candidate retained; active snapshot unchanged.", output)

    def test_update_aligns_change_fields_and_shows_saved_result_counts(self):
        output = self.render(display.human_update, self.summary(), Path("data"), DATABASE)
        values = ["2 live", "1 new;", "extid-alpha", "id-beta"]
        columns = [
            next(line.index(value) for line in output.splitlines() if value in line)
            for value in values
        ]
        self.assertEqual(len(set(columns)), 1)
        compact = " ".join(output.split())
        self.assertIn("Snapshot: 7", compact)
        self.assertIn("New blobs: 3", compact)
        for width in (24, 40, 60):
            with self.subTest(width=width):
                narrow = self.render(
                    display.human_update, self.summary(), Path("data"), DATABASE, width=width
                )
                self.assertTrue(
                    all(
                        len(line) <= width or line.strip() == str(DATABASE)
                        for line in narrow.splitlines()
                    )
                )
                self.assertIn("Downloaded:", narrow)
                self.assertNotIn("Downloaded     Reused", narrow)

    def test_show_urls_and_commit_hashes_stay_complete_even_in_narrow_output(self):
        urls = [
            "https://example.invalid/" + label + "/" + "a" * 80
            for label in ("bug", "c", "repo", "commit", "report")
        ]
        bug = {
            "title": "KASAN: use-after-free in a_function",
            "key": "extid-alpha",
            "bug_type": "kasan",
            "status": "fixed",
            "subsystems": ["net"],
            "bug_url": urls[0],
            "c_reproducer_status": "available",
            "c_reproducer_urls": [urls[1]],
            "fixes": [
                {
                    "title": "Repair",
                    "repo": urls[2],
                    "hash": "b" * 40,
                    "link": urls[3],
                    "patch_available": True,
                }
            ],
            "report": {"available": True, "size": 100, "source_url": urls[4]},
        }
        for width in (24, 40, 96):
            with self.subTest(width=width):
                output = self.render(display.human_bug, bug, False, width=width)
                for url in urls:
                    self.assertIn(url, [line.strip() for line in output.splitlines()])
                self.assertIn("b" * 40, output)

    def test_long_subsystem_tags_use_records_instead_of_overflowing_table_columns(self):
        rows = [
            {
                "key": "extid-alpha",
                "title": "Warning in alpha",
                "subsystems": ["a_very_long_subsystem_tag"],
            }
        ]
        output = self.render(display.human_list, rows, width=110)
        self.assertIn("1. Warning in alpha", output)
        self.assertIn("a_very_long_subsystem_tag", output)
        self.assertNotIn("SUBSYSTEMS", output)

    def test_status_dates_and_migration_steps_are_explicit(self):
        output = " ".join(self.render(display.human_status, self.status()).split())
        self.assertIn("Finished: 2026-09-07 10:00:00 UTC", output)
        self.assertIn("Last checked: 2026-09-07 12:00:00 UTC", output)
        upgraded = self.render(display.human_migrate, self.status(), DATABASE, prior_schema=4)
        self.assertIn("schema 4 -> 5", upgraded)
        self.assertIn("Counts include all retained history.", upgraded)
        current = self.render(display.human_migrate, self.status(), DATABASE, prior_schema=5)
        self.assertIn("already current", current)

    def test_root_help_styles_filter_like_other_commands(self):
        parser = HelpParser(prog="ss")
        parser.add_subparsers().add_parser("filter", help="Find matching fixed bugs")
        output = self.render(parser.print_help, tty=True)
        self.assertIn("\x1b[36mfilter\x1b[0m", output)

    def test_link_fields_escape_source_controls_before_coloring(self):
        output = self.render(
            display.fields,
            [("URL", "https://example.invalid/" + "x" * 70 + "\x1b[2J\nnext")],
            tty=True,
            width=40,
        )
        self.assertNotIn("\x1b[2J", output)
        self.assertIn(r"\x1b[2J\x0anext", output)

    def test_diagnostic_titles_have_consistent_color_across_show_list_and_filter(self):
        bug = {
            "key": "extid-alpha",
            "title": "BUG: KASAN: use-after-free in alpha",
            "subsystems": ["net"],
            "bug_type": "kasan",
        }
        filtering = {
            "bugs": [bug],
            "total": 1,
            "offset": 0,
            "bug_types": [],
            "subsystems": [],
        }
        for width in (40, 96):
            for function, args in (
                (display.human_bug, (bug, False)),
                (display.human_list, ([bug],)),
                (display.human_filter, (filtering,)),
            ):
                with self.subTest(command=function.__name__, width=width):
                    plain = self.render(function, *args, width=width)
                    colored = self.render(function, *args, tty=True, width=width)
                    self.assertIn("\x1b[1;35mBUG: KASAN:\x1b[0m", colored)
                    self.assertEqual(ANSI.sub("", colored), plain)
                    self.assertIn(bug["title"], " ".join(plain.split()))

    def test_links_and_dates_use_bright_terminal_blue(self):
        output = self.render(
            display.fields,
            [("URL", "https://example.invalid/"), ("Finished", "2026-09-07 12:00:00 UTC")],
            tty=True,
        )
        self.assertIn("\x1b[4;94mhttps://example.invalid/", output)
        self.assertIn("\x1b[94m2026-09-07 12:00:00 UTC", output)


if __name__ == "__main__":
    unittest.main()
