from __future__ import annotations

import contextlib
import io
import json
import os
import unittest
from unittest import mock

from syz_sage.cli.presentation.research import human_statistics
from syz_sage.database import Database
from syz_sage.database.research import statistics
from syz_sage.retrieval.client import SyzbotClient
from tests.cli.support import CliFixture, compact, invoke
from tests.support import ALPHA_HASH, BETA_HASH, tree_digests


class ResearchCommandTests(CliFixture, unittest.TestCase):
    def test_statistics_color_respects_no_color_and_escapes_source_labels(self) -> None:
        self.import_fixture()
        with Database(self.database, read_only=True) as database:
            result = statistics(database)
        result["counts"]["subsystems"] = [{"value": "\x1b[31mINJECTED", "count": 1}]
        for no_color in (False, True):
            stream = io.StringIO()
            environment = {"TERM": "xterm", "COLUMNS": "32"}
            if no_color:
                environment["NO_COLOR"] = "1"
            with (
                contextlib.redirect_stdout(stream),
                mock.patch.object(stream, "isatty", return_value=True),
                mock.patch.dict(os.environ, environment, clear=True),
            ):
                human_statistics(result)
            output = stream.getvalue()
            self.assertIn("\\x1b[31mINJECTED", output)
            self.assertNotIn("\x1b[31mINJECTED", output)
            self.assertEqual("\x1b[" not in output, no_color)

    def test_rich_filters_stats_and_related_compare_work_offline_without_writes(self) -> None:
        self.import_fixture()
        before = tree_digests(self.legacy)
        with mock.patch.object(SyzbotClient, "get", side_effect=AssertionError("offline")):
            for arguments in (
                [
                    "filter",
                    "--family",
                    "use-after-free",
                    "--access",
                    "read",
                    "--crash-file",
                    "net/*",
                    "--has-c-repro",
                ],
                ["filter", "--fix-file", "net/*", "--has-patch", "--max-fix-files", "1"],
                ["stats", "--type", "kasan"],
                ["related", "extid-alpha123"],
                ["compare", "extid-alpha123", "id-beta456"],
            ):
                with self.subTest(arguments=arguments):
                    code, output, stderr = invoke(
                        ["--database", str(self.database), *arguments, "--json"]
                    )
                    self.assertEqual(code, 0, stderr)
                    result = json.loads(output)
                    self.assertNotIn("\x1b", output)
                    self.assertEqual(stderr, "")
                    if arguments[0] == "filter":
                        self.assertEqual([bug["key"] for bug in result["bugs"]], ["extid-alpha123"])
                    if arguments[0] == "stats":
                        self.assertEqual(result["total_bugs"], 1)
        self.assertEqual(before, tree_digests(self.legacy))

    def test_patch_and_explanation_json_keep_evidence_and_do_not_include_unrequested_report(
        self,
    ) -> None:
        self.import_fixture()
        code, output, stderr = invoke(
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
        bug = json.loads(output)
        self.assertIn("+        return 0;", bug["patch"]["text"])
        self.assertEqual(bug["explanation"]["crash"]["family"]["value"], "use-after-free")
        self.assertTrue(bug["explanation"]["crash"]["operation"]["report_lines"])
        self.assertNotIn("text", bug["report"])
        code, _, stderr = invoke(
            ["--database", str(self.database), "show", "extid-alpha123", "--patch", BETA_HASH]
        )
        self.assertEqual(code, 1)
        self.assertTrue(stderr)

    def test_human_commands_display_results_without_ansi_in_pipes(self) -> None:
        self.import_fixture()
        for arguments, expected in (
            (["stats", "--type", "kasan"], "Selected bugs: 1"),
            (["related", "extid-alpha123"], "Related bugs"),
            (["compare", "extid-alpha123", "id-beta456"], "Compare fixed bugs"),
            (["show", "extid-alpha123", "--patch", ALPHA_HASH], "return 0;"),
            (["show", "extid-alpha123", "--explain"], "use-after-free"),
        ):
            with self.subTest(arguments=arguments):
                code, output, stderr = invoke(["--database", str(self.database), *arguments])
                self.assertEqual(code, 0, stderr)
                self.assertIn(expected, compact(output))
                self.assertNotIn("\x1b", output)

    def test_fetch_uses_selected_saved_crash_and_keeps_database_unchanged(self) -> None:
        self.import_fixture()
        data_root = self.root / "selected"
        before = self.database.read_bytes()
        with mock.patch.object(
            SyzbotClient, "get", return_value=b"int main(void) { return 0; }\n"
        ) as fetch:
            code, output, stderr = invoke(
                [
                    "--data-dir",
                    str(data_root),
                    "--database",
                    str(self.database),
                    "fetch",
                    "extid-alpha123",
                    "--c-repro",
                    "--crash",
                    "0",
                    "--json",
                ]
            )
            self.assertEqual(code, 0, stderr)
            result = json.loads(output)
            self.assertTrue(result["ok"])
            self.assertEqual(result["downloaded"], 1)
            self.assertEqual(result["crash"]["ordinal"], 0)
            self.assertEqual(fetch.call_count, 1)
            code, output, stderr = invoke(
                [
                    "--data-dir",
                    str(data_root),
                    "--database",
                    str(self.database),
                    "fetch",
                    "extid-alpha123",
                    "--c-repro",
                    "--quiet",
                ]
            )
            self.assertEqual(code, 0, stderr)
            self.assertEqual(stderr, "")
            self.assertIn("Reused: 1", compact(output))
            self.assertEqual(fetch.call_count, 1)
        self.assertEqual(before, self.database.read_bytes())
        with Database(self.database, read_only=True) as database:
            self.assertTrue(database.health_check()["ok"])

    def test_new_options_validate_before_creating_output(self) -> None:
        for arguments in (
            ["filter", "--list-values", "--family", "unknown"],
            ["filter", "--list-values", "--no-c-repro"],
            ["filter", "--max-patch-lines", "-1"],
            ["stats", "--top", "0"],
            ["show", "extid-alpha123", "--file", "net/*"],
            ["fetch", "extid-alpha123"],
            ["fetch", "extid-alpha123", "--c-repro", "--crash", "-1"],
        ):
            with self.subTest(arguments=arguments):
                with self.assertRaises(SystemExit) as error:
                    invoke(["--data-dir", str(self.root / "absent"), *arguments])
                self.assertEqual(error.exception.code, 2)
                self.assertFalse((self.root / "absent").exists())


if __name__ == "__main__":
    unittest.main()
