from __future__ import annotations

import json
import unittest

from tests.cli.support import CliFixture, compact, invoke


class CliQueriesTests(CliFixture, unittest.TestCase):
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
