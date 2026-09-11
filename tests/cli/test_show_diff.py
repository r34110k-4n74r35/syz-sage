from __future__ import annotations

import contextlib
import io
import json
import unittest

from syz_sage.cli import main
from tests.cli.support import CliFixture, compact, invoke
from tests.support import ALPHA_HASH, BETA_HASH


class ShowDiffTests(CliFixture, unittest.TestCase):
    def show(self, *flags: str, key: str = "extid-alpha123") -> tuple[int, str, str]:
        return invoke(["--database", str(self.database), "show", key, *flags])

    def test_diff_adds_patch_body_and_diffstat_alongside_details_and_stack(self) -> None:
        self.import_fixture()
        code, stdout, stderr = self.show("--stack", "--diff")
        self.assertEqual(code, 0, stderr)
        self.assertEqual(stderr, "")
        for expected in (
            "Subsystems:",
            "https://syzkaller.appspot.com/bug?extid=alpha123",
            "Crash stack (1)",
            "alpha_read+0x10/0x20 net/alpha.c:42",
            "Diffstat",
            "net/alpha.c | +1 -0",
            "@@ -1,3 +1,4 @@",
            "+        return 0;",
        ):
            self.assertIn(expected, stdout if "return" in expected else compact(stdout))
        self.assertNotIn("\x1b", stdout)
        self.assertLess(stdout.index("Crash stack"), stdout.index("Diffstat"))
        for redundant in ("Fix patches (", "Saved patch", "Stored bytes:", "SHA-256:"):
            self.assertNotIn(redundant, stdout)
        self.assertEqual(stdout.count("Key:"), 1)
        self.assertEqual(stdout.count("Commit:"), 1)

    def test_json_combines_diff_stack_and_explanation_from_sqlite(self) -> None:
        self.import_fixture()
        patch = self.legacy / f"artifacts/patches/{ALPHA_HASH}.diff"
        text = patch.read_text()
        patch.unlink()  # The retained database body, not the mirror, is the evidence source.
        before = self.database.read_bytes()
        code, stdout, stderr = self.show("--diff", "--stack", "--explain", "--json")
        self.assertEqual(code, 0, stderr)
        bug = json.loads(stdout)
        self.assertEqual(len(bug["patches"]), 1)
        self.assertEqual(bug["patches"][0]["text"], text)
        self.assertEqual(
            bug["patches"][0]["diffstat"],
            {"files_changed": 1, "insertions": 1, "deletions": 0, "complete": True},
        )
        self.assertEqual(bug["patches"][0]["files"][0]["insertions"], 1)
        self.assertEqual(bug["crash_stack"][0]["function_name"], "alpha_read")
        self.assertNotIn("text", bug["report"])
        self.assertIn("explanation", bug)
        self.assertNotIn("patch", bug)
        self.assertNotIn("\x1b", stdout)
        self.assertEqual(self.database.read_bytes(), before)

    def test_diff_includes_multiple_commits_and_an_unresolved_fix(self) -> None:
        path = self.legacy / "raw/bugs/extid-alpha123.json"
        payload = json.loads(path.read_text())
        second = {
            **payload["fix-commits"][0],
            "title": "fs: repair beta reader",
            "hash": BETA_HASH,
            "link": "https://git.kernel.org/commit/?id=" + BETA_HASH,
        }
        payload["fix-commits"].extend([second, {"title": "Unresolved follow-up repair"}])
        path.write_text(json.dumps(payload))
        second_text = (
            f"From {BETA_HASH}\nSubject: [PATCH] fs: repair beta reader\n\n"
            "diff --git a/fs/beta.c b/fs/beta.c\n--- a/fs/beta.c\n+++ b/fs/beta.c\n"
            "@@ -1 +1 @@\n-old();\n+new();\n"
        )
        (self.legacy / f"artifacts/patches/{BETA_HASH}.diff").write_text(second_text)
        self.import_fixture()
        code, stdout, stderr = self.show("--diff", "--json")
        self.assertEqual(code, 0, stderr)
        patches = json.loads(stdout)["patches"]
        self.assertEqual([patch["commit_hash"] for patch in patches], [ALPHA_HASH, BETA_HASH, None])
        self.assertEqual(patches[1]["text"], second_text)
        self.assertFalse(patches[2]["available"])
        self.assertIsNone(patches[2]["text"])
        code, stdout, stderr = self.show("--diff")
        self.assertEqual(code, 0, stderr)
        self.assertEqual(stdout.count("\nDiffstat\n"), 2)
        self.assertNotIn("Saved patch", stdout)
        self.assertEqual(stdout.count("diff --git a/fs/beta.c b/fs/beta.c"), 1)
        self.assertIn("Unresolved follow-up repair", stdout)
        self.assertIn("No retained patch text", stdout)

    def test_missing_patch_is_reported_and_normal_show_does_not_add_patch_bodies(self) -> None:
        self.import_fixture()
        code, stdout, stderr = self.show("--diff", key="id-beta456")
        self.assertEqual(code, 0, stderr)
        self.assertIn("No retained patch text", stdout)
        self.assertNotIn("\nDiffstat\n", stdout)
        code, stdout, stderr = self.show("--json")
        self.assertEqual(code, 0, stderr)
        self.assertNotIn("patches", json.loads(stdout))
        self.assertNotIn("text", json.loads(stdout)["report"])
        code, stdout, stderr = self.show("--diff", key="extid-missing")
        self.assertEqual(code, 3)
        self.assertEqual(stdout, "")
        self.assertIn("Bug not found", stderr)

    def test_diff_option_conflicts_are_reported_before_opening_database(self) -> None:
        for flags, expected in (
            (["--diff", "--patch", ALPHA_HASH], "not allowed with argument"),
            (["--diff", "--file", "net/*"], "--file requires --patch HASH"),
        ):
            with self.subTest(flags=flags):
                error = io.StringIO()
                with contextlib.redirect_stderr(error), self.assertRaises(SystemExit) as raised:
                    main(["--database", str(self.database), "show", "extid-alpha123", *flags])
                self.assertEqual(raised.exception.code, 2)
                self.assertIn(expected, compact(error.getvalue()))
                self.assertFalse(self.database.exists())
