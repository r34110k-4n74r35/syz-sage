from __future__ import annotations

import hashlib
import json
import shutil
import unittest
from pathlib import Path

from syz_sage.database import Database
from syz_sage.database.evidence import _patch_files, patch_view, patch_views
from syz_sage.project.storage import temporary_directory
from tests.support import ALPHA_HASH, BETA_HASH, FIXTURES, GAMMA_HASH

EXTRA_FILES = """
diff --git a/fs/beta.c b/fs/beta.c
--- a/fs/beta.c
+++ b/fs/beta.c
@@ -20 +20 @@ void beta(void)
-old();
+new();
diff --git a/old name.c b/new name.c
similarity index 100%
rename from old name.c
rename to new name.c
diff --git a/blob.bin b/blob.bin
index 1234..5678 100644
Binary files a/blob.bin and b/blob.bin differ
"""


class PatchEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = temporary_directory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.data = self.root / "data"
        shutil.copytree(FIXTURES, self.data)
        self.patch = self.data / f"artifacts/patches/{ALPHA_HASH}.diff"
        self.path = self.root / "database.sqlite3"

    def import_fixture(self):
        with Database(self.path) as database:
            self.assertEqual(database.import_legacy(self.data)["status"], "completed")

    def test_patch_is_exact_saved_text_and_reads_do_not_modify_database(self):
        self.import_fixture()
        content = self.patch.read_bytes()
        before = self.path.read_bytes()
        with Database(self.path, read_only=True) as database:
            changes = database.connection.total_changes
            value = patch_view(database, "extid-alpha123", ALPHA_HASH.upper())
            self.assertEqual(database.connection.total_changes, changes)
        self.assertEqual(self.path.read_bytes(), before)
        self.assertTrue(value["available"])
        self.assertEqual(value["text"], content.decode())
        self.assertEqual(value["sha256"], hashlib.sha256(content).hexdigest())
        self.assertEqual(value["size"], len(content))
        self.assertEqual(value["commit_hash"], ALPHA_HASH)
        self.assertEqual(value["files"][0]["new_file_path"], "net/alpha.c")
        self.assertEqual(
            value["diffstat"],
            {"files_changed": 1, "insertions": 1, "deletions": 0, "complete": True},
        )
        hunk = value["files"][0]["hunks"][0]
        self.assertEqual(hunk["locations"][0]["function_name"], "alpha_read")
        self.assertEqual(hunk["locations"][0]["new_count"], 1)

    def test_commit_must_belong_to_the_selected_active_bug(self):
        self.import_fixture()
        with Database(self.path, read_only=True) as database:
            with self.assertRaisesRegex(ValueError, "not a recorded fix"):
                patch_view(database, "id-beta456", ALPHA_HASH)
            with self.assertRaisesRegex(ValueError, "not a recorded fix"):
                patch_view(database, "extid-alpha123", BETA_HASH)
            self.assertIsNone(patch_view(database, "extid-missing", ALPHA_HASH))

    def test_rejects_hash_prefix_and_blank_file_before_opening_database(self):
        database = Database(self.path, read_only=True)
        for commit in ("a" * 12, "g" * 40, "a" * 41):
            with self.subTest(commit=commit), self.assertRaisesRegex(ValueError, "full 40"):
                patch_view(database, "extid-alpha123", commit)
        for pattern in ("  ", "net/\nalpha.c"):
            with self.subTest(pattern=pattern), self.assertRaisesRegex(ValueError, "--file"):
                patch_view(database, "extid-alpha123", ALPHA_HASH, pattern)
        self.assertFalse(self.path.exists())

    def test_file_selection_keeps_preamble_and_full_selected_diff(self):
        self.patch.write_text(self.patch.read_text() + EXTRA_FILES)
        self.import_fixture()
        with Database(self.path, read_only=True) as database:
            value = patch_view(database, "extid-alpha123", ALPHA_HASH, "fs/*")
            self.assertEqual(value["total_files"], 4)
            self.assertEqual(len(value["files"]), 1)
            self.assertTrue(value["text"].startswith("From " + ALPHA_HASH))
            self.assertIn("@@ -20 +20 @@ void beta(void)", value["text"])
            self.assertNotIn("diff --git a/net/alpha.c", value["text"])
            self.assertEqual(value["files"][0]["hunks"][0]["locations"][0]["function_name"], "beta")
            self.assertEqual(
                value["diffstat"],
                {"files_changed": 1, "insertions": 1, "deletions": 1, "complete": True},
            )
            with self.assertRaisesRegex(ValueError, "no saved patch file matches"):
                patch_view(database, "extid-alpha123", ALPHA_HASH, "FS/*")
            for pattern in ("old name.c", "new name.c"):
                renamed = patch_view(database, "extid-alpha123", ALPHA_HASH, pattern)
                self.assertEqual(renamed["files"][0]["kind"], "rename")
                self.assertEqual(renamed["files"][0]["hunks"], [])
                self.assertEqual(
                    renamed["diffstat"],
                    {"files_changed": 1, "insertions": 0, "deletions": 0, "complete": True},
                )
            binary = patch_view(database, "extid-alpha123", ALPHA_HASH, "blob.bin")
            self.assertEqual(binary["files"][0]["kind"], "binary")
            self.assertIn("Binary files", binary["text"])
            self.assertEqual(
                binary["diffstat"],
                {"files_changed": 1, "insertions": None, "deletions": None, "complete": False},
            )
            full = patch_view(database, "extid-alpha123", ALPHA_HASH)
            self.assertEqual(full["diffstat"]["files_changed"], 4)
            self.assertFalse(full["diffstat"]["complete"])
            self.assertIsNone(full["diffstat"]["insertions"])

    def test_patch_follows_active_association_instead_of_latest_retained_patch(self):
        self.import_fixture()
        original = self.patch.read_text()
        self.patch.write_text(original.replace("return 0", "return 1"))
        with Database(self.path) as database:
            earlier = database.get_bug("extid-alpha123")["snapshot_id"]
            self.assertEqual(database.import_legacy(self.data)["status"], "completed")
            # Exercise a valid older association alongside newer retained bytes.
            database.connection.execute("UPDATE snapshots SET is_current=0")
            database.connection.execute("UPDATE snapshots SET is_current=1 WHERE id=?", (earlier,))
            database.connection.execute(
                "UPDATE app_state SET value=? WHERE key='active_snapshot_id'", (str(earlier),)
            )
        with Database(self.path, read_only=True) as database:
            value = patch_view(database, "extid-alpha123", ALPHA_HASH)
            self.assertEqual(value["text"], original)
            self.assertEqual(patch_views(database, "extid-alpha123")[0]["text"], original)
            latest = database.connection.execute(
                "SELECT b.content FROM patches p JOIN blobs b ON b.sha256=p.current_blob_sha256 "
                "WHERE p.commit_hash=?",
                (ALPHA_HASH,),
            ).fetchone()[0]
            self.assertIn(b"return 1", latest)

    def test_missing_retained_patch_returns_explicit_unavailable_metadata(self):
        self.import_fixture()
        with Database(self.path) as database:
            database.connection.execute(
                "DELETE FROM snapshot_patches WHERE commit_hash=?", (ALPHA_HASH,)
            )
        with Database(self.path, read_only=True) as database:
            value = patch_view(database, "extid-alpha123", ALPHA_HASH, "net/*")
            self.assertFalse(value["available"])
            self.assertIsNone(value["text"])
            self.assertEqual(value["files"], [])
            self.assertIsNone(value["diffstat"])
            self.assertEqual(value["fix"]["commit_hash"], ALPHA_HASH)

    def test_all_patches_keep_fix_order_deduplicate_hashes_and_include_unavailable(self):
        detail_path = self.data / "raw/bugs/extid-alpha123.json"
        detail = json.loads(detail_path.read_text())
        detail["fix-commits"].extend(
            [
                {"title": "Duplicate alpha", "hash": ALPHA_HASH},
                {"title": "Second fix", "hash": BETA_HASH},
                {"title": "Title-only fix"},
                {"title": "Missing saved fix", "hash": GAMMA_HASH},
            ]
        )
        detail_path.write_text(json.dumps(detail))
        original = self.patch.read_text()
        second_patch = self.patch.with_name(f"{BETA_HASH}.diff")
        second_patch.write_text(
            original.replace(ALPHA_HASH, BETA_HASH).replace("return 0", "return 1")
        )
        self.patch.with_name(f"{GAMMA_HASH}.diff").write_text(
            original.replace(ALPHA_HASH, GAMMA_HASH)
        )
        self.import_fixture()
        with Database(self.path) as database:
            database.connection.execute(
                "DELETE FROM snapshot_patches WHERE commit_hash=?", (GAMMA_HASH,)
            )
        # Retained snapshot bytes remain authoritative over later mirror edits.
        self.patch.write_text("corrupt mirror")
        second_patch.unlink()
        before = self.path.read_bytes()
        with Database(self.path, read_only=True) as database:
            values = patch_views(database, "extid-alpha123")
            self.assertEqual(
                [item["commit_hash"] for item in values], [ALPHA_HASH, BETA_HASH, None, GAMMA_HASH]
            )
            self.assertEqual([item["available"] for item in values], [True, True, False, False])
            self.assertEqual(values[0]["text"], original)
            self.assertIn("return 1", values[1]["text"])
            self.assertEqual(values[2]["fix"]["title"], "Title-only fix")
            for item in values[2:]:
                self.assertIsNone(item["text"])
                self.assertIsNone(item["diffstat"])
                self.assertEqual(item["files"], [])
            self.assertIsNone(patch_views(database, "extid-missing"))
            self.assertEqual(database.connection.total_changes, 0)
        self.assertEqual(self.path.read_bytes(), before)

    def test_all_patches_reject_invalid_retained_versions(self):
        self.import_fixture()
        with Database(self.path) as database:
            database.connection.execute(
                "UPDATE patch_versions SET is_valid=0 WHERE commit_hash=?", (ALPHA_HASH,)
            )
        with Database(self.path, read_only=True) as database:
            values = patch_views(database, "extid-alpha123")
            self.assertEqual(len(values), 1)
            self.assertFalse(values[0]["available"])
            self.assertIsNone(values[0]["text"])
            self.assertIsNone(values[0]["diffstat"])

    def test_plain_diff_does_not_split_header_like_removed_source(self):
        patch = """--- a/first.c
+++ b/first.c
@@ -1 +1 @@
--- a/source.c
+++ b/source.c
--- a/second.c
+++ b/second.c
@@ -10 +10 @@
-old
+new
"""
        preamble, files = _patch_files(patch)
        self.assertEqual(preamble, "")
        self.assertEqual(len(files), 2)
        self.assertEqual([item["new_file_path"] for item in files], ["first.c", "second.c"])
        self.assertEqual(
            [(item["insertions"], item["deletions"]) for item in files], [(1, 1), (1, 1)]
        )
        self.assertEqual(
            files[0]["hunks"][0]["text"], "@@ -1 +1 @@\n--- a/source.c\n+++ b/source.c\n"
        )

    def test_hunk_text_preserves_context_no_newline_marker_and_excludes_trailer(self):
        patch = """diff --git a/x.c b/x.c
--- a/x.c
+++ b/x.c
@@ -1 +1 @@ int x(void)
-old
+new
\\ No newline at end of file
@@ -20 +20 @@ int y(void)
-before
+after
--\x20
2.45
"""
        _, files = _patch_files(patch)
        self.assertEqual(len(files[0]["hunks"]), 2)
        self.assertTrue(files[0]["hunks"][0]["text"].endswith("\\ No newline at end of file\n"))
        self.assertNotIn("2.45", files[0]["hunks"][1]["text"])
        self.assertIn("2.45", files[0]["text"])

    def test_counts_exclude_context_headers_and_trailer_but_include_header_like_edits(self):
        patch = """From saved commit

diff --git a/x.c b/x.c
--- a/x.c
+++ b/x.c
@@ -1,4 +1,5 @@ int x(void)
 context
--- a/source.c
+++ b/source.c
-old
+new
+extra
 tail
--\x20
2.45
"""
        _, files = _patch_files(patch)
        self.assertEqual(len(files), 1)
        self.assertEqual(files[0]["insertions"], 3)
        self.assertEqual(files[0]["deletions"], 2)

    def test_incomplete_and_binary_sections_have_unknown_counts(self):
        for body in (
            "--- a/x.c\n+++ b/x.c\n@@ -1,2 +1,2 @@\n-old\n+new\n",
            "--- a/x.c\n+++ b/x.c\n@@ -1 +1 @@\n-old\n+new\n+extra\n",
            "--- a/x.c\n+++ b/x.c\n@@ invalid @@\n-old\n+new\n",
            "Binary files a/x.c and b/x.c differ\n",
            "index 1234..5678 100644\n",
        ):
            with self.subTest(body=body):
                _, files = _patch_files("diff --git a/x.c b/x.c\n" + body)
                self.assertIsNone(files[0]["insertions"])
                self.assertIsNone(files[0]["deletions"])

    def test_mode_only_sections_have_known_zero_counts(self):
        _, files = _patch_files("diff --git a/x.c b/x.c\nold mode 100644\nnew mode 100755\n")
        self.assertEqual(files[0]["insertions"], 0)
        self.assertEqual(files[0]["deletions"], 0)
