from __future__ import annotations

import hashlib
import shutil
import unittest
from pathlib import Path

from syz_sage.database import Database
from syz_sage.database.evidence import _patch_files, patch_view
from syz_sage.project.storage import temporary_directory
from tests.support import ALPHA_HASH, BETA_HASH, FIXTURES

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
            with self.assertRaisesRegex(ValueError, "no saved patch file matches"):
                patch_view(database, "extid-alpha123", ALPHA_HASH, "FS/*")
            for pattern in ("old name.c", "new name.c"):
                renamed = patch_view(database, "extid-alpha123", ALPHA_HASH, pattern)
                self.assertEqual(renamed["files"][0]["kind"], "rename")
                self.assertEqual(renamed["files"][0]["hunks"], [])
            binary = patch_view(database, "extid-alpha123", ALPHA_HASH, "blob.bin")
            self.assertEqual(binary["files"][0]["kind"], "binary")
            self.assertIn("Binary files", binary["text"])

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
            self.assertEqual(value["fix"]["commit_hash"], ALPHA_HASH)

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
