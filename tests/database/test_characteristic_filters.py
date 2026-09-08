from __future__ import annotations

import json
import unittest
from unittest import mock

from syz_sage.database import Database
from tests.database.support import DatabaseFixture
from tests.support import ALPHA_HASH


class CharacteristicFilterTests(DatabaseFixture, unittest.TestCase):
    def keys(self, result: dict) -> list[str]:
        return [row["key"] for row in result["bugs"]]

    def test_family_access_and_evidence_are_queryable_and_keep_diagnostic_type(self) -> None:
        with Database(self.database_path) as database:
            self.import_fixture(database)
            bug = database.get_bug("extid-alpha123")
            self.assertEqual(
                (bug["bug_type"], bug["family"], bug["access_mode"]),
                ("kasan", "use-after-free", "read"),
            )
            self.assertEqual(
                bug["characteristics"]["family"]["source_sha256"], bug["report"]["sha256"]
            )
            self.assertEqual(
                self.keys(
                    database.filter_bugs(
                        families=[" USE-AFTER-FREE "], access_modes=["READ"], subsystems=[]
                    )
                ),
                ["extid-alpha123"],
            )
            self.assertEqual(self.keys(database.filter_bugs(families=["unknown"])), ["id-beta456"])
            values = database.filter_values()
            self.assertIn({"value": "use-after-free", "count": 1}, values["families"])
            self.assertIn({"value": "unknown", "count": 1}, values["access_modes"])

    def test_location_patterns_are_case_sensitive_fnmatch_and_categories_intersect(self) -> None:
        with Database(self.database_path) as database:
            self.import_fixture(database)
            result = database.filter_bugs(
                crash_files=["wrong/*", "net/[!b]*.c"],
                fix_files=["net/*.c"],
                crash_functions=["alpha_?ead"],
                fix_functions=["alpha*"],
                families=["use-after-free"],
            )
            self.assertEqual(self.keys(result), ["extid-alpha123"])
            self.assertEqual(database.filter_bugs(crash_files=["Net/*"])["total"], 0)
            self.assertEqual(database.filter_bugs(fix_functions=["ALPHA*"])["total"], 0)
            self.assertEqual(database.filter_bugs(crash_files=["%' OR 1=1 --"])["total"], 0)

    def test_availability_and_patch_size_filters_preserve_unknown(self) -> None:
        with Database(self.database_path) as database:
            self.import_fixture(database)
            alpha = database.filter_bugs(
                has_c_repro=True,
                has_report=True,
                has_patch=True,
                max_fix_files=1,
                max_patch_lines=1,
            )
            self.assertEqual(self.keys(alpha), ["extid-alpha123"])
            self.assertEqual(
                (alpha["bugs"][0]["fix_file_count"], alpha["bugs"][0]["patch_line_count"]), (1, 1)
            )
            shown = database.get_bug("extid-alpha123")
            for key in ("has_patch", "fix_file_count", "patch_line_count", "patch_urls"):
                self.assertEqual(shown[key], alpha["bugs"][0][key])
            self.assertEqual(
                self.keys(
                    database.filter_bugs(has_c_repro=False, has_report=False, has_patch=False)
                ),
                ["id-beta456"],
            )
            self.assertEqual(database.filter_bugs(max_patch_lines=0)["total"], 0)
            beta = database.get_bug("id-beta456")
            self.assertIsNone(beta["fix_file_count"])
            self.assertIsNone(beta["patch_line_count"])

    def test_unknown_reproducer_is_not_a_negative_availability_claim(self) -> None:
        path = self.legacy / "raw/bugs/id-beta456.json"
        raw = json.loads(path.read_bytes())
        raw.pop("crashes")
        path.write_text(json.dumps(raw))
        with Database(self.database_path) as database:
            self.import_fixture(database)
            self.assertEqual(database.filter_bugs(has_c_repro=False)["total"], 0)
            self.assertEqual(database.get_bug("id-beta456")["c_reproducer_status"], "unknown")

    def test_binary_patch_does_not_pretend_to_have_zero_changed_lines(self) -> None:
        patch = self.legacy / "artifacts/patches" / f"{ALPHA_HASH}.diff"
        patch.write_bytes(
            b"diff --git a/net/a.bin b/net/a.bin\nBinary files a/net/a.bin and b/net/a.bin differ\n"
        )
        with Database(self.database_path) as database:
            self.import_fixture(database)
            alpha = database.get_bug("extid-alpha123")
            self.assertTrue(alpha["has_patch"])
            self.assertIsNone(alpha["patch_line_count"])
            self.assertEqual(database.filter_bugs(max_patch_lines=100)["total"], 0)

    def test_patch_metrics_deduplicate_references_commits_and_changed_paths(self) -> None:
        second_hash = "e" * 40
        path = self.legacy / "raw/bugs/extid-alpha123.json"
        raw = json.loads(path.read_bytes())
        second = {**raw["fix-commits"][0], "hash": second_hash, "title": "net: further fix"}
        second["link"] = second["link"].replace(ALPHA_HASH, second_hash)
        raw["fix-commits"].extend([second, second])
        path.write_text(json.dumps(raw))
        patch = self.legacy / "artifacts/patches" / f"{second_hash}.diff"
        patch.write_text(
            "diff --git a/net/alpha.c b/net/alpha.c\n--- a/net/alpha.c\n+++ b/net/alpha.c\n"
            "@@ -4 +4 @@ int alpha_read(void)\n- return 0;\n+ return 1;\n"
        )
        with Database(self.database_path) as database:
            self.assertEqual(self.import_fixture(database)["status"], "completed")
            bug = database.get_bug("extid-alpha123")
            self.assertEqual((bug["fix_file_count"], bug["patch_line_count"]), (1, 3))
            self.assertEqual(database.filter_bugs(max_patch_lines=2)["total"], 0)
            self.assertEqual(database.filter_bugs(max_fix_files=1)["total"], 1)

    def test_malformed_later_hunks_and_extra_edits_do_not_look_like_small_patches(self) -> None:
        patch = self.legacy / "artifacts/patches" / f"{ALPHA_HASH}.diff"
        original = patch.read_text()
        with Database(self.database_path) as database:
            for extra in ("@@ broken header @@\n+extra\n", "+extra\n", "@@ -6 +7,2 @@\n x\n"):
                with self.subTest(extra=extra):
                    patch.write_text(original + extra)
                    self.assertEqual(database.ingest_files(self.legacy)["status"], "completed")
                    bug = database.get_bug("extid-alpha123")
                    self.assertTrue(bug["has_patch"])
                    self.assertIsNone(bug["fix_file_count"])
                    self.assertIsNone(bug["patch_line_count"])

    def test_mode_only_changes_and_pure_renames_have_zero_text_lines(self) -> None:
        patch = self.legacy / "artifacts/patches" / f"{ALPHA_HASH}.diff"
        with Database(self.database_path) as database:
            for content in (
                "diff --git a/net/alpha.c b/net/alpha.c\nold mode 100644\nnew mode 100755\n",
                "diff --git a/net/alpha.c b/net/new.c\nsimilarity index 100%\n"
                "rename from net/alpha.c\nrename to net/new.c\n",
            ):
                with self.subTest(content=content):
                    patch.write_text(content)
                    self.assertEqual(database.ingest_files(self.legacy)["status"], "completed")
                    bug = database.get_bug("extid-alpha123")
                    self.assertEqual((bug["fix_file_count"], bug["patch_line_count"]), (1, 0))

    def test_bare_file_header_does_not_establish_zero_line_patch(self) -> None:
        patch = self.legacy / "artifacts/patches" / f"{ALPHA_HASH}.diff"
        patch.write_text("diff --git a/net/alpha.c b/net/alpha.c\nindex 1111111..2222222 100644\n")
        with Database(self.database_path) as database:
            self.assertEqual(database.ingest_files(self.legacy)["status"], "completed")
            bug = database.get_bug("extid-alpha123")
            self.assertTrue(bug["has_patch"])
            self.assertIsNone(bug["patch_line_count"])

    def test_additional_unresolved_fix_prevents_complete_patch_size_claim(self) -> None:
        path = self.legacy / "raw/bugs/extid-alpha123.json"
        raw = json.loads(path.read_bytes())
        raw["fix-commits"].append({"title": "net: separate unresolved fix"})
        path.write_text(json.dumps(raw))
        with Database(self.database_path) as database:
            self.assertEqual(self.import_fixture(database)["status"], "completed")
            bug = database.get_bug("extid-alpha123")
            self.assertTrue(bug["has_patch"])
            self.assertIsNone(bug["fix_file_count"])
            self.assertIsNone(bug["patch_line_count"])
            self.assertEqual(database.filter_bugs(max_fix_files=100)["total"], 0)

    def test_title_only_duplicate_of_known_fix_does_not_invalidate_size(self) -> None:
        path = self.legacy / "raw/bugs/extid-alpha123.json"
        raw = json.loads(path.read_bytes())
        raw["fix-commits"][0].pop("hash")
        raw["fix-commits"][0].pop("link")
        path.write_text(json.dumps(raw))
        with Database(self.database_path) as database:
            self.assertEqual(self.import_fixture(database)["status"], "completed")
            bug = database.get_bug("extid-alpha123")
            self.assertEqual((bug["fix_file_count"], bug["patch_line_count"]), (1, 1))

    def test_partial_characteristics_do_not_replace_active_classification(self) -> None:
        with Database(self.database_path) as database:
            self.import_fixture(database)
            before = database.get_bug("extid-alpha123")["characteristics"]
            report = self.legacy / "artifacts/reports/extid-alpha123.txt"
            report.write_text(
                "BUG: KASAN: out-of-bounds in alpha\nWrite of size 4 at addr 0xffff\n"
            )
            self.assertEqual(
                database.ingest_files(self.legacy, errors=["incomplete"])["status"], "partial"
            )
            self.assertEqual(database.get_bug("extid-alpha123")["characteristics"], before)
            self.assertEqual(database.ingest_files(self.legacy)["status"], "completed")
            self.assertEqual(database.get_bug("extid-alpha123")["family"], "out-of-bounds")

    def test_research_selection_batches_evidence_without_loading_reports(self) -> None:
        with Database(self.database_path) as database:
            self.import_fixture(database)
            statements = []
            database.connection.set_trace_callback(statements.append)
            with mock.patch.object(
                database, "_load_json_blob", side_effect=AssertionError("per-bug blob read")
            ):
                rows = database.research_rows()
            database.connection.set_trace_callback(None)
            self.assertEqual(len(rows), 2)
            self.assertEqual(rows[0]["fixes"][0]["hash"], ALPHA_HASH)
            self.assertEqual(rows[0]["crash_locations"][0]["file_path"], "net/alpha.c")
            self.assertTrue(rows[0]["fix_locations"])
            self.assertNotIn("report", rows[0])
            self.assertFalse(any("SELECT content FROM blobs" in query for query in statements))

    def test_invalid_filter_arguments_are_rejected(self) -> None:
        with Database(self.database_path) as database:
            for criteria in (
                {"families": ["kasan"]},
                {"access_modes": ["execute"]},
                {"crash_files": "net/*"},
                {"fix_functions": ["\x1b"]},
                {"has_patch": 1},
                {"max_patch_lines": -1},
                {"max_fix_files": True},
            ):
                with self.subTest(criteria=criteria), self.assertRaises(ValueError):
                    database.filter_bugs(**criteria)


if __name__ == "__main__":
    unittest.main()
