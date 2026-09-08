from __future__ import annotations

import json
import unittest

from syz_sage.database import Database
from syz_sage.database.research import compare_bugs, related_bugs, statistics
from tests.database.support import DatabaseFixture
from tests.support import ALPHA_HASH


class ResearchTests(DatabaseFixture, unittest.TestCase):
    def share_alpha_fix(self) -> None:
        listing_path = self.legacy / "raw/upstream_fixed.json"
        listing = json.loads(listing_path.read_bytes())
        alpha_fix = listing["Bugs"][0]["fix-commits"][0]
        listing["Bugs"][1].setdefault("fix-commits", []).append(alpha_fix)
        listing_path.write_text(json.dumps(listing))
        catalog_path = self.legacy / "processed/catalog.json"
        catalog = json.loads(catalog_path.read_bytes())
        catalog["bugs"][1].setdefault("fix_commits", []).append(alpha_fix)
        catalog_path.write_text(json.dumps(catalog))
        detail_path = self.legacy / "raw/bugs/id-beta456.json"
        detail = json.loads(detail_path.read_bytes())
        detail["fix-commits"].append(alpha_fix)
        detail_path.write_text(json.dumps(detail))

    def test_stats_distinguish_bugs_commits_and_links_and_count_each_path_once_per_bug(
        self,
    ) -> None:
        self.share_alpha_fix()
        with Database(self.database_path) as database:
            self.assertEqual(self.import_fixture(database)["status"], "completed")
        with Database(self.database_path, read_only=True) as database:
            result = statistics(database)
            self.assertEqual(result["total_bugs"], 2)
            self.assertEqual(result["distinct_fix_commits"], 1)
            self.assertEqual(result["bug_commit_links"], 2)
            self.assertEqual(result["availability"]["report_available"], 1)
            self.assertIn(
                {"value": "available", "count": 1}, result["availability"]["c_reproducer"]
            )
            self.assertIn({"value": "net/alpha.c", "count": 2}, result["counts"]["fix_files"])
            selected = statistics(database, families=["use-after-free"], has_c_repro=True)
            self.assertEqual(selected["total_bugs"], 1)
            self.assertEqual(selected["distinct_fix_commits"], 1)
            self.assertEqual(database.connection.total_changes, 0)

    def test_related_excludes_self_and_explains_shared_commit_without_merging_bugs(self) -> None:
        self.share_alpha_fix()
        with Database(self.database_path) as database:
            self.import_fixture(database)
            result = related_bugs(database, "extid-alpha123", limit=1)
            self.assertEqual(result["total"], 1)
            match = result["matches"][0]
            self.assertEqual(match["bug"]["key"], "id-beta456")
            self.assertIn({"kind": "same-fix-commit", "values": [ALPHA_HASH]}, match["reasons"])
            compared = compare_bugs(database, "extid-alpha123", "id-beta456")
            self.assertEqual(compared["shared_evidence"], match["reasons"])
            self.assertTrue(any(item["field"] == "bug_type" for item in compared["differences"]))
            self.assertNotIn("raw", compared["left"])
            self.assertNotIn("report", compared["left"])

    def test_empty_selection_has_explicit_unknown_size_and_zero_denominators(self) -> None:
        with Database(self.database_path) as database:
            self.import_fixture(database)
            result = statistics(database, families=["deadlock"])
            self.assertEqual(result["total_bugs"], 0)
            self.assertEqual(result["bug_commit_links"], 0)
            self.assertEqual(result["distinct_fix_commits"], 0)
            self.assertIsNone(result["fix_size"]["files_per_bug"]["median"])
            self.assertEqual(result["counts"]["families"], [])

    def test_missing_identifiers_and_pagination_errors_do_not_silently_return_empty_results(
        self,
    ) -> None:
        with Database(self.database_path) as database:
            self.import_fixture(database)
            with self.assertRaises(LookupError):
                related_bugs(database, "extid-absent")
            with self.assertRaises(LookupError):
                compare_bugs(database, "extid-alpha123", "extid-absent")
            with self.assertRaises(ValueError):
                compare_bugs(database, "extid-alpha123", "extid-alpha123")
            with self.assertRaises(ValueError):
                related_bugs(database, "extid-alpha123", limit=0)
            with self.assertRaises(ValueError):
                statistics(database, limit=1)


if __name__ == "__main__":
    unittest.main()
