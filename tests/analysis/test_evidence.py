from __future__ import annotations

import copy
import unittest

from syz_sage.analysis.evidence import build_explanation, location_relationship


def bug_fixture():
    report = (
        "BUG: KASAN: use-after-free in alpha\n"
        "Read of size 8 at addr deadbeef by task syz/123\n"
        "Call Trace:\n alpha+0x1/0x2 net/alpha.c:42\n"
        "Freed by task 1:\n release+0x1/0x2 mm/free.c:8\n"
    )
    return {
        "key": "extid-alpha",
        "title": "KASAN: use-after-free in alpha",
        "bug_url": "https://syzkaller.appspot.com/bug?extid=alpha",
        "report": {"available": True, "text": report, "sha256": "d" * 64},
        "crash_locations": [
            {
                "file_path": "net/alpha.c",
                "function_name": "alpha",
                "line_number": 42,
                "role": "primary",
                "confidence": "high",
                "method": "title-matched frame",
                "evidence": " alpha+0x1/0x2 net/alpha.c:42",
                "kernel_source_commit": "c" * 40,
            }
        ],
        "fixes": [{"commit_hash": "a" * 40, "title": "Repair alpha", "patch_available": True}],
        "fix_locations": [
            {
                "commit_hash": "a" * 40,
                "old_file_path": "net/alpha.c",
                "new_file_path": "net/alpha.c",
                "old_start": 900,
                "old_count": 1,
                "new_start": 920,
                "new_count": 1,
                "function_name": "alpha",
                "hunk_header": "@@ -900 +920 @@ int alpha(void)",
                "function_basis": "inferred from hunk heading",
                "kind": "text",
            }
        ],
        "crash_stack": [
            {
                "section": "manifestation",
                "function_name": "alpha",
                "file_path": "net/alpha.c",
                "line_number": 42,
                "report_line": 4,
                "raw_line": " alpha+0x1/0x2 net/alpha.c:42",
            }
        ],
    }


class ExplanationTests(unittest.TestCase):
    def test_relationship_requires_paths_and_does_not_compare_line_numbers(self):
        bug = bug_fixture()
        crash, fix = bug["crash_locations"][0], bug["fix_locations"][0]
        self.assertEqual(location_relationship(crash, fix), "same-function")
        self.assertEqual(
            location_relationship(crash, {**fix, "function_name": "other"}), "same-file"
        )
        self.assertEqual(location_relationship(crash, {**fix, "function_name": None}), "same-file")
        self.assertEqual(
            location_relationship({**crash, "file_path": "other.c"}, fix), "different-file"
        )
        self.assertEqual(location_relationship({**crash, "file_path": None}, fix), "unknown")
        self.assertEqual(location_relationship(crash, {"function_name": "alpha"}), "unknown")
        self.assertEqual(
            location_relationship(crash, {**fix, "old_file_path": "old.c"}), "same-function"
        )

    def test_explanation_retains_operation_report_lines_and_original_evidence(self):
        bug = bug_fixture()
        before = copy.deepcopy(bug)
        value = build_explanation(bug)
        self.assertEqual(bug, before)
        operation = value["crash"]["operation"]
        self.assertEqual(operation["value"], "read")
        self.assertEqual(operation["report_lines"][0]["report_line"], 2)
        self.assertIn("size 8", operation["report_lines"][0]["text"])
        self.assertEqual(operation["source_sha256"], "d" * 64)
        self.assertEqual(value["crash"]["locations"][0]["report_lines"][0]["report_line"], 4)
        hunk = value["fixes"][0]["hunks"][0]
        self.assertEqual(hunk["relationship"], "same-function")
        self.assertEqual(hunk["function_basis"], "inferred from hunk heading")
        comparison = hunk["comparisons"][0]
        self.assertEqual(comparison["confidence"], "inferred")
        self.assertEqual(comparison["crash_location"]["confidence"], "high")
        self.assertIn("not establish causation", " ".join(value["limitations"]))
        self.assertIn("are not compared", " ".join(value["limitations"]))

    def test_each_hunk_has_its_own_relationship_and_edit_blocks_are_grouped(self):
        bug = bug_fixture()
        first = bug["fix_locations"][0]
        bug["fix_locations"] += [
            {**first, "old_start": 903, "new_start": 923},
            {
                **first,
                "old_file_path": "mm/other.c",
                "new_file_path": "mm/other.c",
                "hunk_header": "@@ -1 +1 @@",
            },
            {**first, "old_file_path": None, "new_file_path": None, "hunk_header": ""},
            {**first, "repo": "duplicate reference"},
        ]
        hunks = build_explanation(bug)["fixes"][0]["hunks"]
        self.assertEqual(
            [hunk["relationship"] for hunk in hunks], ["same-function", "different-file", "unknown"]
        )
        self.assertEqual(len(hunks[0]["locations"]), 2)
        self.assertEqual(len(hunks[0]["comparisons"]), 1)

    def test_stack_membership_excludes_auxiliary_stacks_and_other_files(self):
        bug = bug_fixture()
        frame = bug["crash_stack"][0]
        bug["crash_stack"] += [
            {**frame, "section": section}
            for section in (
                "allocation",
                "free",
                "origin",
                "other-task",
                "unwind",
                "conflicting-access",
            )
        ] + [{**frame, "file_path": "unrelated.c"}]
        matches = build_explanation(bug)["fixes"][0]["hunks"][0]["manifestation_stack_matches"]
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["frame"], frame)
        self.assertEqual(matches[0]["method"], "same file and function name")

    def test_symbol_only_stack_match_is_explicitly_low_confidence(self):
        bug = bug_fixture()
        bug["crash_stack"][0]["file_path"] = None
        match = build_explanation(bug)["fixes"][0]["hunks"][0]["manifestation_stack_matches"][0]
        self.assertEqual(match["confidence"], "low")
        self.assertIn("function name only", match["method"])

    def test_missing_evidence_remains_unknown_and_unresolved_fixes_are_retained(self):
        value = build_explanation({"title": "warning", "fixes": [{"title": "unresolved"}]})
        self.assertEqual(value["crash"]["operation"]["value"], "unknown")
        self.assertEqual(value["crash"]["locations"], [])
        self.assertFalse(value["fixes"][0]["patch_available"])
        self.assertIsNone(value["fixes"][0]["commit_hash"])
        self.assertEqual(value["fixes"][0]["hunks"], [])

    def test_access_evidence_does_not_borrow_from_auxiliary_report(self):
        bug = bug_fixture()
        bug["report"]["text"] = (
            "BUG: KASAN: use-after-free\nFreed by task 1:\nWrite of size 8 at addr 0\n"
        )
        self.assertEqual(build_explanation(bug)["crash"]["operation"]["value"], "unknown")

    def test_saved_characteristics_remain_usable_without_report_text(self):
        bug = bug_fixture()
        bug["report"]["text"] = None
        bug["characteristics"] = {
            "access_mode": {
                "value": "write",
                "method": "explicit access diagnostic",
                "evidence": "Write of size 8",
                "source": "report",
                "source_sha256": "e" * 64,
            }
        }
        operation = build_explanation(bug)["crash"]["operation"]
        self.assertEqual(operation["value"], "write")
        self.assertEqual(operation["source_sha256"], "e" * 64)
        self.assertEqual(operation["report_lines"], [])
