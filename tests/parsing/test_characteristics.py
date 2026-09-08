from __future__ import annotations

import unittest

from syz_sage.parsing.characteristics import ACCESS_MODES, BUG_FAMILIES, classify_characteristics


class CharacteristicsTests(unittest.TestCase):
    def test_explicit_families_are_independent_of_diagnostic_labels(self) -> None:
        for title, family in (
            ("KASAN: slab-use-after-free Read in foo", "use-after-free"),
            ("KFENCE: out-of-bounds write in foo", "out-of-bounds"),
            ("KMSAN: uninit-value in foo", "uninitialized-value"),
            (
                "BUG: unable to handle kernel NULL pointer dereference at 00000000",
                "null-dereference",
            ),
            ("UBSAN: shift-out-of-bounds in foo", "shift-out-of-bounds"),
            ("UBSAN: signed-integer-overflow in foo", "integer-overflow"),
            ("WARNING: possible circular locking dependency detected", "deadlock"),
            ("INFO: task hung in foo", "hang"),
            ("BUG: memory leak", "memory-leak"),
            ("KASAN: invalid-free in foo", "invalid-free"),
        ):
            with self.subTest(title=title):
                result = classify_characteristics(title)
                self.assertEqual(result.family.value, family)
                self.assertEqual(result.family.source, "title")
                self.assertEqual(result.family.evidence, title)

    def test_symbols_and_generic_diagnostics_do_not_establish_a_family_or_access(self) -> None:
        for title in (
            "WARNING in read",
            "KASAN: unknown-crash in use_after_free",
            "KMSAN: panic",
            "BUG: foo",
        ):
            with self.subTest(title=title):
                result = classify_characteristics(title)
                self.assertEqual(
                    (result.family.value, result.access_mode.value), ("unknown", "unknown")
                )

    def test_manifestation_report_takes_precedence_over_grouping_title(self) -> None:
        result = classify_characteristics(
            "KASAN: use-after-free Read in foo",
            "BUG: KASAN: slab-out-of-bounds in foo\nWrite of size 8 at addr deadbeef\n",
        )
        self.assertEqual(
            (result.family.value, result.access_mode.value), ("out-of-bounds", "write")
        )
        self.assertEqual(result.family.source, "report")
        self.assertEqual(result.access_mode.evidence, "Write of size 8 at addr deadbeef")

    def test_auxiliary_access_and_diagnostic_traces_do_not_supply_characteristics(self) -> None:
        for boundary in (
            "Freed by task 4:",
            "Uninit was stored to memory at:",
            "Backtrace of CPU 2:",
        ):
            result = classify_characteristics(
                "WARNING in foo",
                f"WARNING in foo\nCall Trace:\n foo+0x1/0x2\n{boundary}\n"
                "Read of size 8 at addr deadbeef\nBUG: KASAN: use-after-free in foo\n",
            )
            self.assertEqual(
                (result.family.value, result.access_mode.value), ("unknown", "unknown")
            )

    def test_kcsan_conflicting_accesses_retain_combined_mode(self) -> None:
        result = classify_characteristics(
            "KCSAN: data-race in foo / bar",
            "BUG: KCSAN: data-race in foo / bar\n"
            "write to 0xffff of 4 bytes by task 1 on cpu 0:\n foo+0x1/0x2\n"
            "read to 0xffff of 4 bytes by interrupt on cpu 1:\n bar+0x1/0x2\n",
        )
        self.assertEqual(
            (result.family.value, result.access_mode.value), ("data-race", "read-write")
        )
        self.assertIn("write to", result.access_mode.evidence)
        self.assertIn("read to", result.access_mode.evidence)

    def test_ambiguous_free_wording_stays_unknown(self) -> None:
        self.assertEqual(
            classify_characteristics("KASAN: double-free or invalid-free in foo").family.value,
            "unknown",
        )
        self.assertIn("unknown", BUG_FAMILIES)
        self.assertEqual(set(ACCESS_MODES), {"unknown", "read", "write", "read-write"})


if __name__ == "__main__":
    unittest.main()
