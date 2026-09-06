from __future__ import annotations

import unittest

from syz_sage.location_store import _crash_sites
from syz_sage.locations import (
    extract_stack_frames,
    locate_crash_site,
    locate_kcsan_sites,
    parse_frames,
    split_manifestation_report,
)
from syz_sage.parsing import parse_subsystem_tags
from syz_sage.patch_locations import extract_fix_locations


class LocationParsingTests(unittest.TestCase):
    def test_kmsan_store_origins_cannot_supply_a_missing_crash_coordinate(self) -> None:
        report = """BUG: KMSAN: uninit-value in access
 access+0x1/0x2
Uninit was stored to memory at:
 access+0x5/0x9 drivers/example.c:42
Uninit was stored to memory at:
 copy_value+0x1/0x2 mm/util.c:30
Uninit was created at:
 allocate+0x1/0x2 mm/slab.c:100
"""
        site = locate_crash_site("KMSAN: uninit-value in access", report)
        self.assertEqual(site.function, "access")
        self.assertIsNone(site.line)
        self.assertEqual(site.path, "")
        frames = extract_stack_frames(report)
        self.assertEqual(
            [f.section for f in frames], ["manifestation", "origin", "origin", "origin"]
        )
        self.assertEqual([f.report_line for f in frames], [2, 4, 6, 8])
        self.assertNotIn("Uninit was stored", split_manifestation_report(report)[0])

    def test_page_history_headings_keep_allocation_and_free_stacks_separate(self) -> None:
        report = """BUG: KASAN: use-after-free in access
 access+0x1/0x2
Freed by task 1:
 release+0x1/0x2 mm/slab.c:90
page_owner tracks the page as allocated
page last allocated via order 1, migratetype Unmovable
 access+0x5/0x9 drivers/example.c:42
page last free stack trace:
 free_page+0x1/0x2 mm/page_alloc.c:123
"""
        frames = extract_stack_frames(report)
        self.assertEqual(
            [f.section for f in frames], ["manifestation", "free", "allocation", "free"]
        )
        main, freed, allocated = split_manifestation_report(report)
        self.assertNotIn("release", main)
        self.assertIn("release", freed)
        self.assertNotIn("drivers/example.c", freed)
        self.assertIn("drivers/example.c", allocated)
        self.assertNotIn("free_page", allocated)
        self.assertIsNone(locate_crash_site("KASAN: use-after-free in access", report).line)

    def test_timestamped_auxiliary_headings_are_case_insensitive(self) -> None:
        for heading, expected in (
            ("UNINIT WAS STORED TO MEMORY AT:", "origin"),
            ("PAGE LAST ALLOCATED VIA ORDER 0", "allocation"),
            ("PAGE LAST FREE STACK TRACE:", "free"),
        ):
            with self.subTest(heading=heading):
                report = f" access+0x1/0x2\n[ 12.000] {heading}\n access drivers/test.c:42\n"
                self.assertIsNone(locate_crash_site("KMSAN: uninit-value in access", report).line)
                self.assertEqual(extract_stack_frames(report)[1].section, expected)

    def test_warning_coordinates_do_not_borrow_later_symbol(self) -> None:
        report = (
            "WARNING: CPU: 0 at include/linux/skbuff.h:2679:2 "
            "skb_assert_len include/linux/skbuff.h:2679:2 [inline]\n"
            "WARNING: CPU: 0 at include/linux/skbuff.h:2679:2 "
            "__dev_queue_xmit+0x1/0x2 net/core/dev.c:4345:6\n"
        )
        frames = parse_frames(report)
        self.assertEqual(
            [(f.function, f.path, f.line, f.column) for f in frames],
            [
                ("skb_assert_len", "include/linux/skbuff.h", 2679, 2),
                ("__dev_queue_xmit", "net/core/dev.c", 4345, 6),
            ],
        )
        site = locate_crash_site("WARNING in __dev_queue_xmit (5)", report)
        self.assertEqual(
            (site.function, site.path, site.line, site.column),
            ("skb_assert_len", "include/linux/skbuff.h", 2679, 2),
        )
        self.assertEqual(len(extract_stack_frames(report)), 2)

    def test_fix_definition_context_is_not_confused_with_function_calls(self) -> None:
        patch = """diff --git a/net/core/netdev-genl.c b/net/core/netdev-genl.c
--- a/net/core/netdev-genl.c
+++ b/net/core/netdev-genl.c
@@ -430,5 +430,5 @@ static int
 netdev_nl_queue_fill(struct sk_buff *rsp,
                     struct net_device *dev)
 {
- return 0;
+ return -ENOENT;
 }
"""
        location = extract_fix_locations(patch)[0]
        self.assertEqual(location.function_name, "netdev_nl_queue_fill")
        self.assertEqual(location.function_basis, "inferred from definition context")
        location = extract_fix_locations(
            patch.replace(
                "static int\n netdev_nl_queue_fill(struct sk_buff *rsp,\n"
                "                     struct net_device *dev)\n {",
                "\n call();\n another();\n {",
            )
        )[0]
        self.assertIsNone(location.function_name)

    def test_rename_literal_prefixes_and_empty_file_sides(self) -> None:
        patch = """diff --git a/a/old.c b/b/new.c
rename from a/old.c
rename to b/new.c
diff --git a/empty.c b/empty.c
new file mode 100644
index 0000000..e69de29
diff --git a/gone.bin b/gone.bin
deleted file mode 100644
Binary files a/gone.bin and /dev/null differ
"""
        renamed, added, deleted = extract_fix_locations(patch)
        self.assertEqual((renamed.old_file_path, renamed.new_file_path), ("a/old.c", "b/new.c"))
        self.assertIsNone(added.old_file_path)
        self.assertEqual(added.new_file_path, "empty.c")
        self.assertIsNone(deleted.new_file_path)
        self.assertEqual(deleted.old_file_path, "gone.bin")

    def test_subsystem_tags_are_scoped_to_bug_rows(self) -> None:
        tags = parse_subsystem_tags("""
            <a href="/upstream/fixed?label=subsystems%3Anavigation">ignored</a>
            <table><tr><td>
            <a href="/upstream/fixed?label=subsystems%3Amm">mm</a>
            <a href="/bug?extid=alpha">bug</a>
            <a href="/upstream/fixed?label=subsystems%3Anet">network</a>
            <a href="/upstream/fixed?label=subsystems%3Amm">duplicate</a>
            <a href="/upstream/fixed?label=prio%3Ahigh">priority</a>
            </td></tr><tr><td><a href="/bug?id=beta">bug</a></td></tr></table>
        """)
        self.assertEqual(tags, {"extid-alpha": ["mm", "net"], "id-beta": []})

    def test_sanitizer_access_and_complete_stack_are_distinct_from_origin(self) -> None:
        report = """BUG: KASAN: use-after-free in access
Call Trace:
 dump_stack+0x1/0x2 lib/dump_stack.c:1
 access+0x1/0x2 net/example.c:42 [inline]
 caller+0x1/0x2 net/example.c:60
Allocated by task 1:
 allocate+0x1/0x2 mm/slab.c:100
Freed by task 2:
 release+0x1/0x2
 [<ffffffff12345678>]
"""
        site = locate_crash_site("KASAN: use-after-free in access", report)
        self.assertEqual((site.function, site.path, site.line), ("access", "net/example.c", 42))
        frames = extract_stack_frames(report)
        self.assertEqual(len(frames), 6)
        self.assertTrue(frames[1].is_inline)
        self.assertEqual(frames[3].section, "allocation")
        self.assertEqual(frames[4].section, "free")
        self.assertIsNone(frames[4].file_path)
        self.assertIsNone(frames[5].function)
        self.assertEqual(frames[1].report_line, 4)
        self.assertEqual(frames[4].raw_line, " release+0x1/0x2")

    def test_origin_frame_cannot_supply_missing_crash_line(self) -> None:
        report = """BUG: KASAN: use-after-free in access
Call Trace:
 access+0x1/0x2
Allocated by task 1:
 access+0x1/0x2 net/example.c:123
"""
        site = locate_crash_site("KASAN: use-after-free in access", report)
        self.assertEqual(site.function, "access")
        self.assertIsNone(site.line)
        self.assertEqual(site.path, "")

    def test_explicit_ubsan_line_takes_precedence_over_runtime(self) -> None:
        report = """UBSAN: shift-out-of-bounds in fs/test.c:42:7
 __ubsan_handle_shift_out_of_bounds+0x1/0x2 lib/ubsan.c:100
 check_shift+0x1/0x2 fs/test.c:42
"""
        site = locate_crash_site("UBSAN: shift-out-of-bounds in check_shift", report)
        self.assertEqual((site.path, site.line, site.function), ("fs/test.c", 42, "check_shift"))

    def test_ubsan_does_not_attribute_a_different_source_line_to_the_crash(self) -> None:
        for caller_line in (43, 100):
            with self.subTest(caller_line=caller_line):
                report = (
                    "UBSAN: shift-out-of-bounds in fs/test.c:42:7\n"
                    f" caller+0x1/0x2 fs/test.c:{caller_line}\n"
                )
                site = locate_crash_site("UBSAN: shift-out-of-bounds in caller", report)
                self.assertEqual((site.path, site.line, site.column), ("fs/test.c", 42, 7))
                self.assertEqual(site.function, "")

    def test_kcsan_repeated_function_preserves_each_interrupt_access(self) -> None:
        title = "KCSAN: data-race in tick_do_update_jiffies64 / tick_do_update_jiffies64"
        report = f"""BUG: {title}
write to 0x123 of 8 bytes by interrupt on cpu 1:
 tick_do_update_jiffies64+0x100/0x250 kernel/time/tick-sched.c:73:2
 tick_sched_do_timer+0xd4/0xe0 kernel/time/tick-sched.c:138

read to 0x123 of 8 bytes by interrupt on cpu 0:
 tick_do_update_jiffies64+0x2b/0x250 kernel/time/tick-sched.c:62:4
 tick_sched_do_timer+0xd4/0xe0 kernel/time/tick-sched.c:138
"""
        sites = locate_kcsan_sites(title, report)
        self.assertEqual([(site.line, site.column) for site in sites], [(73, 2), (62, 4)])
        self.assertEqual(_crash_sites(title, report), sites)
        combined = locate_crash_site(title, report)
        self.assertEqual((combined.line, combined.secondary_line), (73, 62))
        self.assertTrue(
            all(frame.section == "conflicting-access" for frame in extract_stack_frames(report))
        )

    def test_kcsan_prefers_inline_access_and_does_not_substitute_a_caller(self) -> None:
        title = "KCSAN: data-race in outer / outer"
        report = f"""BUG: {title}
read-write to 0x123 of 8 bytes by task 1 on cpu 1:
 inner fs/access.c:5 [inline]
 outer+0x1/0x2 fs/access.c:20

read-write to 0x123 of 8 bytes by task 2 on cpu 0:
 outer+0x2/0x3
 caller+0x4/0x5 fs/access.c:30
"""
        first, second = _crash_sites(title, report)
        self.assertEqual((first.function, first.path, first.line), ("inner", "fs/access.c", 5))
        self.assertEqual(second.function, "outer")
        self.assertEqual(second.path, "")
        self.assertIsNone(second.line)
        self.assertIn("outer+0x2/0x3", second.evidence)

    def test_kcsan_does_not_invent_a_missing_second_access(self) -> None:
        title = "KCSAN: data-race in same / same"
        report = f"""BUG: {title}
write to 0x123 of 8 bytes by task 1:
 same+0x1/0x2 fs/access.c:5
"""
        first, second = _crash_sites(title, report)
        self.assertEqual(first.line, 5)
        self.assertIsNone(second.line)
        self.assertEqual(second.path, "")
        first, second = _crash_sites(title, " same+0x1/0x2 fs/access.c:5\n")
        self.assertEqual((first.function, second.function), ("same", "same"))
        self.assertIsNone(first.line)
        self.assertIsNone(second.line)

    def test_unwind_dump_retains_symbol_entries_without_source_coordinates(self) -> None:
        frames = extract_stack_frames("""unwind stack type:0 next_sp: (null)
ffff8801db3076e8: ffffffff8127e99e (__save_stack_trace+0x6e/0xd0)
ffff8801db3076f0: 0000000000000000 ...
""")
        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0].section, "unwind")
        self.assertEqual(frames[0].function, "__save_stack_trace")
        self.assertIsNone(frames[0].line_number)

    def test_sanitizer_inline_access_is_more_precise_than_grouping_title(self) -> None:
        report = """BUG: KASAN: use-after-free in inner fs/test.c:42 [inline]
BUG: KASAN: use-after-free in outer+0x1/0x2 fs/test.c:50
Call Trace:
 inner fs/test.c:42 [inline]
 outer+0x1/0x2 fs/test.c:50
"""
        site = locate_crash_site("KASAN: use-after-free in outer", report)
        self.assertEqual((site.function, site.line), ("inner", 42))

    def test_fix_ranges_exclude_context_and_split_disjoint_edits(self) -> None:
        locations = extract_fix_locations("""diff --git a/net/a.c b/net/a.c
--- a/net/a.c
+++ b/net/a.c
@@ -10,5 +10,6 @@ int target(void)
 context
-old
+new
+extra
 middle
-last_old
+last_new
 end
""")
        self.assertEqual(len(locations), 2)
        self.assertEqual(
            [(loc.old_start, loc.old_count, loc.new_start, loc.new_count) for loc in locations],
            [(11, 1, 11, 2), (13, 1, 14, 1)],
        )
        self.assertEqual(locations[0].function_name, "target")

    def test_insertions_deletions_and_renames_keep_both_source_versions(self) -> None:
        locations = extract_fix_locations("""diff --git a/old.c b/new.c
similarity index 90%
rename from old.c
rename to new.c
--- a/old.c
+++ b/new.c
@@ -0,0 +1,2 @@
+first
+second
diff --git a/deleted.c b/deleted.c
--- a/deleted.c
+++ /dev/null
@@ -1,2 +0,0 @@
-first
-second
""")
        self.assertEqual(len(locations), 2)
        self.assertEqual((locations[0].old_start, locations[0].old_count), (0, 0))
        self.assertEqual((locations[0].new_start, locations[0].new_count), (1, 2))
        self.assertEqual(locations[0].new_file_path, "new.c")
        self.assertIsNone(locations[1].new_file_path)
        self.assertEqual((locations[1].new_start, locations[1].new_count), (0, 0))

    def test_file_only_and_truncated_diffs_do_not_invent_lines(self) -> None:
        locations = extract_fix_locations("""diff --git a/old.bin b/new.bin
rename from old.bin
rename to new.bin
diff --git a/other.bin b/other.bin
Binary files a/other.bin and b/other.bin differ
diff --git a/truncated.c b/truncated.c
--- a/truncated.c
+++ b/truncated.c
@@ -1,3 +1,3 @@
-old
+new
""")
        self.assertEqual([loc.kind for loc in locations], ["rename", "binary", "unparsed"])
        self.assertTrue(all(loc.old_start is None and loc.new_start is None for loc in locations))


if __name__ == "__main__":
    unittest.main()
