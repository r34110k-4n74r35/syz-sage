from __future__ import annotations

import unittest

from syz_sage.bug_types import BUG_TYPES, classify_bug_type


class BugTypeTests(unittest.TestCase):
    def test_observed_title_markers_cover_every_canonical_type(self) -> None:
        examples = {
            "kasan": "KASAN: slab-use-after-free Read in l2cap_disconn_ind (3)",
            "kmsan": "KMSAN: uninit-value in bch2_alloc_sectors_start_trans (2)",
            "kcsan": "KCSAN: data-race in shmem_getattr / shmem_recalc_inode",
            "kfence": "KFENCE: invalid free in gid_table_release_one",
            "ubsan": "UBSAN: shift-out-of-bounds in squashfs_xz_comp_opts",
            "warning": "WARNING in vma_set_pgoff",
            "info": "INFO: task hung in __bch2_fs_stop",
            "bug": "BUG: unable to handle kernel paging request in integrity_audit_message",
            "panic": "kernel panic: corrupted stack end in blkcg_css_free",
            "general-protection-fault": "general protection fault in iommufd_ioas_change_process",
            "deadlock": "possible deadlock in xfs_dquot_disk_alloc (2)",
            "memory-leak": "memory leak in io_submit_sqes (6)",
            "inconsistent-lock-state": "inconsistent lock state in bpf_lru_push_free",
            "divide-error": "divide error in mac80211_hwsim_write_tsf",
            "rcu": "suspicious RCU usage at ./include/net/inet_sock.h:LINE",
            "unregister-netdevice": "unregister_netdevice: waiting for DEV to become free (8)",
            "stack-segment-fault": "stack segment fault in dev_hash_map_redirect",
            "internal-error": "Internal error in ata_sff_freeze",
            "vfs": "VFS: Busy inodes after unmount (use-after-free) (3)",
            "invalid-opcode": "invalid opcode in __phys_addr (2)",
            "unexpected-reboot": "unexpected kernel reboot (3)",
            "lost-connection": "lost connection to test machine (4)",
            "build-error": "linux-next build error (26)",
            "boot-error": "upstream boot error: can't ssh into the instance",
            "test-error": "upstream test error: failed to run test",
            "other": "Unable to handle kernel write to read-only memory at virtual address ADDR",
        }
        self.assertEqual(set(BUG_TYPES), set(examples))
        self.assertEqual(len(BUG_TYPES), len(set(BUG_TYPES)))
        for expected, title in examples.items():
            with self.subTest(title=title):
                self.assertEqual(classify_bug_type(title), expected)

    def test_case_whitespace_and_duplicate_suffixes_do_not_change_type(self) -> None:
        examples = {
            "  kAsAn \t: use-after-free in alpha (12)  ": "kasan",
            "\nKERNEL\tBUG  in alpha (2)": "bug",
            "PaNiC: double fault in alpha": "panic",
            "panic: runtime error: floating point error": "panic",
            " possible\tdeadlock  (2) ": "deadlock",
            "INFO \t: rcu detected stall (2)": "info",
            "WARNING: suspicious RCU usage in alpha": "warning",
        }
        for title, expected in examples.items():
            with self.subTest(title=title):
                self.assertEqual(classify_bug_type(title), expected)

    def test_manager_boot_and_test_wrappers_expose_the_diagnostic(self) -> None:
        examples = {
            "upstream test error: WARNING in enqueue_to_backlog": "warning",
            "usb-testing boot error: WARNING: refcount bug in alpha": "warning",
            "kmsan boot error: KMSAN: uninit-value in tcp_child_process": "kmsan",
            "kmsan boot error: INFO: task hung in alpha": "info",
            "riscv/fixes test error: kernel panic: Kernel stack overflow": "panic",
            "future-manager/v2+debug test error: KASAN: use-after-free in alpha": "kasan",
            " NEW-MANAGER\tBOOT  ERROR : UBSAN: shift-out-of-bounds in alpha (5) ": "ubsan",
        }
        for title, expected in examples.items():
            with self.subTest(title=title):
                self.assertEqual(classify_bug_type(title), expected)

    def test_build_and_unrecognized_wrapped_errors_keep_the_stage(self) -> None:
        examples = {
            "kmsan build error": "build-error",
            "linux-next build error: KASAN: compiler failure": "build-error",
            "upstream boot error": "boot-error",
            "upstream boot error (2)": "boot-error",
            "future-manager test error:": "test-error",
            "upstream test error: diagnostic mentions KASAN: later": "test-error",
            "upstream boot error: future diagnostic in alpha": "boot-error",
        }
        for title, expected in examples.items():
            with self.subTest(title=title):
                self.assertEqual(classify_bug_type(title), expected)

    def test_embedded_words_and_malformed_prefixes_are_not_classified(self) -> None:
        for title in (
            "",
            " \t ",
            "WARNINGLESS in alpha",
            "INFOGRAPHIC: alpha",
            "KASAN_helper in alpha",
            "KASAN initialization failed",
            "a memory leak in alpha",
            "diagnostic: WARNING in alpha",
            "memory leakage in alpha",
            "kernel BUGGY in alpha",
            "upstream boot errors: KASAN: use-after-free in alpha",
            "upstream boot error KASAN: use-after-free in alpha",
            "upstream debug boot error: KASAN: use-after-free in alpha",
            "../upstream boot error: KASAN: use-after-free in alpha",
            "upstream?debug boot error: WARNING in alpha",
        ):
            with self.subTest(title=title):
                self.assertEqual(classify_bug_type(title), "other")

    def test_leading_report_marker_takes_precedence_over_nested_detector_mentions(self) -> None:
        self.assertEqual(classify_bug_type("WARNING in kasan_report"), "warning")
        self.assertEqual(classify_bug_type("INFO: KASAN: detector unavailable"), "info")
        self.assertEqual(classify_bug_type("BUG: KMSAN: bad report"), "bug")


if __name__ == "__main__":
    unittest.main()
