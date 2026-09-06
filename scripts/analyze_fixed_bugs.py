#!/usr/bin/env python3
"""Analyze fixed syzbot bugs with crash reports and downloaded patches.

The script is intentionally stdlib-only.  It produces an auditable JSON dataset
that is then used by the workbook and report builders.  Its structural distance
implementation follows the study definitions supplied by the project owner:
D0 exact changed statement, D1 same function, D2 same file, D3 same component,
D4 same subsystem, and D5 cross-subsystem.  D4/D5 use a documented path-based
MAINTAINERS proxy because historical kernel trees are not part of this corpus.
"""

from __future__ import annotations

import argparse
import html
import json
import re
from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from syz_sage.parsing.crash import (
    CrashSite,
    Frame,
    clean_function,
    locate_crash_site,
    normalize_path,
    parse_frames,
    split_manifestation_report,
)
from syz_sage.parsing.listing import effective_fixes

from .common import ROOT, writable_path, write_text

SOURCE_SUFFIXES = {".c", ".h", ".s", ".S", ".rs"}
DISTANCE_LABELS = {
    0: "D0 Coincident",
    1: "D1 Intra-function",
    2: "D2 Intra-file",
    3: "D3 Intra-component",
    4: "D4 Intra-subsystem",
    5: "D5 Cross-subsystem",
}

CONTROL_WORDS = {
    "if",
    "for",
    "while",
    "switch",
    "return",
    "sizeof",
    "typeof",
    "defined",
    "container_of",
    "WARN_ON",
    "BUG_ON",
    "IS_ERR",
    "PTR_ERR",
}


@dataclass
class Hunk:
    commit_hash: str
    patch_title: str
    path: str
    old_start: int
    old_count: int
    new_start: int
    new_count: int
    context: str
    functions: list[str]
    changed_old_lines: list[int]
    changed_new_lines: list[int]
    insertion_anchors: list[int]
    additions: int
    deletions: int
    added_text: str
    removed_text: str
    is_source: bool
    distance: int | None = None
    distance_label: str = "Unresolved"
    distance_reason: str = ""
    distance_confidence: str = "low"
    component: str = ""
    subsystem: str = ""


def read_text(path: Path) -> str:
    return path.read_text(errors="replace")


def normalize_fix_title(value: str | None) -> str:
    return " ".join(html.unescape(re.sub(r"<[^>]+>", "", value or "")).split())


def resolved_fixes(
    key: str,
    listing: dict[str, Any],
    detail: dict[str, Any] | None,
    resolutions: dict[tuple[str, str, str], dict[str, Any]],
) -> tuple[list[dict[str, Any]], set[str]]:
    """Merge fix references and count each resolved commit's patch once."""
    commits: dict[str, dict[str, Any]] = {}
    sources: set[str] = set()
    # Prefer the richer detail fields while retaining every listing-only fix.
    for fix in effective_fixes({}, detail) + effective_fixes(listing, None):
        if fix.get("hash"):
            sources.add("Syzbot metadata")
        else:
            identity = (key, normalize_fix_title(fix.get("title")), fix.get("repo") or "")
            supplemental = resolutions.get(identity)
            if supplemental:
                fix["hash"] = supplemental["hash"]
                fix["link"] = supplemental.get("commit_url", "")
                sources.add("exact-title cgit resolution")
        if not fix.get("hash"):
            continue
        commit_hash = fix["hash"].lower()
        fix["hash"] = commit_hash
        if commit_hash not in commits:
            commits[commit_hash] = fix
        else:
            # Listing references commonly omit the richer detail's commit URL.
            for field, value in fix.items():
                if value not in (None, "") and commits[commit_hash].get(field) in (None, ""):
                    commits[commit_hash][field] = value
    return list(commits.values()), sources


def function_candidates(text: str) -> list[str]:
    """Best-effort extraction of C/Rust function names from a patch context."""
    text = text.strip()
    matches = re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", text)
    out: list[str] = []
    for name in matches:
        if name not in CONTROL_WORDS and not name.isupper():
            name = clean_function(name)
            if name and name not in out:
                out.append(name)
    # Rust function definitions usually have an explicit `fn`.
    for name in re.findall(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)", text):
        if name not in out:
            out.append(name)
    return out


def parse_patch(
    patch_path: Path, commit_hash: str, json_title: str
) -> tuple[str, list[Hunk], dict[str, int]]:
    lines = read_text(patch_path).splitlines()
    subject = ""
    for i, line in enumerate(lines):
        if line.startswith("Subject:"):
            subject = line.split(":", 1)[1].strip()
            j = i + 1
            while j < len(lines) and lines[j].startswith((" ", "\t")):
                subject += " " + lines[j].strip()
                j += 1
            subject = re.sub(r"^\[PATCH[^]]*\]\s*", "", subject).strip()
            break
    patch_title = json_title or subject
    hunks: list[Hunk] = []
    current_path = ""
    i = 0
    total_add = total_del = 0
    while i < len(lines):
        line = lines[i]
        if line.startswith("diff --git a/"):
            m = re.match(r"diff --git a/(.*?) b/(.*)$", line)
            current_path = m.group(2) if m else ""
            i += 1
            continue
        hm = re.match(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@\s*(.*)", line)
        if not hm:
            i += 1
            continue
        old_start = int(hm.group(1))
        old_count = int(hm.group(2) or 1)
        new_start = int(hm.group(3))
        new_count = int(hm.group(4) or 1)
        context = hm.group(5).strip()
        old_line, new_line = old_start, new_start
        changed_old: list[int] = []
        changed_new: list[int] = []
        anchors: list[int] = []
        additions: list[str] = []
        deletions: list[str] = []
        body: list[str] = []
        i += 1
        while i < len(lines) and not lines[i].startswith(("@@ ", "diff --git ")):
            raw = lines[i]
            if raw.startswith("+") and not raw.startswith("+++"):
                changed_new.append(new_line)
                anchors.append(old_line)
                additions.append(raw[1:])
                body.append(raw[1:])
                new_line += 1
            elif raw.startswith("-") and not raw.startswith("---"):
                changed_old.append(old_line)
                deletions.append(raw[1:])
                body.append(raw[1:])
                old_line += 1
            elif raw.startswith(" "):
                body.append(raw[1:])
                old_line += 1
                new_line += 1
            i += 1
        funcs = function_candidates(context)
        if not funcs:
            # Prefer actual definition-looking lines in the hunk body.  Limit
            # the scan so calls deeper in a large hunk do not become FS names.
            for body_line in body[:24]:
                stripped = body_line.strip()
                if stripped.endswith(";") or stripped.startswith(("#", "//", "/*", "*")):
                    continue
                for name in function_candidates(stripped):
                    if name not in funcs:
                        funcs.append(name)
                if funcs:
                    break
        total_add += len(additions)
        total_del += len(deletions)
        suffix = Path(current_path).suffix
        hunks.append(
            Hunk(
                commit_hash=commit_hash,
                patch_title=patch_title,
                path=current_path,
                old_start=old_start,
                old_count=old_count,
                new_start=new_start,
                new_count=new_count,
                context=context,
                functions=funcs,
                changed_old_lines=changed_old,
                changed_new_lines=changed_new,
                insertion_anchors=anchors,
                additions=len(additions),
                deletions=len(deletions),
                added_text="\n".join(additions)[:4000],
                removed_text="\n".join(deletions)[:4000],
                is_source=suffix in SOURCE_SUFFIXES or suffix.lower() in SOURCE_SUFFIXES,
            )
        )
    return patch_title, hunks, {"additions": total_add, "deletions": total_del}


def classify_detector(title: str, report: str) -> str:
    text = title + "\n" + report[:5000]
    lower = text.lower()
    for token, label in (
        ("KASAN", "KASAN"),
        ("KMSAN", "KMSAN"),
        ("KCSAN", "KCSAN"),
        ("UBSAN", "UBSAN"),
        ("KFENCE", "KFENCE"),
    ):
        if token in title or re.search(rf"(?:BUG:\s*)?{token}:|\b{token}:\s", report[:5000]):
            return label
    if "lockdep" in lower or "possible deadlock" in lower or "circular locking" in lower:
        return "Lockdep"
    if "hung task" in lower or "task hung" in lower:
        return "Hung-task detector"
    if "rcu" in lower and ("stall" in lower or "suspicious" in lower):
        return "RCU diagnostics"
    if "memory leak" in lower or "kmemleak" in lower or "unreferenced object" in lower:
        return "Leak detector"
    if "warning" in lower:
        return "WARN"
    if "kernel bug" in lower or "bug:" in lower:
        return "BUG/Oops"
    return "Kernel fault/other"


def access_mode(text: str) -> str:
    lower = text.lower()
    if re.search(r"\bwrite(?: of size)?\b", lower):
        return "Write"
    if re.search(r"\bread(?: of size)?\b", lower):
        return "Read"
    if any(
        x in lower
        for x in ("double-free", "double free", "invalid-free", "bad-free", "free of size")
    ):
        return "Free"
    return "Unspecified"


def classify_bug(title: str, report: str) -> dict[str, str]:
    title_l = title.lower()
    text = (title + "\n" + report[:10000]).lower()
    access = access_mode(title + "\n" + report[:2500])
    detector = classify_detector(title, report)
    rules = [
        (("use-after-free", "use after free"), "Memory safety", "Use-after-free"),
        (
            ("double-free", "double free", "invalid-free", "bad-free"),
            "Memory safety",
            "Invalid/double free",
        ),
        (
            (
                "shift-out-of-bounds",
                "signed integer overflow",
                "division by zero",
                "array-index-out-of-bounds",
            ),
            "Undefined behavior",
            "Arithmetic/type UB",
        ),
        (
            ("out-of-bounds", "out of bounds", "slab-out-of-bounds", "global-out-of-bounds"),
            "Memory safety",
            "Out-of-bounds access",
        ),
        (
            ("null-ptr-deref", "null pointer dereference", "null-ptr"),
            "Memory safety",
            "NULL dereference",
        ),
        (
            ("uninit-value", "uninitialized value", "uninitialized memory", "use of uninitialized"),
            "Memory safety",
            "Uninitialized use",
        ),
        (
            ("kernel-infoleak", "infoleak", "information leak"),
            "Memory disclosure",
            "Kernel information leak",
        ),
        (
            ("wild-memory-access", "invalid-access", "bad usercopy"),
            "Memory safety",
            "Invalid/wild memory access",
        ),
        (("memory leak", "kmemleak", "unreferenced object"), "Resource/lifetime", "Memory leak"),
        (("data-race", "data race"), "Concurrency", "Data race"),
        (("deadlock", "circular locking dependency"), "Concurrency", "Deadlock/lock ordering"),
        (
            (
                "sleeping function called",
                "scheduling while atomic",
                "bad unlock balance",
                "held lock freed",
                "register non-static key",
                "non migratable context",
                "smp_processor_id() in preemptible",
            ),
            "Concurrency",
            "Lock/context misuse",
        ),
        (("refcount", "reference count"), "Resource/lifetime", "Refcount error"),
        (("ubsan",), "Undefined behavior", "Arithmetic/type UB"),
        (
            ("stack-overflow", "stack overflow", "stack guard page was hit"),
            "Memory safety",
            "Stack overflow",
        ),
        (
            (
                "hung task",
                "task hung",
                "rcu stall",
                "rcu detected stall",
                "soft lockup",
                "hard lockup",
            ),
            "Liveness",
            "Hang/stall/lockup",
        ),
        (
            (
                "general protection fault",
                "unable to handle kernel",
                "page fault",
                "kernel paging request",
            ),
            "Kernel fault",
            "Page fault/general protection fault",
        ),
        (("warning", "warn_on"), "Invariant violation", "Kernel warning"),
        (("kernel bug", "bug at"), "Invariant violation", "Kernel BUG/assertion"),
    ]
    family, bug_type = "Other", "Other/uncategorized"
    # Syzbot titles are already normalized detector diagnoses.  Classify from
    # the title first so a later secondary warning in a long report does not
    # overwrite the primary failure (e.g., KMSAN uninit followed by a NULL oops).
    for source in (title_l, text):
        for needles, fam, typ in rules:
            if any(n in source for n in needles):
                family, bug_type = fam, typ
                break
        if bug_type != "Other/uncategorized":
            break
    # Lockdep diagnostics are semantically stronger than a generic normalized
    # WARNING title and should be represented as concurrency failures.
    if detector == "Lockdep" and bug_type in {
        "Kernel warning",
        "Kernel BUG/assertion",
        "Other/uncategorized",
    }:
        family = "Concurrency"
        bug_type = (
            "Deadlock/lock ordering"
            if any(x in text for x in ("deadlock", "circular locking"))
            else "Lock/context misuse"
        )
    if bug_type in {"Use-after-free", "Out-of-bounds access"} and access != "Unspecified":
        bug_type += f" ({access.lower()})"
    evidence = title
    first_signal = next(
        (
            line.strip()
            for line in report.splitlines()
            if any(
                marker in line
                for marker in ("BUG:", "WARNING:", "UBSAN:", "KCSAN:", "KMSAN:", "INFO:")
            )
        ),
        "",
    )
    if first_signal and first_signal not in evidence:
        evidence += " | " + first_signal[:300]
    return {
        "detector": detector,
        "bug_family": family,
        "bug_type": bug_type,
        "access_mode": access,
        "bug_class_evidence": evidence[:700],
    }


PATCH_CLASS_RULES: list[tuple[str, tuple[str, ...]]] = [
    (
        "Refcount/accounting correction",
        ("refcount", "kref", "reference count", "put_ref", "get_ref", "accounting"),
    ),
    (
        "Synchronization/ordering",
        (
            "deadlock",
            "race",
            "lock",
            "mutex",
            "spinlock",
            "synchronize",
            "barrier",
            "rcu",
            "workqueue",
            "cancel_work",
            "flush_work",
            "timer",
        ),
    ),
    (
        "Lifetime/resource management",
        (
            "use-after-free",
            "uaf",
            "lifetime",
            "free",
            "destroy",
            "release",
            "leak",
            "cleanup",
            "teardown",
        ),
    ),
    (
        "Bounds/size correction",
        (
            "out-of-bounds",
            "bounds",
            "length",
            "size",
            "index",
            "off-by-one",
            "truncate",
            "overrun",
            "underrun",
        ),
    ),
    (
        "Arithmetic/type correction",
        (
            "shift",
            "integer overflow",
            "signed",
            "unsigned",
            "cast",
            "underflow",
            "arithmetic",
            "1ul",
        ),
    ),
    (
        "Validation/guard",
        (
            "validate",
            "validation",
            "reject",
            "check",
            "invalid",
            "null",
            "sanity",
            "guard",
            "verify",
        ),
    ),
    (
        "Initialization/state correction",
        ("initialize", "initialise", "init ", "reset", "state", "flag", "mark", "clear", "set "),
    ),
    (
        "Error-path handling",
        (
            "error path",
            "error handling",
            "unwind",
            "rollback",
            "failure",
            "fail ",
            "errno",
            "goto err",
        ),
    ),
    (
        "API/protocol contract",
        ("api", "protocol", "ioctl", "attribute", "contract", "instead of", "replace", "use "),
    ),
]


def classify_patch(title: str, hunks: list[Hunk]) -> dict[str, str]:
    added = "\n".join(h.added_text for h in hunks).lower()
    removed = "\n".join(h.removed_text for h in hunks).lower()
    title_l = title.lower()
    scores: dict[str, int] = defaultdict(int)
    evidence: dict[str, list[str]] = defaultdict(list)
    for category, needles in PATCH_CLASS_RULES:
        for needle in needles:
            if needle in title_l:
                scores[category] += 4
                evidence[category].append(f"title:{needle}")
            if needle in added:
                scores[category] += 1
                evidence[category].append(f"added:{needle}")
            if needle in removed:
                scores[category] += 1
    if re.search(
        r"^\s*\+\s*if\s*\(",
        "\n".join("+" + x for h in hunks for x in h.added_text.splitlines()),
        re.M,
    ):
        scores["Validation/guard"] += 3
        evidence["Validation/guard"].append("added conditional")
    if any(x in added for x in ("mutex_lock", "spin_lock", "down_write", "rcu_read_lock")):
        scores["Synchronization/ordering"] += 4
    if any(x in added for x in ("kfree(", "kvfree(", "free_percpu", "put_device", "fput(")):
        scores["Lifetime/resource management"] += 3
    if any(x in added for x in ("refcount_inc", "refcount_dec", "kref_get", "kref_put")):
        scores["Refcount/accounting correction"] += 4
    if not scores:
        scores["Logic/control-flow correction"] = 1
        evidence["Logic/control-flow correction"].append("no stronger lexical signature")
    category = max(scores, key=lambda k: (scores[k], k == "Validation/guard"))

    if category == "Validation/guard":
        action = "Add or strengthen a precondition/validation check"
    elif category == "Synchronization/ordering":
        action = "Correct synchronization, lock ordering, or asynchronous work ordering"
    elif category == "Lifetime/resource management":
        action = "Correct allocation/free, teardown, or object lifetime management"
    elif category == "Refcount/accounting correction":
        action = "Correct reference/resource accounting"
    elif category == "Bounds/size correction":
        action = "Correct a bound, length, size, or index calculation"
    elif category == "Arithmetic/type correction":
        action = "Correct integer type, cast, shift, or arithmetic"
    elif category == "Initialization/state correction":
        action = "Initialize or update state/flags consistently"
    elif category == "Error-path handling":
        action = "Repair failure-path cleanup or error propagation"
    elif category == "API/protocol contract":
        action = "Use the API/protocol according to its contract"
    else:
        action = "Correct logic or control flow"
    confidence = "high" if scores[category] >= 5 else "medium" if scores[category] >= 3 else "low"
    return {
        "patch_type": category,
        "patch_action": action,
        "patch_class_confidence": confidence,
        "patch_class_evidence": ", ".join(dict.fromkeys(evidence[category]))[:700],
    }


def canonical_subsystem(path: str) -> str:
    path = normalize_path(path)
    parts = path.split("/") if path else []
    if not parts:
        return "unknown"
    # Cross-tree subsystem families commonly represented in multiple roots.
    if path.startswith(
        ("arch/x86/kvm/", "virt/kvm/", "include/linux/kvm", "include/uapi/linux/kvm")
    ):
        return "kvm"
    if path.startswith(("kernel/bpf/", "net/bpf/", "include/linux/bpf", "include/uapi/linux/bpf")):
        return "bpf"
    if path.startswith(("block/", "drivers/block/", "include/linux/blk", "include/uapi/linux/blk")):
        return "block"
    if path.startswith(("io_uring/", "include/linux/io_uring", "include/uapi/linux/io_uring")):
        return "io_uring"
    if path.startswith(("drivers/iommu/", "include/linux/iommu", "include/uapi/linux/iommu")):
        return "iommu"
    if path.startswith(("drivers/gpu/", "include/drm/", "include/uapi/drm/")):
        return "gpu/drm"
    if path.startswith(("drivers/media/", "include/media/", "include/uapi/linux/media")):
        return "media"
    if path.startswith(("drivers/scsi/", "include/scsi/")):
        return "scsi"
    if path.startswith(
        ("drivers/net/", "net/", "include/net/", "include/uapi/linux/if_", "include/linux/net")
    ):
        return "net"
    if path.startswith(
        (
            "include/linux/skbuff",
            "include/linux/sockptr",
            "include/linux/if_vlan",
            "include/linux/ieee80211",
            "include/linux/etherdevice",
            "include/linux/ethtool",
            "include/uapi/linux/if_",
            "include/uapi/linux/ieee80211",
        )
    ):
        return "net"
    if path.startswith(("fs/", "include/linux/fs", "include/uapi/linux/fs")):
        return "fs"
    if path.startswith(
        (
            "include/linux/hfs",
            "include/linux/sysv",
            "include/uapi/linux/reiserfs",
            "include/linux/ext4",
            "include/linux/f2fs",
            "include/linux/buffer_head",
        )
    ):
        return "fs"
    if path.startswith(("mm/", "include/linux/mm", "include/linux/memory", "include/linux/page")):
        return "mm"
    if path.startswith(("include/linux/kasan", "include/linux/highmem", "include/linux/huge_mm")):
        return "mm"
    if path.startswith(("include/sound/", "include/uapi/sound/")):
        return "sound"
    if path.startswith(("include/linux/key", "include/uapi/linux/key")):
        return "security"
    if path.startswith(("include/linux/blk", "include/uapi/linux/pr.h")):
        return "block"
    if path.startswith(
        (
            "include/linux/sched",
            "include/linux/cpu",
            "include/linux/cpuhotplug",
            "include/linux/cpumask",
            "include/linux/cgroup",
            "include/linux/perf_event",
            "include/linux/ring_buffer",
            "include/linux/trace",
            "include/linux/lockdep",
            "include/linux/seqlock",
            "include/linux/ns_common",
            "include/trace/events/dma",
        )
    ):
        return "kernel"
    if parts[0] == "drivers":
        return "/".join(parts[:2]) if len(parts) > 1 else "drivers"
    if parts[0] == "arch":
        return "/".join(parts[:3]) if len(parts) > 2 else "/".join(parts)
    if parts[0] == "include":
        return "include/other"
    return parts[0]


def canonical_component(path: str) -> str:
    path = normalize_path(path)
    parts = path.split("/") if path else []
    subsystem = canonical_subsystem(path)
    if not parts:
        return "unknown"
    if subsystem == "kvm":
        if "kvm" in parts:
            idx = parts.index("kvm")
            return "/".join(parts[: min(len(parts), idx + 2)])
        return "kvm/core"
    if subsystem == "bpf":
        return "bpf/" + (parts[1] if len(parts) > 1 else "core")
    if subsystem == "block":
        return "block/" + (
            parts[2] if path.startswith("drivers/block/") and len(parts) > 2 else "core"
        )
    if subsystem == "net":
        if path.startswith("drivers/net/"):
            depth = 4 if len(parts) >= 4 and parts[2] == "ethernet" else 3
            return "/".join(parts[: min(len(parts), depth)])
        if parts[0] == "net":
            return "/".join(parts[:2]) if len(parts) > 1 else "net/core"
        return "net/headers"
    if subsystem == "fs":
        if parts[0] == "fs":
            if len(parts) > 2:
                return "/".join(parts[:2])
            generic = {
                "open.c",
                "read_write.c",
                "namei.c",
                "file.c",
                "inode.c",
                "super.c",
                "dentry.c",
                "ioctl.c",
                "stat.c",
                "exec.c",
            }
            return (
                "fs/vfs"
                if len(parts) == 2 and parts[1] in generic
                else "/".join(parts[:-1] or parts)
            )
        return "fs/headers"
    if subsystem == "mm":
        return "mm"
    if parts[0] == "include" and subsystem not in {"unknown", "include/other"}:
        return subsystem + "/headers"
    if path.startswith("drivers/"):
        if len(parts) >= 4:
            return "/".join(parts[:3])
        return "/".join(parts[:-1] or parts)
    if parts[0] in {"kernel", "security", "sound", "crypto", "arch"}:
        return "/".join(parts[:2]) if len(parts) > 2 else "/".join(parts[:-1] or parts)
    if subsystem in {"iommu", "gpu/drm", "media", "scsi", "io_uring"}:
        return "/".join(parts[:-1]) if len(parts) > 1 else subsystem
    return "/".join(parts[:-1] or parts)


def grade_hunk(cs: CrashSite, hunk: Hunk) -> None:
    hunk.component = canonical_component(hunk.path)
    hunk.subsystem = canonical_subsystem(hunk.path)
    if not cs.path or not hunk.path:
        hunk.distance_reason = "Crash or fix path unresolved"
        return
    if cs.path == hunk.path:
        touched = hunk.changed_old_lines + hunk.insertion_anchors
        # A two-line tolerance accommodates an inserted guard immediately before
        # the faulting statement and small line drift between report and parent.
        if cs.line is not None and touched and min(abs(cs.line - x) for x in touched) <= 2:
            hunk.distance = 0
            hunk.distance_reason = (
                "Fix changed the crashing statement or inserted an adjacent guard"
            )
            hunk.distance_confidence = "high"
        elif cs.function and cs.function in hunk.functions:
            hunk.distance = 1
            hunk.distance_reason = "Crash and fix are in the same function, at different lines"
            hunk.distance_confidence = "high"
        else:
            hunk.distance = 2
            hunk.distance_reason = (
                "Crash and fix are in different/unknown functions in the same file"
            )
            hunk.distance_confidence = "high"
    else:
        cs_component, fs_component = canonical_component(cs.path), canonical_component(hunk.path)
        cs_subsystem, fs_subsystem = canonical_subsystem(cs.path), canonical_subsystem(hunk.path)
        if cs_component == fs_component and cs_component != "unknown":
            hunk.distance = 3
            hunk.distance_reason = f"Cross-file within path-derived component {cs_component}"
            hunk.distance_confidence = "medium"
        elif cs_subsystem == fs_subsystem and cs_subsystem not in {"unknown", "include/other"}:
            hunk.distance = 4
            hunk.distance_reason = (
                f"Different components within path-derived subsystem {cs_subsystem}"
            )
            hunk.distance_confidence = "medium"
        else:
            hunk.distance = 5
            hunk.distance_reason = (
                f"Path-derived subsystems differ: {cs_subsystem} vs {fs_subsystem}"
            )
            hunk.distance_confidence = "low"
    if hunk.distance is not None:
        hunk.distance_label = DISTANCE_LABELS[hunk.distance]


def stack_distance(cs: CrashSite, fix_functions: Iterable[str]) -> tuple[str, str]:
    fix_set = {clean_function(f) for f in fix_functions if f}
    if not fix_set:
        return "unknown", "No fix function could be extracted from a hunk header/body"
    if cs.function and clean_function(cs.function) in fix_set:
        return "0", "The crashing function itself is one of the extracted fixed functions"
    frames = cs.frames
    if not frames:
        return "unknown", "No symbolized manifestation stack was extracted"
    cs_indices = [
        i
        for i, f in enumerate(frames)
        if (
            (cs.function and f.function == cs.function)
            or (
                cs.path and f.path == cs.path and cs.line is not None and abs(f.line - cs.line) <= 1
            )
        )
    ]
    cs_index = cs_indices[0] if cs_indices else 0
    fixed_indices = [i for i, f in enumerate(frames) if f.function in fix_set]
    if not fixed_indices:
        return "∞", "No extracted fixed function appears on the manifestation stack"
    distance = min(abs(i - cs_index) for i in fixed_indices)
    return str(distance), "Frame-edge distance to nearest fixed function on manifestation stack"


def syscall_functions(frames: list[Frame]) -> set[str]:
    return {
        f.function
        for f in frames
        if re.search(r"(?:__do_sys_|__se_sys_|\bdo_sys_|\bsys_)", f.function)
    }


def temporal_distance(bug_type: str, report: str, cs: CrashSite) -> tuple[str, str, str]:
    main, freed, _ = split_manifestation_report(report)
    report.lower()
    if "use-after-free" in bug_type.lower() or "double free" in bug_type.lower():
        current = re.search(r"\bPID:\s*(\d+)", main)
        freed_task = re.search(r"Freed by task\s+(\d+)", report)
        async_markers = (
            "workqueue",
            "process_one_work",
            "rcu_core",
            "call_rcu",
            "timer",
            "tasklet",
            "softirq",
            "irq/",
        )
        if (current and freed_task and current.group(1) != freed_task.group(1)) or any(
            x in (main + freed).lower() for x in async_markers
        ):
            return (
                "unbounded",
                "high",
                "Free/access occur in different tasks or asynchronous contexts",
            )
        if freed:
            shared = syscall_functions(parse_frames(main)) & syscall_functions(parse_frames(freed))
            if shared:
                return (
                    "within the same syscall",
                    "medium",
                    "Free and manifestation stacks share a syscall frame",
                )
            if current and freed_task and current.group(1) == freed_task.group(1):
                return (
                    "across syscalls within one session",
                    "medium",
                    "Free/access share a task but not a syscall frame",
                )
            return "unbounded", "medium", "A distinct free stack precedes the later invalid access"
        return "not determined", "low", "UAF report has no usable free-stack anchor"
    if any(
        x in bug_type.lower()
        for x in ("out-of-bounds", "null dereference", "arithmetic/type ub", "uninitialized")
    ):
        return (
            "within the same syscall",
            "medium",
            "Detector fires at the invalid operation/consumption site",
        )
    if "data race" in bug_type.lower():
        return (
            "unbounded",
            "medium",
            "Conflicting accesses may occur in independently scheduled contexts",
        )
    if any(x in bug_type.lower() for x in ("deadlock", "hang", "lockup")):
        return (
            "not applicable",
            "medium",
            "No corruption-to-manifestation interval is defined for this liveness/locking failure",
        )
    return "not determined", "low", "Report lacks an allocation/free/origin anchor suitable for Δt"


def bug_url_for_key(key: str) -> str:
    if key.startswith("extid-"):
        return "https://syzkaller.appspot.com/bug?extid=" + key[6:]
    if key.startswith("id-"):
        return "https://syzkaller.appspot.com/bug?id=" + key[3:]
    return "https://syzkaller.appspot.com/"


def choose_crash_record(bug: dict[str, Any]) -> dict[str, Any]:
    """Return the first report-bearing crash in the source metadata order.

    Reproducer fields are deliberately ignored: cohort membership and report
    selection depend only on the crash report and downloaded fix patches.
    """
    for crash in bug.get("crashes") or []:
        if not crash.get("crash-report-link"):
            continue
        return crash
    return {}


def parse_timestamp(value: object) -> datetime | None:
    """Read retained syzbot slash timestamps and ISO timestamps without guessing zones."""
    if not isinstance(value, str) or not value.strip():
        return None
    candidate = value.strip()
    if re.match(r"^\d{4}/\d{2}/\d{2}(?:[ T]|$)", candidate):
        candidate = candidate[:10].replace("/", "-") + candidate[10:]
    try:
        return datetime.fromisoformat(candidate.replace("Z", "+00:00"))
    except ValueError:
        return None


def date_only(value: str | None) -> str:
    timestamp = parse_timestamp(value)
    return timestamp.date().isoformat() if timestamp is not None else ""


def make_summary(rows: list[dict[str, Any]], hunk_rows: list[dict[str, Any]]) -> dict[str, Any]:
    def count(field: str) -> dict[str, int]:
        return dict(
            sorted(
                Counter(str(r.get(field, "")) for r in rows).items(), key=lambda x: (-x[1], x[0])
            )
        )

    cross: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for row in rows:
        cross[row["bug_family"]][row["distance_label"]] += 1
    cross_bug_patch: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for row in rows:
        cross_bug_patch[row["bug_family"]][row["patch_type"]] += 1
    return {
        "cohort_size": len(rows),
        "hunk_count": len(hunk_rows),
        "counts": {
            "detector": count("detector"),
            "bug_family": count("bug_family"),
            "bug_type": count("bug_type"),
            "patch_type": count("patch_type"),
            "distance": count("distance_label"),
            "stack_distance": count("stack_distance"),
            "temporal_distance": count("temporal_distance"),
            "crash_confidence": count("cs_confidence"),
            "distance_confidence": count("distance_confidence"),
            "review_status": count("review_status"),
        },
        "bug_family_by_distance": {k: dict(v) for k, v in sorted(cross.items())},
        "bug_family_by_patch_type": {k: dict(v) for k, v in sorted(cross_bug_patch.items())},
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output = writable_path(args.output)
    root = args.root.resolve()
    bug_dir = root / "data/raw/bugs"
    report_dir = root / "data/artifacts/reports"
    patch_dir = root / "data/artifacts/patches"
    catalog_path = root / "data/processed/catalog.json"
    if not catalog_path.is_file():
        parser.error("current catalog is required; run ss update or scripts.build_catalog first")
    catalog_payload = json.loads(read_text(catalog_path))
    baseline_path = root / "data/processed/refresh_baseline.json"
    completeness_baseline = json.loads(read_text(baseline_path)) if baseline_path.exists() else {}
    resolved_fix_path = root / "data/processed/resolved_fix_hashes.json"
    resolved_fix_payload = (
        json.loads(read_text(resolved_fix_path))
        if resolved_fix_path.exists()
        else {"resolutions": []}
    )
    resolved_fix_map = {
        (
            item.get("bug_key", ""),
            normalize_fix_title(item.get("title")),
            item.get("repo") or "",
        ): item
        for item in resolved_fix_payload.get("resolutions", [])
        if item.get("status") == "resolved" and item.get("hash")
    }
    catalog = {entry["key"]: entry for entry in catalog_payload.get("bugs", [])}
    rows: list[dict[str, Any]] = []
    hunk_rows: list[dict[str, Any]] = []
    manifest: list[dict[str, Any]] = []
    local_keys: set[str] = set()

    for bug_path in sorted(bug_dir.glob("*.json")):
        key = bug_path.stem
        if key not in catalog:
            continue
        local_keys.add(key)
        bug = json.loads(read_text(bug_path))
        report_path = report_dir / f"{key}.txt"
        report_ok = report_path.exists() and report_path.stat().st_size > 0
        fixes, fix_hash_sources = resolved_fixes(key, catalog[key], bug, resolved_fix_map)
        available_fixes = [x for x in fixes if (patch_dir / f"{x['hash']}.diff").exists()]
        included = report_ok and bool(available_fixes)
        manifest.append(
            {
                "bug_key": key,
                "title": bug.get("title", ""),
                "report": report_ok,
                "fix_commits_with_hash": len(fixes),
                "patches_available": len(available_fixes),
                "included": included,
                "exclusion_reason": ""
                if included
                else "; ".join(
                    x
                    for x in (
                        "missing/empty report" if not report_ok else "",
                        "no hashed fix commit in Syzbot metadata" if not fixes else "",
                        "no downloaded patch for hashed fix commit"
                        if fixes and not available_fixes
                        else "",
                    )
                    if x
                ),
            }
        )
        if not included:
            continue

        report = read_text(report_path)
        crash_rec = choose_crash_record(bug)
        cs = locate_crash_site(bug.get("title", ""), report)
        bug_class = classify_bug(bug.get("title", ""), report)
        all_hunks: list[Hunk] = []
        patch_titles: list[str] = []
        commit_links: list[str] = []
        total_add = total_del = 0
        for fix in available_fixes:
            patch_title, hunks, stats = parse_patch(
                patch_dir / f"{fix['hash']}.diff", fix["hash"], fix.get("title", "")
            )
            patch_titles.append(patch_title)
            commit_links.append(fix.get("link") or f"https://git.kernel.org/linus/{fix['hash']}")
            total_add += stats["additions"]
            total_del += stats["deletions"]
            all_hunks.extend(hunks)
        code_hunks = [h for h in all_hunks if h.is_source] or all_hunks
        for hunk in code_hunks:
            grade_hunk(cs, hunk)
        distances = [h.distance for h in code_hunks if h.distance is not None]
        max_distance = max(distances) if distances else None
        min_distance = min(distances) if distances else None
        farthest = next((h for h in code_hunks if h.distance == max_distance), None)
        fix_functions = sorted({f for h in code_hunks for f in h.functions})
        # D0 establishes that the changed statement/adjacent guard is in the
        # crashing frame even when git's hunk header names a surrounding macro,
        # label, or global initializer instead of the enclosing function.
        if (
            cs.function
            and any(h.distance == 0 for h in code_hunks)
            and cs.function not in fix_functions
        ):
            fix_functions.append(cs.function)
            fix_functions.sort()
        fix_paths = sorted({h.path for h in code_hunks if h.path})
        patch_class = classify_patch(" | ".join(patch_titles), code_hunks)
        s_value, s_reason = stack_distance(cs, fix_functions)
        t_value, t_conf, t_reason = temporal_distance(bug_class["bug_type"], report, cs)
        distance_label = DISTANCE_LABELS[max_distance] if max_distance is not None else "Unresolved"
        distance_conf = farthest.distance_confidence if farthest else "low"
        qc: list[str] = []
        if cs.confidence == "low" or not cs.path:
            qc.append("CS needs manual review")
        if max_distance is None:
            qc.append("distance unresolved")
        if max_distance in {4, 5}:
            qc.append("D4/D5 uses path-based MAINTAINERS proxy")
        if len(code_hunks) > 1:
            qc.append("multi-hunk maximum applied")
        if len(available_fixes) > 1:
            qc.append("multiple fix commits")
        if "KCSAN" in bug_class["detector"]:
            qc.append("dual conflicting access sites")
        if not fix_functions:
            qc.append("FS function unresolved")
        review_status = (
            "Manual review recommended"
            if any(
                x in "; ".join(qc)
                for x in ("CS needs", "distance unresolved", "FS function unresolved")
            )
            else "Automated classification"
        )
        annotation = f"{distance_label.split()[0]}/S={s_value}/Δt={t_value}"
        row = {
            "bug_key": key,
            "bug_url": bug_url_for_key(key),
            "title": bug.get("title", ""),
            "status": bug.get("status", ""),
            "first_crash": date_only(bug.get("first-crash")),
            "last_crash": date_only(bug.get("last-crash")),
            "fix_time": date_only(bug.get("fix-time")),
            "close_time": date_only(bug.get("close-time")),
            "days_first_to_fix": "",
            "detector": bug_class["detector"],
            "bug_family": bug_class["bug_family"],
            "bug_type": bug_class["bug_type"],
            "access_mode": bug_class["access_mode"],
            "bug_class_evidence": bug_class["bug_class_evidence"],
            "cs_function": cs.function,
            "cs_path": cs.path,
            "cs_line": cs.line,
            "cs_location": f"{cs.path}:{cs.line}" if cs.path and cs.line else cs.path,
            "cs_component": canonical_component(cs.path),
            "cs_subsystem": canonical_subsystem(cs.path),
            "cs_strategy": cs.strategy,
            "cs_confidence": cs.confidence,
            "cs_evidence": cs.evidence,
            "cs_secondary_function": cs.secondary_function,
            "cs_secondary_location": f"{cs.secondary_path}:{cs.secondary_line}"
            if cs.secondary_path
            else "",
            "fix_commit_count": len(available_fixes),
            "fix_hashes": "; ".join(x["hash"] for x in available_fixes),
            "fix_hash_source": "; ".join(sorted(fix_hash_sources)),
            "fix_commit_urls": "; ".join(commit_links),
            "patch_titles": " | ".join(patch_titles),
            "fix_paths": "; ".join(fix_paths),
            "fix_functions": "; ".join(fix_functions),
            "fix_hunk_count": len(code_hunks),
            "patch_additions": total_add,
            "patch_deletions": total_del,
            "patch_type": patch_class["patch_type"],
            "patch_action": patch_class["patch_action"],
            "patch_class_confidence": patch_class["patch_class_confidence"],
            "patch_class_evidence": patch_class["patch_class_evidence"],
            "distance": max_distance,
            "distance_label": distance_label,
            "distance_min": min_distance,
            "distance_rule": "maximum across all source hunks/available fix commits",
            "distance_reason": farthest.distance_reason if farthest else "",
            "distance_confidence": distance_conf,
            "farthest_fs_location": (
                f"{farthest.path}:{farthest.old_start} ({', '.join(farthest.functions) or farthest.context})"
                if farthest
                else ""
            ),
            "farthest_fs_component": farthest.component if farthest else "",
            "farthest_fs_subsystem": farthest.subsystem if farthest else "",
            "stack_distance": s_value,
            "stack_distance_reason": s_reason,
            "temporal_distance": t_value,
            "temporal_confidence": t_conf,
            "temporal_reason": t_reason,
            "full_annotation": annotation,
            "data_flow_hops_T": "not analyzed (taint analysis required)",
            "report_path": str(report_path.relative_to(root)),
            "report_url": (
                "https://syzkaller.appspot.com" + crash_rec.get("crash-report-link", "")
                if crash_rec.get("crash-report-link", "").startswith("/")
                else crash_rec.get("crash-report-link", "")
            ),
            "kernel_repo": crash_rec.get("kernel-source-git", ""),
            "kernel_commit": crash_rec.get("kernel-source-commit", ""),
            "review_status": review_status,
            "qc_flags": "; ".join(qc),
        }
        # Compute elapsed days without forcing invalid/partial dates into Excel.
        first = parse_timestamp(bug.get("first-crash"))
        fixed = parse_timestamp(bug.get("fix-time"))
        # Mixed naive/aware timestamps require timezone information we do not have.
        if (
            first is not None
            and fixed is not None
            and (first.tzinfo is None) == (fixed.tzinfo is None)
        ):
            row["days_first_to_fix"] = round((fixed - first).total_seconds() / 86400, 1)
        rows.append(row)

        for idx, hunk in enumerate(code_hunks, 1):
            hunk_row = asdict(hunk)
            hunk_row.pop("added_text", None)
            hunk_row.pop("removed_text", None)
            hunk_row.update(
                {
                    "bug_key": key,
                    "bug_title": bug.get("title", ""),
                    "cs_function": cs.function,
                    "cs_location": row["cs_location"],
                    "hunk_index_for_bug": idx,
                    "function_text": "; ".join(hunk.functions),
                    "changed_old_line_text": "; ".join(map(str, hunk.changed_old_lines[:30])),
                    "changed_new_line_text": "; ".join(map(str, hunk.changed_new_lines[:30])),
                    "insertion_anchor_text": "; ".join(map(str, hunk.insertion_anchors[:30])),
                }
            )
            hunk_rows.append(hunk_row)

    # Keep the manifest aligned with the live fixed-bug catalog even if an
    # individual bug JSON request failed. Such records cannot be classified,
    # but accounting for them makes residual incompleteness explicit.
    for key in sorted(set(catalog) - local_keys):
        entry = catalog[key]
        report_path = report_dir / f"{key}.txt"
        report_ok = report_path.exists() and report_path.stat().st_size > 0
        fixes, _ = resolved_fixes(key, entry, None, resolved_fix_map)
        available_fixes = [x for x in fixes if (patch_dir / f"{x['hash']}.diff").exists()]
        manifest.append(
            {
                "bug_key": key,
                "title": entry.get("title", ""),
                "report": report_ok,
                "fix_commits_with_hash": len(fixes),
                "patches_available": len(available_fixes),
                "included": False,
                "exclusion_reason": "; ".join(
                    x
                    for x in (
                        "bug JSON unavailable",
                        "missing/empty report" if not report_ok else "",
                        "no hashed fix commit in Syzbot metadata" if not fixes else "",
                        "no downloaded patch for hashed fix commit"
                        if fixes and not available_fixes
                        else "",
                    )
                    if x
                ),
            }
        )

    manifest.sort(key=lambda item: item["bug_key"])

    summary = make_summary(rows, hunk_rows)
    completeness = {
        "live_fixed_listing": len(catalog),
        "local_bug_json": len(local_keys),
        "nonempty_crash_reports": sum(bool(m["report"]) for m in manifest),
        "bugs_with_hashed_fix": sum(m["fix_commits_with_hash"] > 0 for m in manifest),
        "bugs_with_downloaded_patch": sum(m["patches_available"] > 0 for m in manifest),
        "included": len(rows),
        "missing_bug_json": sum("bug JSON unavailable" in m["exclusion_reason"] for m in manifest),
        "missing_or_empty_report": sum(
            "missing/empty report" in m["exclusion_reason"] for m in manifest
        ),
        "no_hashed_fix": sum("no hashed fix commit" in m["exclusion_reason"] for m in manifest),
        "hashed_fix_without_patch": sum(
            "no downloaded patch" in m["exclusion_reason"] for m in manifest
        ),
    }
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "methodology_version": "1.1-report-patch-cohort",
        "cohort_definition": "Current catalog fixed Syzbot bugs with a non-empty local crash-report artifact and >=1 downloaded patch for a hashed fix commit. Short reports are retained; reproducer files and fields are ignored.",
        "distance_note": "D4/D5 are path-taxonomy proxies for MAINTAINERS membership; validate against the historical tree before publication claims.",
        "catalog_source": catalog_payload.get("source", ""),
        "catalog_generated_at": catalog_payload.get("generated_at", ""),
        "completeness": completeness,
        "completeness_baseline": completeness_baseline,
        "supplemental_fix_resolution": {
            "method": resolved_fix_payload.get("method", ""),
            "resolved_fix_records": len(resolved_fix_map),
        },
        "summary": summary,
        "bugs": rows,
        "hunks": hunk_rows,
        "manifest": manifest,
    }
    write_text(args.output, json.dumps(payload, indent=2, ensure_ascii=False) + "\n")
    print(
        json.dumps(
            {
                "output": str(args.output),
                "cohort": len(rows),
                "hunks": len(hunk_rows),
                "distance": summary["counts"]["distance"],
                "review": summary["counts"]["review_status"],
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
