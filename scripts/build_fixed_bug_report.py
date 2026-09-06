#!/usr/bin/env python3
"""Build the comprehensive Markdown report from the auditable analysis JSON."""

from __future__ import annotations

import argparse
import json
import math
import statistics
from collections import Counter
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .common import writable_path, write_text

DISTANCE_NAMES = {
    0: "D0 Coincident",
    1: "D1 Intra-function",
    2: "D2 Intra-file",
    3: "D3 Intra-component",
    4: "D4 Intra-subsystem",
    5: "D5 Cross-subsystem",
}


CURATED_EXAMPLES = {
    "extid-0141c834e47059395621": "An RCU guard is added at the IPv6 multicast manifestation statement.",
    "extid-0315f8fe99120601ba88": "The JFS array-index validation corrects the exact UBSAN expression site.",
    "extid-031d0cfd7c362817963f": "A lifetime correction touches the crashing unregister statement, while the report anchors an unbounded free-to-use interval.",
    "extid-05d7520be047c9be86e0": "The bounds repair stays inside the crashing bcachefs formatting function.",
    "extid-12479ae15958fc3f54ec": "Landlock changes the same hook, but away from the might_sleep manifestation line.",
    "extid-30b53487d00b4f7f0922": "An OCFS2 consistency guard is introduced earlier in the same lookup function.",
    "extid-005d2a9ecd9fbf525f6a": "The victim assertion and missing reference acquisition are in different functions of bnode.c.",
    "extid-0154da2d403396b2bd59": "Steam input opens a freed object; teardown is corrected in another function of the same driver file.",
    "extid-068ff190354d2f74892f": "io_recv consumes uninitialized state prepared by another function in io_uring/net.c.",
    "extid-01218003be74b5e1213a": "exFAT consumes the bad state in dir.c, while initialization is repaired in namei.c.",
    "extid-038b7bf43423e132b308": "An ext4 extent-status invariant fires downstream of invalid inode flags rejected in inode.c.",
    "extid-0d33ab192bd50b6c91e6": "The media test driver frees SI state in another source file of the same component.",
    "extid-08936936fe8132f91f1a": "An XDP warning manifests through generic networking code; the missing ops lock is added elsewhere in net/core.",
    "extid-2fa344348a579b779e05": "skb_clone is the net-core victim; HSR repairs the NULL-producing path in another network component.",
    "extid-346474e3bf0b26bd3090": "Generic socket copyout exposes address bytes left uninitialized by IEEE 802.15.4 code.",
    "extid-019ced393ab913002b75": "I2C object-debugging is the victim; the media frontend repairs its remove lifetime.",
    "extid-25b83a6f2c702075fcbc": "iov_iter detects the overrun, while netfs write-retry logic repairs the iterator state.",
    "extid-37fd81fa4305a9eadfb0": "vsprintf writes through freed data; media request allocation/lifetime is the cross-subsystem cause.",
}


def esc(value: Any, limit: int | None = None) -> str:
    text = "" if value is None else str(value)
    text = " ".join(text.replace("\\|", "|").replace("|", "\\|").split())
    if limit and len(text) > limit:
        return text[: limit - 1].rstrip() + "…"
    return text


def md_table(headers: list[str], rows: Iterable[Iterable[Any]]) -> str:
    body = [[esc(cell) for cell in row] for row in rows]
    out = ["| " + " | ".join(headers) + " |", "| " + " | ".join("---" for _ in headers) + " |"]
    out.extend("| " + " | ".join(row) + " |" for row in body)
    return "\n".join(out)


def pct(numerator: int, denominator: int) -> str:
    return "0.0%" if not denominator else f"{100 * numerator / denominator:.1f}%"


def median_days(rows: Iterable[dict[str, Any]]) -> str:
    values = [
        r["days_first_to_fix"] for r in rows if isinstance(r.get("days_first_to_fix"), (int, float))
    ]
    return "—" if not values else f"{statistics.median(values):.1f}"


def quantile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    if not ordered:
        return float("nan")
    position = (len(ordered) - 1) * fraction
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    weight = position - lower
    return ordered[lower] * (1 - weight) + ordered[upper] * weight


def distance_code(row: dict[str, Any]) -> str:
    return "Unresolved" if row.get("distance") is None else f"D{row['distance']}"


def known_stack(row: dict[str, Any]) -> bool:
    return str(row.get("stack_distance", "")) not in {"", "unknown"}


def wilson_interval(successes: int, observations: int, z: float = 1.96) -> tuple[float, float]:
    if not observations:
        return 0.0, 0.0
    p = successes / observations
    denominator = 1 + z * z / observations
    center = (p + z * z / (2 * observations)) / denominator
    margin = z * math.sqrt((p * (1 - p) + z * z / (4 * observations)) / observations) / denominator
    return center - margin, center + margin


def pct_interval(successes: int, observations: int) -> str:
    low, high = wilson_interval(successes, observations)
    return f"{100 * low:.1f}%–{100 * high:.1f}%"


def odds_ratio_interval(a: int, b: int, c: int, d: int) -> tuple[float, float, float]:
    # Haldane correction keeps the estimate finite for sparse detector slices.
    aa, bb, cc, dd = (value + 0.5 for value in (a, b, c, d))
    odds_ratio = aa * dd / (bb * cc)
    standard_error = math.sqrt(1 / aa + 1 / bb + 1 / cc + 1 / dd)
    return (
        odds_ratio,
        math.exp(math.log(odds_ratio) - 1.96 * standard_error),
        math.exp(math.log(odds_ratio) + 1.96 * standard_error),
    )


def rankdata(values: list[float]) -> list[float]:
    order = sorted(range(len(values)), key=values.__getitem__)
    ranks = [0.0] * len(values)
    index = 0
    while index < len(order):
        end = index + 1
        while end < len(order) and values[order[end]] == values[order[index]]:
            end += 1
        average_rank = (index + 1 + end) / 2
        for position in order[index:end]:
            ranks[position] = average_rank
        index = end
    return ranks


def pearson(x: list[float], y: list[float]) -> float:
    if len(x) < 2 or len(x) != len(y):
        return float("nan")
    x_mean, y_mean = statistics.mean(x), statistics.mean(y)
    numerator = sum((a - x_mean) * (b - y_mean) for a, b in zip(x, y, strict=False))
    denominator = math.sqrt(sum((a - x_mean) ** 2 for a in x) * sum((b - y_mean) ** 2 for b in y))
    return numerator / denominator if denominator else float("nan")


def spearman(x: list[float], y: list[float]) -> float:
    return pearson(rankdata(x), rankdata(y))


def select_detector_examples(bugs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    preferred_strategy = {
        "KASAN": ("sanitizer title", "sanitizer explicit"),
        "KMSAN": ("sanitizer title", "sanitizer explicit"),
        "KFENCE": ("sanitizer title", "sanitizer explicit"),
        "UBSAN": ("sanitizer explicit",),
        "KCSAN": ("KCSAN conflicting",),
        "BUG/Oops": ("RIP symbol", "explicit BUG/WARNING", "ordinary title"),
        "WARN": ("explicit BUG/WARNING", "ordinary title"),
        "Lockdep": ("ordinary title", "explicit BUG/WARNING"),
        "RCU diagnostics": ("explicit RCU", "explicit BUG/WARNING"),
        "Hung-task detector": ("ordinary title",),
        "Leak detector": ("ordinary title",),
        "Kernel fault/other": ("RIP symbol", "ordinary title", "first non-runtime"),
    }
    selected = []
    for detector in sorted({b["detector"] for b in bugs}):
        preferred = preferred_strategy.get(detector, ())
        candidates = sorted(
            (b for b in bugs if b["detector"] == detector and b.get("distance") is not None),
            key=lambda b: (
                next(
                    (
                        i
                        for i, prefix in enumerate(preferred)
                        if b.get("cs_strategy", "").startswith(prefix)
                    ),
                    len(preferred),
                ),
                b.get("cs_confidence") != "high",
                b.get("distance_confidence") == "low",
                b.get("stack_distance") == "unknown",
                -int(b.get("distance") or 0),
                b["bug_key"],
            ),
        )
        if candidates:
            selected.append(candidates[0])
    return selected


def select_temporal_examples(bugs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    selected = []
    for bucket in (
        "within the same syscall",
        "across syscalls within one session",
        "unbounded",
        "not applicable",
        "not determined",
    ):
        candidates = sorted(
            (b for b in bugs if b["temporal_distance"] == bucket and b.get("distance") is not None),
            key=lambda b: (
                b.get("temporal_confidence") == "low",
                b.get("cs_confidence") != "high",
                -int(b.get("distance") or 0),
                b["bug_key"],
            ),
        )
        if candidates:
            selected.append(candidates[0])
    return selected


def select_examples(bugs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_key = {b["bug_key"]: b for b in bugs}
    selected = [by_key[k] for k in CURATED_EXAMPLES if k in by_key]
    selected_keys = {b["bug_key"] for b in selected}
    for distance in range(6):
        have = sum(b.get("distance") == distance for b in selected)
        candidates = sorted(
            (
                b
                for b in bugs
                if b.get("distance") == distance and b["bug_key"] not in selected_keys
            ),
            key=lambda b: (
                b.get("cs_confidence") != "high",
                b.get("distance_confidence") != "high",
                b.get("stack_distance") == "unknown",
                b["bug_key"],
            ),
        )
        for bug in candidates[: max(0, 3 - have)]:
            selected.append(bug)
            selected_keys.add(bug["bug_key"])
    return sorted(selected, key=lambda b: (b.get("distance", 99), b["bug_key"]))


def select_diverse_victims(rows: list[dict[str, Any]], limit: int = 20) -> list[dict[str, Any]]:
    rows = sorted(
        rows,
        key=lambda b: (
            not b.get("bug_type", "").startswith(("Use-after-free", "Out-of-bounds")),
            -int(b.get("distance") or 0),
            b.get("cs_subsystem", ""),
            b["bug_key"],
        ),
    )
    chosen: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for row in rows:
        transition = (row.get("cs_subsystem", ""), row.get("farthest_fs_subsystem", ""))
        if transition in seen:
            continue
        chosen.append(row)
        seen.add(transition)
        if len(chosen) == limit:
            return chosen
    for row in rows:
        if row not in chosen:
            chosen.append(row)
        if len(chosen) == limit:
            break
    return chosen


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("analysis", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    args.output = writable_path(args.output)

    analysis = json.loads(args.analysis.read_text())
    bugs: list[dict[str, Any]] = analysis["bugs"]
    hunks: list[dict[str, Any]] = analysis["hunks"]
    manifest: list[dict[str, Any]] = analysis["manifest"]
    total = len(bugs)
    resolved = [b for b in bugs if b.get("distance") is not None]
    known_s = [b for b in bugs if known_stack(b)]
    far = [b for b in resolved if b["distance"] >= 3]
    off_stack = [b for b in known_s if b["stack_distance"] == "∞"]
    multi_hunk = [b for b in bugs if b.get("fix_hunk_count", 0) > 1]
    max_min_diff = [
        b
        for b in bugs
        if b.get("distance") is not None
        and b.get("distance_min") is not None
        and b["distance"] > b["distance_min"]
    ]
    uaf = [b for b in bugs if b.get("bug_type", "").startswith("Use-after-free")]
    victim = [
        b
        for b in bugs
        if b.get("distance") in {4, 5}
        and b.get("stack_distance") == "∞"
        and b.get("temporal_distance") == "unbounded"
    ]
    latencies = [
        b["days_first_to_fix"] for b in bugs if isinstance(b.get("days_first_to_fix"), (int, float))
    ]
    completeness = analysis.get("completeness") or {}
    baseline = analysis.get("completeness_baseline") or {}

    logic_patch_types = {
        "Validation/guard",
        "Logic/control-flow correction",
        "Bounds/size correction",
        "Arithmetic/type correction",
    }
    ref_lock_patch_types = {"Synchronization/ordering", "Refcount/accounting correction"}
    memory_corruption_types = {
        "Use-after-free (read)",
        "Use-after-free (write)",
        "Use-after-free",
        "Out-of-bounds access (read)",
        "Out-of-bounds access (write)",
        "Invalid/double free",
        "Invalid/wild memory access",
    }
    framework_groups = {
        "Logic/condition repair proxy": [b for b in bugs if b["patch_type"] in logic_patch_types],
        "Refcount/locking repair proxy": [
            b for b in bugs if b["patch_type"] in ref_lock_patch_types
        ],
        "Memory-corruption diagnosis": [
            b for b in bugs if b["bug_type"] in memory_corruption_types
        ],
    }

    far_known = [b for b in known_s if b.get("distance") is not None and b["distance"] >= 3]
    near_known = [b for b in known_s if b.get("distance") is not None and b["distance"] <= 2]
    far_off = sum(b["stack_distance"] == "∞" for b in far_known)
    near_off = sum(b["stack_distance"] == "∞" for b in near_known)
    offstack_or, offstack_or_low, offstack_or_high = odds_ratio_interval(
        far_off, len(far_known) - far_off, near_off, len(near_known) - near_off
    )
    latency_pairs = [b for b in resolved if isinstance(b.get("days_first_to_fix"), (int, float))]
    distance_latency_rho = spearman(
        [float(b["distance"]) for b in latency_pairs],
        [float(b["days_first_to_fix"]) for b in latency_pairs],
    )
    patch_size_pairs = [
        b for b in resolved if (b.get("patch_additions", 0) + b.get("patch_deletions", 0)) > 0
    ]
    distance_patch_size_rho = spearman(
        [float(b["distance"]) for b in patch_size_pairs],
        [
            math.log1p(float(b.get("patch_additions", 0) + b.get("patch_deletions", 0)))
            for b in patch_size_pairs
        ],
    )

    manifest_reasons = Counter(m["exclusion_reason"] for m in manifest if not m["included"])
    distance_counts = Counter(b.get("distance") for b in bugs)
    min_counts = Counter(b.get("distance_min") for b in bugs)
    bug_families = Counter(b["bug_family"] for b in bugs)
    bug_types = Counter(b["bug_type"] for b in bugs)
    patch_types = Counter(b["patch_type"] for b in bugs)
    detectors = Counter(b["detector"] for b in bugs)
    temporal = Counter(b["temporal_distance"] for b in bugs)
    uaf_temporal = Counter(b["temporal_distance"] for b in uaf)

    lines: list[str] = []
    add = lines.append
    add("# Syzbot Fixed-Bug Crash–Fix Distance Study")
    add("")
    add(
        f"Generated {datetime.now(timezone.utc).date().isoformat()} from the synchronized live Syzbot fixed-bug listing and local artifacts. The analysis includes **{total:,} fixed bugs** and **{len(hunks):,} analyzed fix hunks**. A bug is included if and only if it has a non-empty downloaded crash-report artifact and at least one downloaded patch for a hashed fix commit. Short reports are retained and routed to QC when they cannot support CS extraction. Reproducer files and reproducer metadata are not consulted."
    )
    add("")
    add("## Executive findings")
    add("")
    add(
        f"1. **Crash and fix are frequently non-local.** {len(far):,} of {len(resolved):,} structurally resolved bugs ({pct(len(far), len(resolved))}) are D3–D5. Only {distance_counts[0] + distance_counts[1]:,} resolved bugs ({pct(distance_counts[0] + distance_counts[1], len(resolved))}) are D0–D1."
    )
    add(
        f"2. **The stack often omits every fixed function.** {len(off_stack):,} of {len(known_s):,} bugs with known S ({pct(len(off_stack), len(known_s))}) are `S=∞`. D0–D1 are almost always `S=0`, while D4–D5 are predominantly off-stack."
    )
    add(
        f"3. **UAF is the clearest temporal victim-site class.** {uaf_temporal['unbounded']:,} of {len(uaf):,} UAF bugs ({pct(uaf_temporal['unbounded'], len(uaf))}) are `Δt=unbounded`; {len(victim):,} bugs combine `D4/D5`, `S=∞`, and `Δt=unbounded`."
    )
    add(
        f"4. **The required maximum-hunk rule changes the result materially.** {len(max_min_diff):,} bugs have structural D(max) greater than D(min), representing {pct(len(max_min_diff), total)} of the cohort and {pct(len(max_min_diff), len(multi_hunk))} of multi-hunk bugs."
    )
    add(
        f"5. **Distance and repair latency move together descriptively.** Median first-crash-to-fix time rises from {median_days(b for b in bugs if b.get('distance') == 0)} days at D0 to {median_days(b for b in bugs if b.get('distance') == 5)} days at D5. This is association, not causation."
    )
    add(
        f"6. **Structural and stack distance agree without being interchangeable.** Among known-S cases, D3–D5 bugs have {offstack_or:.2f}× the odds of being off-stack compared with D0–D2 (95% CI {offstack_or_low:.2f}–{offstack_or_high:.2f})."
    )
    if baseline and completeness:
        recovered = int(completeness.get("included", total)) - int(
            baseline.get("included_report_and_patch_bugs", 0)
        )
        add(
            f"7. **The completeness work materially expands the evidence base.** It adds {recovered:,} analyzable report-and-patch bugs relative to the prior {int(baseline.get('included_report_and_patch_bugs', 0)):,}-bug cohort."
        )
    add("")
    add("## Corpus and inclusion audit")
    add("")
    add(
        md_table(
            ["Manifest category", "Bugs", f"Share of {len(manifest):,} live fixed records"],
            [
                [
                    "Included: non-empty report + ≥1 downloaded patch",
                    total,
                    pct(total, len(manifest)),
                ],
                *[
                    [reason, count, pct(count, len(manifest))]
                    for reason, count in manifest_reasons.most_common()
                ],
                ["All live fixed-bug records in manifest", len(manifest), "100.0%"],
            ],
        )
    )
    add("")
    add(
        f"The cohort is a report-and-patch intersection. It retains {sum(b.get('fix_commit_count', 0) > 1 for b in bugs):,} bugs with multiple downloaded fix commits and grades every available source hunk. Any non-empty artifact reached through a Syzbot crash-report link satisfies the presence rule; evidence-poor short reports remain analyzable only to the extent their content permits. No record is included, excluded, prioritized, or reweighted based on reproduction material."
    )
    add(
        f"The completeness denominator is the dated Syzbot `upstream/fixed` listing snapshot ({analysis.get('catalog_source') or 'https://syzkaller.appspot.com/upstream/fixed?json=1'}), not every experimental manager or downstream dashboard namespace."
    )
    if baseline and completeness:
        add("")
        add("### Completeness comparison")
        add("")
        add(
            md_table(
                ["Metric", "Earlier dataset", "Current dataset", "Change"],
                [
                    [
                        "Fixed bugs in listing",
                        baseline.get("fixed_listing_records", "—"),
                        completeness.get("live_fixed_listing", len(manifest)),
                        int(completeness.get("live_fixed_listing", len(manifest)))
                        - int(baseline.get("fixed_listing_records", 0)),
                    ],
                    [
                        "Local bug JSON",
                        baseline.get("local_bug_json", "—"),
                        completeness.get("local_bug_json", "—"),
                        int(completeness.get("local_bug_json", 0))
                        - int(baseline.get("local_bug_json", 0)),
                    ],
                    [
                        "Crash reports meeting inclusion rule",
                        baseline.get("usable_crash_reports", "—"),
                        completeness.get("nonempty_crash_reports", "—"),
                        int(completeness.get("nonempty_crash_reports", 0))
                        - int(baseline.get("usable_crash_reports", 0)),
                    ],
                    [
                        "Included report-and-patch bugs",
                        baseline.get("included_report_and_patch_bugs", "—"),
                        completeness.get("included", total),
                        int(completeness.get("included", total))
                        - int(baseline.get("included_report_and_patch_bugs", 0)),
                    ],
                    [
                        "No hashed fix in metadata",
                        baseline.get("title_only_fix_bugs_with_report", "—"),
                        completeness.get("no_hashed_fix", "—"),
                        int(completeness.get("no_hashed_fix", 0))
                        - int(baseline.get("title_only_fix_bugs_with_report", 0)),
                    ],
                    [
                        "Hashed fix without local patch",
                        0,
                        completeness.get("hashed_fix_without_patch", "—"),
                        int(completeness.get("hashed_fix_without_patch", 0)),
                    ],
                ],
            )
        )
        add("")
        recovered = int(
            analysis.get("supplemental_fix_resolution", {}).get("resolved_fix_records", 0)
        )
        add(
            f"The first acquisition stage downloads every patch referenced by a live hashed fix. The second stage fetches missing bug JSON and crash reports and re-queries title-only fixes for newly assigned hashes. Exact commit-subject matching in each record's declared kernel cgit repository established {recovered:,} additional fix hashes; those downloaded patches are included and each affected row is labeled `exact-title cgit resolution` in the workbook. The prior workbook used a >80-byte report threshold; the current cohort follows the owner's exact presence rule and retains all non-empty reports, so the included-bug delta combines artifact recovery with that documented rule correction. Residual exclusions are preserved in the manifest instead of being silently dropped."
        )
    add("")
    add("## Complete conceptual framework")
    add("")
    add("### Basic definitions")
    add("")
    add(
        md_table(
            ["Concept", "Definition", "Operational use in this study"],
            [
                [
                    "Crash site (CS)",
                    "The manifestation point of the fault: symbolize the relevant kernel RIP/PC or detector-specific access/consumption frame to file:line plus enclosing function.",
                    "Runtime detector helpers and user-space RIPs are excluded. The normalized kernel manifestation frame is retained with evidence and confidence.",
                ],
                [
                    "Fix site (FS)",
                    "The root-cause location represented by the fix-commit diff hunks.",
                    "Every available fix hunk is graded. For multi-hunk/multi-commit fixes, the required bug-level result is the maximum distance; the minimum remains a sensitivity measure.",
                ],
                [
                    "Distance",
                    "Deviation between CS and FS along structural, stack, and temporal axes.",
                    "Structural D is primary; S and Δt are orthogonal annotations; T is optional and requires taint analysis.",
                ],
            ],
        )
    )
    add("")
    add(
        "Treating the fix commit as root-cause ground truth follows the project definition and common practice in kernel duplicate-bug research. It is still an operational ground truth: mixed cleanups or broad refactors can extend D(max), which is why the hunk audit and D(min) are retained."
    )
    add("")
    add("### Primary structural grading D0–D5")
    add("")
    add(
        md_table(
            ["Level", "Name", "Definition", "Typical pattern"],
            [
                [
                    "D0",
                    "Coincident",
                    "The fix hunk touches the exact crashing line/statement. The implementation accepts a pure-insertion anchor within ±2 lines for an adjacent guard or small line drift.",
                    "Missing NULL check immediately before dereference; off-by-one at the access.",
                ],
                [
                    "D1",
                    "Intra-function",
                    "FS is in the same function as CS, on different lines.",
                    "Missing lock, state check, or length validation elsewhere in the crashing function.",
                ],
                [
                    "D2",
                    "Intra-file",
                    "FS is in another function within the same source file/compilation unit.",
                    "Handler manifests; a same-file helper produces the invalid state.",
                ],
                [
                    "D3",
                    "Intra-component",
                    "CS and FS cross files within one module, driver, filesystem, or path-derived component.",
                    "Entry point manifests; another file's state machine/lifetime code is repaired.",
                ],
                [
                    "D4",
                    "Intra-subsystem",
                    "CS and FS cross components within one subsystem or MAINTAINERS scope.",
                    "Generic VFS/network path manifests damage produced by a specific component.",
                ],
                [
                    "D5",
                    "Cross-subsystem",
                    "CS and FS belong to different subsystem or MAINTAINERS scopes.",
                    "Classic victim site: allocator, formatter, or generic core reports corruption caused elsewhere.",
                ],
            ],
        )
    )
    add("")
    add(
        "D5 specifically captures the victim-site failure mode: the crashing operation is only where corrupted state is finally consumed. For UAF, arbitrary object reuse can produce many apparently distinct crash sites from one root cause, so crash-site-only deduplication can both overcount and undercount bugs."
    )
    add("")
    add("### Orthogonal annotation axes")
    add("")
    add(
        md_table(
            ["Axis", "Definition", "Values", "Interpretation"],
            [
                [
                    "Stack distance S",
                    "Number of stack-frame edges from CS to the nearest fixed function on the manifestation stack.",
                    "0; finite >0; ∞; unknown",
                    "S=0 means a fixed function is the crashing frame. S=∞ means no extracted fixed function appears on-stack and is a strong localization warning.",
                ],
                [
                    "Temporal distance Δt",
                    "When corruption/state production occurs relative to manifestation.",
                    "within the same syscall; across syscalls within one session; unbounded; not applicable; not determined",
                    "KASAN allocation/free stacks, origin stacks, task IDs, and async contexts anchor the bucket.",
                ],
                [
                    "Data-flow hops T",
                    "Assignments/copies between production of the bad value and its consumption.",
                    "direct; 1–3 hops; >3 hops",
                    "Optional. Not computed here because the corpus has no taint-analysis output.",
                ],
                [
                    "Full annotation",
                    "Conjunction of independent axes.",
                    "Example: D4/S=∞/Δt=unbounded",
                    "Cross-component/subsystem repair, fixed function absent from stack, and temporally decoupled manifestation.",
                ],
            ],
        )
    )
    add("")
    add(
        "The axes must not be collapsed into one another. A D0 fix can still have unbounded Δt when a local lifetime statement is revisited much later; a D5 fix can occasionally be visible on-stack through a cross-subsystem call path."
    )
    add("")
    add("### Expected correlation with bug classes")
    add("")
    add(
        md_table(
            [
                "Bug class",
                "Expected structural locality",
                "Expected S/Δt",
                "Deduplication consequence",
            ],
            [
                [
                    "Logic bugs: missing checks, wrong conditions",
                    "Mostly D0–D1",
                    "Usually S=0 and detected in the invalid operation",
                    "Crash title and top-frame identity often approximate root cause.",
                ],
                [
                    "Refcount and locking bugs",
                    "Mostly D1–D3",
                    "Fixed function often on-stack, but IRQ/process/async context may inflate S",
                    "Include component, execution context, and synchronization/lifetime features.",
                ],
                [
                    "Memory corruption: OOB write, UAF",
                    "Concentrated D3–D5",
                    "Often S=∞ and Δt=unbounded",
                    "Treat CS as victim; prioritize alloc/free stacks, producer subsystem, object type, and fix-root features.",
                ],
            ],
        )
    )
    add("")
    add(
        "The evaluation below tests these expectations using deterministic, explicitly defined proxies. Those proxies improve reproducibility but are not a substitute for expert manual causal labeling."
    )
    add("")
    add("## Operational method")
    add("")
    add("### Crash-site extraction")
    add("")
    add(
        "The crash site is the kernel manifestation point, not automatically the literal machine RIP printed first in the log. The parser applies detector-specific rules:"
    )
    add("")
    add(
        "- **KASAN, KMSAN, and KFENCE:** skip reporting/instrumentation helpers and bind the normalized title function to a symbolized kernel frame. Allocation, free, and origin sections may recover a missing file path for the titled function, but they are not substituted for the manifestation stack."
    )
    add(
        "- **UBSAN:** prefer the explicit `file:line:column` expression location and bind it to the enclosing/titled function."
    )
    add(
        "- **KCSAN:** retain both conflicting access sites; the first normalized access is the primary CS and the second is recorded separately."
    )
    add(
        "- **BUG, WARN, lockdep, and liveness reports:** prefer an explicit source location or the normalized title function on the symbolized kernel stack."
    )
    add(
        "- **Ordinary oops:** match the kernel RIP/PC symbol to a symbolized source frame; user-space RIP values and sanitizer runtime helpers are ignored."
    )
    add("")
    add(
        f"This produces {sum(b['cs_confidence'] == 'high' for b in bugs):,} high-confidence, {sum(b['cs_confidence'] == 'medium' for b in bugs):,} medium-confidence, and {sum(b['cs_confidence'] == 'low' for b in bugs):,} low-confidence CS records."
    )
    add("")
    add("### Fix sites and structural grading")
    add("")
    add(
        "Every changed hunk from every downloaded fix commit is treated as an FS candidate. Source hunks are preferred; a non-source hunk is retained only when no source hunk exists. The bug-level grade is the maximum hunk distance, exactly following the requested rule. D0 accepts a changed old line or pure-insertion anchor within ±2 lines of the CS to accommodate an adjacent guard and small report/patch line drift."
    )
    add("")
    add(
        "D0–D3 use line, function, file, and path-derived component relations. D4–D5 use a documented path taxonomy as a proxy for historical MAINTAINERS membership because the corpus does not contain a checked-out historical kernel tree for every fix. Consequently, D4/D5 are suitable for exploratory pattern analysis but require historical MAINTAINERS validation before publication as exact maintainer-entry boundaries."
    )
    add("")
    add("### Orthogonal annotations and classification")
    add("")
    add(
        "S is the number of manifestation-stack frames from CS to the nearest extracted fixed function; `∞` means no fixed function occurs on the available manifestation stack, and `unknown` preserves insufficient evidence. Δt is derived from allocation/free/origin stacks and task/context changes, using the requested buckets. T is not computed because the corpus has no taint-analysis result."
    )
    add("")
    add(
        "Bug type is classified from the normalized title first and the primary crash diagnostic second. Patch type is inferred from the patch title plus added/removed code tokens and structural cues such as new conditionals, locks, frees, and reference operations. Both evidence strings and confidence fields are retained in the workbook."
    )
    add("")
    add("## Structural distance results")
    add("")
    structural_rows = []
    for d in range(6):
        group = [b for b in bugs if b.get("distance") == d]
        group_known = [b for b in group if known_stack(b)]
        structural_rows.append(
            [
                DISTANCE_NAMES[d],
                len(group),
                pct(len(group), total),
                sum(b["stack_distance"] == "0" for b in group),
                sum(b["stack_distance"] == "∞" for b in group),
                pct(sum(b["stack_distance"] == "∞" for b in group_known), len(group_known)),
                sum(b["temporal_distance"] == "unbounded" for b in group),
                median_days(group),
            ]
        )
    structural_rows.append(
        [
            "Unresolved",
            distance_counts[None],
            pct(distance_counts[None], total),
            "—",
            "—",
            "—",
            "—",
            median_days(b for b in bugs if b.get("distance") is None),
        ]
    )
    add(
        md_table(
            [
                "Grade",
                "Bugs",
                "Cohort share",
                "S=0",
                "S=∞",
                "Off-stack among known S",
                "Δt unbounded",
                "Median days to fix",
            ],
            structural_rows,
        )
    )
    add("")
    add(
        f"D2 is the modal single grade ({distance_counts[2]:,} bugs), but D3–D5 dominate collectively. D0 and D1 strongly couple CS and FS to the same stack frame: {sum(b['stack_distance'] == '0' for b in bugs if b.get('distance') in {0, 1}):,} of {distance_counts[0] + distance_counts[1]:,} D0/D1 bugs are `S=0`. By D5, {sum(b['stack_distance'] == '∞' for b in bugs if b.get('distance') == 5):,} records are off-stack."
    )
    add("")
    add("### Maximum versus nearest hunk")
    add("")
    add(
        md_table(
            ["Grade", "D(max) bugs", "D(min) bugs", "Difference"],
            [
                [f"D{d}", distance_counts[d], min_counts[d], distance_counts[d] - min_counts[d]]
                for d in range(6)
            ],
        )
    )
    add("")
    add(
        f"There are {len(multi_hunk):,} multi-hunk bugs ({pct(len(multi_hunk), total)}). In {len(max_min_diff):,}, at least one hunk is closer to CS than the farthest hunk. The most common shifts are:"
    )
    shifts = Counter((b["distance_min"], b["distance"]) for b in max_min_diff)
    add("")
    add(
        md_table(
            ["Nearest→farthest", "Bugs", "Share of max>min"],
            [
                [f"D{lo}→D{hi}", n, pct(n, len(max_min_diff))]
                for (lo, hi), n in shifts.most_common(12)
            ],
        )
    )
    add("")
    add(
        "The maximum answers how widely the complete causal repair reaches. The minimum answers whether any edit is local to the manifestation. Reporting both avoids collapsing a distributed fix to its nearest hunk."
    )
    add(
        f"Structural distance has Spearman ρ={distance_patch_size_rho:.3f} with log patch size (added + deleted lines). This quantifies patch-breadth association but does not determine whether broad patches reveal distributed causality or merely include ancillary edits."
    )
    add("")
    add("## Stack and temporal results")
    add("")
    stack_rows = []
    for d in range(6):
        group = [b for b in bugs if b.get("distance") == d]
        stack_rows.append(
            [
                f"D{d}",
                len(group),
                sum(b["stack_distance"] == "0" for b in group),
                sum(known_stack(b) and b["stack_distance"] not in {"0", "∞"} for b in group),
                sum(b["stack_distance"] == "∞" for b in group),
                sum(not known_stack(b) for b in group),
            ]
        )
    add(md_table(["Grade", "Bugs", "S=0", "Finite S>0", "S=∞", "S unknown"], stack_rows))
    add("")
    add(
        md_table(
            ["Temporal bucket", "All bugs", "Cohort share", "UAF bugs", "Share of UAF"],
            [
                [
                    bucket,
                    temporal[bucket],
                    pct(temporal[bucket], total),
                    uaf_temporal[bucket],
                    pct(uaf_temporal[bucket], len(uaf)),
                ]
                for bucket in (
                    "within the same syscall",
                    "across syscalls within one session",
                    "unbounded",
                    "not applicable",
                    "not determined",
                )
            ],
        )
    )
    add("")
    add(
        "`S=∞` and `Δt=unbounded` measure different phenomena. The former says the fixed function is absent from the observed manifestation stack; the latter says production and consumption are separated in time. Their conjunction is especially informative for UAF, async teardown, stale work items, and delayed object reuse."
    )
    add("")
    add("## Bug classes and patch classes")
    add("")
    family_rows = []
    for family, count in bug_families.most_common():
        group = [b for b in bugs if b["bug_family"] == family]
        group_known = [b for b in group if known_stack(b)]
        family_rows.append(
            [
                family,
                count,
                pct(count, total),
                sum(b.get("distance") is not None and b["distance"] >= 3 for b in group),
                pct(
                    sum(b.get("distance") is not None and b["distance"] >= 3 for b in group),
                    sum(b.get("distance") is not None for b in group),
                ),
                sum(b["stack_distance"] == "∞" for b in group),
                pct(sum(b["stack_distance"] == "∞" for b in group_known), len(group_known)),
            ]
        )
    add(
        md_table(
            [
                "Bug family",
                "Bugs",
                "Share",
                "D3–D5",
                "Far share resolved",
                "S=∞",
                "Off-stack known S",
            ],
            family_rows,
        )
    )
    add("")
    type_rows = []
    for bug_type, count in bug_types.most_common():
        group = [b for b in bugs if b["bug_type"] == bug_type]
        type_rows.append(
            [
                bug_type,
                count,
                sum(b.get("distance") is not None and b["distance"] >= 3 for b in group),
                pct(
                    sum(b.get("distance") is not None and b["distance"] >= 3 for b in group),
                    sum(b.get("distance") is not None for b in group),
                ),
                sum(b["stack_distance"] == "∞" for b in group),
                median_days(group),
            ]
        )
    add(
        md_table(
            [
                "Normalized bug type",
                "Bugs",
                "D3–D5",
                "Far share resolved",
                "S=∞",
                "Median days to fix",
            ],
            type_rows,
        )
    )
    add("")
    patch_rows = []
    for patch_type, count in patch_types.most_common():
        group = [b for b in bugs if b["patch_type"] == patch_type]
        patch_rows.append(
            [
                patch_type,
                count,
                pct(count, total),
                sum(b.get("distance") is not None and b["distance"] >= 3 for b in group),
                pct(
                    sum(b.get("distance") is not None and b["distance"] >= 3 for b in group),
                    sum(b.get("distance") is not None for b in group),
                ),
                sum(b["stack_distance"] == "∞" for b in group),
            ]
        )
    add(md_table(["Patch type", "Bugs", "Share", "D3–D5", "Far share resolved", "S=∞"], patch_rows))
    add("")
    add(
        "The largest normalized patch class is validation/guard, but a validation patch need not be local: a downstream assertion may manifest far from the producer-side guard. Synchronization/ordering and lifetime/resource management are also prominent, consistent with delayed manifestation and off-stack repair. The detailed evidence columns should be used when auditing borderline lexical classifications."
    )
    add("")
    add("### Detectors")
    add("")
    detector_rows = []
    for detector, count in detectors.most_common():
        group = [b for b in bugs if b["detector"] == detector]
        detector_rows.append(
            [
                detector,
                count,
                sum(b.get("distance") is not None and b["distance"] >= 3 for b in group),
                pct(
                    sum(b.get("distance") is not None and b["distance"] >= 3 for b in group),
                    sum(b.get("distance") is not None for b in group),
                ),
                sum(b["stack_distance"] == "∞" for b in group),
            ]
        )
    add(md_table(["Detector", "Bugs", "D3–D5", "Far share resolved", "S=∞"], detector_rows))
    add("")
    add(
        "Sanitizer-aware parsing is necessary even when the normalized title is informative. KASAN/KMSAN/KFENCE first RIPs often belong to detector machinery; UBSAN has a more precise expression line; KCSAN has two legitimate access sites. Treating all formats as an ordinary RIP would systematically bias CS toward runtime helpers."
    )
    add("")
    add("### Crash-site selection strategies")
    add("")
    strategies = Counter(b["cs_strategy"] for b in bugs)
    add(
        md_table(
            ["Selection strategy", "Bugs", "Share", "Low-confidence CS"],
            [
                [
                    strategy,
                    count,
                    pct(count, total),
                    sum(b["cs_confidence"] == "low" for b in bugs if b["cs_strategy"] == strategy),
                ]
                for strategy, count in strategies.most_common()
            ],
        )
    )
    add("")
    add("## Evaluation of the framework predictions")
    add("")
    framework_rows = []
    for name, group in framework_groups.items():
        group_resolved = [b for b in group if b.get("distance") is not None]
        group_known = [b for b in group if known_stack(b)]
        group_far = sum(b["distance"] >= 3 for b in group_resolved)
        group_off = sum(b["stack_distance"] == "∞" for b in group_known)
        framework_rows.append(
            [
                name,
                len(group),
                sum(b["distance"] <= 1 for b in group_resolved),
                pct(sum(b["distance"] <= 1 for b in group_resolved), len(group_resolved)),
                group_far,
                pct(group_far, len(group_resolved)),
                pct_interval(group_far, len(group_resolved)),
                group_off,
                pct(group_off, len(group_known)),
                sum(b["temporal_distance"] == "unbounded" for b in group),
            ]
        )
    add(
        md_table(
            [
                "Operational group",
                "Bugs",
                "D0–D1",
                "Local share",
                "D3–D5",
                "Far share",
                "95% CI",
                "S=∞",
                "Off-stack share",
                "Δt unbounded",
            ],
            framework_rows,
        )
    )
    add("")
    add(
        "Three conclusions follow. First, the logic/condition *patch* proxy is broader than the title-level logic-bug expectation: producer-side validation frequently repairs a downstream manifestation, and D(max) counts any farther causal hunk. Second, refcount/locking repairs are structurally distributed, consistent with cross-function ordering and context changes. Third, memory-corruption diagnoses show the strongest temporal decoupling, especially through UAF free/access anchors."
    )
    add("")
    add("### Quantifying structural–stack association")
    add("")
    add(
        md_table(
            ["Structural group", "Known S", "S=∞", "Off-stack share", "95% CI"],
            [
                [
                    "D0–D2",
                    len(near_known),
                    near_off,
                    pct(near_off, len(near_known)),
                    pct_interval(near_off, len(near_known)),
                ],
                [
                    "D3–D5",
                    len(far_known),
                    far_off,
                    pct(far_off, len(far_known)),
                    pct_interval(far_off, len(far_known)),
                ],
            ],
        )
    )
    add("")
    add(
        f"The estimated odds ratio is **{offstack_or:.2f}** (95% CI **{offstack_or_low:.2f}–{offstack_or_high:.2f}**): a D3–D5 bug has substantially greater odds of being off-stack than a D0–D2 bug. This supports the framework while confirming that D and S are not duplicates—some far fixes remain visible on-stack, and D2 already contains many off-stack helper splits."
    )
    add("")
    add("### Sensitivity to confidence and patch structure")
    add("")
    sensitivity_slices = {
        "All structurally resolved": resolved,
        "High CS + non-low D confidence": [
            b
            for b in resolved
            if b["cs_confidence"] == "high" and b["distance_confidence"] != "low"
        ],
        "Single-hunk fixes": [b for b in resolved if b["fix_hunk_count"] == 1],
        "Multi-hunk fixes": [b for b in resolved if b["fix_hunk_count"] > 1],
    }
    sensitivity_rows = []
    for name, group in sensitivity_slices.items():
        group_known = [b for b in group if known_stack(b)]
        group_far = sum(b["distance"] >= 3 for b in group)
        group_off = sum(b["stack_distance"] == "∞" for b in group_known)
        sensitivity_rows.append(
            [
                name,
                len(group),
                group_far,
                pct(group_far, len(group)),
                pct_interval(group_far, len(group)),
                len(group_known),
                group_off,
                pct(group_off, len(group_known)),
            ]
        )
    add(
        md_table(
            [
                "Slice",
                "Resolved bugs",
                "D3–D5",
                "Far share",
                "95% CI",
                "Known S",
                "S=∞",
                "Off-stack share",
            ],
            sensitivity_rows,
        )
    )
    add("")
    all_far_share = pct(
        sum(b["distance"] >= 3 for b in sensitivity_slices["All structurally resolved"]),
        len(sensitivity_slices["All structurally resolved"]),
    )
    high_far_share = pct(
        sum(b["distance"] >= 3 for b in sensitivity_slices["High CS + non-low D confidence"]),
        len(sensitivity_slices["High CS + non-low D confidence"]),
    )
    single_far_share = pct(
        sum(b["distance"] >= 3 for b in sensitivity_slices["Single-hunk fixes"]),
        len(sensitivity_slices["Single-hunk fixes"]),
    )
    multi_far_share = pct(
        sum(b["distance"] >= 3 for b in sensitivity_slices["Multi-hunk fixes"]),
        len(sensitivity_slices["Multi-hunk fixes"]),
    )
    add(
        f"The strict high-confidence slice has a lower D3–D5 share than the full corpus ({high_far_share} versus {all_far_share}), so the aggregate magnitude is sensitive to extraction confidence and the cases that survive that filter. The conclusion that non-local fixes are common still holds, but the single-versus-multi-hunk split ({single_far_share} versus {multi_far_share}) shows that patch breadth and the required maximum-hunk rule are major contributors. These slices should be reported alongside the headline estimate."
    )
    add("")
    add("### Frequent bug-family × patch-type combinations")
    add("")
    family_patch_pairs = Counter((b["bug_family"], b["patch_type"]) for b in bugs)
    add(
        md_table(
            ["Bug family", "Patch type", "Bugs", "D3–D5", "Far share resolved"],
            [
                [
                    family,
                    patch,
                    count,
                    sum(
                        b.get("distance") is not None and b["distance"] >= 3
                        for b in bugs
                        if b["bug_family"] == family and b["patch_type"] == patch
                    ),
                    pct(
                        sum(
                            b.get("distance") is not None and b["distance"] >= 3
                            for b in bugs
                            if b["bug_family"] == family and b["patch_type"] == patch
                        ),
                        sum(
                            b.get("distance") is not None
                            for b in bugs
                            if b["bug_family"] == family and b["patch_type"] == patch
                        ),
                    ),
                ]
                for (family, patch), count in family_patch_pairs.most_common(20)
            ],
        )
    )
    add("")
    add("## Cross-subsystem transitions")
    add("")
    transitions = Counter(
        (b["cs_subsystem"], b["farthest_fs_subsystem"]) for b in bugs if b.get("distance") == 5
    )
    add(
        md_table(
            ["CS subsystem", "Farthest FS subsystem", "D5 bugs", "Share of D5"],
            [
                [cs, fs, n, pct(n, distance_counts[5])]
                for (cs, fs), n in transitions.most_common(20)
            ],
        )
    )
    add("")
    add(
        "Frequent transitions into networking, filesystems, block, BPF, and generic include/header families match the classic victim mechanism: shared infrastructure reports a violated invariant, while a producer in a more specific component creates the bad pointer, length, state, or lifecycle. Because subsystem labels are path-taxonomy proxies, these transitions are descriptive groupings rather than exact historical maintainer edges."
    )
    add("")
    add("## Representative examples across D0–D5")
    add("")
    examples = select_examples(bugs)
    example_rows = []
    for b in examples:
        interpretation = CURATED_EXAMPLES.get(b["bug_key"])
        if not interpretation:
            interpretation = {
                0: "The fix changes the crashing statement or an adjacent guard.",
                1: "The repair stays inside the crashing function but changes another statement.",
                2: "Manifestation and repair are in different functions of the same source file.",
                3: "Manifestation and repair cross files within one component.",
                4: "Manifestation and repair cross components within the same path-derived subsystem.",
                5: "The manifestation is in a different path-derived subsystem from the farthest causal edit.",
            }.get(b.get("distance"), "Structural site unresolved.")
        example_rows.append(
            [
                b["full_annotation"],
                f"[{esc(b['title'], 85)}]({b['bug_url']})",
                esc(b["bug_type"], 36),
                esc(b["cs_location"], 54),
                esc(b["farthest_fs_location"], 62),
                esc(b["patch_titles"], 75),
                interpretation,
            ]
        )
    add(
        md_table(
            [
                "Annotation",
                "Syzbot bug",
                "Bug type",
                "Crash site",
                "Farthest fix site",
                "Patch",
                "Why it illustrates the grade",
            ],
            example_rows,
        )
    )
    add("")
    add(
        "These examples show why title-only or top-frame clustering works best for D0/D1, becomes component-sensitive at D2/D3, and should defer to root-cause/lifetime evidence at D4/D5."
    )
    add("")
    add("## Detector-specific crash-site examples")
    add("")
    detector_example_rows = []
    for b in select_detector_examples(bugs):
        detector_example_rows.append(
            [
                b["detector"],
                f"[{esc(b['title'], 86)}]({b['bug_url']})",
                b["full_annotation"],
                esc(b["cs_location"], 54),
                esc(b["cs_strategy"], 42),
                esc(b["cs_evidence"], 80),
            ]
        )
    add(
        md_table(
            [
                "Detector",
                "Syzbot bug",
                "Annotation",
                "Selected CS",
                "Selection rule",
                "Why this is the manifestation site",
            ],
            detector_example_rows,
        )
    )
    add("")
    add(
        "These examples make the parser's format dependence concrete. An ordinary RIP rule is appropriate for a symbolized oops but wrong for KASAN/KMSAN/KFENCE runtime frames; UBSAN's expression site and KCSAN's dual accesses require their own treatment."
    )
    add("")
    add("## Temporal-bucket examples")
    add("")
    temporal_example_rows = []
    for b in select_temporal_examples(bugs):
        temporal_example_rows.append(
            [
                b["temporal_distance"],
                f"[{esc(b['title'], 86)}]({b['bug_url']})",
                b["full_annotation"],
                esc(b["temporal_reason"], 90),
                esc(b["cs_location"], 52),
                esc(b["farthest_fs_location"], 58),
            ]
        )
    add(
        md_table(
            [
                "Δt bucket",
                "Syzbot bug",
                "Annotation",
                "Report-derived anchor",
                "Crash site",
                "Farthest fix site",
            ],
            temporal_example_rows,
        )
    )
    add("")
    add(
        "The `not determined` bucket is an evidence-preserving outcome, not a negative result. It separates reports without a lifecycle anchor from truly same-syscall or unbounded cases."
    )
    add("")
    add("## Strong victim-site examples")
    add("")
    add(
        f"The corpus contains {len(victim):,} bugs with the full `D4/D5 + S=∞ + Δt=unbounded` signature. The following 20 examples are selected to diversify CS→FS subsystem transitions:"
    )
    add("")
    victim_rows = []
    for b in select_diverse_victims(victim):
        victim_rows.append(
            [
                f"[{esc(b['title'], 84)}]({b['bug_url']})",
                b["full_annotation"],
                esc(b["bug_type"], 32),
                f"{esc(b['cs_location'], 50)} → {esc(b['farthest_fs_location'], 56)}",
                f"{b['cs_subsystem']} → {b['farthest_fs_subsystem']}",
                esc(b["patch_titles"], 72),
            ]
        )
    add(
        md_table(
            [
                "Syzbot bug",
                "Annotation",
                "Bug type",
                "CS → farthest FS",
                "Subsystem transition",
                "Patch",
            ],
            victim_rows,
        )
    )
    add("")
    add(
        "For these records, the manifestation frame is a victim by all three available signals: it is structurally separated from the causal edit, the fixed function is absent from the crash stack, and the report shows temporal decoupling. Alloc/free stacks, object type, teardown path, and fix-commit semantics are therefore better duplicate features than crash RIP alone."
    )
    add("")
    add("## Multi-hunk examples where maximum D matters")
    add("")
    widest = sorted(
        max_min_diff,
        key=lambda b: (
            b["distance"] - b["distance_min"],
            b["distance"],
            b.get("fix_hunk_count", 0),
        ),
        reverse=True,
    )[:20]
    add(
        md_table(
            ["Syzbot bug", "D(min)→D(max)", "Hunks", "Crash site", "Farthest fix site", "Patch"],
            [
                [
                    f"[{esc(b['title'], 82)}]({b['bug_url']})",
                    f"D{b['distance_min']}→D{b['distance']}",
                    b["fix_hunk_count"],
                    esc(b["cs_location"], 52),
                    esc(b["farthest_fs_location"], 60),
                    esc(b["patch_titles"], 75),
                ]
                for b in widest
            ],
        )
    )
    add("")
    add(
        "These cases contain a local edit that could make the patch appear close under a nearest-hunk metric, plus a farther edit that reveals the distributed repair. They are the clearest reason to retain the per-hunk audit sheet."
    )
    add("")
    add("## Repair latency")
    add("")
    if latencies:
        latency_rows = []
        for d in range(6):
            values = [
                b["days_first_to_fix"]
                for b in bugs
                if b.get("distance") == d and isinstance(b.get("days_first_to_fix"), (int, float))
            ]
            latency_rows.append(
                [
                    f"D{d}",
                    len(values),
                    f"{statistics.median(values):.1f}" if values else "—",
                    f"{quantile(values, 0.25):.1f}" if values else "—",
                    f"{quantile(values, 0.75):.1f}" if values else "—",
                    f"{statistics.mean(values):.1f}" if values else "—",
                ]
            )
        add(
            md_table(
                ["Grade", "Bugs with dates", "Median days", "Q1", "Q3", "Mean days"], latency_rows
            )
        )
        add("")
        add(
            f"Among {len(latencies):,} bugs with parseable dates, median first-crash-to-fix time is {statistics.median(latencies):.1f} days; the interquartile range is {quantile(latencies, 0.25):.1f}–{quantile(latencies, 0.75):.1f} days, and the mean is {statistics.mean(latencies):.1f} days. Spearman ρ between structural D and latency is {distance_latency_rho:.3f}. The distribution has a long tail. D5 has the highest grade median in this corpus, but distance, subsystem, report age, backporting, and local patch availability are confounded; no causal claim is made."
        )
    add("")
    add("## Implications for duplicate detection and triage")
    add("")
    add(
        "1. **Use the crash statement aggressively only for D0/D1-like cases.** Exact detector expression, function, access type, and top stack frames are effective identifiers when FS remains local."
    )
    add(
        "2. **Add component and call-path context for D2/D3.** Same-file helpers and same-driver cross-file state machines frequently separate the violated invariant from the bad update."
    )
    add(
        "3. **Switch to root-cause clustering for D4/D5 or S=∞.** Fix paths/functions, allocation/free stacks, object type, lifetime transition, producer subsystem, and patch semantics should dominate the identifier."
    )
    add(
        "4. **Do not hash sanitizer helpers.** KASAN/KMSAN/KFENCE runtime frames and UBSAN handlers describe detection machinery, not the kernel manifestation statement."
    )
    add(
        f"5. **Preserve both D(max) and D(min).** D(max) measures the reach of the complete repair; D(min) identifies whether any causal edit is local. The {len(max_min_diff):,} disagreements in this corpus are too numerous to discard."
    )
    add(
        "6. **Use Δt conservatively.** Alloc/free/task anchors support useful buckets, but `not determined` is preferable to inventing a lifecycle when the report lacks evidence."
    )
    add("")
    add("## Quality control and limitations")
    add("")
    add(
        f"- Structural distance is resolved for {len(resolved):,} of {total:,} bugs ({pct(len(resolved), total)}). The {total - len(resolved):,} unresolved records remain in the Bugs and QC sheets."
    )
    add(
        f"- {sum(b['review_status'] != 'Automated classification' for b in bugs):,} records are placed in the manual-review queue, primarily because CS or FS function extraction is weak or unresolved."
    )
    add(
        f"- FS function extraction is unavailable for {sum(not b.get('fix_functions') for b in bugs):,} bugs, usually because hunks describe global initializers, labels, macros, build/configuration files, or ambiguous headers. File/component distance may still be resolvable."
    )
    add(
        "- Source symbolization is taken from downloaded reports. Exact replication should pin the report build, run addr2line for that binary, and compare against the fix commit's parent tree."
    )
    add(
        "- D0 uses the documented ±2-line insertion/adjacency tolerance. Workbook evidence and hunk anchors permit manual regrading under a zero-tolerance rule."
    )
    add(
        "- D4/D5 are path-based MAINTAINERS proxies. Publication-level use requires checking the historical MAINTAINERS entry at each relevant kernel revision."
    )
    add(
        "- Bug and patch classification are deterministic lexical/structural classifications, not expert adjudications. Titles, evidence snippets, confidence fields, and source URLs are retained to support correction."
    )
    add(
        "- S is computed against extracted fixed functions and the available manifestation stack. Missing/inlined/macro functions can inflate `unknown` or `∞`."
    )
    add(
        "- Δt is a report-derived annotation rather than dynamic data provenance; T remains uncomputed without taint analysis."
    )
    add(
        "- Completeness is measured against a dated live Syzbot listing snapshot. Syzbot is continuously updated, so later runs may add fixes, hashes, reports, or corrected metadata."
    )
    add(
        "- Wilson intervals and the off-stack odds ratio quantify sampling uncertainty within this observed corpus; they do not correct classification error, selection effects, or multiple comparisons."
    )
    add(
        "- All latency and association results are descriptive. Subsystem mix, bug age, detector, patch breadth, backports, and metadata availability are plausible confounders."
    )
    add("")
    add("## Deliverables and reproducibility")
    add("")
    add(
        f"The companion workbook contains eleven sheets: README, Definitions, the {total:,}-row Bugs table, the {len(hunks):,}-row Fix Hunks audit trail, Evidence, a formula-driven Dashboard, Evaluation, Examples, Taxonomy, QC, and the complete {len(manifest):,}-record Cohort Manifest. The analysis JSON, analyzer, and workbook/report builders preserve the transformation from live Syzbot metadata and local artifacts to the published tables and report."
    )

    write_text(args.output, "\n".join(lines) + "\n")
    print(
        json.dumps(
            {
                "output": str(args.output),
                "bugs": total,
                "hunks": len(hunks),
                "examples": len(examples),
                "detector_examples": len(detector_example_rows),
                "temporal_examples": len(temporal_example_rows),
                "victim_examples": min(20, len(victim)),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
