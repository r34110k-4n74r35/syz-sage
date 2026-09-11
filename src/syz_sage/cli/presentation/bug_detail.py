"""Detailed bug, crash stack, and fix-location presentation."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from ..terminal import paragraph, section, style
from .common import bug_type_label, c_reproducer_label, fields, format_date, title_colors
from .locations import render_crash_locations, render_fixes

_STACK_TOKENS = re.compile(
    r"(?P<path>\b[\w./-]+\.(?:c|h|S|s|rs):\d+(?::\d+)?)"
    r"|(?P<function>\b[A-Za-z_][\w.]*\+0x[\da-f]+/0x[\da-f]+)"
    r"|(?P<inline>\[inline\])"
)


def _stack_colors(line: str) -> str:
    return _STACK_TOKENS.sub(
        lambda match: style(
            match.group(),
            tone={"path": "accent", "function": "function", "inline": "tag"}[str(match.lastgroup)],
        ),
        line,
    )


def human_bug(bug: dict[str, Any], include_stack: bool = False) -> None:
    paragraph(bug.get("title", "Untitled bug"), highlight=title_colors)
    metadata: list[tuple[str, object]] = [
        ("Key", bug.get("key", "")),
        ("Bug type", bug_type_label(bug.get("bug_type"))),
        ("Failure pattern", bug.get("family") or "unknown"),
        ("Access", bug.get("access_mode") or "unknown"),
    ]
    if bug.get("status"):
        metadata.append(("Status", bug["status"]))
    metadata.extend(
        [
            (
                "Subsystems",
                ", ".join(bug.get("subsystems", [])) or "unknown (no saved syzbot tags)",
            ),
            ("URL", bug.get("bug_url") or "unknown"),
        ]
    )
    reproducer_status = bug.get("c_reproducer_status", "unknown")
    reproducer_urls = bug.get("c_reproducer_urls", [])
    metadata.extend(
        [("C reproducer", c_reproducer_label(reproducer_status))]
        + [("C repro URL", url) for url in reproducer_urls[:3]]
    )
    fields(metadata)
    if len(reproducer_urls) > 3:
        paragraph(
            f"{len(reproducer_urls) - 3:,} more C reproducer URLs; use --json to display all.",
            indent=2,
            tone="muted",
        )
    dates = [
        (label, format_date(bug[field]))
        for label, field in (
            ("First crash", "first_crash"),
            ("Last crash", "last_crash"),
            ("Fix time", "fix_time"),
            ("Close time", "close_time"),
        )
        if bug.get(field)
    ]
    if dates:
        section("Timeline")
        fields(dates)

    locations = bug.get("crash_locations", [])
    section("Crash locations · representative report", count=len(locations))
    render_crash_locations(locations)

    fixes = bug.get("fixes", [])
    fix_locations = bug.get("fix_locations", [])
    section("Fixes", count=len(fixes))
    render_fixes(fixes, fix_locations)

    stack = bug.get("crash_stack", [])
    report = bug.get("report")
    available = isinstance(report, Mapping) and bool(
        report.get("available", report.get("text") is not None)
    )
    section("Saved evidence")
    report_label = "unavailable"
    if available:
        assert isinstance(report, Mapping)
        size = report.get("size")
        if size is None:
            size = len(str(report.get("text") or "").encode("utf-8"))
        report_label = f"available ({size:,} bytes)"
    evidence: list[tuple[str, object]] = [
        ("Crash records", f"{len(bug.get('crashes', [])):,}"),
        ("Representative report", report_label),
        (
            "Stack",
            f"{len(stack):,} extracted frames"
            + ("; use --stack to display" if stack and not include_stack else ""),
        ),
    ]
    if available and isinstance(report, Mapping) and report.get("source_url"):
        evidence.append(("Report URL", report["source_url"]))
    fields(evidence)
    if include_stack:
        section("Crash stack", count=len(stack))
        previous_section = None
        for index, frame in enumerate(stack, 1):
            if frame["section"] != previous_section:
                previous_section = frame["section"]
                paragraph(
                    str(previous_section).replace("_", " ").capitalize(), indent=2, tone="accent"
                )
            paragraph(
                f"{index:>3}. {str(frame['raw_line']).strip()}",
                indent=4,
                hanging=5,
                highlight=_stack_colors,
            )
        if not stack:
            paragraph("No stack frames indexed.", indent=2, tone="muted")
