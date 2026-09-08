"""Detailed bug, crash stack, report, and fix-location presentation."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any

from ..terminal import paragraph, safe_text, section, style
from .common import bug_type_label, c_reproducer_label, fields, format_date, title_colors


def _range_colors(line: str) -> str:
    return re.sub(
        r"\b(old|new)\b[^>]*?(?= -> |$)",
        lambda match: style(match.group(), tone="error" if match[1] == "old" else "success"),
        line,
    )


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


def _source_coordinate(location: Mapping[str, Any]) -> str:
    path = location.get("file_path") or "unknown file"
    line = location.get("line_number")
    coordinate = f"{path}:{line}" if line else str(path)
    if line and location.get("column_number"):
        coordinate += f":{location['column_number']}"
    return coordinate


def _range(location: Mapping[str, Any], side: str) -> str:
    if not location.get(f"{side}_file_path"):
        return "/dev/null"
    start, count = location.get(f"{side}_start"), location.get(f"{side}_count", 0)
    if start is None:
        return "lines unknown"
    if count == 0:
        return f"after line {start}" if start else "before line 1"
    return str(start) + (f"-{start + count - 1}" if count > 1 else "")


def _fix_locations(locations: Sequence[Mapping[str, Any]]) -> None:
    previous_file = None
    previous_function = None
    for location in locations:
        old_file, new_file = location.get("old_file_path"), location.get("new_file_path")
        identity = old_file, new_file
        if identity != previous_file:
            path = (
                old_file
                if old_file == new_file
                else f"{old_file or '/dev/null'} -> {new_file or '/dev/null'}"
            )
            paragraph(path or "unknown file", indent=4, tone="accent" if path else "warning")
            previous_file = identity
            previous_function = None
        function = location.get("function_name") or "unknown function"
        basis = location.get("function_basis")
        if (function, basis) != previous_function:
            paragraph(
                function, indent=6, tone="function" if location.get("function_name") else "warning"
            )
            if location.get("function_name") and basis and basis != "unknown":
                paragraph(basis, indent=6, tone="muted")
            previous_function = function, basis
        paragraph(
            f"old {_range(location, 'old')} -> new {_range(location, 'new')}",
            indent=6,
            highlight=_range_colors,
        )


def human_bug(bug: dict[str, Any], include_report: bool, include_stack: bool = False) -> None:
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
    for location in locations:
        paragraph(
            _source_coordinate(location),
            indent=2,
            tone="accent" if location.get("file_path") else "warning",
        )
        detail: list[tuple[str, object]] = [
            ("Function", location.get("function_name") or "unknown"),
            ("Role", location.get("role") or "crash"),
            ("Confidence", location.get("confidence") or "unknown"),
            ("Method", location.get("method") or "unknown"),
        ]
        if location.get("kernel_source_commit"):
            detail.append(("Kernel commit", location["kernel_source_commit"]))
        fields(detail, indent=4)
    if not locations:
        paragraph("Unknown; no crash site could be indexed.", indent=2, tone="muted")

    fixes = bug.get("fixes", [])
    fix_locations = bug.get("fix_locations", [])
    section("Fixes", count=len(fixes))
    displayed: set[int] = set()
    for index, fix in enumerate(fixes, 1):
        paragraph(
            f"{index}. {fix.get('title') or 'Untitled fix'}",
            indent=2,
            hanging=len(str(index)) + 2,
            tone="strong",
        )
        commit_hash = fix.get("hash")
        detail = [("Commit", commit_hash or "unresolved (title only)")]
        if fix.get("repo"):
            detail.append(("Repository", fix["repo"]))
        if fix.get("link"):
            detail.append(("URL", fix["link"]))
        detail.append(("Patch", "available" if fix.get("patch_available") else "unavailable"))
        fields(detail, indent=4)
        related = []
        for i, location in enumerate(fix_locations):
            if location.get("commit_hash") == commit_hash and (location.get("repo") or "") == (
                fix.get("repo") or ""
            ):
                related.append(location)
                displayed.add(i)
        if related:
            _fix_locations(related)
        else:
            paragraph("Changed locations unknown.", indent=4, tone="muted")
        if index < len(fixes):
            print()
    remaining = [location for i, location in enumerate(fix_locations) if i not in displayed]
    if remaining:
        _fix_locations(remaining)
    if not fixes and not remaining:
        paragraph("No fix commits indexed.", indent=2, tone="muted")

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
    if (
        include_report
        and available
        and isinstance(report, Mapping)
        and report.get("text") is not None
    ):
        section("Full representative report")
        print(safe_text(report["text"], multiline=True))
