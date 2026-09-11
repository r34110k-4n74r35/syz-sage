"""Timeline, source locations, and evidence sections within filter results."""

from __future__ import annotations

from typing import Any

from ..terminal import paragraph, terminal_width
from .common import c_reproducer_label, fields, format_date
from .locations import render_crash_locations, render_fixes


def _heading(title: str) -> None:
    print()
    paragraph(title, indent=2, tone="heading")


def filter_details(bug: dict[str, Any]) -> None:
    dates = [
        (label, format_date(value))
        for label, value in (
            ("First crash", bug.get("first_crash") or bug.get("first_crash_at")),
            ("Last crash", bug.get("last_crash") or bug.get("last_crash_at")),
            ("Fix time", bug.get("fix_time")),
            ("Close time", bug.get("close_time")),
        )
        if value
    ]
    if dates:
        _heading("Timeline")
        fields(dates, indent=4)

    locations = bug.get("crash_locations", [])
    _heading(f"Crash locations · representative report ({len(locations):,})")
    render_crash_locations(locations, indent=4)

    fixes = bug.get("fixes", [])
    _heading(f"Fix commits ({len(fixes):,})")
    render_fixes(fixes, bug.get("fix_locations", []), indent=4, standalone_links=True)

    _heading("Saved evidence")
    report = bug.get("report") or {}
    available = report.get("available", bug.get("has_report", False))
    report_label = "unavailable"
    if available:
        report_label = "available"
        if report.get("size") is not None:
            report_label += f" ({report['size']:,} bytes)"
    evidence: list[tuple[str, object]] = [("Representative report", report_label)]
    stack_count = bug.get("crash_stack_count")
    stack_label = "unknown"
    if stack_count is not None:
        stack_label = f"{stack_count:,} extracted frame" + ("" if stack_count == 1 else "s")
    evidence.append(("Stack", stack_label))
    fields(evidence, indent=2 if terminal_width() < 28 else 4)
    if report.get("source_url"):
        paragraph("Report URL:", indent=4, tone="muted")
        paragraph(report["source_url"], indent=6, tone="link")

    patch_urls = bug.get("patch_urls", [])
    fix_urls = {fix["link"] for fix in fixes if fix.get("link")}
    additional_urls = [url for url in patch_urls if url not in fix_urls]
    if additional_urls:
        paragraph("Patch / commit URLs:", indent=4, tone="muted")
        for url in additional_urls:
            paragraph(url, indent=6, tone="link")
    elif not patch_urls:
        fields([("Patch / commit URLs", "not recorded")], indent=4)
    fields([("C reproducer", c_reproducer_label(bug.get("c_reproducer_status")))], indent=4)
    for url in bug.get("c_reproducer_urls", []):
        paragraph(url, indent=6, tone="link")
