"""Bug lists, filter result cards, and observed filter values."""

from __future__ import annotations

import textwrap
from typing import Any

from ..terminal import paragraph, safe_text, section, style, terminal_width
from .common import bug_type_label, c_reproducer_label, fields, title_colors


def human_list(rows: list[dict[str, Any]], *, offset: int = 0) -> None:
    if not rows:
        paragraph("No bugs found.", tone="muted")
        return
    paragraph(f"Fixed bugs ({offset + 1:,}-{offset + len(rows):,})", tone="heading")
    print()
    key_width = max(len(safe_text(row.get("key", ""))) for row in rows)
    width = terminal_width()
    # A long identifier or narrow terminal is clearer as a compact record.
    long_tag = any(len(safe_text(tag)) > 16 for row in rows for tag in row.get("subsystems", []))
    if width - key_width - 22 < 28 or long_tag:
        for index, row in enumerate(rows, offset + 1):
            paragraph(
                f"{index}. {row.get('title', '')}",
                highlight=title_colors,
                hanging=len(str(index)) + 2,
            )
            fields(
                [
                    ("Key", row.get("key", "")),
                    ("Subsystems", ", ".join(row.get("subsystems", [])) or "unknown"),
                ]
            )
            print()
    else:
        tags_width = 16
        title_width = width - key_width - tags_width - 4
        print(style(f"{'KEY':<{key_width}}  {'SUBSYSTEMS':<{tags_width}}  TITLE", tone="muted"))
        for row in rows:
            key = safe_text(row.get("key", ""))
            tags = ", ".join(row.get("subsystems", [])) or "unknown"
            tag_lines = textwrap.wrap(
                safe_text(tags), tags_width, break_long_words=False, break_on_hyphens=False
            )
            title_lines = textwrap.wrap(
                safe_text(row.get("title", "")),
                title_width,
                break_long_words=False,
                break_on_hyphens=False,
            ) or [""]
            for index in range(max(len(tag_lines), len(title_lines))):
                key_cell = key if index == 0 else ""
                tag_cell = tag_lines[index] if index < len(tag_lines) else ""
                title_cell = title_lines[index] if index < len(title_lines) else ""
                tag_tone = "tag" if row.get("subsystems") else "warning"
                print(
                    f"{style(key_cell.ljust(key_width), tone='accent')}  "
                    f"{style(tag_cell.ljust(tags_width), tone=tag_tone)}  "
                    f"{title_colors(title_cell)}"
                )
        print()
    paragraph(
        "Inspect: ss show KEY    |    More: ss list --offset " + str(offset + len(rows)),
        tone="muted",
    )


def human_filter(value: dict[str, Any], *, query: str | None = None) -> None:
    """Show full titles and URLs, keeping pagination separate from match counts."""
    rows = value["bugs"]
    total, offset = value["total"], value["offset"]
    paragraph(f"Matching fixed bugs ({total:,})", tone="heading")
    criteria: list[tuple[str, object]] = []
    if value["bug_types"]:
        criteria.append(("Types", ", ".join(value["bug_types"])))
    if value["subsystems"]:
        criteria.append(("Subsystems", ", ".join(value["subsystems"])))
    if query:
        criteria.append(("Query", query))
    for name, label in (
        ("families", "Failure patterns"),
        ("access_modes", "Access modes"),
        ("crash_files", "Crash paths"),
        ("fix_files", "Fix paths"),
        ("crash_functions", "Crash functions"),
        ("fix_functions", "Fix functions"),
    ):
        if value.get(name):
            criteria.append((label, ", ".join(value[name])))
    for name, label in (
        ("has_c_repro", "C repro filter"),
        ("has_report", "Report filter"),
        ("has_patch", "Patch filter"),
        ("max_fix_files", "Maximum changed files"),
        ("max_patch_lines", "Maximum changed lines"),
    ):
        if value.get(name) is not None:
            criteria.append((label, value[name]))
    if rows:
        criteria.append(("Showing", f"{offset + 1:,}-{offset + len(rows):,} of {total:,}"))
    fields(criteria)
    if not rows:
        print()
        paragraph(
            "No bugs match these filters."
            if not total
            else f"No rows at offset {offset:,}; lower --offset to see the {total:,} matches.",
            tone="muted",
        )
        return
    for index, row in enumerate(rows, offset + 1):
        print()
        paragraph(
            f"{index}. {row.get('title') or 'Untitled bug'}",
            highlight=title_colors,
            hanging=len(str(index)) + 2,
        )
        # Keep each URL intact for copying, including in a narrow terminal.
        paragraph(row.get("bug_url") or "URL unknown", indent=2, tone="link")
        fields(
            [
                ("Key", row.get("key", "")),
                ("Bug type", bug_type_label(row.get("bug_type"))),
                ("Failure pattern", row.get("family") or "unknown"),
                ("Access", row.get("access_mode") or "unknown"),
                ("Subsystems", ", ".join(row.get("subsystems", [])) or "unknown"),
                ("Saved status", row.get("status") or "unknown"),
                ("Crashes", f"{row.get('crash_count', 0):,}"),
                ("Fixes", f"{row.get('fix_count', 0):,}"),
                ("Representative report", "available" if row.get("has_report") else "unavailable"),
                (
                    "Changed files",
                    row.get("fix_file_count")
                    if row.get("fix_file_count") is not None
                    else "unknown",
                ),
                (
                    "Changed lines",
                    row.get("patch_line_count")
                    if row.get("patch_line_count") is not None
                    else "unknown",
                ),
            ]
        )
        patch_urls = row.get("patch_urls", [])
        if patch_urls:
            paragraph("Patch / commit URLs:", indent=2, tone="muted")
            for url in patch_urls:
                paragraph(url, indent=4, tone="link")
        else:
            fields([("Patch / commit URLs", "not recorded")])
        fields([("C reproducer", c_reproducer_label(row.get("c_reproducer_status")))])
        for url in row.get("c_reproducer_urls", []):
            paragraph(url, indent=4, tone="link")
    print()
    if offset + len(rows) < total:
        paragraph(
            f"More matches: repeat these filters with --offset {offset + len(rows)} "
            "or replace --limit with --all.",
            tone="muted",
        )
    paragraph("Inspect a result: ss show KEY", tone="muted")


def human_filter_values(value: dict[str, Any]) -> None:
    paragraph("Filter values · active snapshot", tone="heading")
    for label, key in (
        ("Bug types", "bug_types"),
        ("Failure patterns", "families"),
        ("Access modes", "access_modes"),
        ("Subsystem tags", "subsystems"),
    ):
        section(label)
        entries = value.get(key, [])
        if not entries:
            paragraph("None recorded.", indent=2, tone="muted")
            continue
        fields([(safe_text(entry["value"]), f"{entry['count']:,} bugs") for entry in entries])
    print()
    paragraph("Use --type TYPE and --subsystem TAG; subsystem tags match exactly.", tone="muted")
