"""Shared crash coordinates and changed source ranges for bug views."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any

from ..terminal import paragraph, style
from .common import fields


def _range_colors(line: str) -> str:
    return re.sub(
        r"\b(old|new)\b[^>]*?(?= -> |$)",
        lambda match: style(match.group(), tone="error" if match[1] == "old" else "success"),
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


def render_crash_locations(locations: Sequence[Mapping[str, Any]], *, indent: int = 2) -> None:
    for location in locations:
        paragraph(
            _source_coordinate(location),
            indent=indent,
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
        fields(detail, indent=indent + 2)
    if not locations:
        paragraph("Unknown; no crash site could be indexed.", indent=indent, tone="muted")


def render_fix_locations(locations: Sequence[Mapping[str, Any]], *, indent: int = 4) -> None:
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
            paragraph(path or "unknown file", indent=indent, tone="accent" if path else "warning")
            previous_file = identity
            previous_function = None
        function = location.get("function_name") or "unknown function"
        basis = location.get("function_basis")
        if (function, basis) != previous_function:
            paragraph(
                function,
                indent=indent + 2,
                tone="function" if location.get("function_name") else "warning",
            )
            if location.get("function_name") and basis and basis != "unknown":
                paragraph(basis, indent=indent + 2, tone="muted")
            previous_function = function, basis
        paragraph(
            f"old {_range(location, 'old')} -> new {_range(location, 'new')}",
            indent=indent + 2,
            highlight=_range_colors,
        )


def render_fixes(
    fixes: Sequence[Mapping[str, Any]],
    locations: Sequence[Mapping[str, Any]],
    *,
    indent: int = 2,
    standalone_links: bool = False,
) -> None:
    """Keep each changed range under its own commit and repository."""
    displayed: set[int] = set()
    for index, fix in enumerate(fixes, 1):
        paragraph(
            f"{index}. {fix.get('title') or 'Untitled fix'}",
            indent=indent,
            hanging=len(str(index)) + 2,
            tone="strong",
        )
        commit_hash = fix.get("hash")
        detail = [("Commit", commit_hash or "unresolved (title only)")]
        if fix.get("repo"):
            detail.append(("Repository", fix["repo"]))
        if fix.get("link") and not standalone_links:
            detail.append(("URL", fix["link"]))
        detail.append(("Patch", "available" if fix.get("patch_available") else "unavailable"))
        fields(detail, indent=indent + 2)
        if fix.get("link") and standalone_links:
            paragraph("URL:", indent=indent + 2, tone="muted")
            paragraph(fix["link"], indent=indent + 4, tone="link")
        related = []
        for i, location in enumerate(locations):
            if location.get("commit_hash") == commit_hash and (location.get("repo") or "") == (
                fix.get("repo") or ""
            ):
                related.append(location)
                displayed.add(i)
        if related:
            render_fix_locations(related, indent=indent + 2)
        else:
            paragraph("Changed locations unknown.", indent=indent + 2, tone="muted")
        if index < len(fixes):
            print()
    remaining = [location for i, location in enumerate(locations) if i not in displayed]
    if remaining:
        render_fix_locations(remaining, indent=indent + 2)
    if not fixes and not remaining:
        paragraph("No fix commits indexed.", indent=indent, tone="muted")
