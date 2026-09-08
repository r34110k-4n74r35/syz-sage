"""Human views of retained diffs and evidence-based crash/fix relationships."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ..terminal import paragraph, safe_text, section, style
from .common import fields, title_colors


def human_patch(value: Mapping[str, Any]) -> None:
    section("Saved patch")
    paragraph(value.get("fix", {}).get("title") or "Untitled fix", highlight=title_colors)
    metadata: list[tuple[str, object]] = [
        ("Key", value.get("key") or "unknown"),
        ("Commit", value.get("commit_hash") or "unresolved"),
        ("Patch", "available" if value.get("available") else "not recorded"),
    ]
    if value.get("source_url"):
        metadata.append(("URL", value["source_url"]))
    if value.get("available"):
        count = len(value.get("files") or [])
        metadata.extend(
            [
                ("Files", f"{count} selected / {value.get('total_files', count)} total"),
                ("Stored bytes", value.get("size", 0)),
                ("SHA-256", value.get("sha256") or "unknown"),
            ]
        )
    fields(metadata)
    if not value.get("available"):
        paragraph("No retained patch text is available for this fix.", indent=2, tone="warning")
        return
    section("Diff")
    # Do not wrap or truncate diff lines. JSON preserves the original bytes as
    # decoded text; the terminal view escapes control sequences before coloring.
    text = str(value.get("text") or "")
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    for line in lines:
        tone = (
            "heading"
            if line.startswith("diff --git ")
            else "accent"
            if line.startswith(("@@", "--- ", "+++ "))
            else "success"
            if line.startswith("+")
            else "error"
            if line.startswith("-")
            else None
        )
        rendered = safe_text(line.removesuffix("\r"), multiline=True)
        print(style(rendered, tone=tone) if tone else rendered)


def _coordinate(value: Mapping[str, Any]) -> str:
    result = str(value.get("file_path") or "unknown file")
    if value.get("line_number"):
        result += f":{value['line_number']}"
    if value.get("column_number"):
        result += f":{value['column_number']}"
    return result


def _evidence(value: Mapping[str, Any], *, indent: int = 4) -> None:
    rows = value.get("report_lines") or []
    if rows:
        for row in rows:
            paragraph(f"Report line {row['report_line']}: {row['text']}", indent=indent)
    elif value.get("evidence"):
        label = "Title" if value.get("source") == "title" else "Evidence"
        paragraph(f"{label}: {value['evidence']}", indent=indent)


def human_explanation(value: Mapping[str, Any]) -> None:
    section("Crash-to-fix evidence")
    paragraph(value.get("title") or "Untitled bug", highlight=title_colors)
    fields([("Key", value.get("key") or "unknown")])
    if value.get("bug_url"):
        fields([("URL", value["bug_url"])])
    crash = value.get("crash") or {}
    family, operation = crash.get("family") or {}, crash.get("operation") or {}
    fields(
        [
            ("Failure family", family.get("value") or "unknown"),
            ("Operation", operation.get("value") or "unknown"),
            (
                "Representative report",
                "available" if crash.get("report_available") else "not recorded",
            ),
        ]
    )
    if crash.get("report_url"):
        fields([("Report URL", crash["report_url"])])
    for label, characteristic in (("Family", family), ("Operation", operation)):
        paragraph(
            f"{label} method: {characteristic.get('method') or 'unknown'} "
            f"(source: {characteristic.get('source') or 'unknown'})",
            indent=2,
            tone="muted",
        )
        _evidence(characteristic)
    locations = crash.get("locations") or []
    section("Crash locations", count=len(locations))
    if not locations:
        paragraph("No crash source location is recorded.", indent=2, tone="warning")
    for location in locations:
        fields(
            [
                ("Role", location.get("role") or "unknown"),
                ("File", _coordinate(location)),
                ("Function", location.get("function_name") or "unknown"),
                ("Method", location.get("method") or "unknown"),
                ("Confidence", location.get("confidence") or "unknown"),
                ("Kernel commit", location.get("kernel_source_commit") or "unknown"),
            ]
        )
        _evidence(location)
    fixes = value.get("fixes") or []
    section("Fix relationships", count=len(fixes))
    if not fixes:
        paragraph("No fix references are recorded.", indent=2, tone="warning")
    for fix in fixes:
        paragraph(fix.get("title") or "Untitled fix", indent=2, tone="strong")
        fields(
            [
                ("Commit", fix.get("commit_hash") or "unresolved"),
                ("Patch", "available" if fix.get("patch_available") else "not recorded"),
            ],
            indent=4,
        )
        if fix.get("link"):
            fields([("URL", fix["link"])], indent=4)
        hunks = fix.get("hunks") or []
        if not hunks:
            paragraph("No parsed changed regions are recorded.", indent=4, tone="warning")
        for hunk in hunks:
            old_path, new_path = hunk.get("old_file_path"), hunk.get("new_file_path")
            path = (
                old_path
                if old_path == new_path
                else f"{old_path or '/dev/null'} -> {new_path or '/dev/null'}"
            )
            paragraph(f"Region {hunk['number']}: {path or 'unknown file'}", indent=4, tone="accent")
            fields(
                [
                    ("Relationship", hunk.get("relationship") or "unknown"),
                    ("Function", hunk.get("function_name") or "unknown"),
                    ("Function basis", hunk.get("function_basis") or "unknown"),
                    ("Change kind", hunk.get("kind") or "unknown"),
                ],
                indent=6,
            )
            if hunk.get("hunk_header"):
                paragraph(hunk["hunk_header"], indent=6, tone="muted")
            for comparison in hunk.get("comparisons") or []:
                location = comparison["crash_location"]
                paragraph(
                    f"{location.get('role') or 'crash'} {_coordinate(location)}: "
                    f"{comparison['relationship']}",
                    indent=6,
                )
                paragraph(
                    f"Method: {comparison['method']} (confidence: {comparison['confidence']}).",
                    indent=8,
                    tone="muted",
                )
            matches = hunk.get("manifestation_stack_matches") or []
            if matches:
                paragraph("Matching manifestation frames:", indent=6, tone="strong")
                for match in matches:
                    frame = match["frame"]
                    paragraph(
                        f"Report line {frame.get('report_line') or '?'}: "
                        f"{frame.get('raw_line') or frame.get('function_name')}",
                        indent=8,
                    )
                    paragraph(
                        f"{match['method']} (confidence: {match['confidence']}).",
                        indent=8,
                        tone="muted",
                    )
            else:
                paragraph("No matching manifestation frame recorded.", indent=6, tone="muted")
    section("Interpretation limits")
    for limitation in value.get("limitations") or []:
        paragraph(limitation, indent=2, tone="muted")
