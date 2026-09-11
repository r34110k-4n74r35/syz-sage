"""Human views of retained diffs and evidence-based crash/fix relationships."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from ..terminal import paragraph, safe_text, section, style, terminal_width
from .common import fields, title_colors


def _diffstat(value: Mapping[str, Any]) -> None:
    stats = value.get("diffstat")
    if not isinstance(stats, Mapping):
        return
    section("Diffstat")
    rows: list[tuple[str, str, str]] = []
    for file in value.get("files") or []:
        old, new = file.get("old_file_path"), file.get("new_file_path")
        path = (
            f"{old} -> {new}" if old and new and old != new else str(new or old or "unknown file")
        )
        if old and not new:
            path += " (deleted)"
        elif new and not old:
            path += " (new)"
        inserted, deleted = file.get("insertions"), file.get("deletions")
        if inserted is None or deleted is None:
            counts = (
                "binary (line counts unknown)"
                if file.get("kind") == "binary"
                else "unknown (incomplete or unparsed diff)"
            )
            rendered = style(counts, tone="warning")
        else:
            counts = f"+{inserted:,} -{deleted:,}"
            rendered = (
                style(f"+{inserted:,}", tone="success") + " " + style(f"-{deleted:,}", tone="error")
            )
            if inserted == deleted == 0:
                counts += " (no text changes)"
                rendered += style(" (no text changes)", tone="muted")
        rows.append((safe_text(path), counts, rendered))
    path_width = max((len(path) for path, _, _ in rows), default=0)
    aligned = all(path_width + len(counts) + 5 <= terminal_width() for _, counts, _ in rows)
    for path, _, rendered in rows:
        if aligned:
            print("  " + style(path.ljust(path_width), tone="accent") + " | " + rendered)
        else:
            paragraph(path, indent=2, tone="accent")
            print("    " + rendered)
    total = stats["files_changed"]
    files_label = "file" if total == 1 else "files"
    if stats.get("complete"):
        inserted, deleted = stats["insertions"], stats["deletions"]
        insertion_label = "insertion" if inserted == 1 else "insertions"
        deletion_label = "deletion" if deleted == 1 else "deletions"
        paragraph(
            f"{total:,} {files_label} changed, {inserted:,} {insertion_label}(+), "
            f"{deleted:,} {deletion_label}(-).",
            indent=2,
            tone="strong",
        )
    else:
        paragraph(
            f"{total:,} {files_label} identified; total line counts unknown "
            "(binary, incomplete, or unparsed diff).",
            indent=2,
            tone="warning",
        )


def human_patches(values: Sequence[Mapping[str, Any]]) -> None:
    if not values:
        paragraph("No fix references are recorded for this bug.", indent=2, tone="muted")
    for value in values:
        human_patch(value, include_metadata=False)


def human_patch(value: Mapping[str, Any], *, include_metadata: bool = True) -> None:
    if include_metadata:
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
        label = (
            "this fix"
            if include_metadata
            else value.get("commit_hash") or value.get("fix", {}).get("title") or "this fix"
        )
        paragraph(f"No retained patch text is available for {label}.", indent=2, tone="warning")
        return
    _diffstat(value)
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
