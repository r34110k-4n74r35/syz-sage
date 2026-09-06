"""Human-readable CLI views; JSON output stays separate from presentation."""

from __future__ import annotations

import re
import sys
import textwrap
from collections.abc import Mapping, Sequence
from datetime import datetime
from pathlib import Path
from typing import Any

from .sync import UpdateSummary
from .terminal import fields as _fields
from .terminal import paragraph, safe_text, section, style, terminal_width


def _value_tone(label: str, value: object) -> str:
    """Color the meaning of values while leaving the displayed text intact."""
    text = str(value).lower()
    if text.startswith(
        ("unknown", "unavailable", "unresolved", "partial", "not yet", "not recorded")
    ):
        return "warning"
    if label in {"SQLite", "Foreign keys", "Blob hashes", "Snapshots"}:
        return "success" if text in {"ok", "0 errors"} else "error"
    if label in {"Status", "Result"}:
        if text.startswith(("failed", "error")):
            return "error"
        if "not activated" in text:
            return "warning"
        if text.startswith(("fixed", "complete", "unchanged")):
            return "success"
    if label in {"Patch", "Representative report", "C reproducer"}:
        return "success" if text.startswith("available") else "warning"
    if label == "Confidence":
        return "success" if text == "high" else "warning"
    if label == "Unavailable":
        return "warning" if text != "0" else "muted"
    if label == "Downloaded":
        return "success" if text != "0" else "muted"
    if label == "Reused":
        return "accent" if text != "0" else "muted"
    if label in {"Bug type", "Types", "Subsystems", "Subsystem tags"}:
        return "tag"
    if label == "Function":
        return "function"
    if label in {"Commit", "Kernel commit"}:
        return "hash"
    if label in {"URL", "Report URL", "Repository", "C repro URL"}:
        return "link"
    if label in {"Key", "File", "Database", "Retained files", "Role"}:
        return "accent"
    if label in {"First crash", "Last crash", "Fix time", "Close time", "Finished"}:
        return "date"
    if label.endswith("keys") or label in {"Changes", "No longer listed"}:
        return "accent"
    if re.match(r"^\d", text):
        return "number"
    return "strong"


def fields(rows: Sequence[tuple[str, object]], *, indent: int = 2) -> None:
    _fields(rows, indent=indent, tones={label: _value_tone(label, value) for label, value in rows})


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


def _date(value: object) -> str:
    raw = str(value or "unknown")
    try:
        date = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        return date.isoformat(sep=" ", timespec="seconds").replace("+00:00", " UTC")
    except ValueError:
        return raw


def human_status(value: dict[str, Any]) -> None:
    paragraph("Local database", tone="heading")
    fields(
        [("File", value.get("database", "")), ("Schema", value.get("schema_version", "unknown"))]
    )
    section("Active snapshot")
    fields(
        [
            ("Fixed bugs", f"{value.get('bugs', 0):,}"),
            ("Fix commits", f"{value.get('fixes', 0):,}"),
            ("Crash records", f"{value.get('crashes', 0):,}"),
            ("Reports", f"{value.get('reports', 0):,}"),
            ("Patches", f"{value.get('patches', 0):,}"),
        ]
    )
    section("Last synchronization")
    state = value.get("last_sync_status") or "not yet run"
    paragraph(state, indent=2, tone="success" if state == "completed" else "warning")
    if value.get("last_sync_at"):
        fields([("Finished", _date(value["last_sync_at"]))])
    if not value.get("current_snapshot"):
        paragraph("No complete snapshot is active yet.", indent=2, tone="muted")


def human_check(value: dict[str, Any], database_path: Path) -> None:
    passed = bool(value.get("ok"))
    paragraph(
        "Database check: " + ("passed" if passed else "failed"),
        tone="success" if passed else "error",
    )
    fields(
        [
            ("File", database_path),
            ("Schema", value["schema_version"]),
            ("Blobs checked", f"{value.get('blob_count', 0):,}"),
        ]
    )
    section("Integrity")
    checks = [("SQLite", ", ".join(value.get("quick_check", [])))]
    for label, field in (
        ("Foreign keys", "foreign_key_errors"),
        ("Blob hashes", "blob_hash_mismatches"),
        ("Snapshots", "snapshot_errors"),
    ):
        errors = value.get(field) or []
        checks.append((label, f"{len(errors):,} errors" if errors else "ok"))
    fields(checks)
    for label, field in (
        ("Foreign keys", "foreign_key_errors"),
        ("Blob hashes", "blob_hash_mismatches"),
        ("Snapshots", "snapshot_errors"),
    ):
        errors = value.get(field) or []
        for item in errors[:3]:
            paragraph(f"{label}: {item}", indent=4, tone="error")
    if not passed:
        print()
        paragraph("Use 'ss check --json' for full diagnostics.", tone="muted")


def human_list(rows: list[dict[str, Any]], *, offset: int = 0) -> None:
    if not rows:
        paragraph("No bugs found.", tone="muted")
        return
    paragraph(f"Fixed bugs ({offset + 1:,}-{offset + len(rows):,})", tone="heading")
    print()
    key_width = max(len(safe_text(row.get("key", ""))) for row in rows)
    width = terminal_width()
    # A long identifier or narrow terminal is clearer as a compact record.
    if width - key_width - 22 < 28:
        for index, row in enumerate(rows, offset + 1):
            paragraph(
                f"{index}. {row.get('title', '')}", tone="strong", hanging=len(str(index)) + 2
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
                    f"{style(title_cell, tone='strong')}"
                )
        print()
    paragraph(
        "Inspect: ss show KEY    |    More: ss list --offset " + str(offset + len(rows)),
        tone="muted",
    )


def _bug_type_label(value: object) -> str:
    label = str(value or "other")
    if label in {
        "kasan",
        "kmsan",
        "ubsan",
        "kcsan",
        "kfence",
        "warning",
        "info",
        "bug",
        "rcu",
        "vfs",
    }:
        return label.upper()
    return label.replace("-", " ").capitalize()


def _c_reproducer_label(status: object) -> str:
    return {
        "available": "available (URL recorded)",
        "not_provided": "not provided in saved crash metadata",
    }.get(str(status), "unknown (metadata missing or invalid)")


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
            tone="strong",
            hanging=len(str(index)) + 2,
        )
        # Keep each URL intact for copying, including in a narrow terminal.
        paragraph(row.get("bug_url") or "URL unknown", indent=2, tone="link")
        fields(
            [
                ("Key", row.get("key", "")),
                ("Bug type", _bug_type_label(row.get("bug_type"))),
                ("Subsystems", ", ".join(row.get("subsystems", [])) or "unknown"),
                ("Saved status", row.get("status") or "unknown"),
                ("Crashes", f"{row.get('crash_count', 0):,}"),
                ("Fixes", f"{row.get('fix_count', 0):,}"),
                ("Representative report", "available" if row.get("has_report") else "unavailable"),
            ]
        )
        patch_urls = row.get("patch_urls", [])
        if patch_urls:
            paragraph("Patch / commit URLs:", indent=2, tone="muted")
            for url in patch_urls:
                paragraph(url, indent=4, tone="link")
        else:
            fields([("Patch / commit URLs", "not recorded")])
        fields([("C reproducer", _c_reproducer_label(row.get("c_reproducer_status")))])
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
    for label, key in (("Bug types", "bug_types"), ("Subsystem tags", "subsystems")):
        section(label)
        entries = value[key]
        if not entries:
            paragraph("None recorded.", indent=2, tone="muted")
            continue
        fields([(safe_text(entry["value"]), f"{entry['count']:,} bugs") for entry in entries])
    print()
    paragraph("Use --type TYPE and --subsystem TAG; subsystem tags match exactly.", tone="muted")


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
    paragraph(bug.get("title", "Untitled bug"), tone="heading")
    metadata: list[tuple[str, object]] = [
        ("Key", bug.get("key", "")),
        ("Bug type", _bug_type_label(bug.get("bug_type"))),
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
        [("C reproducer", _c_reproducer_label(reproducer_status))]
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
        (label, _date(bug[field]))
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


def _issues(messages: Sequence[str]) -> None:
    messages = list(dict.fromkeys(messages))
    if not messages:
        return
    section("Issues", count=len(messages))
    for message in messages[:5]:
        paragraph("- " + message, indent=2, hanging=2, tone="warning")
    if len(messages) > 5:
        paragraph(
            f"{len(messages) - 5:,} more; use --json for all issue details.", indent=2, tone="muted"
        )


def _download_table(summary: UpdateSummary) -> None:
    rows = [
        ("Bug details", summary.details_downloaded, summary.details_reused, None),
        (
            "Reports",
            summary.reports_downloaded,
            summary.reports_reused,
            summary.reports_unavailable,
        ),
        ("Patches", summary.patches_downloaded, summary.patches_reused, None),
    ]
    section("Downloads")
    if terminal_width() < 64:
        for label, downloaded, reused, unavailable in rows:
            paragraph(label, indent=2, tone="strong")
            fields(
                [("Downloaded", f"{downloaded:,}"), ("Reused", f"{reused:,}")]
                + ([("Unavailable", f"{unavailable:,}")] if unavailable is not None else []),
                indent=4,
            )
        return
    print(style(f"  {'':14} {'Downloaded':>10}  {'Reused':>10}  {'Unavailable':>11}", tone="muted"))
    for label, downloaded, reused, unavailable in rows:
        missing = f"{unavailable:,}" if unavailable is not None else "-"
        downloaded_cell = style(f"{downloaded:>10,}", tone=_value_tone("Downloaded", downloaded))
        reused_cell = style(f"{reused:>10,}", tone=_value_tone("Reused", reused))
        missing_cell = style(f"{missing:>11}", tone="warning" if unavailable else "muted")
        print(
            f"  {style(label.ljust(14), tone='strong')} {downloaded_cell}  "
            f"{reused_cell}  {missing_cell}"
        )


def human_update(summary: UpdateSummary, data_root: Path, database_path: Path) -> None:
    state = str(summary.database.get("status") or "unknown")
    activated = bool(summary.database.get("activated"))
    heading = {
        "unchanged": "Already up to date",
        "completed": "Update complete" if activated else "Update not activated",
        "partial": "Update incomplete",
        "failed": "Update failed",
    }.get(state, "Update result unknown")
    tone = "success" if state == "unchanged" or state == "completed" and activated else "warning"
    if state == "failed":
        tone = "error"
    paragraph(heading, tone=tone)
    fields(
        [
            ("Fixed bugs", f"{summary.listing_bugs:,} live"),
            (
                "Changes",
                f"{summary.new_fixed_bugs:,} new; {summary.changed_bugs:,} changed; "
                f"{summary.no_longer_listed_bugs:,} no longer listed",
            ),
        ]
    )
    for label, keys in (
        ("New keys", summary.new_fixed_bug_keys),
        ("Changed keys", summary.changed_bug_keys),
        ("No longer listed", summary.no_longer_listed_bug_keys),
    ):
        if keys:
            preview = ", ".join(keys[:10])
            if len(keys) > 10:
                preview += f", ... (+{len(keys) - 10:,} more)"
            fields([(label, preview)])
    _download_table(summary)
    section("Database")
    result = {
        "unchanged": "unchanged; SQLite write skipped",
        "completed": "complete; snapshot activated"
        if activated
        else "complete; snapshot not activated",
        "partial": "partial; no snapshot activated",
    }.get(state, state)
    fields([("Result", result), ("File", database_path), ("Retained files", data_root)])
    if state == "partial":
        paragraph(
            "Any previously active snapshot is unchanged. Retry 'ss update' to resume.",
            indent=2,
            tone="warning",
        )
    retrieval_errors = {str(failure.get("error", "unknown error")) for failure in summary.failures}
    messages = []
    for failure in summary.failures:
        identity = " ".join(str(failure.get(key) or "") for key in ("kind", "key")).strip()
        messages.append(f"{identity}: {failure.get('error', 'unknown error')}")
    messages.extend(
        str(failure)
        for failure in summary.database.get("failures") or []
        if str(failure) not in retrieval_errors
    )
    _issues(messages)
    if state == "unchanged" and not any(
        (
            summary.new_fixed_bugs,
            summary.changed_bugs,
            summary.no_longer_listed_bugs,
            summary.details_downloaded,
            summary.reports_downloaded,
            summary.patches_downloaded,
            summary.failures,
            summary.database.get("failure_count"),
            summary.database.get("failures"),
        )
    ):
        print()
        paragraph(
            "No new fixed bugs; local files and database are already current.", tone="success"
        )


def human_import(result: dict[str, Any], database_path: Path) -> None:
    state = result.get("status", "unknown")
    paragraph(
        f"Import: {state}", tone="success" if state in {"completed", "unchanged"} else "warning"
    )
    fields(
        [
            ("Database", database_path),
            ("Bugs", f"{result.get('bugs', 0):,}"),
            ("Reports", f"{result.get('reports', 0):,}"),
            ("Patches", f"{result.get('patches', 0):,}"),
        ]
    )
    if state == "partial":
        paragraph("Candidate retained; active snapshot unchanged.", indent=2, tone="warning")
    _issues([str(item) for item in result.get("failures") or []])


def human_migrate(result: dict[str, Any], database_path: Path) -> None:
    paragraph(f"Database ready · schema {result['schema_version']}", tone="success")
    fields([("File", database_path)])
    section("Indexed locations")
    fields(
        [
            (label, f"{result['counts'][table]:,}")
            for label, table in (
                ("Subsystem tags", "bug_subsystems"),
                ("Crash locations", "crash_locations"),
                ("Stack frames", "crash_stack_frames"),
                ("Fix locations", "fix_locations"),
            )
        ]
    )


def progress(message: str) -> None:
    destination = sys.stderr
    label, separator, rest = safe_text(message).partition(": ")
    prefix = style("  > ", tone="accent", stream=destination)
    if separator and len(label) < 30:
        rest = re.sub(
            r"\b\d[\d,]*(?:/[\d,]+)?\b",
            lambda match: style(match.group(), tone="number", stream=destination),
            rest,
        )
        rendered = style(label + ":", tone="strong", stream=destination) + " " + rest
    else:
        rendered = safe_text(message)
    print(prefix + rendered, file=destination, flush=True)


def error(message: object) -> None:
    paragraph("Error: " + str(message), tone="error", stream=sys.stderr)
