"""Human summaries for updates, imports, migrations, and database checks."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from ...retrieval.models import UpdateSummary
from ..terminal import paragraph, section, style, terminal_width
from .common import fields, format_date, value_tone


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
    times = [
        (label, format_date(value[field]))
        for label, field in (("Finished", "last_sync_at"), ("Last checked", "last_checked_at"))
        if value.get(field)
    ]
    fields(times)
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
        downloaded_cell = style(f"{downloaded:>10,}", tone=value_tone("Downloaded", downloaded))
        reused_cell = style(f"{reused:>10,}", tone=value_tone("Reused", reused))
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
    changes: list[tuple[str, object]] = [
        ("Fixed bugs", f"{summary.listing_bugs:,} live"),
        (
            "Changes",
            f"{summary.new_fixed_bugs:,} new; {summary.changed_bugs:,} changed; "
            f"{summary.no_longer_listed_bugs:,} no longer listed",
        ),
    ]
    for label, keys in (
        ("New keys", summary.new_fixed_bug_keys),
        ("Changed keys", summary.changed_bug_keys),
        ("No longer listed", summary.no_longer_listed_bug_keys),
    ):
        if keys:
            preview = ", ".join(keys[:10])
            if len(keys) > 10:
                preview += f", ... (+{len(keys) - 10:,} more)"
            changes.append((label, preview))
    fields(changes)
    _download_table(summary)
    section("Database")
    result = {
        "unchanged": "unchanged; SQLite write skipped",
        "completed": "complete; snapshot activated"
        if activated
        else "complete; snapshot not activated",
        "partial": "partial; no snapshot activated",
    }.get(state, state)
    database_rows: list[tuple[str, object]] = [("Result", result)]
    if summary.database.get("snapshot_id") is not None:
        database_rows.append(("Snapshot", summary.database["snapshot_id"]))
    if "blobs_added" in summary.database:
        database_rows.append(("New blobs", f"{summary.database['blobs_added']:,}"))
    database_rows.extend([("File", database_path), ("Retained files", data_root)])
    fields(database_rows)
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
    activated = bool(result.get("activated"))
    heading = {
        "completed": "Import complete" if activated else "Import not activated",
        "unchanged": "Import already current",
        "partial": "Import incomplete",
        "failed": "Import failed",
    }.get(state, "Import result unknown")
    paragraph(
        heading,
        tone="error"
        if state == "failed"
        else "success"
        if state == "unchanged" or state == "completed" and activated
        else "warning",
    )
    outcome = {
        "completed": "complete; snapshot activated"
        if activated
        else "complete; snapshot not activated",
        "unchanged": "unchanged; SQLite write skipped",
        "partial": "partial; no snapshot activated",
        "failed": "failed; no snapshot activated",
    }.get(state, str(state))
    fields([("Result", outcome), ("Database", database_path)])
    rows: list[tuple[str, object]] = []
    bug_count = result.get("bugs", result.get("records_imported"))
    if bug_count is not None:
        rows.append(("Bugs", f"{bug_count:,}"))
    for label, key in (
        ("Bug details", "bug_payloads"),
        ("Reports", "reports"),
        ("Patches", "patches"),
    ):
        count = result.get(key)
        details = result.get(
            {"reports": "report_details", "patches": "patch_details"}.get(key, key), count
        )
        if isinstance(details, Mapping):
            text = f"{details.get('valid', 0):,} valid"
            if "expected" in details:
                text += f" / {details['expected']:,} expected"
            for field, suffix in (
                ("missing", "missing"),
                ("invalid", "invalid"),
                ("unavailable_upstream", "not provided upstream"),
            ):
                if details.get(field):
                    text += f"; {details[field]:,} {suffix}"
            rows.append((label, text))
        elif count is not None:
            rows.append((label, f"{count:,}"))
    if "blobs_added" in result:
        rows.append(("New blobs", f"{result['blobs_added']:,}"))
    if rows:
        section("Imported data" if state == "completed" and activated else "Local data")
        fields(rows)
    if state == "partial":
        paragraph("Candidate retained; active snapshot unchanged.", indent=2, tone="warning")
    _issues([str(item) for item in result.get("failures") or []])


def human_migrate(
    result: dict[str, Any], database_path: Path, *, prior_schema: int | None = None
) -> None:
    paragraph(f"Database ready · schema {result['schema_version']}", tone="success")
    rows: list[tuple[str, object]] = [("File", database_path)]
    if prior_schema is not None:
        rows.append(
            (
                "Migration",
                "already current"
                if prior_schema == result["schema_version"]
                else f"schema {prior_schema} -> {result['schema_version']}",
            )
        )
    fields(rows)
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
    paragraph("Counts include all retained history.", indent=2, tone="muted")
