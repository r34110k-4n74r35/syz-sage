"""Repair crash locations that borrowed source coordinates from diagnostic stacks."""

from __future__ import annotations

import sqlite3

from ..project.progress_events import ProgressCallback, progress_items, report_progress
from . import location_store


def migrate(connection: sqlite3.Connection, *, on_progress: ProgressCallback | None = None) -> None:
    """Reparse retained report associations while preserving their complete raw stacks."""
    report_progress(on_progress, "migrate-v6", "Migrating database to schema 6")
    connection.execute("BEGIN IMMEDIATE")
    try:
        pairs = connection.execute("""
            SELECT report_version_id, crash_id FROM crash_locations
            UNION SELECT report_version_id, crash_id FROM snapshot_reports
        """).fetchall()
        for report_version_id, crash_id in progress_items(
            pairs,
            on_progress,
            "migrate-v6-reports",
            "Reparsing stored crash reports",
            total=len(pairs),
        ):
            location_store.index_report(connection, int(report_version_id), int(crash_id))
        connection.execute("PRAGMA user_version = 6")
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    report_progress(on_progress, "migrate-v6", "Database schema 6 committed", 1, 1)
