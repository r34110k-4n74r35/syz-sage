"""Repair crash/origin interpretation without changing stored source evidence."""

from __future__ import annotations

import sqlite3

from . import location_store
from .progress_events import ProgressCallback, progress_items, report_progress


def migrate(connection: sqlite3.Connection, *, on_progress: ProgressCallback | None = None) -> None:
    """Reparse current and historical report associations in one transaction."""
    report_progress(on_progress, "migrate-v5", "Migrating database to schema 5")
    connection.execute("BEGIN IMMEDIATE")
    try:
        pairs = connection.execute("""
            SELECT report_version_id, crash_id FROM crash_locations
            UNION SELECT report_version_id, crash_id FROM snapshot_reports
        """).fetchall()
        for report_version_id, crash_id in progress_items(
            pairs,
            on_progress,
            "migrate-v5-reports",
            "Reparsing stored crash reports",
            total=len(pairs),
        ):
            location_store.index_report(connection, int(report_version_id), int(crash_id))
        connection.execute("PRAGMA user_version = 5")
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    report_progress(on_progress, "migrate-v5", "Database schema 5 committed", 1, 1)
