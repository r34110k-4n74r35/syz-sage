"""Repair crash/origin interpretation without changing stored source evidence."""

from __future__ import annotations

import sqlite3

from . import location_store


def migrate(connection: sqlite3.Connection) -> None:
    """Reparse current and historical report associations in one transaction."""
    connection.execute("BEGIN IMMEDIATE")
    try:
        pairs = connection.execute("""
            SELECT report_version_id, crash_id FROM crash_locations
            UNION SELECT report_version_id, crash_id FROM snapshot_reports
        """).fetchall()
        for report_version_id, crash_id in pairs:
            location_store.index_report(connection, int(report_version_id), int(crash_id))
        connection.execute("PRAGMA user_version = 5")
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
