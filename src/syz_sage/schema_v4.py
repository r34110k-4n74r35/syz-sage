"""Snapshot-scoped bug classifications for offline filtering."""

from __future__ import annotations

import sqlite3

from .bug_types import BUG_TYPES, classify_bug_type
from .progress_events import ProgressCallback, report_progress

CURRENT_BUG_ROWS_V3 = """
CREATE VIEW current_bug_rows AS
SELECT b.id AS bug_id, b.key, b.syzbot_id, sb.title, sb.bug_url, sb.json_url,
       bv.id AS bug_version_id, bv.status, bv.first_crash_at, bv.last_crash_at,
       bv.fix_time, bv.close_time, bv.raw_sha256, sb.position, s.id AS snapshot_id
FROM snapshots AS s
JOIN snapshot_bugs AS sb ON sb.snapshot_id = s.id
JOIN bugs AS b ON b.id = sb.bug_id
JOIN bug_versions AS bv ON bv.id = sb.bug_version_id
WHERE s.is_current = 1
"""
CURRENT_BUG_ROWS = CURRENT_BUG_ROWS_V3.replace("sb.title,", "sb.title, sb.bug_type,")
INDEX_NAME = "snapshot_bugs_type_idx"


def validate(connection: sqlite3.Connection) -> None:
    columns = {row["name"]: row for row in connection.execute("PRAGMA table_info(snapshot_bugs)")}
    column = columns.get("bug_type")
    if column is None or not column["notnull"] or str(column["type"]).upper() != "TEXT":
        raise RuntimeError("database schema version 4 is incomplete: snapshot_bugs.bug_type")
    view_columns = {
        row["name"] for row in connection.execute("PRAGMA table_info(current_bug_rows)")
    }
    if "bug_type" not in view_columns:
        raise RuntimeError("database schema version 4 is incomplete: current_bug_rows.bug_type")
    indexed = [row["name"] for row in connection.execute(f"PRAGMA index_info({INDEX_NAME})")]
    if indexed != ["snapshot_id", "bug_type"]:
        raise RuntimeError(f"database schema version 4 is incomplete: {INDEX_NAME}")


def migrate(connection: sqlite3.Connection, *, on_progress: ProgressCallback | None = None) -> None:
    """Classify retained snapshot titles atomically without changing raw evidence."""
    report_progress(on_progress, "migrate-v4", "Migrating database to schema 4")
    connection.execute("BEGIN IMMEDIATE")
    try:
        allowed = ", ".join("'" + value.replace("'", "''") + "'" for value in BUG_TYPES)
        connection.execute(
            "ALTER TABLE snapshot_bugs ADD COLUMN bug_type TEXT NOT NULL DEFAULT 'other' "
            f"CHECK (bug_type IN ({allowed}))"
        )
        total = int(connection.execute("SELECT COUNT(*) FROM snapshot_bugs").fetchone()[0])
        completed = 0
        report_progress(on_progress, "migrate-v4-bugs", "Classifying stored bug titles", 0, total)
        cursor = connection.execute("SELECT snapshot_id, bug_id, title FROM snapshot_bugs")
        while rows := cursor.fetchmany(256):
            connection.executemany(
                "UPDATE snapshot_bugs SET bug_type = ? WHERE snapshot_id = ? AND bug_id = ?",
                [
                    (classify_bug_type(row["title"]), row["snapshot_id"], row["bug_id"])
                    for row in rows
                ],
            )
            completed += len(rows)
            report_progress(
                on_progress, "migrate-v4-bugs", "Classifying stored bug titles", completed, total
            )
        connection.execute(f"CREATE INDEX {INDEX_NAME} ON snapshot_bugs(snapshot_id, bug_type)")
        connection.execute("DROP VIEW current_bug_rows")
        connection.execute(CURRENT_BUG_ROWS)
        connection.execute("PRAGMA user_version = 4")
        validate(connection)
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    report_progress(on_progress, "migrate-v4", "Database schema 4 committed", 1, 1)


def consistency_errors(connection: sqlite3.Connection) -> list[str]:
    """Detect incorrect classifications without repairing retained snapshots."""
    mismatches = sum(
        row["bug_type"] != classify_bug_type(row["title"])
        for row in connection.execute("SELECT title, bug_type FROM snapshot_bugs")
    )
    return [f"snapshot bug type mismatch: {mismatches}"] if mismatches else []
