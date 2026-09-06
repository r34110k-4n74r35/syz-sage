"""Snapshot artifact provenance and transactional parser repair for schema v3."""

from __future__ import annotations

import sqlite3

from . import location_store

SCHEMA = """
CREATE TABLE snapshot_reports (
    snapshot_id INTEGER NOT NULL,
    bug_id INTEGER NOT NULL,
    report_version_id INTEGER NOT NULL REFERENCES report_versions(id),
    crash_id INTEGER NOT NULL REFERENCES crashes(id),
    source_url TEXT NOT NULL,
    PRIMARY KEY (snapshot_id, bug_id),
    FOREIGN KEY (snapshot_id, bug_id) REFERENCES snapshot_bugs(snapshot_id, bug_id)
);
CREATE INDEX snapshot_reports_version_idx ON snapshot_reports(report_version_id);
CREATE TRIGGER snapshot_reports_owner BEFORE INSERT ON snapshot_reports
WHEN NOT EXISTS (
    SELECT 1 FROM report_versions rv JOIN reports r ON r.id = rv.report_id
    JOIN snapshot_bugs sb ON sb.snapshot_id = NEW.snapshot_id AND sb.bug_id = NEW.bug_id
    JOIN crashes cr ON cr.bug_version_id = sb.bug_version_id
    WHERE rv.id = NEW.report_version_id AND r.bug_id = NEW.bug_id AND cr.id = NEW.crash_id
)
BEGIN SELECT RAISE(ABORT, 'snapshot report belongs to a different bug or crash version'); END;
CREATE TRIGGER snapshot_reports_owner_update BEFORE UPDATE ON snapshot_reports
WHEN NOT EXISTS (
    SELECT 1 FROM report_versions rv JOIN reports r ON r.id = rv.report_id
    JOIN snapshot_bugs sb ON sb.snapshot_id = NEW.snapshot_id AND sb.bug_id = NEW.bug_id
    JOIN crashes cr ON cr.bug_version_id = sb.bug_version_id
    WHERE rv.id = NEW.report_version_id AND r.bug_id = NEW.bug_id AND cr.id = NEW.crash_id
)
BEGIN SELECT RAISE(ABORT, 'snapshot report belongs to a different bug or crash version'); END;
CREATE TABLE snapshot_patches (
    snapshot_id INTEGER NOT NULL REFERENCES snapshots(id),
    commit_hash TEXT NOT NULL REFERENCES commits(hash),
    patch_version_id INTEGER NOT NULL REFERENCES patch_versions(id),
    source_url TEXT NOT NULL,
    PRIMARY KEY (snapshot_id, commit_hash)
);
CREATE INDEX snapshot_patches_version_idx ON snapshot_patches(patch_version_id);
CREATE TRIGGER snapshot_patches_owner BEFORE INSERT ON snapshot_patches
WHEN NOT EXISTS (
    SELECT 1 FROM patch_versions WHERE id = NEW.patch_version_id AND commit_hash = NEW.commit_hash
)
BEGIN SELECT RAISE(ABORT, 'snapshot patch belongs to a different commit'); END;
CREATE TRIGGER snapshot_patches_owner_update BEFORE UPDATE ON snapshot_patches
WHEN NOT EXISTS (
    SELECT 1 FROM patch_versions WHERE id = NEW.patch_version_id AND commit_hash = NEW.commit_hash
)
BEGIN SELECT RAISE(ABORT, 'snapshot patch belongs to a different commit'); END;

DROP VIEW current_crash_locations;
CREATE VIEW current_crash_locations AS
SELECT c.key, c.title, c.bug_id, l.*, cr.kernel_source_git, cr.kernel_source_commit,
       rv.blob_sha256 AS report_sha256, sr.source_url AS report_url
FROM current_bug_rows c
JOIN snapshot_reports sr ON sr.snapshot_id = c.snapshot_id AND sr.bug_id = c.bug_id
JOIN report_versions rv ON rv.id = sr.report_version_id
JOIN crash_locations l ON l.report_version_id = rv.id AND l.crash_id = sr.crash_id
JOIN crashes cr ON cr.id = l.crash_id;

DROP VIEW current_crash_stack_frames;
CREATE VIEW current_crash_stack_frames AS
SELECT c.key, c.bug_id, f.* FROM current_bug_rows c
JOIN snapshot_reports sr ON sr.snapshot_id = c.snapshot_id AND sr.bug_id = c.bug_id
JOIN crash_stack_frames f ON f.report_version_id = sr.report_version_id;

DROP VIEW current_fix_locations;
CREATE VIEW current_fix_locations AS
WITH bug_fixes AS (
    SELECT c.bug_id, COALESCE(f.reported_hash, f.resolved_hash) AS commit_hash, f.repo
    FROM current_bug_rows c
    JOIN listing_fix_commits f ON f.snapshot_id = c.snapshot_id AND f.bug_id = c.bug_id
    UNION
    SELECT c.bug_id, COALESCE(f.reported_hash, f.resolved_hash) AS commit_hash, f.repo
    FROM current_bug_rows c JOIN fix_commits f ON f.bug_version_id = c.bug_version_id
)
SELECT c.key, c.title, c.bug_id, bf.commit_hash, bf.repo, pv.blob_sha256 AS patch_sha256,
       sp.source_url AS patch_url, l.*
FROM current_bug_rows c
JOIN bug_fixes bf ON bf.bug_id = c.bug_id
JOIN snapshot_patches sp ON sp.snapshot_id = c.snapshot_id AND sp.commit_hash = bf.commit_hash
JOIN patch_versions pv ON pv.id = sp.patch_version_id
JOIN fix_locations l ON l.patch_version_id = pv.id;
"""

REQUIRED_COLUMNS = {
    "snapshot_reports": {"snapshot_id", "bug_id", "report_version_id", "crash_id", "source_url"},
    "snapshot_patches": {"snapshot_id", "commit_hash", "patch_version_id", "source_url"},
}


def validate(connection: sqlite3.Connection) -> None:
    for table, required in REQUIRED_COLUMNS.items():
        columns = {row["name"] for row in connection.execute(f'PRAGMA table_info("{table}")')}
        if required - columns:
            raise RuntimeError(f"database schema version 3 is incomplete: {table}")
    for trigger in (
        "snapshot_reports_owner",
        "snapshot_reports_owner_update",
        "snapshot_patches_owner",
        "snapshot_patches_owner_update",
    ):
        if (
            connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'trigger' AND name = ?",
                (trigger,),
            ).fetchone()
            is None
        ):
            raise RuntimeError(f"database schema version 3 is incomplete: {trigger}")


def migrate(connection: sqlite3.Connection) -> None:
    """Preserve raw history; repair derived fields and record provable associations."""
    connection.execute("BEGIN IMMEDIATE")
    try:
        statement = ""
        for line in SCHEMA.splitlines(keepends=True):
            statement += line
            if sqlite3.complete_statement(statement):
                connection.execute(statement)
                statement = ""
        # v2 retained current pointers, but did not record which artifact version
        # belonged to each older snapshot. Do not guess historical associations.
        connection.execute("""
            INSERT INTO snapshot_reports
            SELECT c.snapshot_id, c.bug_id, rv.id, r.crash_id, r.source_url
            FROM current_bug_rows c JOIN reports r ON r.bug_id = c.bug_id
            JOIN report_versions rv ON rv.report_id = r.id
                 AND rv.blob_sha256 = r.current_blob_sha256 AND rv.is_valid = 1
            JOIN crashes cr ON cr.id = r.crash_id AND cr.bug_version_id = c.bug_version_id
        """)
        connection.execute("""
            INSERT INTO snapshot_patches
            SELECT s.id, p.commit_hash, pv.id, p.source_url FROM snapshots s
            CROSS JOIN patches p JOIN patch_versions pv ON pv.commit_hash = p.commit_hash
                 AND pv.blob_sha256 = p.current_blob_sha256 AND pv.is_valid = 1
            WHERE s.is_current = 1
        """)
        pairs = connection.execute("""
            SELECT DISTINCT report_version_id, crash_id FROM crash_locations
            UNION SELECT report_version_id, crash_id FROM snapshot_reports
        """).fetchall()
        for row in pairs:
            location_store.index_report(connection, int(row[0]), int(row[1]))
        for row in connection.execute(
            "SELECT id FROM patch_versions WHERE is_valid = 1"
        ).fetchall():
            location_store.index_patch(connection, int(row[0]))
        connection.execute("PRAGMA user_version = 3")
        validate(connection)
        connection.commit()
    except BaseException:
        connection.rollback()
        raise


def consistency_errors(connection: sqlite3.Connection) -> list[str]:
    """Check logical associations not covered by ordinary foreign keys."""
    errors: list[str] = []
    checks = {
        "snapshot report ownership mismatch": """
            SELECT COUNT(*) FROM snapshot_reports sr
            JOIN report_versions rv ON rv.id = sr.report_version_id
            JOIN reports r ON r.id = rv.report_id JOIN crashes cr ON cr.id = sr.crash_id
            JOIN snapshot_bugs sb ON sb.snapshot_id = sr.snapshot_id AND sb.bug_id = sr.bug_id
            WHERE r.bug_id <> sr.bug_id OR cr.bug_version_id <> sb.bug_version_id
        """,
        "snapshot patch ownership mismatch": """
            SELECT COUNT(*) FROM snapshot_patches sp JOIN patch_versions pv
            ON pv.id = sp.patch_version_id WHERE pv.commit_hash <> sp.commit_hash
        """,
        "snapshot uses invalid report version": """
            SELECT COUNT(*) FROM snapshot_reports sr
            JOIN report_versions rv ON rv.id = sr.report_version_id WHERE rv.is_valid <> 1
        """,
        "snapshot uses invalid patch version": """
            SELECT COUNT(*) FROM snapshot_patches sp
            JOIN patch_versions pv ON pv.id = sp.patch_version_id WHERE pv.is_valid <> 1
        """,
        "active report has no snapshot association": """
            SELECT COUNT(*) FROM current_bug_rows c JOIN reports r ON r.bug_id = c.bug_id
            LEFT JOIN snapshot_reports sr ON sr.snapshot_id = c.snapshot_id AND sr.bug_id = c.bug_id
            WHERE r.current_blob_sha256 IS NOT NULL AND sr.report_version_id IS NULL
        """,
        "active report has no current location extraction": f"""
            SELECT COUNT(*) FROM snapshot_reports sr JOIN snapshots s ON s.id = sr.snapshot_id
            WHERE s.is_current = 1 AND NOT EXISTS (
                SELECT 1 FROM crash_locations l WHERE l.report_version_id = sr.report_version_id
                AND l.crash_id = sr.crash_id
                AND l.parser_version = {location_store.REPORT_PARSER_VERSION})
        """,
        "active patch has no current location extraction": f"""
            SELECT COUNT(*) FROM snapshot_patches sp JOIN snapshots s ON s.id = sp.snapshot_id
            WHERE s.is_current = 1 AND NOT EXISTS (
                SELECT 1 FROM fix_locations l WHERE l.patch_version_id = sp.patch_version_id
                AND l.parser_version = {location_store.PATCH_PARSER_VERSION})
        """,
    }
    for name, query in checks.items():
        count = int(connection.execute(query).fetchone()[0])
        if count:
            errors.append(f"{name}: {count}")
    return errors
