"""Snapshot-scoped failure/access classifications and queryable patch-size coverage."""

from __future__ import annotations

import sqlite3

from ..parsing.characteristics import ACCESS_MODES, BUG_FAMILIES
from ..project.progress_events import ProgressCallback, progress_items, report_progress
from . import patch_metrics
from .characteristics import index_snapshot

METRICS_VIEW = """
CREATE VIEW IF NOT EXISTS current_bug_patch_metrics AS
WITH refs AS (
 SELECT c.bug_id,c.snapshot_id,f.normalized_title,f.repo,
 COALESCE(f.reported_hash,f.resolved_hash) AS hash
 FROM current_bug_rows c JOIN listing_fix_commits f
 ON f.snapshot_id=c.snapshot_id AND f.bug_id=c.bug_id
 UNION ALL
 SELECT c.bug_id,c.snapshot_id,f.normalized_title,f.repo,COALESCE(f.reported_hash,f.resolved_hash)
 FROM current_bug_rows c JOIN fix_commits f ON f.bug_version_id=c.bug_version_id
), hashes AS (
 SELECT DISTINCT bug_id,snapshot_id,hash FROM refs WHERE hash IS NOT NULL
), patches AS (
 SELECT h.bug_id,h.hash,pv.id AS version_id,pc.is_complete
 FROM hashes h LEFT JOIN snapshot_patches sp
 ON sp.snapshot_id=h.snapshot_id AND sp.commit_hash=h.hash
 LEFT JOIN patch_versions pv ON pv.id=sp.patch_version_id AND pv.is_valid=1
 LEFT JOIN patch_metric_coverage pc ON pc.patch_version_id=pv.id
), counts AS (
 SELECT p.bug_id,COUNT(DISTINCT p.hash) AS hash_count,
 COUNT(DISTINCT CASE WHEN p.version_id IS NOT NULL THEN p.hash END) AS patch_count,
 COUNT(DISTINCT COALESCE(l.new_file_path,l.old_file_path)) AS file_count,
 SUM(l.old_count+l.new_count) AS line_count,
 MAX(CASE WHEN COALESCE(p.is_complete,0)=0 OR l.id IS NULL OR l.kind IN ('binary','unparsed')
              OR COALESCE(l.new_file_path,l.old_file_path) IS NULL THEN 1 ELSE 0 END) AS unknown
 FROM patches p LEFT JOIN fix_locations l ON l.patch_version_id=p.version_id GROUP BY p.bug_id
), unknown_refs AS (
 SELECT DISTINCT r.bug_id FROM refs r WHERE r.hash IS NULL AND (r.normalized_title='' OR
 (SELECT COUNT(DISTINCT k.hash) FROM refs k WHERE k.bug_id=r.bug_id
 AND k.normalized_title=r.normalized_title AND k.repo=r.repo AND k.hash IS NOT NULL)<>1)
)
SELECT c.bug_id,COALESCE(n.patch_count,0)>0 AS has_patch,
 CASE WHEN n.hash_count>0 AND n.hash_count=n.patch_count AND n.unknown=0 AND u.bug_id IS NULL
 THEN n.file_count END AS fix_file_count,
 CASE WHEN n.hash_count>0 AND n.hash_count=n.patch_count AND n.unknown=0 AND u.bug_id IS NULL
 THEN COALESCE(n.line_count,0) END AS patch_line_count
FROM current_bug_rows c LEFT JOIN counts n ON n.bug_id=c.bug_id
LEFT JOIN unknown_refs u ON u.bug_id=c.bug_id
"""


def validate(connection: sqlite3.Connection) -> None:
    required = {
        "snapshot_id",
        "bug_id",
        "family",
        "access_mode",
        "evidence_json",
        "c_reproducer_status",
        "c_reproducer_urls_json",
        "classifier_version",
    }
    columns = {
        row["name"] for row in connection.execute("PRAGMA table_info(snapshot_bug_characteristics)")
    }
    if required - columns:
        raise RuntimeError("database schema version 7 is incomplete: snapshot_bug_characteristics")
    connection.execute(
        "SELECT has_patch,fix_file_count,patch_line_count FROM current_bug_patch_metrics LIMIT 0"
    )
    connection.execute("SELECT patch_version_id,is_complete FROM patch_metric_coverage LIMIT 0")


def migrate(connection: sqlite3.Connection, *, on_progress: ProgressCallback | None = None) -> None:
    report_progress(on_progress, "migrate-v7", "Migrating database to schema 7")
    connection.execute("BEGIN IMMEDIATE")
    try:
        families = ",".join(repr(value) for value in BUG_FAMILIES)
        access = ",".join(repr(value) for value in ACCESS_MODES)
        connection.execute(f"""CREATE TABLE IF NOT EXISTS snapshot_bug_characteristics(
            snapshot_id INTEGER NOT NULL,bug_id INTEGER NOT NULL,
            family TEXT NOT NULL CHECK(family IN ({families})),
            access_mode TEXT NOT NULL CHECK(access_mode IN ({access})),
            evidence_json TEXT NOT NULL,c_reproducer_status TEXT NOT NULL
              CHECK(c_reproducer_status IN ('available','not_provided','unknown')),
            c_reproducer_urls_json TEXT NOT NULL,classifier_version INTEGER NOT NULL,
            PRIMARY KEY(snapshot_id,bug_id),
            FOREIGN KEY(snapshot_id,bug_id) REFERENCES snapshot_bugs(snapshot_id,bug_id)
        )""")
        connection.execute(
            "CREATE INDEX IF NOT EXISTS characteristics_family_idx "
            "ON snapshot_bug_characteristics(snapshot_id,family)"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS characteristics_access_idx "
            "ON snapshot_bug_characteristics(snapshot_id,access_mode)"
        )
        connection.execute(
            "CREATE TABLE IF NOT EXISTS patch_metric_coverage("
            "patch_version_id INTEGER PRIMARY KEY REFERENCES patch_versions(id),"
            "is_complete INTEGER NOT NULL CHECK(is_complete IN (0,1)))"
        )
        connection.execute(METRICS_VIEW)
        patches = connection.execute("SELECT id FROM patch_versions WHERE is_valid=1").fetchall()
        for row in progress_items(
            patches,
            on_progress,
            "migrate-v7-patches",
            "Checking stored patch coverage",
            total=len(patches),
        ):
            patch_metrics.index_patch(connection, int(row[0]))
        snapshots = connection.execute("SELECT id FROM snapshots ORDER BY id").fetchall()
        for row in progress_items(
            snapshots,
            on_progress,
            "migrate-v7-snapshots",
            "Classifying stored snapshots",
            total=len(snapshots),
        ):
            index_snapshot(connection, int(row[0]), on_progress=on_progress)
        validate(connection)
        connection.execute("PRAGMA user_version=7")
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    report_progress(on_progress, "migrate-v7", "Database schema 7 committed", 1, 1)


def consistency_errors(connection: sqlite3.Connection) -> list[str]:
    count = int(
        connection.execute(
            "SELECT COUNT(*) FROM snapshot_bugs sb LEFT JOIN snapshot_bug_characteristics ch "
            "ON ch.snapshot_id=sb.snapshot_id AND ch.bug_id=sb.bug_id "
            "WHERE ch.bug_id IS NULL OR ch.classifier_version<>1"
        ).fetchone()[0]
    )
    errors = [f"missing or stale bug characteristics: {count}"] if count else []
    missing_patches = connection.execute(
        "SELECT COUNT(*) FROM patch_versions pv LEFT JOIN patch_metric_coverage pc "
        "ON pc.patch_version_id=pv.id WHERE pv.is_valid=1 AND pc.patch_version_id IS NULL"
    ).fetchone()[0]
    if missing_patches:
        errors.append(f"missing patch coverage: {missing_patches}")
    return errors
