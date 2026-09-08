"""Base SQL schema and schema-shape validation for the database facade."""

from __future__ import annotations

import sqlite3

SCHEMA_VERSION = 7


DEFAULT_SOURCE_URL = "https://syzkaller.appspot.com/upstream/fixed?json=1"


_REQUIRED_V1_COLUMNS: dict[str, frozenset[str]] = {
    "blobs": frozenset({"sha256", "content", "size_bytes", "media_type", "created_at"}),
    "sync_runs": frozenset(
        {
            "id",
            "source_url",
            "started_at",
            "completed_at",
            "status",
            "listing_json_sha256",
            "listing_html_sha256",
            "error_count",
            "summary_json",
        }
    ),
    "snapshots": frozenset(
        {
            "id",
            "run_id",
            "source_url",
            "source_version",
            "captured_at",
            "listing_json_sha256",
            "listing_html_sha256",
            "source_record_count",
            "record_count",
            "status",
            "is_current",
        }
    ),
    "bugs": frozenset(
        {
            "id",
            "key",
            "syzbot_id",
            "title",
            "bug_url",
            "json_url",
            "first_seen_at",
            "last_seen_at",
            "first_seen_run_id",
            "last_seen_run_id",
            "current_version_id",
        }
    ),
    "bug_versions": frozenset(
        {
            "id",
            "bug_id",
            "raw_sha256",
            "payload_kind",
            "fetched_at",
            "source_version",
            "title",
            "status",
            "first_crash_at",
            "last_crash_at",
            "fix_time",
            "close_time",
        }
    ),
    "snapshot_bugs": frozenset(
        {
            "snapshot_id",
            "bug_id",
            "bug_version_id",
            "position",
            "title",
            "bug_url",
            "json_url",
            "listing_record_sha256",
        }
    ),
    "commits": frozenset({"hash", "first_seen_run_id", "last_seen_run_id"}),
    "fix_commits": frozenset(
        {
            "id",
            "bug_version_id",
            "ordinal",
            "title",
            "normalized_title",
            "repo",
            "branch",
            "link",
            "reported_hash",
            "resolved_hash",
            "author_email",
            "author_name",
            "commit_date",
            "raw_sha256",
        }
    ),
    "listing_fix_commits": frozenset(
        {
            "id",
            "snapshot_id",
            "bug_id",
            "ordinal",
            "title",
            "normalized_title",
            "repo",
            "branch",
            "link",
            "reported_hash",
            "resolved_hash",
            "author_email",
            "author_name",
            "commit_date",
            "raw_sha256",
        }
    ),
    "cause_commits": frozenset(
        {
            "id",
            "bug_version_id",
            "title",
            "repo",
            "branch",
            "link",
            "commit_hash",
            "commit_date",
            "raw_sha256",
        }
    ),
    "crashes": frozenset(
        {
            "id",
            "bug_version_id",
            "ordinal",
            "title",
            "kernel_config_url",
            "kernel_source_git",
            "kernel_source_commit",
            "syzkaller_git",
            "syzkaller_commit",
            "crash_report_url",
            "c_reproducer_url",
            "syz_reproducer_url",
            "repro_opts_json",
            "raw_sha256",
        }
    ),
    "discussions": frozenset({"bug_version_id", "ordinal", "url"}),
    "fix_resolutions": frozenset(
        {
            "id",
            "bug_id",
            "normalized_title",
            "repo",
            "status",
            "resolved_hash",
            "search_url",
            "details_json",
            "raw_sha256",
            "first_seen_run_id",
            "last_seen_run_id",
        }
    ),
    "documents": frozenset(
        {
            "id",
            "kind",
            "natural_key",
            "source_url",
            "blob_sha256",
            "is_valid",
            "validation_error",
            "first_seen_run_id",
            "last_seen_run_id",
        }
    ),
    "reports": frozenset(
        {
            "id",
            "bug_id",
            "crash_id",
            "source_url",
            "current_blob_sha256",
            "first_seen_run_id",
            "last_seen_run_id",
        }
    ),
    "report_versions": frozenset(
        {
            "id",
            "report_id",
            "blob_sha256",
            "source_url",
            "is_valid",
            "validation_error",
            "first_seen_run_id",
            "last_seen_run_id",
        }
    ),
    "patches": frozenset(
        {
            "commit_hash",
            "current_blob_sha256",
            "source_url",
            "first_seen_run_id",
            "last_seen_run_id",
        }
    ),
    "patch_versions": frozenset(
        {
            "id",
            "commit_hash",
            "blob_sha256",
            "source_url",
            "is_valid",
            "validation_error",
            "first_seen_run_id",
            "last_seen_run_id",
        }
    ),
    "app_state": frozenset({"key", "value"}),
}


_SCHEMA_V1 = r"""
BEGIN IMMEDIATE;

CREATE TABLE IF NOT EXISTS blobs (
    sha256 TEXT PRIMARY KEY,
    content BLOB NOT NULL,
    size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0),
    media_type TEXT NOT NULL,
    created_at TEXT NOT NULL,
    CHECK (length(sha256) = 64),
    CHECK (size_bytes = length(content))
);

CREATE TABLE IF NOT EXISTS sync_runs (
    id INTEGER PRIMARY KEY,
    source_url TEXT NOT NULL,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    status TEXT NOT NULL CHECK (status IN ('running', 'completed', 'partial', 'failed')),
    listing_json_sha256 TEXT NOT NULL REFERENCES blobs(sha256),
    listing_html_sha256 TEXT REFERENCES blobs(sha256),
    error_count INTEGER NOT NULL DEFAULT 0 CHECK (error_count >= 0),
    summary_json TEXT
);

CREATE TABLE IF NOT EXISTS snapshots (
    id INTEGER PRIMARY KEY,
    run_id INTEGER NOT NULL UNIQUE REFERENCES sync_runs(id),
    source_url TEXT NOT NULL,
    source_version INTEGER,
    captured_at TEXT NOT NULL,
    listing_json_sha256 TEXT NOT NULL REFERENCES blobs(sha256),
    listing_html_sha256 TEXT REFERENCES blobs(sha256),
    source_record_count INTEGER NOT NULL CHECK (source_record_count >= 0),
    record_count INTEGER NOT NULL CHECK (record_count >= 0),
    status TEXT NOT NULL CHECK (status IN ('completed', 'partial')),
    is_current INTEGER NOT NULL DEFAULT 0 CHECK (is_current IN (0, 1))
);

CREATE UNIQUE INDEX IF NOT EXISTS one_current_snapshot
    ON snapshots(is_current) WHERE is_current = 1;

CREATE TABLE IF NOT EXISTS bugs (
    id INTEGER PRIMARY KEY,
    key TEXT NOT NULL UNIQUE,
    syzbot_id TEXT,
    title TEXT NOT NULL,
    bug_url TEXT NOT NULL DEFAULT '',
    json_url TEXT NOT NULL DEFAULT '',
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    first_seen_run_id INTEGER NOT NULL REFERENCES sync_runs(id),
    last_seen_run_id INTEGER NOT NULL REFERENCES sync_runs(id),
    current_version_id INTEGER REFERENCES bug_versions(id) DEFERRABLE INITIALLY DEFERRED
);

CREATE INDEX IF NOT EXISTS bugs_syzbot_id_idx ON bugs(syzbot_id);
CREATE INDEX IF NOT EXISTS bugs_title_idx ON bugs(title COLLATE NOCASE);

CREATE TABLE IF NOT EXISTS bug_versions (
    id INTEGER PRIMARY KEY,
    bug_id INTEGER NOT NULL REFERENCES bugs(id),
    raw_sha256 TEXT NOT NULL REFERENCES blobs(sha256),
    payload_kind TEXT NOT NULL CHECK (payload_kind IN ('bug-json', 'listing-record')),
    fetched_at TEXT NOT NULL,
    source_version INTEGER,
    title TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT '',
    first_crash_at TEXT,
    last_crash_at TEXT,
    fix_time TEXT,
    close_time TEXT,
    UNIQUE (bug_id, raw_sha256, payload_kind)
);

CREATE TABLE IF NOT EXISTS snapshot_bugs (
    snapshot_id INTEGER NOT NULL REFERENCES snapshots(id),
    bug_id INTEGER NOT NULL REFERENCES bugs(id),
    bug_version_id INTEGER NOT NULL REFERENCES bug_versions(id),
    position INTEGER NOT NULL CHECK (position >= 0),
    title TEXT NOT NULL,
    bug_url TEXT NOT NULL DEFAULT '',
    json_url TEXT NOT NULL DEFAULT '',
    listing_record_sha256 TEXT NOT NULL REFERENCES blobs(sha256),
    PRIMARY KEY (snapshot_id, bug_id),
    UNIQUE (snapshot_id, position)
);

CREATE INDEX IF NOT EXISTS snapshot_bugs_version_idx
    ON snapshot_bugs(bug_version_id);

CREATE TABLE IF NOT EXISTS commits (
    hash TEXT PRIMARY KEY,
    first_seen_run_id INTEGER NOT NULL REFERENCES sync_runs(id),
    last_seen_run_id INTEGER NOT NULL REFERENCES sync_runs(id)
);

CREATE TABLE IF NOT EXISTS fix_commits (
    id INTEGER PRIMARY KEY,
    bug_version_id INTEGER NOT NULL REFERENCES bug_versions(id),
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    title TEXT NOT NULL,
    normalized_title TEXT NOT NULL,
    repo TEXT NOT NULL DEFAULT '',
    branch TEXT NOT NULL DEFAULT '',
    link TEXT NOT NULL DEFAULT '',
    reported_hash TEXT REFERENCES commits(hash),
    resolved_hash TEXT REFERENCES commits(hash),
    author_email TEXT NOT NULL DEFAULT '',
    author_name TEXT NOT NULL DEFAULT '',
    commit_date TEXT,
    raw_sha256 TEXT NOT NULL REFERENCES blobs(sha256),
    UNIQUE (bug_version_id, ordinal)
);

CREATE INDEX IF NOT EXISTS fix_commits_reported_hash_idx ON fix_commits(reported_hash);
CREATE INDEX IF NOT EXISTS fix_commits_resolved_hash_idx ON fix_commits(resolved_hash);

CREATE TABLE IF NOT EXISTS listing_fix_commits (
    id INTEGER PRIMARY KEY,
    snapshot_id INTEGER NOT NULL REFERENCES snapshots(id),
    bug_id INTEGER NOT NULL REFERENCES bugs(id),
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    title TEXT NOT NULL,
    normalized_title TEXT NOT NULL,
    repo TEXT NOT NULL DEFAULT '',
    branch TEXT NOT NULL DEFAULT '',
    link TEXT NOT NULL DEFAULT '',
    reported_hash TEXT REFERENCES commits(hash),
    resolved_hash TEXT REFERENCES commits(hash),
    author_email TEXT NOT NULL DEFAULT '',
    author_name TEXT NOT NULL DEFAULT '',
    commit_date TEXT,
    raw_sha256 TEXT NOT NULL REFERENCES blobs(sha256),
    UNIQUE (snapshot_id, bug_id, ordinal)
);

CREATE INDEX IF NOT EXISTS listing_fix_commits_bug_idx
    ON listing_fix_commits(snapshot_id, bug_id);
CREATE INDEX IF NOT EXISTS listing_fix_commits_reported_hash_idx
    ON listing_fix_commits(reported_hash);
CREATE INDEX IF NOT EXISTS listing_fix_commits_resolved_hash_idx
    ON listing_fix_commits(resolved_hash);

CREATE TABLE IF NOT EXISTS cause_commits (
    id INTEGER PRIMARY KEY,
    bug_version_id INTEGER NOT NULL UNIQUE REFERENCES bug_versions(id),
    title TEXT NOT NULL,
    repo TEXT NOT NULL DEFAULT '',
    branch TEXT NOT NULL DEFAULT '',
    link TEXT NOT NULL DEFAULT '',
    commit_hash TEXT REFERENCES commits(hash),
    commit_date TEXT,
    raw_sha256 TEXT NOT NULL REFERENCES blobs(sha256)
);

CREATE TABLE IF NOT EXISTS crashes (
    id INTEGER PRIMARY KEY,
    bug_version_id INTEGER NOT NULL REFERENCES bug_versions(id),
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    title TEXT NOT NULL,
    kernel_config_url TEXT NOT NULL DEFAULT '',
    kernel_source_git TEXT NOT NULL DEFAULT '',
    kernel_source_commit TEXT NOT NULL DEFAULT '',
    syzkaller_git TEXT NOT NULL DEFAULT '',
    syzkaller_commit TEXT NOT NULL DEFAULT '',
    crash_report_url TEXT NOT NULL DEFAULT '',
    c_reproducer_url TEXT NOT NULL DEFAULT '',
    syz_reproducer_url TEXT NOT NULL DEFAULT '',
    repro_opts_json TEXT,
    raw_sha256 TEXT NOT NULL REFERENCES blobs(sha256),
    UNIQUE (bug_version_id, ordinal)
);

CREATE INDEX IF NOT EXISTS crashes_report_url_idx ON crashes(crash_report_url);

CREATE TABLE IF NOT EXISTS discussions (
    bug_version_id INTEGER NOT NULL REFERENCES bug_versions(id),
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    url TEXT NOT NULL,
    PRIMARY KEY (bug_version_id, ordinal)
);

CREATE TABLE IF NOT EXISTS fix_resolutions (
    id INTEGER PRIMARY KEY,
    bug_id INTEGER NOT NULL REFERENCES bugs(id),
    normalized_title TEXT NOT NULL,
    repo TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL,
    resolved_hash TEXT REFERENCES commits(hash),
    search_url TEXT NOT NULL DEFAULT '',
    details_json TEXT NOT NULL,
    raw_sha256 TEXT NOT NULL REFERENCES blobs(sha256),
    first_seen_run_id INTEGER NOT NULL REFERENCES sync_runs(id),
    last_seen_run_id INTEGER NOT NULL REFERENCES sync_runs(id),
    UNIQUE (bug_id, normalized_title, repo)
);

CREATE TABLE IF NOT EXISTS documents (
    id INTEGER PRIMARY KEY,
    kind TEXT NOT NULL,
    natural_key TEXT NOT NULL,
    source_url TEXT NOT NULL DEFAULT '',
    blob_sha256 TEXT NOT NULL REFERENCES blobs(sha256),
    is_valid INTEGER NOT NULL CHECK (is_valid IN (0, 1)),
    validation_error TEXT,
    first_seen_run_id INTEGER NOT NULL REFERENCES sync_runs(id),
    last_seen_run_id INTEGER NOT NULL REFERENCES sync_runs(id),
    UNIQUE (kind, natural_key, blob_sha256)
);

CREATE INDEX IF NOT EXISTS documents_kind_key_idx ON documents(kind, natural_key);

CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY,
    bug_id INTEGER NOT NULL UNIQUE REFERENCES bugs(id),
    crash_id INTEGER REFERENCES crashes(id),
    source_url TEXT NOT NULL DEFAULT '',
    current_blob_sha256 TEXT REFERENCES blobs(sha256),
    first_seen_run_id INTEGER NOT NULL REFERENCES sync_runs(id),
    last_seen_run_id INTEGER NOT NULL REFERENCES sync_runs(id)
);

CREATE TABLE IF NOT EXISTS report_versions (
    id INTEGER PRIMARY KEY,
    report_id INTEGER NOT NULL REFERENCES reports(id),
    blob_sha256 TEXT NOT NULL REFERENCES blobs(sha256),
    source_url TEXT NOT NULL DEFAULT '',
    is_valid INTEGER NOT NULL CHECK (is_valid IN (0, 1)),
    validation_error TEXT,
    first_seen_run_id INTEGER NOT NULL REFERENCES sync_runs(id),
    last_seen_run_id INTEGER NOT NULL REFERENCES sync_runs(id),
    UNIQUE (report_id, blob_sha256)
);

CREATE TABLE IF NOT EXISTS patches (
    commit_hash TEXT PRIMARY KEY REFERENCES commits(hash),
    current_blob_sha256 TEXT REFERENCES blobs(sha256),
    source_url TEXT NOT NULL DEFAULT '',
    first_seen_run_id INTEGER NOT NULL REFERENCES sync_runs(id),
    last_seen_run_id INTEGER NOT NULL REFERENCES sync_runs(id)
);

CREATE TABLE IF NOT EXISTS patch_versions (
    id INTEGER PRIMARY KEY,
    commit_hash TEXT NOT NULL REFERENCES patches(commit_hash),
    blob_sha256 TEXT NOT NULL REFERENCES blobs(sha256),
    source_url TEXT NOT NULL DEFAULT '',
    is_valid INTEGER NOT NULL CHECK (is_valid IN (0, 1)),
    validation_error TEXT,
    first_seen_run_id INTEGER NOT NULL REFERENCES sync_runs(id),
    last_seen_run_id INTEGER NOT NULL REFERENCES sync_runs(id),
    UNIQUE (commit_hash, blob_sha256)
);

CREATE TABLE IF NOT EXISTS app_state (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE VIEW IF NOT EXISTS current_bug_rows AS
SELECT
    b.id AS bug_id,
    b.key,
    b.syzbot_id,
    sb.title,
    sb.bug_url,
    sb.json_url,
    bv.id AS bug_version_id,
    bv.status,
    bv.first_crash_at,
    bv.last_crash_at,
    bv.fix_time,
    bv.close_time,
    bv.raw_sha256,
    sb.position,
    s.id AS snapshot_id
FROM snapshots AS s
JOIN snapshot_bugs AS sb ON sb.snapshot_id = s.id
JOIN bugs AS b ON b.id = sb.bug_id
JOIN bug_versions AS bv ON bv.id = sb.bug_version_id
WHERE s.is_current = 1;

PRAGMA user_version = 1;
COMMIT;
"""


def _validate_v1_schema(connection: sqlite3.Connection) -> None:
    objects = {
        (str(row["type"]), str(row["name"]))
        for row in connection.execute(
            """
            SELECT type, name FROM sqlite_master
            WHERE name NOT LIKE 'sqlite_%' AND type IN ('table', 'view')
            """
        )
    }
    missing_tables = [table for table in _REQUIRED_V1_COLUMNS if ("table", table) not in objects]
    problems: list[str] = []
    if missing_tables:
        problems.append("missing tables: " + ", ".join(sorted(missing_tables)))
    for table, required in _REQUIRED_V1_COLUMNS.items():
        if ("table", table) not in objects:
            continue
        # Table names come exclusively from the static manifest above.
        columns = {str(row["name"]) for row in connection.execute(f'PRAGMA table_info("{table}")')}
        missing_columns = sorted(required - columns)
        if missing_columns:
            problems.append(f"{table} missing columns: {', '.join(missing_columns)}")
    if ("view", "current_bug_rows") not in objects:
        problems.append("missing view: current_bug_rows")
    if problems:
        raise RuntimeError(
            "database schema version 1 is incomplete or incompatible; " + "; ".join(problems)
        )
