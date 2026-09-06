"""Schema v2: subsystem labels, crash locations/stacks and fix locations."""

from __future__ import annotations

import hashlib
import sqlite3
from dataclasses import asdict, dataclass
from typing import Any

from .locations import (
    CrashSite,
    StackFrame,
    extract_stack_frames,
    locate_crash_site,
    locate_kcsan_sites,
    title_functions,
)
from .parsing import parse_subsystem_tags
from .patch_locations import FixLocation, extract_fix_locations

PARSER_VERSION = 2


@dataclass(frozen=True)
class PreparedReport:
    digest: str
    title: str
    sites: list[CrashSite]
    frames: list[StackFrame]


@dataclass(frozen=True)
class PreparedPatch:
    digest: str
    locations: list[FixLocation]


def prepare_report(payload: bytes, title: str) -> PreparedReport:
    report = payload.decode("utf-8", errors="replace")
    return PreparedReport(
        hashlib.sha256(payload).hexdigest(),
        title,
        _crash_sites(title, report),
        extract_stack_frames(report),
    )


def prepare_patch(payload: bytes) -> PreparedPatch:
    locations = extract_fix_locations(payload.decode("utf-8", errors="replace"))
    if not locations:
        locations = [FixLocation(None, None, None, 0, None, 0, None, "", "unparsed")]
    return PreparedPatch(hashlib.sha256(payload).hexdigest(), locations)


# The caller owns the transaction, including the backfill and schema version.
SCHEMA_V2 = """
CREATE TABLE bug_subsystems (
    snapshot_id INTEGER NOT NULL,
    bug_id INTEGER NOT NULL,
    tag TEXT NOT NULL CHECK (length(tag) > 0),
    source_blob_sha256 TEXT NOT NULL REFERENCES blobs(sha256),
    PRIMARY KEY (snapshot_id, bug_id, tag),
    FOREIGN KEY (snapshot_id, bug_id) REFERENCES snapshot_bugs(snapshot_id, bug_id)
);
CREATE INDEX bug_subsystems_tag_idx ON bug_subsystems(tag, snapshot_id, bug_id);

CREATE TABLE crash_locations (
    id INTEGER PRIMARY KEY,
    report_version_id INTEGER NOT NULL REFERENCES report_versions(id),
    crash_id INTEGER NOT NULL REFERENCES crashes(id),
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    role TEXT NOT NULL,
    file_path TEXT,
    function_name TEXT,
    line_number INTEGER CHECK (line_number > 0),
    column_number INTEGER CHECK (column_number > 0),
    confidence TEXT NOT NULL CHECK (confidence IN ('high', 'medium', 'low')),
    method TEXT NOT NULL,
    evidence TEXT NOT NULL,
    parser_version INTEGER NOT NULL,
    UNIQUE (report_version_id, crash_id, ordinal)
);
CREATE INDEX crash_locations_file_idx ON crash_locations(file_path, line_number);

CREATE TABLE crash_stack_frames (
    report_version_id INTEGER NOT NULL REFERENCES report_versions(id),
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    section TEXT NOT NULL,
    report_line INTEGER NOT NULL CHECK (report_line > 0),
    function_name TEXT,
    file_path TEXT,
    line_number INTEGER CHECK (line_number > 0),
    column_number INTEGER CHECK (column_number > 0),
    is_inline INTEGER NOT NULL CHECK (is_inline IN (0, 1)),
    raw_line TEXT NOT NULL,
    parser_version INTEGER NOT NULL,
    PRIMARY KEY (report_version_id, ordinal)
);

CREATE TABLE fix_locations (
    id INTEGER PRIMARY KEY,
    patch_version_id INTEGER NOT NULL REFERENCES patch_versions(id),
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    old_file_path TEXT,
    new_file_path TEXT,
    old_start INTEGER CHECK (old_start >= 0),
    old_count INTEGER NOT NULL CHECK (old_count >= 0),
    new_start INTEGER CHECK (new_start >= 0),
    new_count INTEGER NOT NULL CHECK (new_count >= 0),
    function_name TEXT,
    function_basis TEXT NOT NULL,
    hunk_header TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('text', 'file-only', 'rename', 'binary', 'unparsed')),
    parser_version INTEGER NOT NULL,
    UNIQUE (patch_version_id, ordinal)
);
CREATE INDEX fix_locations_old_file_idx ON fix_locations(old_file_path, old_start);
CREATE INDEX fix_locations_new_file_idx ON fix_locations(new_file_path, new_start);

CREATE VIEW current_bug_subsystems AS
SELECT c.key, c.title, t.* FROM current_bug_rows c
JOIN bug_subsystems t ON t.snapshot_id = c.snapshot_id AND t.bug_id = c.bug_id;

CREATE VIEW current_crash_locations AS
SELECT c.key, c.title, c.bug_id, l.*, cr.kernel_source_git, cr.kernel_source_commit,
       rv.blob_sha256 AS report_sha256, rv.source_url AS report_url
FROM current_bug_rows c
JOIN reports r ON r.bug_id = c.bug_id
JOIN report_versions rv ON rv.report_id = r.id AND rv.blob_sha256 = r.current_blob_sha256
JOIN crash_locations l ON l.report_version_id = rv.id AND l.crash_id = r.crash_id
JOIN crashes cr ON cr.id = l.crash_id;

CREATE VIEW current_crash_stack_frames AS
SELECT c.key, c.bug_id, f.* FROM current_bug_rows c
JOIN reports r ON r.bug_id = c.bug_id
JOIN report_versions rv ON rv.report_id = r.id AND rv.blob_sha256 = r.current_blob_sha256
JOIN crash_stack_frames f ON f.report_version_id = rv.id;

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
       pv.source_url AS patch_url, l.*
FROM current_bug_rows c
JOIN bug_fixes bf ON bf.bug_id = c.bug_id
JOIN patches p ON p.commit_hash = bf.commit_hash
JOIN patch_versions pv ON pv.commit_hash = p.commit_hash AND pv.blob_sha256 = p.current_blob_sha256
JOIN fix_locations l ON l.patch_version_id = pv.id;
"""

REQUIRED_COLUMNS = {
    "bug_subsystems": {"snapshot_id", "bug_id", "tag", "source_blob_sha256"},
    "crash_locations": {
        "id",
        "report_version_id",
        "crash_id",
        "ordinal",
        "role",
        "file_path",
        "function_name",
        "line_number",
        "column_number",
        "confidence",
        "method",
        "evidence",
        "parser_version",
    },
    "crash_stack_frames": {
        "report_version_id",
        "ordinal",
        "section",
        "report_line",
        "function_name",
        "file_path",
        "line_number",
        "column_number",
        "is_inline",
        "raw_line",
        "parser_version",
    },
    "fix_locations": {
        "id",
        "patch_version_id",
        "ordinal",
        "old_file_path",
        "new_file_path",
        "old_start",
        "old_count",
        "new_start",
        "new_count",
        "function_name",
        "function_basis",
        "hunk_header",
        "kind",
        "parser_version",
    },
}


def validate_schema(connection: sqlite3.Connection) -> None:
    for table, required in REQUIRED_COLUMNS.items():
        actual = {str(row["name"]) for row in connection.execute(f'PRAGMA table_info("{table}")')}
        if required - actual:
            raise RuntimeError(f"database schema version 2 is incomplete: {table}")
    for view in (
        "current_bug_subsystems",
        "current_crash_locations",
        "current_crash_stack_frames",
        "current_fix_locations",
    ):
        if (
            connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'view' AND name = ?",
                (view,),
            ).fetchone()
            is None
        ):
            raise RuntimeError(f"database schema version 2 is incomplete: {view}")


def index_subsystems(connection: sqlite3.Connection, snapshot_id: int) -> None:
    row = connection.execute(
        """SELECT s.listing_html_sha256, b.content FROM snapshots s
           JOIN blobs b ON b.sha256 = s.listing_html_sha256 WHERE s.id = ?""",
        (snapshot_id,),
    ).fetchone()
    if row is None:
        return
    tags = parse_subsystem_tags(bytes(row["content"]).decode("utf-8", errors="replace"))
    for bug in connection.execute(
        """SELECT sb.bug_id, b.key FROM snapshot_bugs sb
           JOIN bugs b ON b.id = sb.bug_id WHERE sb.snapshot_id = ?""",
        (snapshot_id,),
    ):
        connection.executemany(
            "INSERT OR IGNORE INTO bug_subsystems VALUES (?, ?, ?, ?)",
            [
                (snapshot_id, bug["bug_id"], tag, row["listing_html_sha256"])
                for tag in tags.get(bug["key"], [])
            ],
        )


def _crash_sites(title: str, report: str) -> list[CrashSite]:
    targets = title_functions(title)
    if "KCSAN" not in title + report or len(targets) < 2:
        return [locate_crash_site(title, report)]
    return locate_kcsan_sites(title, report)


def index_report(
    connection: sqlite3.Connection,
    report_version_id: int,
    crash_id: int,
    *,
    prepared: PreparedReport | None = None,
) -> None:
    if connection.execute(
        "SELECT 1 FROM crash_locations WHERE report_version_id = ? AND crash_id = ? "
        "AND parser_version = ?",
        (report_version_id, crash_id, PARSER_VERSION),
    ).fetchone():
        return
    row = connection.execute(
        """SELECT rv.blob_sha256, COALESCE(NULLIF(c.title, ''), bv.title) AS title
           FROM report_versions rv
           JOIN crashes c ON c.id = ? JOIN bug_versions bv ON bv.id = c.bug_version_id
           WHERE rv.id = ? AND rv.is_valid = 1""",
        (crash_id, report_version_id),
    ).fetchone()
    if row is None:
        return
    if prepared is None:
        content = connection.execute(
            "SELECT content FROM blobs WHERE sha256 = ?", (row["blob_sha256"],)
        ).fetchone()[0]
        prepared = prepare_report(bytes(content), row["title"])
    elif prepared.digest != row["blob_sha256"] or prepared.title != row["title"]:
        raise ValueError("prepared report does not match the stored report and crash title")
    connection.execute(
        "DELETE FROM crash_locations WHERE report_version_id = ? AND crash_id = ?",
        (report_version_id, crash_id),
    )
    connection.execute(
        "DELETE FROM crash_stack_frames WHERE report_version_id = ? AND parser_version <> ?",
        (report_version_id, PARSER_VERSION),
    )
    for ordinal, site in enumerate(prepared.sites):
        connection.execute(
            """INSERT INTO crash_locations(
               report_version_id, crash_id, ordinal, role, file_path, function_name,
               line_number, column_number, confidence, method, evidence, parser_version
               ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                report_version_id,
                crash_id,
                ordinal,
                "primary" if ordinal == 0 else "conflicting-access",
                site.path or None,
                site.function or None,
                site.line or None,
                site.column or None,
                site.confidence,
                site.strategy,
                site.evidence,
                PARSER_VERSION,
            ),
        )
    for ordinal, frame in enumerate(prepared.frames):
        connection.execute(
            """INSERT OR IGNORE INTO crash_stack_frames(
               report_version_id, ordinal, section, report_line, function_name, file_path,
               line_number, column_number, is_inline, raw_line, parser_version
               ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                report_version_id,
                ordinal,
                frame.section,
                frame.report_line,
                frame.function,
                frame.file_path,
                frame.line_number,
                frame.column_number,
                int(frame.is_inline),
                frame.raw_line,
                PARSER_VERSION,
            ),
        )


def index_patch(
    connection: sqlite3.Connection,
    patch_version_id: int,
    *,
    prepared: PreparedPatch | None = None,
) -> None:
    if connection.execute(
        "SELECT 1 FROM fix_locations WHERE patch_version_id = ? AND parser_version = ?",
        (patch_version_id, PARSER_VERSION),
    ).fetchone():
        return
    row = connection.execute(
        """SELECT blob_sha256 FROM patch_versions WHERE id = ? AND is_valid = 1""",
        (patch_version_id,),
    ).fetchone()
    if row is None:
        return
    if prepared is None:
        content = connection.execute(
            "SELECT content FROM blobs WHERE sha256 = ?", (row["blob_sha256"],)
        ).fetchone()[0]
        prepared = prepare_patch(bytes(content))
    elif prepared.digest != row["blob_sha256"]:
        raise ValueError("prepared patch does not match the stored patch")
    connection.execute("DELETE FROM fix_locations WHERE patch_version_id = ?", (patch_version_id,))
    for ordinal, location in enumerate(prepared.locations):
        values = asdict(location)
        values.update(
            patch_version_id=patch_version_id,
            ordinal=ordinal,
            parser_version=PARSER_VERSION,
        )
        connection.execute(
            """INSERT INTO fix_locations(
               patch_version_id, ordinal, old_file_path, new_file_path, old_start, old_count,
               new_start, new_count, function_name, function_basis,
               hunk_header, kind, parser_version
               ) VALUES (:patch_version_id, :ordinal, :old_file_path, :new_file_path,
                 :old_start, :old_count, :new_start, :new_count, :function_name, :function_basis,
                 :hunk_header, :kind, :parser_version)""",
            values,
        )


def migrate_v2(connection: sqlite3.Connection) -> None:
    """Add derived data atomically, using stored blobs and no network access."""
    connection.execute("BEGIN IMMEDIATE")
    try:
        # Avoid executescript's implicit commit: schema and backfill must be atomic.
        for statement in SCHEMA_V2.split(";"):
            if statement.strip():
                connection.execute(statement)
        for row in connection.execute("SELECT id FROM snapshots").fetchall():
            index_subsystems(connection, int(row["id"]))
        for row in connection.execute(
            """SELECT rv.id, r.crash_id FROM reports r JOIN report_versions rv
               ON rv.report_id = r.id AND rv.blob_sha256 = r.current_blob_sha256
               WHERE r.crash_id IS NOT NULL AND rv.is_valid = 1""",
        ).fetchall():
            index_report(connection, int(row["id"]), int(row["crash_id"]))
        for row in connection.execute(
            "SELECT id FROM patch_versions WHERE is_valid = 1"
        ).fetchall():
            index_patch(connection, int(row["id"]))
        connection.execute("PRAGMA user_version = 2")
        connection.commit()
    except BaseException:
        connection.rollback()
        raise


def bug_locations(connection: sqlite3.Connection, bug_id: int) -> dict[str, Any]:
    tags = [
        row["tag"]
        for row in connection.execute(
            "SELECT tag FROM current_bug_subsystems WHERE bug_id = ? ORDER BY tag",
            (bug_id,),
        )
    ]
    result: dict[str, Any] = {"subsystems": tags}
    for name, view, order in (
        ("crash_locations", "current_crash_locations", "ordinal"),
        ("crash_stack", "current_crash_stack_frames", "ordinal"),
        ("fix_locations", "current_fix_locations", "commit_hash, repo, ordinal"),
    ):
        rows = [
            dict(row)
            for row in connection.execute(
                f"SELECT * FROM {view} WHERE bug_id = ? ORDER BY {order}",
                (bug_id,),
            )
        ]
        for row in rows:
            for key in ("key", "title", "bug_id"):
                row.pop(key, None)
            if "is_inline" in row:
                row["is_inline"] = bool(row["is_inline"])
        result[name] = rows
    return result
