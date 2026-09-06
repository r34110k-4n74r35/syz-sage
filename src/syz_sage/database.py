"""SQLite persistence for syz-sage snapshots and fetched artifacts.

The database deliberately keeps two representations of the source data:

* exact, content-addressed response bytes in :table:`blobs`; and
* normalized rows used by the command-line inspection commands.

Source payload bytes are immutable. A refresh creates a snapshot
which points at an existing version when the bytes have not changed, and at a
new version otherwise.  Consequently, an update never has to delete an old
bug, response, report, or patch to present the latest snapshot.
Normalized fix resolutions can be enriched, and parser migrations can repair
derived locations without changing those original source bytes.
"""

from __future__ import annotations

import hashlib
import html
import json
import os
import re
import sqlite3
from collections.abc import Callable, Collection, Iterator, Mapping, Sequence
from contextlib import contextmanager, suppress
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from . import location_store, schema_v3, schema_v4, schema_v5
from .bug_types import BUG_TYPES, classify_bug_type
from .ingestion import UNPARSED, ArtifactInspection, FileInventory
from .parsing import (
    PayloadError,
    absolute_syzbot_url,
    validate_http_url,
    validate_listing_membership,
)
from .progress_events import ProgressCallback, progress_items, report_progress
from .resolutions import (
    ResolutionTargets,
    resolution_identity,
    resolution_matches,
    resolution_targets,
)
from .retry_state import load_sync_state
from .storage import writable_path

SCHEMA_VERSION = 5
DEFAULT_SOURCE_URL = "https://syzkaller.appspot.com/upstream/fixed?json=1"
_MAX_BUG_KEY_LENGTH = 128
_HASH_RE = re.compile(r"^[0-9a-fA-F]{7,128}$")
_BUG_KEY_RE = re.compile(r"^(?:extid|id)-[A-Za-z0-9_%+~-](?:[A-Za-z0-9._%+~-]*[A-Za-z0-9_%+~-])?$")
_TAG_RE = re.compile(r"<[^>]+>")

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


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _json_text(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


def _json_bytes(value: Any) -> bytes:
    return _json_text(value).encode("utf-8")


def _coerce_bytes(value: Any) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, memoryview):
        return value.tobytes()
    if isinstance(value, str):
        return value.encode("utf-8")
    return _json_bytes(value)


def _as_mapping(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    if is_dataclass(value) and not isinstance(value, type):
        dataclass_values = asdict(value)
        if isinstance(dataclass_values, dict):
            return dataclass_values
    try:
        attribute_values: dict[str, Any] | None = vars(value)
    except TypeError:
        attribute_values = None
    if attribute_values is not None:
        return {key: item for key, item in attribute_values.items() if not key.startswith("_")}
    fields = ("key", "title", "bug_url", "json_url", "fix_commits", "raw")
    out = {name: getattr(value, name) for name in fields if hasattr(value, name)}
    if out:
        return out
    raise TypeError(f"record is not mapping-like: {type(value).__name__}")


def _field(mapping: Mapping[str, Any], *names: str, default: Any = "") -> Any:
    for name in names:
        if name in mapping:
            value = mapping[name]
            return default if value is None else value
    return default


def _text(value: Any) -> str:
    if value is None:
        return ""
    return value if isinstance(value, str) else str(value)


def _normal_title(value: Any) -> str:
    cleaned = html.unescape(_TAG_RE.sub("", _text(value)))
    return " ".join(cleaned.split()).strip()


def _safe_file_key(value: str) -> bool:
    return len(value) <= _MAX_BUG_KEY_LENGTH and _BUG_KEY_RE.fullmatch(value) is not None


def _looks_like_html(data: bytes) -> bool:
    prefix = data.lstrip().lower()[:4096]
    if prefix.startswith(b"\xef\xbb\xbf"):
        prefix = prefix[3:].lstrip()
    return prefix.startswith((b"<!doctype html", b"<html", b"<head", b"<body", b"<?xml"))


def _validate_listing_html(data: bytes) -> str | None:
    if not data.strip():
        return "empty or whitespace-only HTML listing"
    if not _looks_like_html(data):
        return "listing does not look like HTML"
    lowered = data.lower()
    if b"<html" not in lowered or b"</html>" not in lowered:
        return "listing is missing a complete html element"
    return None


def _validate_report(data: bytes) -> str | None:
    if not data.strip():
        return "empty or whitespace-only report"
    if _looks_like_html(data):
        return "report response is HTML"
    return None


def _validate_patch(data: bytes) -> str | None:
    if len(data) <= 40:
        return "patch is not larger than 40 bytes"
    if _looks_like_html(data):
        return "patch response is HTML"
    if b"diff --git" not in data:
        return "patch is missing 'diff --git' marker"
    return None


def _key_from_link(link: Any) -> str:
    if not isinstance(link, str) or not link:
        return ""
    try:
        candidates = [
            (name, value)
            for name, value in parse_qsl(urlsplit(link).query, keep_blank_values=True)
            if name in {"id", "extid"}
        ]
    except ValueError:
        return ""
    if len(candidates) != 1 or not candidates[0][1]:
        return ""
    key = f"{candidates[0][0]}-{candidates[0][1]}"
    return key if _safe_file_key(key) else ""


def _absolute_syzbot_url(link: Any, dashboard: str = "https://syzkaller.appspot.com") -> str:
    value = _text(link)
    if not value:
        return ""
    if value.startswith(("http://", "https://")):
        return value
    return dashboard.rstrip("/") + "/" + value.lstrip("/")


def _dashboard_from_bug_url(value: Any) -> str:
    try:
        parsed = urlsplit(_text(value))
    except ValueError:
        return "https://syzkaller.appspot.com"
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return "https://syzkaller.appspot.com"
    path = parsed.path
    if path.endswith("/bug"):
        path = path[: -len("/bug")]
    return f"{parsed.scheme}://{parsed.netloc}{path.rstrip('/')}"


def _c_reproducer_fields(raw: Any, payload_kind: str, dashboard: str) -> dict[str, Any]:
    """Summarize recorded C links across this version's crashes without fetching.

    The original payload distinguishes missing metadata from an explicit crash
    list with no C link, and lets older databases reject malformed values that
    their permissive URL normalization may have converted into plausible URLs.
    """
    urls: list[str] = []
    unknown = (
        payload_kind != "bug-json"
        or not isinstance(raw, Mapping)
        or not isinstance(raw.get("crashes"), list)
    )
    if not unknown:
        for crash in raw["crashes"]:
            if not isinstance(crash, Mapping):
                unknown = True
                continue
            value = crash.get("c-reproducer")
            if value is None or value == "":
                continue
            if not isinstance(value, str):
                unknown = True
                continue
            try:
                url = absolute_syzbot_url(value, dashboard)
            except PayloadError:
                unknown = True
                continue
            if url and url not in urls:
                urls.append(url)
    return {
        "c_reproducer_status": "available" if urls else "unknown" if unknown else "not_provided",
        "c_reproducer_urls": urls,
    }


def _patch_urls(fixes: Sequence[Mapping[str, Any]]) -> list[str]:
    """Collect recorded patch sources, falling back to saved fix commit links."""
    urls: list[str] = []
    for fix in fixes:
        for candidate in (fix.get("patch_source_url"), fix.get("link")):
            if not isinstance(candidate, str):
                continue
            try:
                url = validate_http_url(candidate)
            except PayloadError:
                continue
            if url not in urls:
                urls.append(url)
            break
    return urls


class Database:
    """A small, migration-aware SQLite repository for syzbot data."""

    def __init__(
        self,
        path: str | os.PathLike[str],
        *,
        read_only: bool = False,
        on_progress: ProgressCallback | None = None,
    ) -> None:
        self._path_text = os.fspath(path)
        if self._path_text != ":memory:":
            self._path_text = str(writable_path(self._path_text))
        self.path = Path(self._path_text) if self._path_text != ":memory:" else Path(":memory:")
        self._connection: sqlite3.Connection | None = None
        self._read_only = read_only
        self._on_progress = on_progress

    def __enter__(self) -> Database:
        try:
            self.initialize()
        except BaseException:
            self.close()
            raise
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        if self._connection is not None:
            if self._connection.in_transaction:
                self._connection.rollback()
            self._connection.close()
            self._connection = None

    def close(self) -> None:
        """Close the underlying connection, if it has been opened."""
        self.__exit__(None, None, None)

    @property
    def connection(self) -> sqlite3.Connection:
        if self._connection is None:
            if self._read_only:
                self._connection = sqlite3.connect(
                    f"{self.path.expanduser().resolve().as_uri()}?mode=ro",
                    uri=True,
                    timeout=5.0,
                    isolation_level=None,
                )
            else:
                if self._path_text != ":memory:":
                    Path(self._path_text).expanduser().parent.mkdir(parents=True, exist_ok=True)
                self._connection = sqlite3.connect(
                    self._path_text,
                    timeout=5.0,
                    isolation_level=None,
                )
            self._connection.row_factory = sqlite3.Row
            self._connection.execute("PRAGMA foreign_keys = ON")
            self._connection.execute("PRAGMA busy_timeout = 5000")
            if not self._read_only:
                self._connection.execute("PRAGMA journal_mode = WAL")
                self._connection.execute("PRAGMA synchronous = NORMAL")
        return self._connection

    @contextmanager
    def _transaction(self, mode: str = "IMMEDIATE") -> Iterator[sqlite3.Connection]:
        connection = self.connection
        if connection.in_transaction:
            raise RuntimeError("nested database transaction")
        connection.execute(f"BEGIN {mode}")
        try:
            yield connection
        except BaseException:
            connection.rollback()
            raise
        else:
            connection.commit()

    def initialize(self) -> Database:
        """Open and validate the database; migrate older schemas on writable opens."""
        connection = self.connection
        version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        creating = version == 0
        migration_progress = None if creating else self._on_progress
        if version > SCHEMA_VERSION:
            raise RuntimeError(
                f"database schema {version} is newer than supported schema {SCHEMA_VERSION}"
            )
        if version == 0:
            if self._read_only:
                raise RuntimeError("cannot initialize an empty database in read-only mode")
            existing = [
                f"{row['type']} {row['name']}"
                for row in connection.execute(
                    """
                    SELECT type, name
                    FROM sqlite_master
                    WHERE name NOT LIKE 'sqlite_%'
                      AND type IN ('table', 'view', 'index', 'trigger')
                    ORDER BY type, name
                    """
                )
            ]
            if existing:
                sample = ", ".join(existing[:5])
                suffix = " ..." if len(existing) > 5 else ""
                raise RuntimeError(
                    "refusing to initialize a non-pristine schema-version-0 database: "
                    f"found {sample}{suffix}"
                )
            try:
                report_progress(self._on_progress, "initialize", "Creating database schema")
                connection.executescript(_SCHEMA_V1)
            except BaseException:
                if connection.in_transaction:
                    connection.rollback()
                raise
            version = 1
        self._validate_v1_schema(connection)
        if version == 1:
            if self._read_only:
                raise RuntimeError("database schema needs migration; run 'ss migrate' first")
            location_store.migrate_v2(connection, on_progress=migration_progress)
            version = 2
        location_store.validate_schema(connection)
        if version == 2:
            if self._read_only:
                raise RuntimeError("database schema needs migration; run 'ss migrate' first")
            schema_v3.migrate(connection, on_progress=migration_progress)
            version = 3
        schema_v3.validate(connection)
        if version == 3:
            if self._read_only:
                raise RuntimeError("database schema needs migration; run 'ss migrate' first")
            schema_v4.migrate(connection, on_progress=migration_progress)
            version = 4
        schema_v4.validate(connection)
        if version == 4:
            if self._read_only:
                raise RuntimeError("database schema needs migration; run 'ss migrate' first")
            schema_v5.migrate(connection, on_progress=migration_progress)
        if not bool(connection.execute("PRAGMA foreign_keys").fetchone()[0]):
            raise RuntimeError("SQLite foreign-key enforcement could not be enabled")
        if creating:
            report_progress(self._on_progress, "initialize", "Created database schema", 1, 1)
        return self

    @staticmethod
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
        missing_tables = [
            table for table in _REQUIRED_V1_COLUMNS if ("table", table) not in objects
        ]
        problems: list[str] = []
        if missing_tables:
            problems.append("missing tables: " + ", ".join(sorted(missing_tables)))
        for table, required in _REQUIRED_V1_COLUMNS.items():
            if ("table", table) not in objects:
                continue
            # Table names come exclusively from the static manifest above.
            columns = {
                str(row["name"]) for row in connection.execute(f'PRAGMA table_info("{table}")')
            }
            missing_columns = sorted(required - columns)
            if missing_columns:
                problems.append(f"{table} missing columns: {', '.join(missing_columns)}")
        if ("view", "current_bug_rows") not in objects:
            problems.append("missing view: current_bug_rows")
        if problems:
            raise RuntimeError(
                "database schema version 1 is incomplete or incompatible; " + "; ".join(problems)
            )

    @staticmethod
    def _put_blob(
        connection: sqlite3.Connection,
        data: bytes,
        media_type: str,
        now: str,
        *,
        digest: str | None = None,
    ) -> tuple[str, bool]:
        digest = digest or hashlib.sha256(data).hexdigest()
        cursor = connection.execute(
            """
            INSERT INTO blobs(sha256, content, size_bytes, media_type, created_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(sha256) DO NOTHING
            """,
            (digest, sqlite3.Binary(data), len(data), media_type, now),
        )
        return digest, cursor.rowcount == 1

    @staticmethod
    def _put_document(
        connection: sqlite3.Connection,
        *,
        kind: str,
        natural_key: str,
        source_url: str,
        blob_sha256: str,
        valid: bool,
        error: str | None,
        run_id: int,
    ) -> None:
        connection.execute(
            """
            INSERT INTO documents(
                kind, natural_key, source_url, blob_sha256, is_valid,
                validation_error, first_seen_run_id, last_seen_run_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(kind, natural_key, blob_sha256) DO UPDATE SET
                source_url = CASE
                    WHEN excluded.source_url <> '' THEN excluded.source_url
                    ELSE documents.source_url
                END,
                is_valid = MAX(documents.is_valid, excluded.is_valid),
                validation_error = CASE
                    WHEN excluded.is_valid = 1 THEN NULL
                    ELSE excluded.validation_error
                END,
                last_seen_run_id = excluded.last_seen_run_id
            """,
            (kind, natural_key, source_url, blob_sha256, int(valid), error, run_id, run_id),
        )

    def _start_run(
        self,
        listing_json: bytes,
        listing_html: bytes | None,
        source_url: str,
        listing_error: str | None,
        html_error: str | None,
    ) -> tuple[int, str, str | None, int]:
        now = _utc_now()
        added = 0
        with self._transaction() as connection:
            listing_digest, was_added = self._put_blob(
                connection, listing_json, "application/json", now
            )
            added += int(was_added)
            html_digest: str | None = None
            if listing_html is not None:
                html_digest, was_added = self._put_blob(connection, listing_html, "text/html", now)
                added += int(was_added)
            cursor = connection.execute(
                """
                INSERT INTO sync_runs(
                    source_url, started_at, status, listing_json_sha256,
                    listing_html_sha256
                ) VALUES (?, ?, 'running', ?, ?)
                """,
                (source_url, now, listing_digest, html_digest),
            )
            if cursor.lastrowid is None:
                raise RuntimeError("SQLite did not return a sync-run identifier")
            run_id = cursor.lastrowid
            self._put_document(
                connection,
                kind="listing-json",
                natural_key=source_url,
                source_url=source_url,
                blob_sha256=listing_digest,
                valid=listing_error is None,
                error=listing_error,
                run_id=run_id,
            )
            if html_digest is not None:
                html_source = source_url.removesuffix("?json=1").removesuffix("&json=1")
                self._put_document(
                    connection,
                    kind="listing-html",
                    natural_key=html_source,
                    source_url=html_source,
                    blob_sha256=html_digest,
                    valid=html_error is None,
                    error=html_error,
                    run_id=run_id,
                )
        return run_id, listing_digest, html_digest, added

    def _finish_failed(self, run_id: int, summary: dict[str, Any]) -> dict[str, Any]:
        summary["status"] = "failed"
        summary["snapshot_id"] = None
        summary["activated"] = False
        summary.setdefault("known_fixed_bugs", 0)
        summary.setdefault("new_fixed_bugs", 0)
        summary.setdefault("new_fixed_bug_keys", [])
        summary.setdefault("no_longer_listed_bugs", 0)
        summary.setdefault("no_longer_listed_bug_keys", [])
        with self._transaction() as connection:
            connection.execute(
                """
                UPDATE sync_runs
                SET completed_at = ?, status = 'failed', error_count = ?, summary_json = ?
                WHERE id = ?
                """,
                (
                    _utc_now(),
                    int(summary.get("failure_count", 1)),
                    _json_text(summary),
                    run_id,
                ),
            )
        return summary

    @staticmethod
    def _listing_records(payload: Any) -> tuple[list[Any], int | None]:
        if isinstance(payload, list):
            return payload, None
        if not isinstance(payload, Mapping):
            return [], None
        value = payload.get("Bugs", payload.get("bugs", []))
        if isinstance(value, list):
            return list(value), payload.get("version")
        return [], payload.get("version")

    @staticmethod
    def _catalog_record_from_listing(value: Any) -> dict[str, Any] | None:
        try:
            raw = _as_mapping(value)
        except TypeError:
            return None
        link = _text(raw.get("link"))
        key = _key_from_link(link)
        if not key:
            return None
        bug_url = _absolute_syzbot_url(link)
        separator = "&" if "?" in bug_url else "?"
        return {
            "key": key,
            "title": _text(raw.get("title")),
            "bug_url": bug_url,
            "json_url": f"{bug_url}{separator}json=1",
            "fix_commits": raw.get("fix-commits", []),
            "raw": raw,
        }

    @staticmethod
    def _prepare_records(records: Sequence[Any]) -> tuple[list[dict[str, Any]], list[str]]:
        prepared: list[dict[str, Any]] = []
        errors: list[str] = []
        seen: set[str] = set()
        for index, value in enumerate(records):
            try:
                item = _as_mapping(value)
            except (TypeError, ValueError) as exc:
                errors.append(f"record[{index}]: {exc}")
                continue
            key = _text(_field(item, "key"))
            if not _safe_file_key(key):
                errors.append(f"record[{index}]: missing or unsafe bug key")
                continue
            if key in seen:
                errors.append(f"record[{index}]: duplicate bug key {key}")
                continue
            seen.add(key)
            raw_value = item.get("raw", item)
            try:
                raw_bytes = _coerce_bytes(raw_value)
            except (TypeError, ValueError) as exc:
                errors.append(f"record[{index}] {key}: cannot serialize raw record: {exc}")
                continue
            fixes_value = _field(item, "fix_commits", "fix-commits", default=[])
            if not isinstance(fixes_value, Sequence) or isinstance(fixes_value, (str, bytes)):
                errors.append(f"record[{index}] {key}: fix_commits is not a sequence")
                fixes_value = []
            fixes: list[dict[str, Any]] = []
            for fix_index, fix in enumerate(fixes_value):
                try:
                    fixes.append(_as_mapping(fix))
                except TypeError as exc:
                    errors.append(f"record[{index}] {key} fix[{fix_index}]: {exc}")
            prepared.append(
                {
                    "key": key,
                    "title": _text(_field(item, "title")),
                    "bug_url": _text(_field(item, "bug_url", "bug-url")),
                    "json_url": _text(_field(item, "json_url", "json-url")),
                    "fix_commits": fixes,
                    "raw_bytes": raw_bytes,
                }
            )
        return prepared, errors

    @staticmethod
    def _prepare_bug_payloads(
        records: Sequence[dict[str, Any]],
        bug_payloads: Mapping[str, bytes],
        parsed_payloads: Mapping[str, Any] | None = None,
        *,
        on_progress: ProgressCallback | None = None,
    ) -> tuple[dict[str, tuple[bytes, dict[str, Any] | None, str | None]], list[str]]:
        out: dict[str, tuple[bytes, dict[str, Any] | None, str | None]] = {}
        errors: list[str] = []
        for record in progress_items(
            records, on_progress, "prepare-bugs", "Validating bug details", total=len(records)
        ):
            key = record["key"]
            value = bug_payloads.get(key)
            if value is None:
                continue
            try:
                raw = _coerce_bytes(value)
            except (TypeError, ValueError) as exc:
                errors.append(f"bug JSON {key}: cannot convert to bytes: {exc}")
                continue
            try:
                decoded = (parsed_payloads or {}).get(key, UNPARSED)
                if decoded is UNPARSED:
                    decoded = json.loads(raw.decode("utf-8"))
                if not isinstance(decoded, dict):
                    raise ValueError("top-level value is not an object")
                if not (
                    decoded.get("title") or decoded.get("id") or decoded.get("crashes") is not None
                ):
                    raise ValueError("object does not look like a syzbot bug payload")
                for field in ("fix-commits", "crashes", "discussions"):
                    if field in decoded and not isinstance(decoded[field], list):
                        raise ValueError(f"{field} is not a list")
                for field in ("fix-commits", "crashes"):
                    if any(not isinstance(item, Mapping) for item in decoded.get(field, [])):
                        raise ValueError(f"{field} contains a non-object entry")
                if any(
                    not isinstance(item, str) or not item.strip()
                    for item in decoded.get("discussions", [])
                ):
                    raise ValueError("discussions contains a non-string or empty entry")
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
                out[key] = (raw, None, str(exc))
                errors.append(f"bug JSON {key}: {exc}")
            else:
                out[key] = (raw, decoded, None)
        return out, errors

    @staticmethod
    def _fix_hashes(record: Mapping[str, Any], bug: Mapping[str, Any] | None) -> dict[str, str]:
        hashes: dict[str, str] = {}
        sources: list[Any] = list(record.get("fix_commits", []))
        if bug is not None:
            fixes = bug.get("fix-commits", [])
            if isinstance(fixes, list):
                sources.extend(fixes)
        for value in sources:
            try:
                fix = _as_mapping(value)
            except TypeError:
                continue
            commit_hash = _text(fix.get("hash")).lower()
            if _HASH_RE.fullmatch(commit_hash):
                hashes.setdefault(commit_hash, _text(fix.get("link")))
        return hashes

    @staticmethod
    def _first_report(bug: Mapping[str, Any] | None, dashboard: str) -> tuple[int | None, str]:
        if bug is None:
            return None, ""
        crashes = bug.get("crashes", [])
        if not isinstance(crashes, list):
            return None, ""
        for ordinal, value in enumerate(crashes):
            if not isinstance(value, Mapping):
                continue
            link = _text(value.get("crash-report-link"))
            if link:
                return ordinal, _absolute_syzbot_url(link, dashboard)
        return None, ""

    @staticmethod
    def _read_artifact_files(
        directory: Path,
        suffix: str,
    ) -> tuple[dict[str, Path], list[str]]:
        return FileInventory.artifact_paths(directory, suffix)

    def _inspect_artifacts(
        self,
        paths: Mapping[str, Path],
        *,
        kind: str,
        inventory: FileInventory,
        expected_reports: Mapping[str, tuple[int, str]],
        payloads: Mapping[str, tuple[bytes, dict[str, Any] | None, str | None]],
        records: Mapping[str, dict[str, Any]],
        unavailable_reports: Collection[str],
    ) -> tuple[dict[str, ArtifactInspection], list[str]]:
        """Stream validation outside the writer transaction; preparse changed artifacts.

        Bound preparation by source bytes so a cold bulk import does not keep
        every extracted stack in memory. The remaining artifacts use the same
        parser during indexing; ordinary small incremental updates preparse all
        their new locations before acquiring the write transaction.
        """
        prepared: dict[str, ArtifactInspection] = {}
        errors: list[str] = []
        budget = 8 * 1024 * 1024
        report_known: set[tuple[str, str, str, int]] = set()
        patch_known: set[tuple[str, str]] = set()
        if kind == "report":
            report_known = {
                (row[0], row[1], row[2], int(row[3]))
                for row in self.connection.execute(
                    """SELECT DISTINCT b.key, rv.blob_sha256, bv.raw_sha256, cr.ordinal
                       FROM crash_locations l JOIN report_versions rv ON rv.id=l.report_version_id
                       JOIN crashes cr ON cr.id=l.crash_id
                       JOIN bug_versions bv ON bv.id=cr.bug_version_id
                       JOIN bugs b ON b.id=bv.bug_id WHERE l.parser_version=?""",
                    (location_store.REPORT_PARSER_VERSION,),
                )
            }
        else:
            patch_known = {
                (row[0], row[1])
                for row in self.connection.execute(
                    """SELECT DISTINCT pv.commit_hash, pv.blob_sha256 FROM fix_locations l
                       JOIN patch_versions pv ON pv.id=l.patch_version_id
                       WHERE l.parser_version=?""",
                    (location_store.PATCH_PARSER_VERSION,),
                )
            }
        plural = "reports" if kind == "report" else "patches"
        for key, path in progress_items(
            paths.items(),
            self._on_progress,
            f"prepare-{plural}",
            f"Preparing {plural}",
            total=len(paths),
        ):
            try:
                data, stamp, digest = inventory.read_observation(path)
                inspection = ArtifactInspection(path, stamp, digest, None)
            except OSError as exc:
                errors.append(f"cannot read {path}: {exc}")
                continue
            if kind == "report":
                inspection.error = _validate_report(data)
                entry = payloads.get(key)
                expected = expected_reports.get(key)
                if (
                    inspection.error is None
                    and entry
                    and entry[1]
                    and expected
                    and key not in unavailable_reports
                ):
                    detail = entry[1]
                    identity = (
                        key,
                        inspection.digest,
                        hashlib.sha256(entry[0]).hexdigest(),
                        expected[0],
                    )
                    if identity not in report_known and len(data) <= budget:
                        title = _text(detail["crashes"][expected[0]].get("title")) or _text(
                            detail.get("title") or records[key]["title"] or key
                        )
                        inspection.prepared = location_store.prepare_report(data, title)
                        budget -= len(data)
            else:
                inspection.error = (
                    "patch filename is not a hexadecimal commit hash"
                    if not _HASH_RE.fullmatch(key.lower())
                    else _validate_patch(data)
                )
                if (
                    inspection.error is None
                    and (key.lower(), inspection.digest) not in patch_known
                    and len(data) <= budget
                ):
                    inspection.prepared = location_store.prepare_patch(data)
                    budget -= len(data)
            prepared[key] = inspection
        return prepared, errors

    @staticmethod
    def _artifact_source(
        connection: sqlite3.Connection,
        kind: str,
        key: str,
        digest: str,
        supplied: str,
        fallback: str,
    ) -> str:
        if supplied:
            return supplied
        known = connection.execute(
            "SELECT source_url FROM documents WHERE kind=? AND natural_key=? AND blob_sha256=?",
            (kind, key, digest),
        ).fetchone()
        return _text(known[0]) if known is not None and known[0] else fallback

    def ingest_snapshot(
        self,
        listing_json: bytes,
        listing_html: bytes | None,
        records: Sequence[Any],
        bug_payloads: Mapping[str, bytes],
        reports_dir: Path,
        patches_dir: Path,
        source_url: str,
        *,
        errors: Sequence[str] = (),
    ) -> dict[str, Any]:
        """Atomically ingest one fixed-bug listing and its fetched artifacts.

        Network requests intentionally do not live here.  Callers fetch to
        memory or disk first, then pass the validated candidate snapshot to
        this method.  Invalid individual payloads/artifacts are retained as
        documents, counted as failures, and never replace a prior valid
        report or patch.
        """
        return self._ingest_snapshot(
            listing_json=listing_json,
            listing_html=listing_html,
            records=records,
            bug_payloads=bug_payloads,
            reports_dir=Path(reports_dir),
            patches_dir=Path(patches_dir),
            source_url=source_url,
            resolutions=(),
            extra_documents=(),
            inherited_errors=errors,
        )

    def _ingest_snapshot(
        self,
        *,
        listing_json: bytes,
        listing_html: bytes | None,
        records: Sequence[Any],
        bug_payloads: Mapping[str, bytes],
        reports_dir: Path,
        patches_dir: Path,
        source_url: str,
        resolutions: Sequence[Any],
        extra_documents: Sequence[tuple[str, str, str, bytes, bool, str | None]],
        inherited_errors: Sequence[str],
        unavailable_reports: Collection[str] = (),
        inventory: FileInventory | None = None,
        source_urls: Mapping[Path, str] | None = None,
        parsed_listing: Any = UNPARSED,
        parsed_payloads: Mapping[str, Any] | None = None,
        verify_files: Callable[[], None] | None = None,
    ) -> dict[str, Any]:
        self.initialize()
        inventory = inventory or FileInventory()
        source_urls = {Path(path).absolute(): url for path, url in (source_urls or {}).items()}
        listing_bytes = _coerce_bytes(listing_json)
        html_bytes = None if listing_html is None else _coerce_bytes(listing_html)
        listing_payload: Any = None
        source_records: list[Any] = []
        source_version: int | None = None
        listing_keys: list[str] = []
        listing_candidates: list[dict[str, Any]] = []
        listing_error: str | None = None
        try:
            listing_payload = (
                json.loads(listing_bytes.decode("utf-8"))
                if parsed_listing is UNPARSED
                else parsed_listing
            )
            if not isinstance(listing_payload, Mapping):
                raise ValueError("top-level listing is not an object")
            bugs_value = (
                listing_payload.get("Bugs")
                if "Bugs" in listing_payload
                else listing_payload.get("bugs")
            )
            if not isinstance(bugs_value, list):
                raise ValueError("listing must contain a Bugs or bugs list")
            if not bugs_value:
                raise ValueError("listing Bugs list is empty")
            source_records = list(bugs_value)
            version_value = listing_payload.get("version")
            source_version = version_value if isinstance(version_value, int) else None
            for index, raw in enumerate(source_records):
                candidate = self._catalog_record_from_listing(raw)
                if candidate is None:
                    raise ValueError(f"listing Bugs[{index}] has no valid bug key")
                listing_keys.append(candidate["key"])
                listing_candidates.append(candidate)
            if len(set(listing_keys)) != len(listing_keys):
                raise ValueError("listing Bugs list contains duplicate bug keys")
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            listing_error = str(exc)
        html_error = _validate_listing_html(html_bytes) if html_bytes is not None else None
        if (
            html_bytes is not None
            and html_error is None
            and listing_error is None
            and not validate_listing_membership(html_bytes, listing_keys)
        ):
            html_error = "HTML listing bug keys do not match the JSON listing"
        if (
            html_bytes is None
            and self.connection.execute("SELECT 1 FROM current_bug_subsystems LIMIT 1").fetchone()
        ):
            html_error = "missing HTML listing would discard known subsystem tags"

        run_id, listing_digest, html_digest, initially_added = self._start_run(
            listing_bytes, html_bytes, source_url, listing_error, html_error
        )
        errors = list(inherited_errors)
        if listing_error:
            errors.append(f"listing JSON: {listing_error}")
        if html_error:
            errors.append(f"listing HTML: {html_error}")
        if listing_error:
            failed_summary = {
                "run_id": run_id,
                "status": "failed",
                "source_url": source_url,
                "records_seen": 0,
                "records_imported": 0,
                "failure_count": len(errors),
                "failures": errors[:100],
                "blobs_added": initially_added,
            }
            return self._finish_failed(run_id, failed_summary)

        supplied = list(records)
        if not supplied and source_records:
            supplied = [
                candidate
                for raw in source_records
                if (candidate := self._catalog_record_from_listing(raw)) is not None
            ]
        prepared, record_errors = self._prepare_records(supplied)
        errors.extend(record_errors)
        prepared_keys = [record["key"] for record in prepared]
        if prepared_keys != listing_keys:
            errors.append(
                "listing/record key mismatch: prepared records must exactly match "
                "the ordered listing Bugs keys"
            )
            failed_summary = {
                "run_id": run_id,
                "status": "failed",
                "source_url": source_url,
                "records_seen": len(supplied),
                "records_imported": 0,
                "failure_count": len(errors),
                "failures": errors[:100],
                "blobs_added": initially_added,
            }
            return self._finish_failed(run_id, failed_summary)

        prepared_payloads, payload_errors = self._prepare_bug_payloads(
            prepared, bug_payloads, parsed_payloads, on_progress=self._on_progress
        )
        errors.extend(payload_errors)
        payload_valid = sum(
            1
            for _, value, error in prepared_payloads.values()
            if value is not None and error is None
        )
        payload_invalid = sum(
            1
            for _, value, error in prepared_payloads.values()
            if value is None or error is not None
        )
        payload_missing = len(prepared) - len(prepared_payloads)
        if payload_missing:
            errors.append(f"{payload_missing} bug JSON payload(s) missing")

        expected_reports: dict[str, tuple[int, str]] = {}
        expected_hashes: dict[str, str] = {}
        record_by_key = {record["key"]: record for record in prepared}
        listing_by_key = {record["key"]: record for record in listing_candidates}
        for record in prepared:
            payload_entry = prepared_payloads.get(record["key"])
            bug = payload_entry[1] if payload_entry else None
            dashboard = _dashboard_from_bug_url(record["bug_url"])
            ordinal, url = self._first_report(bug, dashboard)
            if ordinal is not None:
                expected_reports[record["key"]] = (ordinal, url)
            expected_hashes.update(self._fix_hashes(record, bug))
            expected_hashes.update(self._fix_hashes(listing_by_key[record["key"]], bug))

        targets = resolution_targets(
            listing_candidates,
            {key: value[1] for key, value in prepared_payloads.items() if value[1] is not None},
        )
        resolution_choices = {
            resolution_identity(value): value for value in self.accepted_resolutions(targets)
        }
        prepared_resolutions: list[dict[str, Any]] = []
        for index, value in enumerate(resolutions):
            try:
                resolution = _as_mapping(value)
            except TypeError as exc:
                errors.append(f"resolution[{index}]: {exc}")
                continue
            key = _text(_field(resolution, "bug_key", "key"))
            if not _safe_file_key(key):
                errors.append(f"resolution[{index}]: missing or unsafe bug key {key!r}")
                continue
            if key not in record_by_key:
                # Resolution files are retained across rolling-listing changes.
                # A safe key absent from this candidate is historical, not malformed.
                continue
            if not resolution_matches(resolution, targets):
                # An obsolete subject/repository is retained in the source
                # document but is not a dependency of this candidate snapshot.
                continue
            prepared_resolution = dict(resolution)
            resolved_hash = _text(resolution.get("hash")).lower()
            if resolved_hash and not _HASH_RE.fullmatch(resolved_hash):
                errors.append(f"resolution[{index}] {key}: invalid commit hash")
                resolved_hash = ""
                prepared_resolution["hash"] = ""
            repo_value = resolution.get("repo")
            if repo_value is not None and not isinstance(repo_value, str):
                errors.append(f"resolution[{index}] {key}: repository is not a string")
                prepared_resolution["repo"] = ""
            if resolved_hash:
                prepared_resolution["hash"] = resolved_hash
                resolution_choices[resolution_identity(resolution)] = prepared_resolution
            prepared_resolutions.append(prepared_resolution)
        for resolution in resolution_choices.values():
            expected_hashes.setdefault(
                _text(resolution["hash"]).lower(), _text(resolution.get("commit_url"))
            )

        report_paths, report_read_errors = self._read_artifact_files(reports_dir, ".txt")
        patch_paths, patch_read_errors = self._read_artifact_files(patches_dir, ".diff")
        errors.extend(report_read_errors)
        errors.extend(patch_read_errors)
        try:
            if verify_files is not None:
                verify_files()
            report_files, report_read_errors = self._inspect_artifacts(
                report_paths,
                kind="report",
                inventory=inventory,
                expected_reports=expected_reports,
                payloads=prepared_payloads,
                records=record_by_key,
                unavailable_reports=unavailable_reports,
            )
            patch_files, patch_read_errors = self._inspect_artifacts(
                patch_paths,
                kind="patch",
                inventory=inventory,
                expected_reports=expected_reports,
                payloads=prepared_payloads,
                records=record_by_key,
                unavailable_reports=unavailable_reports,
            )
        except Exception as exc:
            errors.append(f"artifact preparation: {type(exc).__name__}: {exc}")
            return self._finish_failed(
                run_id,
                {
                    "run_id": run_id,
                    "source_url": source_url,
                    "records_seen": len(supplied),
                    "records_imported": 0,
                    "failure_count": len(errors),
                    "failures": errors[:100],
                    "blobs_added": initially_added,
                },
            )
        errors.extend(report_read_errors)
        errors.extend(patch_read_errors)

        report_missing = sorted(
            (set(expected_reports) - set(report_files))
            | (set(expected_reports) & set(unavailable_reports))
        )
        if report_missing:
            errors.append(f"{len(report_missing)} expected representative report(s) missing")
        patch_missing = sorted(set(expected_hashes) - {key.lower() for key in patch_files})
        if patch_missing:
            errors.append(f"{len(patch_missing)} expected patch(es) missing")

        summary: dict[str, Any] = {
            "run_id": run_id,
            "snapshot_id": None,
            "status": "running",
            "source_url": source_url,
            "source_records": len(source_records),
            "records_seen": len(supplied),
            "records_imported": len(prepared),
            "bug_payloads": {
                "provided": len(prepared_payloads),
                "valid": payload_valid,
                "invalid": payload_invalid,
                "missing": payload_missing,
            },
            "reports": {
                "expected": len(expected_reports),
                "available_files": len(report_files),
                "valid": 0,
                "invalid": 0,
                "missing": len(report_missing),
                "unavailable_upstream": len(prepared) - len(expected_reports),
                "orphan_files": 0,
                "pending_refresh": len(set(expected_reports) & set(unavailable_reports)),
            },
            "patches": {
                "expected": len(expected_hashes),
                "available_files": len(patch_files),
                "valid": 0,
                "invalid": 0,
                "missing": len(patch_missing),
                "orphan_files": 0,
            },
            "failure_count": 0,
            "failures": [],
            "blobs_added": initially_added,
            "known_fixed_bugs": 0,
            "new_fixed_bugs": 0,
            "new_fixed_bug_keys": [],
            "no_longer_listed_bugs": 0,
            "no_longer_listed_bug_keys": [],
        }

        now = _utc_now()
        blob_additions = initially_added
        try:
            with self._transaction() as connection:
                active_keys = [
                    _text(row["key"])
                    for row in connection.execute(
                        "SELECT key FROM current_bug_rows ORDER BY position"
                    )
                ]
                candidate_keys = [record["key"] for record in prepared]
                active_key_set = set(active_keys)
                candidate_key_set = set(candidate_keys)
                new_fixed_bug_keys = [key for key in candidate_keys if key not in active_key_set]
                no_longer_listed_bug_keys = [
                    key for key in active_keys if key not in candidate_key_set
                ]
                summary.update(
                    known_fixed_bugs=len(candidate_keys) - len(new_fixed_bug_keys),
                    new_fixed_bugs=len(new_fixed_bug_keys),
                    new_fixed_bug_keys=new_fixed_bug_keys,
                    no_longer_listed_bugs=len(no_longer_listed_bug_keys),
                    no_longer_listed_bug_keys=no_longer_listed_bug_keys,
                )
                cursor = connection.execute(
                    """
                    INSERT INTO snapshots(
                        run_id, source_url, source_version, captured_at,
                        listing_json_sha256, listing_html_sha256,
                        source_record_count, record_count, status, is_current
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'completed', 0)
                    """,
                    (
                        run_id,
                        source_url,
                        source_version,
                        now,
                        listing_digest,
                        html_digest,
                        len(source_records),
                        len(prepared),
                    ),
                )
                if cursor.lastrowid is None:
                    raise RuntimeError("SQLite did not return a snapshot identifier")
                snapshot_id = cursor.lastrowid

                for kind, natural_key, document_url, raw, valid, error in extra_documents:
                    digest, was_added = self._put_blob(connection, raw, "application/json", now)
                    blob_additions += int(was_added)
                    self._put_document(
                        connection,
                        kind=kind,
                        natural_key=natural_key,
                        source_url=document_url,
                        blob_sha256=digest,
                        valid=valid,
                        error=error,
                        run_id=run_id,
                    )

                bug_ids: dict[str, int] = {}
                version_ids: dict[str, int] = {}
                candidate_bug_updates: list[tuple[str, str, str, str, int, int]] = []
                candidate_resolution_versions: list[tuple[int, int]] = []
                for position, record in enumerate(
                    progress_items(
                        prepared,
                        self._on_progress,
                        "index-bugs",
                        "Indexing bug details",
                        total=len(prepared),
                    )
                ):
                    key = record["key"]
                    listing_record_digest, was_added = self._put_blob(
                        connection, record["raw_bytes"], "application/json", now
                    )
                    blob_additions += int(was_added)
                    self._put_document(
                        connection,
                        kind="listing-record",
                        natural_key=key,
                        source_url=record["bug_url"],
                        blob_sha256=listing_record_digest,
                        valid=True,
                        error=None,
                        run_id=run_id,
                    )

                    payload_entry = prepared_payloads.get(key)
                    bug_data = payload_entry[1] if payload_entry else None
                    payload_error = payload_entry[2] if payload_entry else None
                    syzbot_id = _text(bug_data.get("id")) if bug_data else ""
                    detail_title = _text(bug_data.get("title")) if bug_data else ""
                    current_title = record["title"] or detail_title or key
                    connection.execute(
                        """
                        INSERT INTO bugs(
                            key, syzbot_id, title, bug_url, json_url,
                            first_seen_at, last_seen_at, first_seen_run_id, last_seen_run_id
                        ) VALUES (?, NULLIF(?, ''), ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(key) DO UPDATE SET
                            last_seen_at = excluded.last_seen_at,
                            last_seen_run_id = excluded.last_seen_run_id
                        """,
                        (
                            key,
                            syzbot_id,
                            current_title,
                            record["bug_url"],
                            record["json_url"],
                            now,
                            now,
                            run_id,
                            run_id,
                        ),
                    )
                    bug_row = connection.execute(
                        "SELECT id, current_version_id FROM bugs WHERE key = ?", (key,)
                    ).fetchone()
                    assert bug_row is not None
                    bug_id = int(bug_row["id"])
                    bug_ids[key] = bug_id

                    if payload_entry is not None:
                        payload_raw = payload_entry[0]
                        document_digest, was_added = self._put_blob(
                            connection, payload_raw, "application/json", now
                        )
                        blob_additions += int(was_added)
                        self._put_document(
                            connection,
                            kind="bug-json",
                            natural_key=key,
                            source_url=record["json_url"],
                            blob_sha256=document_digest,
                            valid=bug_data is not None,
                            error=payload_error,
                            run_id=run_id,
                        )

                    if bug_data is not None:
                        payload_digest = document_digest
                        payload_kind = "bug-json"
                        version_title = detail_title or current_title
                        version_values = (
                            bug_data.get("version"),
                            version_title,
                            _text(bug_data.get("status")),
                            bug_data.get("first-crash"),
                            bug_data.get("last-crash"),
                            bug_data.get("fix-time"),
                            bug_data.get("close-time"),
                        )
                    else:
                        payload_digest = listing_record_digest
                        payload_kind = "listing-record"
                        version_title = current_title
                        version_values = (
                            source_version,
                            current_title,
                            "",
                            None,
                            None,
                            None,
                            None,
                        )

                    connection.execute(
                        """
                        INSERT INTO bug_versions(
                            bug_id, raw_sha256, payload_kind, fetched_at,
                            source_version, title, status, first_crash_at,
                            last_crash_at, fix_time, close_time
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(bug_id, raw_sha256, payload_kind) DO NOTHING
                        """,
                        (bug_id, payload_digest, payload_kind, now, *version_values),
                    )
                    version_row = connection.execute(
                        """
                        SELECT id FROM bug_versions
                        WHERE bug_id = ? AND raw_sha256 = ? AND payload_kind = ?
                        """,
                        (bug_id, payload_digest, payload_kind),
                    ).fetchone()
                    assert version_row is not None
                    version_id = int(version_row["id"])
                    version_ids[key] = version_id

                    if bug_data is not None:
                        blob_additions += self._insert_bug_children(
                            connection,
                            version_id,
                            bug_data,
                            run_id,
                            now,
                            _dashboard_from_bug_url(record["bug_url"]),
                        )
                        candidate_resolution_versions.append((bug_id, version_id))
                    elif bug_row["current_version_id"] is not None:
                        version_id = int(bug_row["current_version_id"])
                        version_ids[key] = version_id

                    candidate_bug_updates.append(
                        (
                            syzbot_id,
                            current_title,
                            record["bug_url"],
                            record["json_url"],
                            version_id,
                            bug_id,
                        )
                    )

                    connection.execute(
                        """
                        INSERT INTO snapshot_bugs(
                            snapshot_id, bug_id, bug_version_id, position,
                            title, bug_url, json_url, listing_record_sha256, bug_type
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            snapshot_id,
                            bug_id,
                            version_id,
                            position,
                            current_title,
                            record["bug_url"],
                            record["json_url"],
                            listing_record_digest,
                            classify_bug_type(current_title),
                        ),
                    )

                    blob_additions += self._insert_listing_fixes(
                        connection,
                        snapshot_id,
                        bug_id,
                        listing_by_key[key]["fix_commits"],
                        run_id,
                        now,
                    )

                    for commit_hash, _ in self._fix_hashes(record, bug_data).items():
                        self._upsert_commit(connection, commit_hash, run_id)

                location_store.index_subsystems(connection, snapshot_id)
                candidate_resolutions: list[tuple[str, int, str, str]] = []
                candidate_resolution_rows: list[tuple[Any, ...]] = []
                for resolution in prepared_resolutions:
                    key = _text(_field(resolution, "bug_key", "key"))
                    bug_id = bug_ids[key]
                    title_normalized = _normal_title(resolution.get("title"))
                    repo = _text(resolution.get("repo"))
                    resolved_hash = _text(resolution.get("hash")).lower()
                    if resolved_hash:
                        self._upsert_commit(connection, resolved_hash, run_id)
                    raw = _json_bytes(resolution)
                    raw_digest, was_added = self._put_blob(connection, raw, "application/json", now)
                    blob_additions += int(was_added)
                    details = {
                        name: value
                        for name, value in resolution.items()
                        if name
                        not in {
                            "bug_key",
                            "key",
                            "title",
                            "repo",
                            "hash",
                            "status",
                            "search_url",
                        }
                    }
                    self._put_document(
                        connection,
                        kind="fix-resolution",
                        natural_key=f"{key}:{title_normalized}:{repo}",
                        source_url=_text(resolution.get("search_url")),
                        blob_sha256=raw_digest,
                        valid=True,
                        error=None,
                        run_id=run_id,
                    )
                    candidate_resolution_rows.append(
                        (
                            bug_id,
                            title_normalized,
                            repo,
                            _text(resolution.get("status")) or "unknown",
                            resolved_hash,
                            _text(resolution.get("search_url")),
                            _json_text(details),
                            raw_digest,
                            run_id,
                            run_id,
                        ),
                    )
                    if resolved_hash:
                        candidate_resolutions.append(
                            (resolved_hash, bug_id, title_normalized, repo)
                        )

                candidate_reports: list[tuple[str, int | None, str, int]] = []
                for key, inspection in progress_items(
                    report_files.items(),
                    self._on_progress,
                    "index-reports",
                    "Indexing reports",
                    total=len(report_files),
                ):
                    data, path = inspection.read(inventory), inspection.path
                    validation_error = inspection.error
                    valid = validation_error is None
                    digest, was_added = self._put_blob(
                        connection, data, "text/plain", now, digest=inspection.digest
                    )
                    blob_additions += int(was_added)
                    source = (
                        ""
                        if key in unavailable_reports
                        else expected_reports.get(key, (None, ""))[1]
                    )
                    self._put_document(
                        connection,
                        kind="crash-report",
                        natural_key=key,
                        source_url=source,
                        blob_sha256=digest,
                        valid=valid,
                        error=validation_error,
                        run_id=run_id,
                    )
                    if key in unavailable_reports:
                        # These bytes predate an unfinished detail/report
                        # refresh. Retain them without claiming they belong to
                        # the newly cached crash or its report URL.
                        continue
                    report_bug_id = bug_ids.get(key)
                    expected = expected_reports.get(key)
                    if report_bug_id is None or expected is None:
                        summary["reports"]["orphan_files"] += 1
                        continue
                    report_crash_id: int | None = None
                    crash_row = connection.execute(
                        "SELECT id FROM crashes WHERE bug_version_id = ? AND ordinal = ?",
                        (version_ids[key], expected[0]),
                    ).fetchone()
                    report_crash_id = int(crash_row[0]) if crash_row else None
                    connection.execute(
                        """
                        INSERT INTO reports(
                            bug_id, crash_id, source_url, current_blob_sha256,
                            first_seen_run_id, last_seen_run_id
                        ) VALUES (?, NULL, '', NULL, ?, ?)
                        ON CONFLICT(bug_id) DO UPDATE SET
                            last_seen_run_id = excluded.last_seen_run_id
                        """,
                        (report_bug_id, run_id, run_id),
                    )
                    report_id = int(
                        connection.execute(
                            "SELECT id FROM reports WHERE bug_id = ?", (report_bug_id,)
                        ).fetchone()[0]
                    )
                    connection.execute(
                        """
                        INSERT INTO report_versions(
                            report_id, blob_sha256, source_url, is_valid,
                            validation_error, first_seen_run_id, last_seen_run_id
                        ) VALUES (?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(report_id, blob_sha256) DO UPDATE SET
                            last_seen_run_id = excluded.last_seen_run_id,
                            is_valid = MAX(report_versions.is_valid, excluded.is_valid),
                            validation_error = CASE
                                WHEN excluded.is_valid = 1 THEN NULL
                                ELSE excluded.validation_error
                            END
                        """,
                        (report_id, digest, source, int(valid), validation_error, run_id, run_id),
                    )
                    if valid:
                        if report_crash_id is not None:
                            report_version_id = int(
                                connection.execute(
                                    "SELECT id FROM report_versions "
                                    "WHERE report_id = ? AND blob_sha256 = ?",
                                    (report_id, digest),
                                ).fetchone()[0]
                            )
                            location_store.index_report(
                                connection,
                                report_version_id,
                                report_crash_id,
                                prepared=inspection.prepared,
                            )
                            connection.execute(
                                "INSERT INTO snapshot_reports VALUES (?, ?, ?, ?, ?)",
                                (
                                    snapshot_id,
                                    report_bug_id,
                                    report_version_id,
                                    report_crash_id,
                                    source,
                                ),
                            )
                        candidate_reports.append((digest, report_crash_id, source, report_id))
                        summary["reports"]["valid"] += 1
                    else:
                        summary["reports"]["invalid"] += 1
                        errors.append(f"report {path.name}: {validation_error}")

                candidate_patches: list[tuple[str, str, str]] = []
                normalized_patch_files = {key.lower(): value for key, value in patch_files.items()}
                for commit_hash, inspection in progress_items(
                    normalized_patch_files.items(),
                    self._on_progress,
                    "index-patches",
                    "Indexing patches",
                    total=len(normalized_patch_files),
                ):
                    data, path = inspection.read(inventory), inspection.path
                    validation_error = inspection.error
                    valid = validation_error is None
                    digest, was_added = self._put_blob(
                        connection, data, "text/x-diff", now, digest=inspection.digest
                    )
                    blob_additions += int(was_added)
                    source = self._artifact_source(
                        connection,
                        "patch",
                        commit_hash,
                        digest,
                        source_urls.get(path.absolute(), ""),
                        expected_hashes.get(commit_hash, ""),
                    )
                    self._put_document(
                        connection,
                        kind="patch",
                        natural_key=commit_hash,
                        source_url=source,
                        blob_sha256=digest,
                        valid=valid,
                        error=validation_error,
                        run_id=run_id,
                    )
                    if not _HASH_RE.fullmatch(commit_hash):
                        summary["patches"]["orphan_files"] += 1
                        summary["patches"]["invalid"] += 1
                        continue
                    self._upsert_commit(connection, commit_hash, run_id)
                    connection.execute(
                        """
                        INSERT INTO patches(
                            commit_hash, current_blob_sha256, source_url,
                            first_seen_run_id, last_seen_run_id
                        ) VALUES (?, NULL, '', ?, ?)
                        ON CONFLICT(commit_hash) DO UPDATE SET
                            last_seen_run_id = excluded.last_seen_run_id
                        """,
                        (commit_hash, run_id, run_id),
                    )
                    connection.execute(
                        """
                        INSERT INTO patch_versions(
                            commit_hash, blob_sha256, source_url, is_valid,
                            validation_error, first_seen_run_id, last_seen_run_id
                        ) VALUES (?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(commit_hash, blob_sha256) DO UPDATE SET
                            last_seen_run_id = excluded.last_seen_run_id,
                            is_valid = MAX(patch_versions.is_valid, excluded.is_valid),
                            validation_error = CASE
                                WHEN excluded.is_valid = 1 THEN NULL
                                ELSE excluded.validation_error
                            END
                        """,
                        (commit_hash, digest, source, int(valid), validation_error, run_id, run_id),
                    )
                    if valid:
                        patch_version_id = int(
                            connection.execute(
                                "SELECT id FROM patch_versions "
                                "WHERE commit_hash = ? AND blob_sha256 = ?",
                                (commit_hash, digest),
                            ).fetchone()[0]
                        )
                        location_store.index_patch(
                            connection, patch_version_id, prepared=inspection.prepared
                        )
                        connection.execute(
                            "INSERT INTO snapshot_patches VALUES (?, ?, ?, ?)",
                            (snapshot_id, commit_hash, patch_version_id, source),
                        )
                        candidate_patches.append((digest, source, commit_hash))
                        summary["patches"]["valid"] += 1
                    else:
                        summary["patches"]["invalid"] += 1
                        if commit_hash in expected_hashes:
                            errors.append(f"patch {path.name}: {validation_error}")
                    if commit_hash not in expected_hashes:
                        summary["patches"]["orphan_files"] += 1

                report_progress(
                    self._on_progress, "commit-snapshot", "Saving snapshot result", 0, 1
                )
                if verify_files is not None:
                    verify_files()
                current_snapshot = connection.execute(
                    "SELECT run_id FROM snapshots WHERE is_current = 1"
                ).fetchone()
                if (
                    not errors
                    and current_snapshot is not None
                    and int(current_snapshot["run_id"]) > run_id
                ):
                    errors.append("a newer sync run is already active")
                run_status = "partial" if errors else "completed"

                if run_status == "completed":
                    # Keep candidate evidence above, but expose reusable
                    # resolutions only once this entire candidate can activate.
                    connection.executemany(
                        """
                        INSERT INTO fix_resolutions(
                            bug_id, normalized_title, repo, status, resolved_hash,
                            search_url, details_json, raw_sha256,
                            first_seen_run_id, last_seen_run_id
                        ) VALUES (?, ?, ?, ?, NULLIF(?, ''), ?, ?, ?, ?, ?)
                        ON CONFLICT(bug_id, normalized_title, repo) DO UPDATE SET
                            status = excluded.status,
                            resolved_hash = COALESCE(
                                excluded.resolved_hash,
                                CASE WHEN EXISTS (
                                    SELECT 1 FROM sync_runs
                                    WHERE id = fix_resolutions.last_seen_run_id
                                      AND (status = 'completed' OR id = excluded.last_seen_run_id)
                                ) THEN fix_resolutions.resolved_hash END
                            ),
                            search_url = excluded.search_url,
                            details_json = excluded.details_json,
                            raw_sha256 = excluded.raw_sha256,
                            last_seen_run_id = excluded.last_seen_run_id
                        """,
                        candidate_resolution_rows,
                    )
                    for (
                        syzbot_id,
                        title,
                        bug_url,
                        json_url,
                        version_id,
                        bug_id,
                    ) in candidate_bug_updates:
                        connection.execute(
                            """
                            UPDATE bugs
                            SET syzbot_id = COALESCE(NULLIF(?, ''), syzbot_id),
                                title = CASE WHEN ? <> '' THEN ? ELSE title END,
                                bug_url = CASE WHEN ? <> '' THEN ? ELSE bug_url END,
                                json_url = CASE WHEN ? <> '' THEN ? ELSE json_url END,
                                current_version_id = ?
                            WHERE id = ?
                            """,
                            (
                                syzbot_id,
                                title,
                                title,
                                bug_url,
                                bug_url,
                                json_url,
                                json_url,
                                version_id,
                                bug_id,
                            ),
                        )
                    for bug_id, version_id in candidate_resolution_versions:
                        self._apply_known_resolutions(
                            connection, bug_id, version_id, accepted_run_id=run_id
                        )
                    for resolved_hash, bug_id, title_normalized, repo in candidate_resolutions:
                        connection.execute(
                            """
                            UPDATE fix_commits
                            SET resolved_hash = ?
                            WHERE bug_version_id IN (
                                SELECT id FROM bug_versions WHERE bug_id = ?
                            ) AND normalized_title = ? AND repo = ?
                              AND reported_hash IS NULL
                            """,
                            (resolved_hash, bug_id, title_normalized, repo),
                        )
                        connection.execute(
                            """
                            UPDATE listing_fix_commits
                            SET resolved_hash = ?
                            WHERE bug_id = ? AND normalized_title = ? AND repo = ?
                              AND reported_hash IS NULL
                            """,
                            (resolved_hash, bug_id, title_normalized, repo),
                        )
                    # A complete bug payload with no report-bearing crash
                    # supersedes report availability for that bug.  The
                    # content remains in report_versions/blobs as history.
                    for bug_id in bug_ids.values():
                        connection.execute(
                            """
                            UPDATE reports
                            SET crash_id = NULL, source_url = '', current_blob_sha256 = NULL
                            WHERE bug_id = ?
                            """,
                            (bug_id,),
                        )
                    for digest, crash_id, report_source, report_id in candidate_reports:
                        connection.execute(
                            """
                            UPDATE reports
                            SET crash_id = ?, source_url = ?, current_blob_sha256 = ?
                            WHERE id = ?
                            """,
                            (crash_id, report_source, digest, report_id),
                        )
                    for digest, patch_source, commit_hash in candidate_patches:
                        connection.execute(
                            """
                            UPDATE patches
                            SET source_url = ?, current_blob_sha256 = ?
                            WHERE commit_hash = ?
                            """,
                            (patch_source, digest, commit_hash),
                        )

                report_details = summary.pop("reports")
                patch_details = summary.pop("patches")
                summary["bugs"] = len(prepared)
                summary["reports"] = int(report_details["valid"])
                summary["patches"] = int(patch_details["valid"])
                summary["report_details"] = report_details
                summary["patch_details"] = patch_details
                summary["status"] = run_status
                summary["snapshot_id"] = snapshot_id
                summary["failure_count"] = len(errors)
                summary["failures"] = errors[:100]
                summary["blobs_added"] = blob_additions
                summary["activated"] = run_status == "completed"

                connection.execute(
                    "UPDATE snapshots SET status = ? WHERE id = ?",
                    (run_status, snapshot_id),
                )
                if run_status == "completed":
                    connection.execute("UPDATE snapshots SET is_current = 0 WHERE is_current = 1")
                    connection.execute(
                        "UPDATE snapshots SET is_current = 1 WHERE id = ?", (snapshot_id,)
                    )
                    connection.execute(
                        """
                        INSERT INTO app_state(key, value) VALUES ('active_snapshot_id', ?)
                        ON CONFLICT(key) DO UPDATE SET value = excluded.value
                        """,
                        (str(snapshot_id),),
                    )
                connection.execute(
                    """
                    UPDATE sync_runs
                    SET completed_at = ?, status = ?, error_count = ?, summary_json = ?
                    WHERE id = ?
                    """,
                    (now, run_status, len(errors), _json_text(summary), run_id),
                )
        except Exception as exc:
            errors.append(f"snapshot transaction: {type(exc).__name__}: {exc}")
            summary["failure_count"] = len(errors)
            summary["failures"] = errors[:100]
            summary["blobs_added"] = initially_added
            return self._finish_failed(run_id, summary)
        report_progress(self._on_progress, "commit-snapshot", "Snapshot result committed", 1, 1)
        return summary

    def _upsert_commit(self, connection: sqlite3.Connection, commit_hash: str, run_id: int) -> None:
        commit_hash = commit_hash.lower()
        if not _HASH_RE.fullmatch(commit_hash):
            return
        connection.execute(
            """
            INSERT INTO commits(hash, first_seen_run_id, last_seen_run_id)
            VALUES (?, ?, ?)
            ON CONFLICT(hash) DO UPDATE SET last_seen_run_id = excluded.last_seen_run_id
            """,
            (commit_hash, run_id, run_id),
        )

    @staticmethod
    def _apply_known_resolutions(
        connection: sqlite3.Connection,
        bug_id: int,
        version_id: int,
        *,
        accepted_run_id: int | None = None,
    ) -> None:
        """Enrich a normalized bug version with accepted exact-title resolutions."""
        fixes = connection.execute(
            """
            SELECT id, normalized_title, repo
            FROM fix_commits
            WHERE bug_version_id = ? AND reported_hash IS NULL
            """,
            (version_id,),
        ).fetchall()
        for fix in fixes:
            resolution = connection.execute(
                """
                SELECT r.resolved_hash
                FROM fix_resolutions r JOIN sync_runs sr ON sr.id = r.last_seen_run_id
                WHERE r.bug_id = ? AND r.normalized_title = ? AND r.repo = ?
                  AND r.resolved_hash IS NOT NULL
                  AND (sr.status = 'completed' OR sr.id = ?)
                ORDER BY r.last_seen_run_id DESC, r.id DESC
                LIMIT 1
                """,
                (bug_id, fix["normalized_title"], fix["repo"], accepted_run_id),
            ).fetchone()
            if resolution is not None:
                connection.execute(
                    "UPDATE fix_commits SET resolved_hash = ? WHERE id = ?",
                    (resolution["resolved_hash"], fix["id"]),
                )

    def _insert_listing_fixes(
        self,
        connection: sqlite3.Connection,
        snapshot_id: int,
        bug_id: int,
        fixes: Any,
        run_id: int,
        now: str,
    ) -> int:
        """Persist fix references carried by the fixed-bug listing itself."""
        if not isinstance(fixes, Sequence) or isinstance(fixes, (str, bytes, bytearray)):
            return 0
        blobs_added = 0
        for ordinal, value in enumerate(fixes):
            if not isinstance(value, Mapping):
                continue
            fix = dict(value)
            raw_digest, was_added = self._put_blob(
                connection, _json_bytes(fix), "application/json", now
            )
            blobs_added += int(was_added)
            reported_hash = _text(fix.get("hash")).lower()
            if not _HASH_RE.fullmatch(reported_hash):
                reported_hash = ""
            if reported_hash:
                self._upsert_commit(connection, reported_hash, run_id)
            normalized_title = _normal_title(fix.get("title"))
            repo = _text(fix.get("repo"))
            resolved_hash = ""
            if not reported_hash:
                resolution = connection.execute(
                    """
                    SELECT r.resolved_hash
                    FROM fix_resolutions r JOIN sync_runs sr ON sr.id = r.last_seen_run_id
                    WHERE r.bug_id = ? AND r.normalized_title = ? AND r.repo = ?
                      AND r.resolved_hash IS NOT NULL AND sr.status = 'completed'
                    ORDER BY r.last_seen_run_id DESC, r.id DESC
                    LIMIT 1
                    """,
                    (bug_id, normalized_title, repo),
                ).fetchone()
                if resolution is not None:
                    resolved_hash = _text(resolution["resolved_hash"])
            connection.execute(
                """
                INSERT INTO listing_fix_commits(
                    snapshot_id, bug_id, ordinal, title, normalized_title,
                    repo, branch, link, reported_hash, resolved_hash,
                    author_email, author_name, commit_date, raw_sha256
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULLIF(?, ''), NULLIF(?, ''), ?, ?, ?, ?)
                ON CONFLICT(snapshot_id, bug_id, ordinal) DO NOTHING
                """,
                (
                    snapshot_id,
                    bug_id,
                    ordinal,
                    _text(fix.get("title")),
                    normalized_title,
                    repo,
                    _text(fix.get("branch")),
                    _text(fix.get("link")),
                    reported_hash,
                    resolved_hash,
                    _text(fix.get("author")),
                    _text(fix.get("author-name")),
                    fix.get("date"),
                    raw_digest,
                ),
            )
        return blobs_added

    def _insert_bug_children(
        self,
        connection: sqlite3.Connection,
        version_id: int,
        bug: Mapping[str, Any],
        run_id: int,
        now: str,
        dashboard: str,
    ) -> int:
        # An existing immutable version already owns its complete children.
        if (
            connection.execute(
                "SELECT 1 FROM crashes WHERE bug_version_id = ? LIMIT 1", (version_id,)
            ).fetchone()
            or connection.execute(
                "SELECT 1 FROM fix_commits WHERE bug_version_id = ? LIMIT 1", (version_id,)
            ).fetchone()
            or connection.execute(
                "SELECT 1 FROM discussions WHERE bug_version_id = ? LIMIT 1", (version_id,)
            ).fetchone()
            or connection.execute(
                "SELECT 1 FROM cause_commits WHERE bug_version_id = ?", (version_id,)
            ).fetchone()
        ):
            return 0

        blobs_added = 0
        fixes = bug.get("fix-commits", [])
        if isinstance(fixes, list):
            for ordinal, value in enumerate(fixes):
                if not isinstance(value, Mapping):
                    continue
                fix = dict(value)
                raw_digest, was_added = self._put_blob(
                    connection, _json_bytes(fix), "application/json", now
                )
                blobs_added += int(was_added)
                commit_hash = _text(fix.get("hash")).lower()
                if not _HASH_RE.fullmatch(commit_hash):
                    commit_hash = ""
                if commit_hash:
                    self._upsert_commit(connection, commit_hash, run_id)
                connection.execute(
                    """
                    INSERT INTO fix_commits(
                        bug_version_id, ordinal, title, normalized_title,
                        repo, branch, link, reported_hash, author_email,
                        author_name, commit_date, raw_sha256
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, NULLIF(?, ''), ?, ?, ?, ?)
                    ON CONFLICT(bug_version_id, ordinal) DO NOTHING
                    """,
                    (
                        version_id,
                        ordinal,
                        _text(fix.get("title")),
                        _normal_title(fix.get("title")),
                        _text(fix.get("repo")),
                        _text(fix.get("branch")),
                        _text(fix.get("link")),
                        commit_hash,
                        _text(fix.get("author")),
                        _text(fix.get("author-name")),
                        fix.get("date"),
                        raw_digest,
                    ),
                )

        cause = bug.get("cause-commit")
        if isinstance(cause, Mapping):
            cause_value = dict(cause)
            raw_digest, was_added = self._put_blob(
                connection, _json_bytes(cause_value), "application/json", now
            )
            blobs_added += int(was_added)
            commit_hash = _text(cause_value.get("hash")).lower()
            if not _HASH_RE.fullmatch(commit_hash):
                commit_hash = ""
            if commit_hash:
                self._upsert_commit(connection, commit_hash, run_id)
            connection.execute(
                """
                INSERT INTO cause_commits(
                    bug_version_id, title, repo, branch, link,
                    commit_hash, commit_date, raw_sha256
                ) VALUES (?, ?, ?, ?, ?, NULLIF(?, ''), ?, ?)
                ON CONFLICT(bug_version_id) DO NOTHING
                """,
                (
                    version_id,
                    _text(cause_value.get("title")),
                    _text(cause_value.get("repo")),
                    _text(cause_value.get("branch")),
                    _text(cause_value.get("link")),
                    commit_hash,
                    cause_value.get("date"),
                    raw_digest,
                ),
            )

        crashes = bug.get("crashes", [])
        if isinstance(crashes, list):
            for ordinal, value in enumerate(crashes):
                if not isinstance(value, Mapping):
                    continue
                crash = dict(value)
                raw_digest, was_added = self._put_blob(
                    connection, _json_bytes(crash), "application/json", now
                )
                blobs_added += int(was_added)
                repro_opts = crash.get("repro-opts")
                connection.execute(
                    """
                    INSERT INTO crashes(
                        bug_version_id, ordinal, title, kernel_config_url,
                        kernel_source_git, kernel_source_commit, syzkaller_git,
                        syzkaller_commit, crash_report_url, c_reproducer_url,
                        syz_reproducer_url, repro_opts_json, raw_sha256
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(bug_version_id, ordinal) DO NOTHING
                    """,
                    (
                        version_id,
                        ordinal,
                        _text(crash.get("title")),
                        _absolute_syzbot_url(crash.get("kernel-config"), dashboard),
                        _text(crash.get("kernel-source-git")),
                        _text(crash.get("kernel-source-commit")),
                        _text(crash.get("syzkaller-git")),
                        _text(crash.get("syzkaller-commit")),
                        _absolute_syzbot_url(crash.get("crash-report-link"), dashboard),
                        _absolute_syzbot_url(crash.get("c-reproducer"), dashboard),
                        _absolute_syzbot_url(crash.get("syz-reproducer"), dashboard),
                        None if repro_opts is None else _json_text(repro_opts),
                        raw_digest,
                    ),
                )

        discussions = bug.get("discussions", [])
        if isinstance(discussions, list):
            for ordinal, url in enumerate(discussions):
                connection.execute(
                    """
                    INSERT INTO discussions(bug_version_id, ordinal, url)
                    VALUES (?, ?, ?)
                    ON CONFLICT(bug_version_id, ordinal) DO NOTHING
                    """,
                    (version_id, ordinal, _text(url)),
                )
        return blobs_added

    @staticmethod
    def _path_member(paths: Any, names: Sequence[str]) -> Path | None:
        # pathlib.Path has attributes named ``root`` and ``raw`` which are not
        # members of our DataPaths protocol.  Treat path-like inputs solely as
        # a root directory instead of accidentally resolving them to ``/``.
        if isinstance(paths, (str, os.PathLike)):
            return None
        for name in names:
            if isinstance(paths, Mapping) and name in paths:
                value = paths[name]
            elif hasattr(paths, name):
                value = getattr(paths, name)
            else:
                continue
            if value is not None:
                return Path(value)
        return None

    @classmethod
    def _legacy_layout(cls, paths: Any) -> dict[str, Path]:
        explicit_root: Path | None
        if isinstance(paths, (str, os.PathLike)):
            explicit_root = Path(paths)
        else:
            explicit_root = cls._path_member(paths, ("root", "data", "data_dir"))
        root = explicit_root or Path("data")
        if (root / "data" / "raw").is_dir():
            root = root / "data"
        raw = cls._path_member(paths, ("raw", "raw_dir")) or root / "raw"
        processed = cls._path_member(paths, ("processed", "processed_dir")) or root / "processed"
        artifacts = cls._path_member(paths, ("artifacts", "artifacts_dir")) or root / "artifacts"
        return {
            "root": root,
            "listing_json": cls._path_member(
                paths, ("listing_json", "upstream_fixed_json", "fixed_json")
            )
            or raw / "upstream_fixed.json",
            "listing_html": cls._path_member(
                paths, ("listing_html", "upstream_fixed_html", "fixed_html")
            )
            or raw / "upstream_fixed.html",
            "catalog": cls._path_member(paths, ("catalog", "catalog_json"))
            or processed / "catalog.json",
            "resolutions": cls._path_member(
                paths, ("resolutions", "resolved_fix_hashes", "resolved_fix_hashes_json")
            )
            or processed / "resolved_fix_hashes.json",
            "sync_state": cls._path_member(paths, ("sync_state",)) or processed / "sync_state.json",
            "bugs": cls._path_member(paths, ("bugs", "bug_json", "bug_json_dir")) or raw / "bugs",
            "reports": cls._path_member(paths, ("reports", "reports_dir")) or artifacts / "reports",
            "patches": cls._path_member(paths, ("patches", "patches_dir")) or artifacts / "patches",
        }

    def accepted_resolutions(self, targets: ResolutionTargets) -> list[dict[str, Any]]:
        """Read accepted hashes applicable to current title-only fix references.

        This uses the stable v1 tables so an updater can inspect an older
        database read-only before its eventual indexing/migration phase.
        """
        if not targets:
            return []
        self._validate_v1_schema(self.connection)
        resolutions: list[dict[str, Any]] = []
        for row in self.connection.execute(
            """SELECT b.key, r.normalized_title, r.repo, r.resolved_hash, r.details_json
               FROM fix_resolutions r JOIN bugs b ON b.id=r.bug_id
               JOIN sync_runs sr ON sr.id=r.last_seen_run_id
               WHERE r.resolved_hash IS NOT NULL AND sr.status='completed'
               ORDER BY r.id"""
        ):
            if (row["normalized_title"], row["repo"]) not in targets.get(row["key"], set()):
                continue
            try:
                details = json.loads(row["details_json"])
            except (TypeError, ValueError):
                details = {}
            resolutions.append(
                {
                    "bug_key": row["key"],
                    # Escape the already normalized title so a subsequent
                    # resolution_identity call preserves literal angle brackets.
                    "title": html.escape(row["normalized_title"], quote=False),
                    "repo": row["repo"],
                    "hash": row["resolved_hash"],
                    "commit_url": _text(details.get("commit_url"))
                    if isinstance(details, dict)
                    else "",
                }
            )
        return resolutions

    def _pending_file_retries(
        self,
        layout: Mapping[str, Path],
        inventory: FileInventory | None = None,
    ) -> tuple[set[str], list[str]]:
        """Block incomplete live work without letting retained history block updates."""
        inventory = inventory or FileInventory()
        state, state_error = load_sync_state(layout["sync_state"])
        if not state_error and not (
            state.pending_details or state.pending_reports or state.pending_patches
        ):
            return set(), []
        errors = [f"sync state: {state_error}"] if state_error else []
        try:
            listing = inventory.read_json(layout["listing_json"])
            raw_records, _ = self._listing_records(listing)
        except (OSError, ValueError) as exc:
            return set(), [*errors, f"cannot match pending retries to listing: {exc}"]
        records = [
            record
            for value in raw_records
            if (record := self._catalog_record_from_listing(value)) is not None
        ]
        live_keys = {record["key"] for record in records}
        if state_error:
            # A malformed queue cannot establish which retained reports are
            # still awaiting a new fetch, so preserve bytes without association.
            return live_keys, errors
        pending_details = state.pending_details & live_keys
        pending_reports = state.pending_reports & live_keys
        if pending_details:
            errors.append(f"sync state: {len(pending_details)} live bug detail refresh(es) pending")
        if pending_reports:
            errors.append(
                f"sync state: {len(pending_reports)} live crash report refresh(es) pending"
            )
        if state.pending_patches:
            expected_hashes: set[str] = set()
            details: dict[str, Mapping[str, Any]] = {}
            for record in records:
                if not isinstance(record.get("fix_commits"), list):
                    record["fix_commits"] = []
                detail: dict[str, Any] | None = None
                try:
                    payload = inventory.read_json(layout["bugs"] / f"{record['key']}.json")
                    if isinstance(payload, dict):
                        detail = payload
                        details[record["key"]] = payload
                except (OSError, ValueError):
                    # Normal ingestion reports missing/malformed payloads.
                    pass
                expected_hashes.update(self._fix_hashes(record, detail))
            try:
                catalog = inventory.read_json(layout["catalog"])
                catalog_records = catalog.get("bugs", [])
                if isinstance(catalog_records, list):
                    for record in catalog_records:
                        if (
                            isinstance(record, Mapping)
                            and _text(record.get("key")) in live_keys
                            and isinstance(record.get("fix_commits"), list)
                        ):
                            expected_hashes.update(self._fix_hashes(record, None))
            except (OSError, ValueError, AttributeError):
                pass
            targets = resolution_targets(records, details)
            choices = {
                resolution_identity(value): value for value in self.accepted_resolutions(targets)
            }
            try:
                resolution_payload = inventory.read_json(layout["resolutions"])
                resolutions = resolution_payload.get("resolutions", [])
                if isinstance(resolutions, list):
                    for resolution in resolutions:
                        if isinstance(resolution, Mapping) and resolution_matches(
                            resolution, targets
                        ):
                            commit_hash = _text(resolution.get("hash")).lower()
                            if _HASH_RE.fullmatch(commit_hash):
                                choices[resolution_identity(resolution)] = dict(resolution)
            except (OSError, ValueError, AttributeError):
                pass
            expected_hashes.update(_text(value["hash"]).lower() for value in choices.values())
            pending_patches = state.pending_patches & expected_hashes
            if pending_patches:
                errors.append(f"sync state: {len(pending_patches)} live patch refresh(es) pending")
        return pending_details | pending_reports, errors

    @staticmethod
    def _legacy_fingerprint(layout: Mapping[str, Path]) -> tuple[str, list[str]]:
        """Hash only retained input files; databases and analysis outputs are excluded."""
        return FileInventory().fingerprint(layout)

    def _fingerprint_files(
        self, inventory: FileInventory, layout: Mapping[str, Path]
    ) -> tuple[str, list[str]]:
        if self._on_progress is None:
            return inventory.fingerprint(layout)
        return inventory.fingerprint(layout, on_progress=self._on_progress)

    @staticmethod
    def _set_last_checked(connection: sqlite3.Connection, checked_at: str) -> str:
        connection.execute(
            """
            INSERT INTO app_state(key, value) VALUES ('last_checked_at', ?)
            ON CONFLICT(key) DO UPDATE SET value = CASE
                WHEN excluded.value > app_state.value THEN excluded.value
                ELSE app_state.value
            END
            """,
            (checked_at,),
        )
        row = connection.execute(
            "SELECT value FROM app_state WHERE key = 'last_checked_at'"
        ).fetchone()
        if row is None:
            raise RuntimeError("could not persist last_checked_at")
        return _text(row["value"])

    def check_files_current(
        self,
        paths: Any,
        *,
        source_kind: str = "snapshot",
        inventory: FileInventory | None = None,
    ) -> dict[str, Any] | None:
        """Return an unchanged summary when files match the last complete active run.

        This check performs no database writes. Use a read-only Database to avoid
        writable initialization as well. A missing fingerprint, pending partial
        run, or changed file requires normal ingestion instead.
        """
        if int(self.connection.execute("PRAGMA user_version").fetchone()[0]) < SCHEMA_VERSION:
            return None
        self.initialize()
        layout = self._legacy_layout(paths)
        inventory = inventory or FileInventory()
        _, pending_errors = self._pending_file_retries(layout, inventory)
        if pending_errors:
            return None
        fingerprint, errors = self._fingerprint_files(inventory, layout)
        if errors:
            return None
        result = self._unchanged_files_result(fingerprint, source_kind)
        if result is not None:
            try:
                inventory.assert_fingerprint_current(layout, fingerprint)
            except OSError:
                return None
        return result

    def _unchanged_files_result(self, fingerprint: str, source_kind: str) -> dict[str, Any] | None:
        state_key = f"file_import:{source_kind}"
        prior = self.connection.execute(
            "SELECT value FROM app_state WHERE key = ?", (state_key,)
        ).fetchone()
        if prior is not None:
            try:
                prior_value = json.loads(prior["value"])
            except (TypeError, json.JSONDecodeError):
                prior_value = {}
            current = self.connection.execute(
                "SELECT id, run_id FROM snapshots WHERE is_current = 1"
            ).fetchone()
            latest_run = self.connection.execute(
                "SELECT id FROM sync_runs ORDER BY id DESC LIMIT 1"
            ).fetchone()
            if (
                isinstance(prior_value, dict)
                and prior_value.get("fingerprint") == fingerprint
                and current is not None
                and latest_run is not None
                and latest_run["id"] == current["run_id"]
                and prior_value.get("snapshot_id") == current["id"]
            ):
                active_status = self.status()
                return {
                    "status": "unchanged",
                    "activated": False,
                    "snapshot_id": int(current["id"]),
                    "fingerprint": fingerprint,
                    "failure_count": 0,
                    "failures": [],
                    "bugs": active_status["bugs"],
                    "reports": active_status["reports"],
                    "patches": active_status["patches"],
                    "known_fixed_bugs": active_status["bugs"],
                    "new_fixed_bugs": 0,
                    "new_fixed_bug_keys": [],
                    "no_longer_listed_bugs": 0,
                    "no_longer_listed_bug_keys": [],
                    "blobs_added": 0,
                    "last_checked_at": active_status["last_checked_at"],
                }
        return None

    def ingest_files(
        self,
        paths: Any,
        *,
        errors: Sequence[str] = (),
        source_kind: str = "snapshot",
        inventory: FileInventory | None = None,
        source_urls: Mapping[Path, str] | None = None,
    ) -> dict[str, Any]:
        """Read a retained on-disk snapshot and transactionally index it.

        The files remain authoritative and are never modified here.  A stable
        fingerprint makes a repeated successful ingestion entity-idempotent.
        Caller-supplied errors deliberately bypass the unchanged fast path so
        an incomplete fetch is recorded as a non-active partial run.
        """
        self.initialize()
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", source_kind):
            raise ValueError("source_kind must contain only letters, digits, '.', '_' or '-'")
        layout = self._legacy_layout(paths)
        inventory = inventory or FileInventory()
        inherited_errors = list(errors)
        unavailable_reports, pending_errors = self._pending_file_retries(layout, inventory)
        inherited_errors.extend(pending_errors)
        fingerprint, fingerprint_errors = self._fingerprint_files(inventory, layout)
        inherited_errors.extend(fingerprint_errors)

        def verify_files() -> None:
            inventory.assert_fingerprint_current(layout, fingerprint)

        state_key = f"file_import:{source_kind}"
        if not inherited_errors:
            unchanged = self._unchanged_files_result(fingerprint, source_kind)
            if unchanged is not None:
                try:
                    verify_files()
                except OSError as exc:
                    inherited_errors.append(str(exc))
                else:
                    return unchanged
        extra_documents: list[tuple[str, str, str, bytes, bool, str | None]] = []

        try:
            listing_json = inventory.read_bytes(layout["listing_json"])
        except OSError as exc:
            # ingest_snapshot will retain this failed attempt as an empty raw
            # listing document and will not alter the current snapshot.
            listing_json = b""
            inherited_errors.append(f"cannot read {layout['listing_json']}: {exc}")
        try:
            listing_html = inventory.read_bytes(layout["listing_html"])
        except FileNotFoundError:
            listing_html = None
        except OSError as exc:
            listing_html = None
            inherited_errors.append(f"cannot read {layout['listing_html']}: {exc}")

        records: list[Any] = []
        parsed_listing = UNPARSED
        with suppress(OSError, ValueError):
            parsed_listing = inventory.read_json(layout["listing_json"], payload=listing_json)
        source_url = DEFAULT_SOURCE_URL
        try:
            catalog_raw = inventory.read_bytes(layout["catalog"])
        except FileNotFoundError:
            catalog_raw = None
        except OSError as exc:
            catalog_raw = None
            inherited_errors.append(f"cannot read {layout['catalog']}: {exc}")
        if catalog_raw is not None:
            catalog_error: str | None = None
            try:
                catalog = inventory.read_json(layout["catalog"], payload=catalog_raw)
                if not isinstance(catalog, dict) or not isinstance(catalog.get("bugs"), list):
                    raise ValueError("catalog must be an object with a bugs list")
                records = list(catalog["bugs"])
                source_url = _text(catalog.get("source")) or source_url
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
                catalog_error = str(exc)
                inherited_errors.append(f"catalog: {exc}")
            extra_documents.append(
                (
                    f"{source_kind}-catalog",
                    str(layout["catalog"]),
                    "",
                    catalog_raw,
                    catalog_error is None,
                    catalog_error,
                )
            )

        if not records:
            try:
                raw_records, _ = self._listing_records(parsed_listing)
                records = [
                    candidate
                    for raw in raw_records
                    if (candidate := self._catalog_record_from_listing(raw)) is not None
                ]
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
                records = []

        bug_payloads: dict[str, bytes] = {}
        parsed_payloads: dict[str, Any] = {}
        for value in progress_items(
            records, self._on_progress, "read-bugs", "Reading saved bug details", total=len(records)
        ):
            try:
                key = _text(_as_mapping(value).get("key"))
            except TypeError:
                continue
            if not _safe_file_key(key):
                continue
            path = layout["bugs"] / f"{key}.json"
            try:
                bug_payloads[key] = inventory.read_bytes(path)
                with suppress(ValueError):
                    parsed_payloads[key] = inventory.read_json(path, payload=bug_payloads[key])
            except FileNotFoundError:
                continue
            except OSError as exc:
                inherited_errors.append(f"cannot read {path}: {exc}")

        resolutions: list[Any] = []
        try:
            resolution_raw = inventory.read_bytes(layout["resolutions"])
        except FileNotFoundError:
            resolution_raw = None
        except OSError as exc:
            resolution_raw = None
            inherited_errors.append(f"cannot read {layout['resolutions']}: {exc}")
        if resolution_raw is not None:
            resolution_error: str | None = None
            try:
                payload = inventory.read_json(layout["resolutions"], payload=resolution_raw)
                if not isinstance(payload, dict) or not isinstance(
                    payload.get("resolutions"), list
                ):
                    raise ValueError("resolution file must contain a resolutions list")
                resolutions = list(payload["resolutions"])
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
                resolution_error = str(exc)
                inherited_errors.append(f"resolutions: {exc}")
            extra_documents.append(
                (
                    f"{source_kind}-resolutions",
                    str(layout["resolutions"]),
                    "",
                    resolution_raw,
                    resolution_error is None,
                    resolution_error,
                )
            )

        result = self._ingest_snapshot(
            listing_json=listing_json,
            listing_html=listing_html,
            records=records,
            bug_payloads=bug_payloads,
            reports_dir=layout["reports"],
            patches_dir=layout["patches"],
            source_url=source_url,
            resolutions=resolutions,
            extra_documents=extra_documents,
            inherited_errors=inherited_errors,
            unavailable_reports=unavailable_reports,
            inventory=inventory,
            source_urls=source_urls,
            parsed_listing=parsed_listing,
            parsed_payloads=parsed_payloads,
            verify_files=verify_files,
        )
        result["fingerprint"] = fingerprint
        result_status = _text(result.get("status"))
        if result_status in {"completed", "partial"}:
            with self._transaction() as connection:
                if result_status == "completed":
                    connection.execute(
                        """
                        INSERT INTO app_state(key, value) VALUES (?, ?)
                        ON CONFLICT(key) DO UPDATE SET value = excluded.value
                        """,
                        (
                            state_key,
                            _json_text(
                                {
                                    "fingerprint": fingerprint,
                                    "snapshot_id": result.get("snapshot_id"),
                                }
                            ),
                        ),
                    )
                result["last_checked_at"] = self._set_last_checked(connection, _utc_now())
        return result

    def import_legacy(self, paths: Any) -> dict[str, Any]:
        """Compatibility wrapper for importing an existing repository snapshot."""
        return self.ingest_files(paths, source_kind="legacy")

    @staticmethod
    def _merge_fix_rows(rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
        """Merge duplicate references without treating a subject as a commit ID.

        Known hashes are grouped first. A title-only reference can enrich one
        unambiguous commit, but remains unresolved when multiple commits share
        the subject and repository (for example, backports).
        """
        merged: list[dict[str, Any]] = []
        identities: list[tuple[str, str, str]] = []
        positions: list[int] = []
        ordered_rows = sorted(
            enumerate(rows),
            key=lambda pair: not bool(pair[1].get("reported_hash") or pair[1].get("resolved_hash")),
        )
        for position, row in ordered_rows:
            item = dict(row)
            source_kind = _text(item.pop("source_kind"))
            normalized_title = _text(item.pop("normalized_title"))
            repo = _text(item.get("repo"))
            commit_hash = _text(item.get("reported_hash") or item.get("resolved_hash"))
            patch_available = item.pop("patch_sha256", None) is not None
            hash_matches: list[int] = []
            subject_matches: list[int] = []
            for index, (known_hash, known_title, known_repo) in enumerate(identities):
                same_hash = bool(commit_hash and known_hash and commit_hash == known_hash)
                same_subject = bool(
                    normalized_title and normalized_title == known_title and repo == known_repo
                )
                if same_hash:
                    hash_matches.append(index)
                elif not commit_hash and same_subject:
                    subject_matches.append(index)
            # Repeated ambiguous title-only references can still merge with
            # each other, never with an arbitrarily selected known hash.
            unresolved_matches = [index for index in subject_matches if not identities[index][0]]
            match_index = (
                hash_matches[0]
                if hash_matches
                else unresolved_matches[0]
                if unresolved_matches
                else subject_matches[0]
                if len(subject_matches) == 1
                else None
            )
            if match_index is None:
                item["commit_hash"] = commit_hash or None
                item["hash"] = commit_hash or None
                item["patch_available"] = patch_available
                item["sources"] = [source_kind]
                merged.append(item)
                identities.append((commit_hash, normalized_title, repo))
                positions.append(position)
                continue

            current = merged[match_index]
            for name, value in item.items():
                if value not in (None, "") and current.get(name) in (None, ""):
                    current[name] = value
            sources = current["sources"]
            if source_kind not in sources:
                sources.append(source_kind)
            current["patch_available"] = bool(current["patch_available"] or patch_available)
            current_hash = _text(current.get("reported_hash") or current.get("resolved_hash"))
            current["commit_hash"] = current_hash or None
            current["hash"] = current_hash or None
            positions[match_index] = min(positions[match_index], position)
            identities[match_index] = (
                current_hash,
                identities[match_index][1] or normalized_title,
                identities[match_index][2] or repo,
            )
        return [
            item
            for _, item in sorted(zip(positions, merged, strict=True), key=lambda pair: pair[0])
        ]

    def _effective_fixes(
        self,
        *,
        bug_id: int,
        version_id: int,
        snapshot_id: int | None,
    ) -> list[dict[str, Any]]:
        rows: list[sqlite3.Row] = []
        if snapshot_id is not None:
            rows.extend(
                self.connection.execute(
                    """
                    SELECT 'listing' AS source_kind, f.ordinal, f.title,
                           f.normalized_title, f.repo, f.branch, f.link,
                           f.reported_hash, f.resolved_hash, f.author_email,
                           f.author_name, f.commit_date,
                           pv.blob_sha256 AS patch_sha256,
                           CASE WHEN pv.is_valid = 1 THEN sp.source_url END AS patch_source_url
                    FROM listing_fix_commits AS f
                    LEFT JOIN snapshot_patches AS sp
                      ON sp.snapshot_id = f.snapshot_id
                     AND sp.commit_hash = COALESCE(f.reported_hash, f.resolved_hash)
                    LEFT JOIN patch_versions AS pv
                      ON pv.id = sp.patch_version_id AND pv.is_valid = 1
                    WHERE f.snapshot_id = ? AND f.bug_id = ?
                    ORDER BY f.ordinal
                    """,
                    (snapshot_id, bug_id),
                ).fetchall()
            )
        rows.extend(
            self.connection.execute(
                """
                SELECT 'bug-json' AS source_kind, f.ordinal, f.title,
                       f.normalized_title, f.repo, f.branch, f.link,
                       f.reported_hash, f.resolved_hash, f.author_email,
                       f.author_name, f.commit_date,
                       pv.blob_sha256 AS patch_sha256,
                       CASE WHEN pv.is_valid = 1 THEN sp.source_url END AS patch_source_url
                FROM fix_commits AS f
                LEFT JOIN snapshot_patches AS sp
                  ON sp.snapshot_id = ?
                 AND sp.commit_hash = COALESCE(f.reported_hash, f.resolved_hash)
                LEFT JOIN patch_versions AS pv
                  ON pv.id = sp.patch_version_id AND pv.is_valid = 1
                WHERE f.bug_version_id = ?
                ORDER BY f.ordinal
                """,
                (snapshot_id, version_id),
            ).fetchall()
        )
        return self._merge_fix_rows([dict(row) for row in rows])

    def _current_effective_fixes(self) -> dict[int, list[dict[str, Any]]]:
        grouped: dict[int, list[dict[str, Any]]] = {}
        listing_rows = self.connection.execute(
            """
            SELECT c.bug_id, 'listing' AS source_kind, f.ordinal, f.title,
                   f.normalized_title, f.repo, f.branch, f.link,
                   f.reported_hash, f.resolved_hash, f.author_email,
                   f.author_name, f.commit_date,
                   pv.blob_sha256 AS patch_sha256,
                   CASE WHEN pv.is_valid = 1 THEN sp.source_url END AS patch_source_url
            FROM current_bug_rows AS c
            JOIN listing_fix_commits AS f
              ON f.snapshot_id = c.snapshot_id AND f.bug_id = c.bug_id
            LEFT JOIN snapshot_patches AS sp
              ON sp.snapshot_id = c.snapshot_id
             AND sp.commit_hash = COALESCE(f.reported_hash, f.resolved_hash)
            LEFT JOIN patch_versions AS pv
              ON pv.id = sp.patch_version_id AND pv.is_valid = 1
            ORDER BY c.position, f.ordinal
            """
        ).fetchall()
        detail_rows = self.connection.execute(
            """
            SELECT c.bug_id, 'bug-json' AS source_kind, f.ordinal, f.title,
                   f.normalized_title, f.repo, f.branch, f.link,
                   f.reported_hash, f.resolved_hash, f.author_email,
                   f.author_name, f.commit_date,
                   pv.blob_sha256 AS patch_sha256,
                   CASE WHEN pv.is_valid = 1 THEN sp.source_url END AS patch_source_url
            FROM current_bug_rows AS c
            JOIN fix_commits AS f ON f.bug_version_id = c.bug_version_id
            LEFT JOIN snapshot_patches AS sp
              ON sp.snapshot_id = c.snapshot_id
             AND sp.commit_hash = COALESCE(f.reported_hash, f.resolved_hash)
            LEFT JOIN patch_versions AS pv
              ON pv.id = sp.patch_version_id AND pv.is_valid = 1
            ORDER BY c.position, f.ordinal
            """
        ).fetchall()
        for row in (*listing_rows, *detail_rows):
            item = dict(row)
            bug_id = int(item.pop("bug_id"))
            grouped.setdefault(bug_id, []).append(item)
        return {bug_id: self._merge_fix_rows(group) for bug_id, group in grouped.items()}

    def status(self) -> dict[str, Any]:
        """Return JSON-serializable coverage and snapshot statistics."""
        self.initialize()
        connection = self.connection
        current = connection.execute(
            """
            SELECT id, run_id, source_url, source_version, captured_at,
                   source_record_count, record_count, status
            FROM snapshots WHERE is_current = 1
            """
        ).fetchone()
        latest_run = connection.execute(
            """
            SELECT id, source_url, started_at, completed_at, status, error_count
            FROM sync_runs ORDER BY id DESC LIMIT 1
            """
        ).fetchone()
        table_counts = {}
        for table in (
            "blobs",
            "documents",
            "sync_runs",
            "snapshots",
            "bugs",
            "bug_versions",
            "fix_commits",
            "listing_fix_commits",
            "cause_commits",
            "crashes",
            "discussions",
            "commits",
            "fix_resolutions",
            "reports",
            "report_versions",
            "patches",
            "patch_versions",
            "bug_subsystems",
            "crash_locations",
            "crash_stack_frames",
            "fix_locations",
            "snapshot_reports",
            "snapshot_patches",
        ):
            table_counts[table] = int(
                connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            )
        current_bugs = int(
            connection.execute("SELECT COUNT(*) FROM current_bug_rows").fetchone()[0]
        )
        effective_fixes = self._current_effective_fixes()
        current_fixes = sum(len(fixes) for fixes in effective_fixes.values())
        current_crashes = int(
            connection.execute(
                """
                SELECT COUNT(*)
                FROM current_bug_rows AS c
                JOIN crashes AS cr ON cr.bug_version_id = c.bug_version_id
                """
            ).fetchone()[0]
        )
        valid_reports = int(
            connection.execute(
                """
                SELECT COUNT(*)
                FROM current_bug_rows AS c
                JOIN snapshot_reports AS sr
                  ON sr.snapshot_id = c.snapshot_id AND sr.bug_id = c.bug_id
                JOIN report_versions AS rv ON rv.id = sr.report_version_id
                WHERE rv.is_valid = 1
                """
            ).fetchone()[0]
        )
        valid_patches = len(
            {
                _text(fix.get("hash"))
                for fixes in effective_fixes.values()
                for fix in fixes
                if fix.get("hash") and fix.get("patch_available")
            }
        )
        blob_bytes = int(
            connection.execute("SELECT COALESCE(SUM(size_bytes), 0) FROM blobs").fetchone()[0]
        )
        run_statuses = {
            row["status"]: int(row["amount"])
            for row in connection.execute(
                "SELECT status, COUNT(*) AS amount FROM sync_runs GROUP BY status"
            )
        }
        last_checked_row = connection.execute(
            "SELECT value FROM app_state WHERE key = 'last_checked_at'"
        ).fetchone()
        last_checked_at = _text(last_checked_row["value"]) if last_checked_row else None
        return {
            "database": self._path_text,
            "schema_version": int(connection.execute("PRAGMA user_version").fetchone()[0]),
            "current_snapshot": dict(current) if current else None,
            "latest_run": dict(latest_run) if latest_run else None,
            "counts": {
                **table_counts,
                "current_bugs": current_bugs,
                "valid_reports": valid_reports,
                "valid_patches": valid_patches,
                "blob_bytes": blob_bytes,
            },
            "run_statuses": run_statuses,
            # Flat compatibility counters are convenient for both CLI text
            # output and small API clients.
            "bugs": current_bugs,
            "current_bugs": current_bugs,
            "fixes": current_fixes,
            "crashes": current_crashes,
            "reports": valid_reports,
            "patches": valid_patches,
            "last_sync_status": latest_run["status"] if latest_run else None,
            "last_sync_at": latest_run["completed_at"] if latest_run else None,
            "last_checked_at": last_checked_at,
        }

    def list_bugs(
        self,
        query: str | None = None,
        limit: int = 20,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """List bugs in the active snapshot, newest listing order first."""
        result: list[dict[str, Any]] = self.filter_bugs(query=query, limit=limit, offset=offset)[
            "bugs"
        ]
        return result

    @contextmanager
    def _read_transaction(self) -> Iterator[sqlite3.Connection]:
        """Keep related reads on one snapshot without acquiring a writer lock."""
        if self.connection.in_transaction:
            yield self.connection
        else:
            with self._transaction("DEFERRED") as connection:
                yield connection

    @staticmethod
    def _filter_terms(values: Sequence[str], label: str) -> list[str]:
        if isinstance(values, (str, bytes)):
            raise ValueError(f"{label} must be a sequence of strings")
        result: list[str] = []
        for value in values:
            if not isinstance(value, str):
                raise ValueError(f"{label} must contain only strings")
            normalized = value.strip().lower()
            if not normalized or any(
                character.isspace() or ord(character) < 32 or 127 <= ord(character) <= 159
                for character in normalized
            ):
                raise ValueError(f"invalid {label} value: {value!r}")
            if normalized not in result:
                result.append(normalized)
        return result

    def filter_bugs(
        self,
        *,
        bug_types: Sequence[str] = (),
        subsystems: Sequence[str] = (),
        query: str | None = None,
        limit: int | None = 20,
        offset: int = 0,
    ) -> dict[str, Any]:
        """Filter active fixed-listing membership and enrich only the requested page.

        Values within one category are alternatives; type, tag and optional
        literal key/title search categories are intersected. Subsystem matching
        uses complete tags, without inferring parent/child relationships.
        """
        types = self._filter_terms(bug_types, "bug type")
        tags = self._filter_terms(subsystems, "subsystem")
        unknown = [value for value in types if value not in BUG_TYPES]
        if unknown:
            raise ValueError("unknown bug type: " + ", ".join(unknown))
        if (limit is not None and (type(limit) is not int or limit < 0)) or (
            type(offset) is not int or offset < 0
        ):
            raise ValueError("limit and offset must be non-negative integers")
        self.initialize()
        conditions: list[str] = []
        parameters: list[Any] = []
        if types:
            placeholders = ", ".join("?" for _ in types)
            conditions.append(f"c.bug_type IN ({placeholders})")
            parameters.extend(types)
        if tags:
            placeholders = ", ".join("?" for _ in tags)
            conditions.append(
                "EXISTS (SELECT 1 FROM bug_subsystems AS tags "
                "WHERE tags.snapshot_id = c.snapshot_id AND tags.bug_id = c.bug_id "
                f"AND tags.tag COLLATE NOCASE IN ({placeholders}))"
            )
            parameters.extend(tags)
        if query:
            conditions.append(
                "(c.key COLLATE NOCASE LIKE ? ESCAPE '\\' "
                "OR c.title COLLATE NOCASE LIKE ? ESCAPE '\\')"
            )
            escaped = query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            parameters.extend((f"%{escaped}%", f"%{escaped}%"))
        where = "WHERE " + " AND ".join(conditions) if conditions else ""
        with self._read_transaction():
            total = int(
                self.connection.execute(
                    f"SELECT COUNT(*) FROM current_bug_rows AS c {where}", parameters
                ).fetchone()[0]
            )
            return {
                "bugs": self._list_filtered_rows(where, parameters, limit, offset),
                "total": total,
                "limit": limit,
                "offset": offset,
                "bug_types": types,
                "subsystems": tags,
            }

    def filter_values(self) -> dict[str, list[dict[str, Any]]]:
        """Count distinct active bugs for each stored type and exact subsystem tag."""
        self.initialize()
        with self._read_transaction():
            types = [
                {"value": row["bug_type"], "count": int(row["amount"])}
                for row in self.connection.execute(
                    "SELECT bug_type, COUNT(*) AS amount FROM current_bug_rows "
                    "GROUP BY bug_type ORDER BY bug_type"
                )
            ]
            tags = [
                {"value": row["tag"], "count": int(row["amount"])}
                for row in self.connection.execute(
                    "SELECT LOWER(tag) AS tag, COUNT(DISTINCT bug_id) AS amount "
                    "FROM current_bug_subsystems GROUP BY tag COLLATE NOCASE "
                    "ORDER BY tag COLLATE NOCASE"
                )
            ]
            return {"bug_types": types, "subsystems": tags}

    def _list_filtered_rows(
        self,
        where: str,
        parameters: Sequence[Any],
        limit: int | None,
        offset: int,
    ) -> list[dict[str, Any]]:
        parameters = [*parameters, -1 if limit is None else limit, offset]
        rows = self.connection.execute(
            f"""
            SELECT
                c.bug_id, c.bug_version_id, c.snapshot_id,
                c.key, c.title, c.bug_type, c.status, c.bug_url,
                c.raw_sha256, bv.payload_kind,
                c.first_crash_at, c.last_crash_at, c.fix_time, c.close_time,
                (SELECT COUNT(*) FROM crashes AS cr
                 WHERE cr.bug_version_id = c.bug_version_id) AS crash_count,
                EXISTS(
                    SELECT 1 FROM snapshot_reports AS sr
                    JOIN report_versions AS rv ON rv.id = sr.report_version_id
                    WHERE sr.snapshot_id = c.snapshot_id AND sr.bug_id = c.bug_id
                      AND rv.is_valid = 1
                ) AS has_report
            FROM current_bug_rows AS c
            JOIN bug_versions AS bv ON bv.id = c.bug_version_id
            {where}
            ORDER BY c.position
            LIMIT ? OFFSET ?
            """,
            parameters,
        ).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            bug_id = int(item.pop("bug_id"))
            version_id = int(item.pop("bug_version_id"))
            snapshot_id = int(item.pop("snapshot_id"))
            fixes = self._effective_fixes(
                bug_id=bug_id,
                version_id=version_id,
                snapshot_id=snapshot_id,
            )
            item["fix_count"] = len(fixes)
            item["patch_urls"] = _patch_urls(fixes)
            item.update(
                _c_reproducer_fields(
                    self._load_json_blob(item.pop("raw_sha256")),
                    item.pop("payload_kind"),
                    _dashboard_from_bug_url(item["bug_url"]),
                )
            )
            item["has_report"] = bool(item["has_report"])
            item["subsystems"] = [
                tag[0]
                for tag in self.connection.execute(
                    "SELECT tag FROM current_bug_subsystems WHERE bug_id = ? ORDER BY tag",
                    (bug_id,),
                )
            ]
            result.append(item)
        return result

    def _load_json_blob(self, digest: str) -> Any:
        row = self.connection.execute(
            "SELECT content FROM blobs WHERE sha256 = ?", (digest,)
        ).fetchone()
        if row is not None:
            try:
                return json.loads(bytes(row[0]).decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                pass
        return None

    def get_bug(self, key: str) -> dict[str, Any] | None:
        """Return normalized details (and parsed raw JSON) for one bug."""
        self.initialize()
        with self._read_transaction():
            return self._get_bug(key)

    def _get_bug(self, key: str) -> dict[str, Any] | None:
        bug_row = self.connection.execute(
            """
            SELECT b.id, b.key, b.syzbot_id, c.title, c.bug_type, c.bug_url, c.json_url,
                   c.bug_version_id, c.snapshot_id
            FROM current_bug_rows AS c
            JOIN bugs AS b ON b.id = c.bug_id
            WHERE b.key = ?
            """,
            (key,),
        ).fetchone()
        if bug_row is None:
            return None
        bug_id = int(bug_row["id"])
        version_id = int(bug_row["bug_version_id"])
        version_row = self.connection.execute(
            """
            SELECT raw_sha256, payload_kind, source_version, status,
                   first_crash_at, last_crash_at, fix_time, close_time
            FROM bug_versions WHERE id = ?
            """,
            (version_id,),
        ).fetchone()
        if version_row is None:
            return None
        snapshot_id = int(bug_row["snapshot_id"])
        fixes = self._effective_fixes(
            bug_id=bug_id,
            version_id=version_id,
            snapshot_id=snapshot_id,
        )
        crashes = [
            dict(item)
            for item in self.connection.execute(
                """
                SELECT ordinal, title, kernel_config_url, kernel_source_git,
                       kernel_source_commit, syzkaller_git, syzkaller_commit,
                       crash_report_url, c_reproducer_url, syz_reproducer_url,
                       repro_opts_json
                FROM crashes WHERE bug_version_id = ? ORDER BY ordinal
                """,
                (version_id,),
            )
        ]
        for crash in crashes:
            if crash["repro_opts_json"] is not None:
                try:
                    crash["repro_opts"] = json.loads(crash.pop("repro_opts_json"))
                except json.JSONDecodeError:
                    crash["repro_opts"] = crash.pop("repro_opts_json")
            else:
                crash.pop("repro_opts_json")
        discussions = [
            item[0]
            for item in self.connection.execute(
                "SELECT url FROM discussions WHERE bug_version_id = ? ORDER BY ordinal",
                (version_id,),
            )
        ]
        cause_row = self.connection.execute(
            """
            SELECT title, repo, branch, link, commit_hash, commit_date
            FROM cause_commits WHERE bug_version_id = ?
            """,
            (version_id,),
        ).fetchone()
        report_row = self.connection.execute(
            """
            SELECT COALESCE(sr.source_url, '') AS source_url,
                   rv.blob_sha256 AS current_blob_sha256, b.content
            FROM reports AS r
            LEFT JOIN snapshot_reports AS sr
              ON sr.snapshot_id = ? AND sr.bug_id = r.bug_id
            LEFT JOIN report_versions AS rv
              ON rv.id = sr.report_version_id AND rv.is_valid = 1
            LEFT JOIN blobs AS b ON b.sha256 = rv.blob_sha256
            WHERE r.bug_id = ?
            """,
            (snapshot_id, bug_id),
        ).fetchone()
        report = None
        if report_row is not None:
            content = report_row["content"]
            decoded = (
                bytes(content).decode("utf-8", errors="replace") if content is not None else None
            )
            report = {
                "source_url": report_row["source_url"],
                "sha256": report_row["current_blob_sha256"],
                "available": content is not None,
                "size": len(content) if content is not None else 0,
                "text": decoded,
            }
        raw = self._load_json_blob(version_row["raw_sha256"])
        return {
            "key": bug_row["key"],
            "syzbot_id": bug_row["syzbot_id"],
            "title": bug_row["title"],
            "bug_type": bug_row["bug_type"],
            "status": version_row["status"],
            "bug_url": bug_row["bug_url"],
            "json_url": bug_row["json_url"],
            "first_crash": version_row["first_crash_at"],
            "last_crash": version_row["last_crash_at"],
            "fix_time": version_row["fix_time"],
            "close_time": version_row["close_time"],
            "source_version": version_row["source_version"],
            "payload_kind": version_row["payload_kind"],
            "raw_sha256": version_row["raw_sha256"],
            "snapshot_id": snapshot_id,
            "in_current_snapshot": True,
            "fixes": fixes,
            "fix_commits": fixes,
            "cause_commit": dict(cause_row) if cause_row else None,
            "crashes": crashes,
            "discussions": discussions,
            "report": report,
            "raw": raw,
            **_c_reproducer_fields(
                raw, version_row["payload_kind"], _dashboard_from_bug_url(bug_row["bug_url"])
            ),
            **location_store.bug_locations(self.connection, bug_id),
        }

    def health_check(self) -> dict[str, Any]:
        """Check SQLite integrity, foreign keys, snapshots, and blob hashes."""
        self.initialize()
        connection = self.connection
        report_progress(self._on_progress, "check-sqlite", "Checking SQLite integrity", 0, 2)
        quick_rows = [row[0] for row in connection.execute("PRAGMA quick_check")]
        report_progress(self._on_progress, "check-sqlite", "Checking foreign keys", 1, 2)
        foreign_rows = [tuple(row) for row in connection.execute("PRAGMA foreign_key_check")]
        report_progress(self._on_progress, "check-sqlite", "SQLite checks processed", 2, 2)
        blob_mismatches: list[dict[str, Any]] = []
        blob_count = 0
        for row in progress_items(
            connection.execute("SELECT sha256, size_bytes, content FROM blobs"),
            self._on_progress,
            "check-blobs",
            "Checking saved blob hashes",
        ):
            blob_count += 1
            content = bytes(row["content"])
            actual = hashlib.sha256(content).hexdigest()
            if actual != row["sha256"] or len(content) != row["size_bytes"]:
                blob_mismatches.append(
                    {
                        "stored_sha256": row["sha256"],
                        "actual_sha256": actual,
                        "stored_size": row["size_bytes"],
                        "actual_size": len(content),
                    }
                )
        snapshot_errors: list[str] = []
        report_progress(self._on_progress, "check-snapshots", "Checking snapshot consistency", 0, 3)
        snapshot_errors.extend(schema_v3.consistency_errors(connection))
        report_progress(self._on_progress, "check-snapshots", "Checking bug classifications", 1, 3)
        snapshot_errors.extend(schema_v4.consistency_errors(connection))
        report_progress(self._on_progress, "check-snapshots", "Checking active membership", 2, 3)
        current_rows = connection.execute(
            "SELECT id, record_count FROM snapshots WHERE is_current = 1"
        ).fetchall()
        if len(current_rows) > 1:
            snapshot_errors.append("more than one current snapshot")
        if current_rows:
            membership_count = int(
                connection.execute(
                    "SELECT COUNT(*) FROM snapshot_bugs WHERE snapshot_id = ?",
                    (current_rows[0]["id"],),
                ).fetchone()[0]
            )
            if membership_count != int(current_rows[0]["record_count"]):
                snapshot_errors.append(
                    "current snapshot record_count="
                    f"{current_rows[0]['record_count']} but has "
                    f"{membership_count} memberships"
                )
        report_progress(self._on_progress, "check-snapshots", "Snapshot checks processed", 3, 3)
        ok = (
            quick_rows == ["ok"]
            and not foreign_rows
            and not blob_mismatches
            and not snapshot_errors
            and int(connection.execute("PRAGMA user_version").fetchone()[0]) == SCHEMA_VERSION
            and bool(connection.execute("PRAGMA foreign_keys").fetchone()[0])
        )
        return {
            "ok": ok,
            "schema_version": int(connection.execute("PRAGMA user_version").fetchone()[0]),
            "foreign_keys_enabled": bool(connection.execute("PRAGMA foreign_keys").fetchone()[0]),
            "journal_mode": _text(connection.execute("PRAGMA journal_mode").fetchone()[0]),
            "quick_check": quick_rows,
            "foreign_key_errors": [list(row) for row in foreign_rows],
            "blob_count": blob_count,
            "blob_hash_mismatches": blob_mismatches,
            "snapshot_errors": snapshot_errors,
        }


__all__ = ["Database", "SCHEMA_VERSION"]
