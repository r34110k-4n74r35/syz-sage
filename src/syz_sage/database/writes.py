"""Normalized row and artifact writes within caller-owned transactions."""

from __future__ import annotations

import hashlib
import sqlite3
from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING, Any

from .records import _HASH_RE, _absolute_syzbot_url, _json_bytes, _json_text, _normal_title, _text

if TYPE_CHECKING:
    from .repository import Database


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


def _upsert_commit(
    database: Database, connection: sqlite3.Connection, commit_hash: str, run_id: int
) -> None:
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
    database: Database,
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
        raw_digest, was_added = database._put_blob(
            connection, _json_bytes(fix), "application/json", now
        )
        blobs_added += int(was_added)
        reported_hash = _text(fix.get("hash")).lower()
        if not _HASH_RE.fullmatch(reported_hash):
            reported_hash = ""
        if reported_hash:
            database._upsert_commit(connection, reported_hash, run_id)
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
    database: Database,
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
            raw_digest, was_added = database._put_blob(
                connection, _json_bytes(fix), "application/json", now
            )
            blobs_added += int(was_added)
            commit_hash = _text(fix.get("hash")).lower()
            if not _HASH_RE.fullmatch(commit_hash):
                commit_hash = ""
            if commit_hash:
                database._upsert_commit(connection, commit_hash, run_id)
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
        raw_digest, was_added = database._put_blob(
            connection, _json_bytes(cause_value), "application/json", now
        )
        blobs_added += int(was_added)
        commit_hash = _text(cause_value.get("hash")).lower()
        if not _HASH_RE.fullmatch(commit_hash):
            commit_hash = ""
        if commit_hash:
            database._upsert_commit(connection, commit_hash, run_id)
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
            raw_digest, was_added = database._put_blob(
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
    row = connection.execute("SELECT value FROM app_state WHERE key = 'last_checked_at'").fetchone()
    if row is None:
        raise RuntimeError("could not persist last_checked_at")
    return _text(row["value"])
