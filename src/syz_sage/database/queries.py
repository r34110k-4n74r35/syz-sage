"""Read models for bugs, filters, accepted resolutions, and integrity checks."""

from __future__ import annotations

import hashlib
import html
import json
import sqlite3
from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING, Any

from ..parsing.bug_types import BUG_TYPES
from ..project.progress_events import progress_items, report_progress
from ..retrieval.resolutions import (
    ResolutionTargets,
)
from . import location_store, schema_v3, schema_v4
from .records import _c_reproducer_fields, _dashboard_from_bug_url, _patch_urls, _text
from .schema import SCHEMA_VERSION

if TYPE_CHECKING:
    from .repository import Database


def accepted_resolutions(database: Database, targets: ResolutionTargets) -> list[dict[str, Any]]:
    """Read accepted hashes applicable to current title-only fix references.

    This uses the stable v1 tables so an updater can inspect an older
    database read-only before its eventual indexing/migration phase.
    """
    if not targets:
        return []
    database._validate_v1_schema(database.connection)
    resolutions: list[dict[str, Any]] = []
    for row in database.connection.execute(
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
                "commit_url": _text(details.get("commit_url")) if isinstance(details, dict) else "",
            }
        )
    return resolutions


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
        item for _, item in sorted(zip(positions, merged, strict=True), key=lambda pair: pair[0])
    ]


def _effective_fixes(
    database: Database,
    *,
    bug_id: int,
    version_id: int,
    snapshot_id: int | None,
) -> list[dict[str, Any]]:
    rows: list[sqlite3.Row] = []
    if snapshot_id is not None:
        rows.extend(
            database.connection.execute(
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
        database.connection.execute(
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
    return database._merge_fix_rows([dict(row) for row in rows])


def _current_effective_fixes(database: Database) -> dict[int, list[dict[str, Any]]]:
    grouped: dict[int, list[dict[str, Any]]] = {}
    listing_rows = database.connection.execute(
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
    detail_rows = database.connection.execute(
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
    return {bug_id: database._merge_fix_rows(group) for bug_id, group in grouped.items()}


def status(database: Database) -> dict[str, Any]:
    """Return JSON-serializable coverage and snapshot statistics."""
    database.initialize()
    with database._read_transaction():
        return _status(database)


def _status(database: Database) -> dict[str, Any]:
    connection = database.connection
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
        table_counts[table] = int(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
    current_bugs = int(connection.execute("SELECT COUNT(*) FROM current_bug_rows").fetchone()[0])
    effective_fixes = database._current_effective_fixes()
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
        "database": database._path_text,
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
    database: Database,
    query: str | None = None,
    limit: int = 20,
    offset: int = 0,
) -> list[dict[str, Any]]:
    """List bugs in the active snapshot, newest listing order first."""
    result: list[dict[str, Any]] = database.filter_bugs(query=query, limit=limit, offset=offset)[
        "bugs"
    ]
    return result


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
    database: Database,
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
    types = database._filter_terms(bug_types, "bug type")
    tags = database._filter_terms(subsystems, "subsystem")
    unknown = [value for value in types if value not in BUG_TYPES]
    if unknown:
        raise ValueError("unknown bug type: " + ", ".join(unknown))
    if (limit is not None and (type(limit) is not int or limit < 0)) or (
        type(offset) is not int or offset < 0
    ):
        raise ValueError("limit and offset must be non-negative integers")
    database.initialize()
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
            "(c.key COLLATE NOCASE LIKE ? ESCAPE '\\' OR c.title COLLATE NOCASE LIKE ? ESCAPE '\\')"
        )
        escaped = query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        parameters.extend((f"%{escaped}%", f"%{escaped}%"))
    where = "WHERE " + " AND ".join(conditions) if conditions else ""
    with database._read_transaction():
        total = int(
            database.connection.execute(
                f"SELECT COUNT(*) FROM current_bug_rows AS c {where}", parameters
            ).fetchone()[0]
        )
        return {
            "bugs": database._list_filtered_rows(where, parameters, limit, offset),
            "total": total,
            "limit": limit,
            "offset": offset,
            "bug_types": types,
            "subsystems": tags,
        }


def filter_values(database: Database) -> dict[str, list[dict[str, Any]]]:
    """Count distinct active bugs for each stored type and exact subsystem tag."""
    database.initialize()
    with database._read_transaction():
        types = [
            {"value": row["bug_type"], "count": int(row["amount"])}
            for row in database.connection.execute(
                "SELECT bug_type, COUNT(*) AS amount FROM current_bug_rows "
                "GROUP BY bug_type ORDER BY bug_type"
            )
        ]
        tags = [
            {"value": row["tag"], "count": int(row["amount"])}
            for row in database.connection.execute(
                "SELECT LOWER(tag) AS tag, COUNT(DISTINCT bug_id) AS amount "
                "FROM current_bug_subsystems GROUP BY tag COLLATE NOCASE "
                "ORDER BY tag COLLATE NOCASE"
            )
        ]
        return {"bug_types": types, "subsystems": tags}


def _list_filtered_rows(
    database: Database,
    where: str,
    parameters: Sequence[Any],
    limit: int | None,
    offset: int,
) -> list[dict[str, Any]]:
    parameters = [*parameters, -1 if limit is None else limit, offset]
    rows = database.connection.execute(
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
        fixes = database._effective_fixes(
            bug_id=bug_id,
            version_id=version_id,
            snapshot_id=snapshot_id,
        )
        item["fix_count"] = len(fixes)
        item["patch_urls"] = _patch_urls(fixes)
        item.update(
            _c_reproducer_fields(
                database._load_json_blob(item.pop("raw_sha256")),
                item.pop("payload_kind"),
                _dashboard_from_bug_url(item["bug_url"]),
            )
        )
        item["has_report"] = bool(item["has_report"])
        item["subsystems"] = [
            tag[0]
            for tag in database.connection.execute(
                "SELECT tag FROM current_bug_subsystems WHERE bug_id = ? ORDER BY tag",
                (bug_id,),
            )
        ]
        result.append(item)
    return result


def _load_json_blob(database: Database, digest: str) -> Any:
    row = database.connection.execute(
        "SELECT content FROM blobs WHERE sha256 = ?", (digest,)
    ).fetchone()
    if row is not None:
        try:
            return json.loads(bytes(row[0]).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            pass
    return None


def get_bug(database: Database, key: str) -> dict[str, Any] | None:
    """Return normalized details (and parsed raw JSON) for one bug."""
    database.initialize()
    with database._read_transaction():
        return database._get_bug(key)


def _get_bug(database: Database, key: str) -> dict[str, Any] | None:
    bug_row = database.connection.execute(
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
    version_row = database.connection.execute(
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
    fixes = database._effective_fixes(
        bug_id=bug_id,
        version_id=version_id,
        snapshot_id=snapshot_id,
    )
    crashes = [
        dict(item)
        for item in database.connection.execute(
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
        for item in database.connection.execute(
            "SELECT url FROM discussions WHERE bug_version_id = ? ORDER BY ordinal",
            (version_id,),
        )
    ]
    cause_row = database.connection.execute(
        """
        SELECT title, repo, branch, link, commit_hash, commit_date
        FROM cause_commits WHERE bug_version_id = ?
        """,
        (version_id,),
    ).fetchone()
    report_row = database.connection.execute(
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
        decoded = bytes(content).decode("utf-8", errors="replace") if content is not None else None
        report = {
            "source_url": report_row["source_url"],
            "sha256": report_row["current_blob_sha256"],
            "available": content is not None,
            "size": len(content) if content is not None else 0,
            "text": decoded,
        }
    raw = database._load_json_blob(version_row["raw_sha256"])
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
        **location_store.bug_locations(database.connection, bug_id),
    }


def health_check(database: Database) -> dict[str, Any]:
    """Check SQLite integrity, foreign keys, snapshots, and blob hashes."""
    database.initialize()
    with database._read_transaction():
        return _health_check(database)


def _health_check(database: Database) -> dict[str, Any]:
    connection = database.connection
    report_progress(database._on_progress, "check-sqlite", "Checking SQLite integrity", 0, 2)
    quick_rows = [row[0] for row in connection.execute("PRAGMA quick_check")]
    report_progress(database._on_progress, "check-sqlite", "Checking foreign keys", 1, 2)
    foreign_rows = [tuple(row) for row in connection.execute("PRAGMA foreign_key_check")]
    report_progress(database._on_progress, "check-sqlite", "SQLite checks processed", 2, 2)
    blob_mismatches: list[dict[str, Any]] = []
    blob_count = 0
    for row in progress_items(
        connection.execute("SELECT sha256, size_bytes, content FROM blobs"),
        database._on_progress,
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
    report_progress(database._on_progress, "check-snapshots", "Checking snapshot consistency", 0, 3)
    snapshot_errors.extend(schema_v3.consistency_errors(connection))
    report_progress(database._on_progress, "check-snapshots", "Checking bug classifications", 1, 3)
    snapshot_errors.extend(schema_v4.consistency_errors(connection))
    report_progress(database._on_progress, "check-snapshots", "Checking active membership", 2, 3)
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
    report_progress(database._on_progress, "check-snapshots", "Snapshot checks processed", 3, 3)
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
