"""Cohesive snapshot ingestion, completion, and activation transactions."""

from __future__ import annotations

import json
from collections.abc import Callable, Collection, Mapping, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ..parsing.bug_types import classify_bug_type
from ..parsing.listing import (
    validate_listing_membership,
)
from ..project.progress_events import progress_items, report_progress
from ..retrieval.resolutions import (
    resolution_identity,
    resolution_matches,
    resolution_targets,
)
from . import location_store
from .ingestion import UNPARSED, FileInventory
from .records import (
    _HASH_RE,
    _as_mapping,
    _coerce_bytes,
    _dashboard_from_bug_url,
    _field,
    _json_bytes,
    _json_text,
    _normal_title,
    _safe_file_key,
    _text,
    _utc_now,
    _validate_listing_html,
)

if TYPE_CHECKING:
    from .repository import Database


def _start_run(
    database: Database,
    listing_json: bytes,
    listing_html: bytes | None,
    source_url: str,
    listing_error: str | None,
    html_error: str | None,
) -> tuple[int, str, str | None, int]:
    now = _utc_now()
    added = 0
    with database._transaction() as connection:
        listing_digest, was_added = database._put_blob(
            connection, listing_json, "application/json", now
        )
        added += int(was_added)
        html_digest: str | None = None
        if listing_html is not None:
            html_digest, was_added = database._put_blob(connection, listing_html, "text/html", now)
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
        database._put_document(
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
            database._put_document(
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


def _finish_failed(database: Database, run_id: int, summary: dict[str, Any]) -> dict[str, Any]:
    summary["status"] = "failed"
    summary["snapshot_id"] = None
    summary["activated"] = False
    summary.setdefault("known_fixed_bugs", 0)
    summary.setdefault("new_fixed_bugs", 0)
    summary.setdefault("new_fixed_bug_keys", [])
    summary.setdefault("no_longer_listed_bugs", 0)
    summary.setdefault("no_longer_listed_bug_keys", [])
    with database._transaction() as connection:
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


def ingest_snapshot(
    database: Database,
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
    return database._ingest_snapshot(
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
    database: Database,
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
    database.initialize()
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
            candidate = database._catalog_record_from_listing(raw)
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
        and database.connection.execute("SELECT 1 FROM current_bug_subsystems LIMIT 1").fetchone()
    ):
        html_error = "missing HTML listing would discard known subsystem tags"

    run_id, listing_digest, html_digest, initially_added = database._start_run(
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
        return database._finish_failed(run_id, failed_summary)

    supplied = list(records)
    if not supplied and source_records:
        supplied = [
            candidate
            for raw in source_records
            if (candidate := database._catalog_record_from_listing(raw)) is not None
        ]
    prepared, record_errors = database._prepare_records(supplied)
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
        return database._finish_failed(run_id, failed_summary)

    prepared_payloads, payload_errors = database._prepare_bug_payloads(
        prepared, bug_payloads, parsed_payloads, on_progress=database._on_progress
    )
    errors.extend(payload_errors)
    payload_valid = sum(
        1 for _, value, error in prepared_payloads.values() if value is not None and error is None
    )
    payload_invalid = sum(
        1 for _, value, error in prepared_payloads.values() if value is None or error is not None
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
        ordinal, url = database._first_report(bug, dashboard)
        if ordinal is not None:
            expected_reports[record["key"]] = (ordinal, url)
        expected_hashes.update(database._fix_hashes(record, bug))
        expected_hashes.update(database._fix_hashes(listing_by_key[record["key"]], bug))

    targets = resolution_targets(
        listing_candidates,
        {key: value[1] for key, value in prepared_payloads.items() if value[1] is not None},
    )
    resolution_choices = {
        resolution_identity(value): value for value in database.accepted_resolutions(targets)
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

    report_paths, report_read_errors = database._read_artifact_files(reports_dir, ".txt")
    patch_paths, patch_read_errors = database._read_artifact_files(patches_dir, ".diff")
    errors.extend(report_read_errors)
    errors.extend(patch_read_errors)
    try:
        if verify_files is not None:
            verify_files()
        report_files, report_read_errors = database._inspect_artifacts(
            report_paths,
            kind="report",
            inventory=inventory,
            expected_reports=expected_reports,
            payloads=prepared_payloads,
            records=record_by_key,
            unavailable_reports=unavailable_reports,
        )
        patch_files, patch_read_errors = database._inspect_artifacts(
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
        return database._finish_failed(
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
        with database._transaction() as connection:
            active_keys = [
                _text(row["key"])
                for row in connection.execute("SELECT key FROM current_bug_rows ORDER BY position")
            ]
            candidate_keys = [record["key"] for record in prepared]
            active_key_set = set(active_keys)
            candidate_key_set = set(candidate_keys)
            new_fixed_bug_keys = [key for key in candidate_keys if key not in active_key_set]
            no_longer_listed_bug_keys = [key for key in active_keys if key not in candidate_key_set]
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
                digest, was_added = database._put_blob(connection, raw, "application/json", now)
                blob_additions += int(was_added)
                database._put_document(
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
                    database._on_progress,
                    "index-bugs",
                    "Indexing bug details",
                    total=len(prepared),
                )
            ):
                key = record["key"]
                listing_record_digest, was_added = database._put_blob(
                    connection, record["raw_bytes"], "application/json", now
                )
                blob_additions += int(was_added)
                database._put_document(
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
                    document_digest, was_added = database._put_blob(
                        connection, payload_raw, "application/json", now
                    )
                    blob_additions += int(was_added)
                    database._put_document(
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
                    blob_additions += database._insert_bug_children(
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

                blob_additions += database._insert_listing_fixes(
                    connection,
                    snapshot_id,
                    bug_id,
                    listing_by_key[key]["fix_commits"],
                    run_id,
                    now,
                )

                for commit_hash, _ in database._fix_hashes(record, bug_data).items():
                    database._upsert_commit(connection, commit_hash, run_id)

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
                    database._upsert_commit(connection, resolved_hash, run_id)
                raw = _json_bytes(resolution)
                raw_digest, was_added = database._put_blob(connection, raw, "application/json", now)
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
                database._put_document(
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
                    candidate_resolutions.append((resolved_hash, bug_id, title_normalized, repo))

            candidate_reports: list[tuple[str, int | None, str, int]] = []
            for key, inspection in progress_items(
                report_files.items(),
                database._on_progress,
                "index-reports",
                "Indexing reports",
                total=len(report_files),
            ):
                data, path = inspection.read(inventory), inspection.path
                validation_error = inspection.error
                valid = validation_error is None
                digest, was_added = database._put_blob(
                    connection, data, "text/plain", now, digest=inspection.digest
                )
                blob_additions += int(was_added)
                source = (
                    "" if key in unavailable_reports else expected_reports.get(key, (None, ""))[1]
                )
                database._put_document(
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
                database._on_progress,
                "index-patches",
                "Indexing patches",
                total=len(normalized_patch_files),
            ):
                data, path = inspection.read(inventory), inspection.path
                validation_error = inspection.error
                valid = validation_error is None
                digest, was_added = database._put_blob(
                    connection, data, "text/x-diff", now, digest=inspection.digest
                )
                blob_additions += int(was_added)
                source = database._artifact_source(
                    connection,
                    "patch",
                    commit_hash,
                    digest,
                    source_urls.get(path.absolute(), ""),
                    expected_hashes.get(commit_hash, ""),
                )
                database._put_document(
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
                database._upsert_commit(connection, commit_hash, run_id)
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
                database._on_progress, "commit-snapshot", "Saving snapshot result", 0, 1
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
                    database._apply_known_resolutions(
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
        return database._finish_failed(run_id, summary)
    report_progress(database._on_progress, "commit-snapshot", "Snapshot result committed", 1, 1)
    return summary
