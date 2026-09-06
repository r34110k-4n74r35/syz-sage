"""Retained-file inspection, retry reconciliation, and offline ingestion."""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Collection, Mapping, Sequence
from contextlib import suppress
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ..project.progress_events import progress_items
from ..retrieval.resolutions import (
    resolution_identity,
    resolution_matches,
    resolution_targets,
)
from ..retrieval.retry_state import load_sync_state
from . import location_store
from .ingestion import UNPARSED, ArtifactInspection, FileInventory
from .records import (
    _HASH_RE,
    _as_mapping,
    _json_text,
    _safe_file_key,
    _text,
    _utc_now,
    _validate_patch,
    _validate_report,
)
from .schema import DEFAULT_SOURCE_URL, SCHEMA_VERSION

if TYPE_CHECKING:
    from .repository import Database


def _read_artifact_files(
    directory: Path,
    suffix: str,
) -> tuple[dict[str, Path], list[str]]:
    return FileInventory.artifact_paths(directory, suffix)


def _inspect_artifacts(
    database: Database,
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
            for row in database.connection.execute(
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
            for row in database.connection.execute(
                """SELECT DISTINCT pv.commit_hash, pv.blob_sha256 FROM fix_locations l
                   JOIN patch_versions pv ON pv.id=l.patch_version_id
                   WHERE l.parser_version=?""",
                (location_store.PATCH_PARSER_VERSION,),
            )
        }
    plural = "reports" if kind == "report" else "patches"
    for key, path in progress_items(
        paths.items(),
        database._on_progress,
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


def _legacy_layout(cls: type[Database], paths: Any) -> dict[str, Path]:
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


def _pending_file_retries(
    database: Database,
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
        raw_records, _ = database._listing_records(listing)
    except (OSError, ValueError) as exc:
        return set(), [*errors, f"cannot match pending retries to listing: {exc}"]
    records = [
        record
        for value in raw_records
        if (record := database._catalog_record_from_listing(value)) is not None
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
        errors.append(f"sync state: {len(pending_reports)} live crash report refresh(es) pending")
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
            expected_hashes.update(database._fix_hashes(record, detail))
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
                        expected_hashes.update(database._fix_hashes(record, None))
        except (OSError, ValueError, AttributeError):
            pass
        targets = resolution_targets(records, details)
        choices = {
            resolution_identity(value): value for value in database.accepted_resolutions(targets)
        }
        try:
            resolution_payload = inventory.read_json(layout["resolutions"])
            resolutions = resolution_payload.get("resolutions", [])
            if isinstance(resolutions, list):
                for resolution in resolutions:
                    if isinstance(resolution, Mapping) and resolution_matches(resolution, targets):
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


def _legacy_fingerprint(layout: Mapping[str, Path]) -> tuple[str, list[str]]:
    """Hash only retained input files; databases and analysis outputs are excluded."""
    return FileInventory().fingerprint(layout)


def _fingerprint_files(
    database: Database, inventory: FileInventory, layout: Mapping[str, Path]
) -> tuple[str, list[str]]:
    if database._on_progress is None:
        return inventory.fingerprint(layout)
    return inventory.fingerprint(layout, on_progress=database._on_progress)


def check_files_current(
    database: Database,
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
    if int(database.connection.execute("PRAGMA user_version").fetchone()[0]) < SCHEMA_VERSION:
        return None
    database.initialize()
    layout = database._legacy_layout(paths)
    inventory = inventory or FileInventory()
    _, pending_errors = database._pending_file_retries(layout, inventory)
    if pending_errors:
        return None
    fingerprint, errors = database._fingerprint_files(inventory, layout)
    if errors:
        return None
    result = database._unchanged_files_result(fingerprint, source_kind)
    if result is not None:
        try:
            inventory.assert_fingerprint_current(layout, fingerprint)
        except OSError:
            return None
    return result


def _unchanged_files_result(
    database: Database, fingerprint: str, source_kind: str
) -> dict[str, Any] | None:
    with database._read_transaction():
        return _read_unchanged_files_result(database, fingerprint, source_kind)


def _read_unchanged_files_result(
    database: Database, fingerprint: str, source_kind: str
) -> dict[str, Any] | None:
    state_key = f"file_import:{source_kind}"
    prior = database.connection.execute(
        "SELECT value FROM app_state WHERE key = ?", (state_key,)
    ).fetchone()
    if prior is not None:
        try:
            prior_value = json.loads(prior["value"])
        except (TypeError, json.JSONDecodeError):
            prior_value = {}
        current = database.connection.execute(
            "SELECT id, run_id FROM snapshots WHERE is_current = 1"
        ).fetchone()
        latest_run = database.connection.execute(
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
            active_status = database.status()
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
    database: Database,
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
    database.initialize()
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", source_kind):
        raise ValueError("source_kind must contain only letters, digits, '.', '_' or '-'")
    layout = database._legacy_layout(paths)
    inventory = inventory or FileInventory()
    inherited_errors = list(errors)
    unavailable_reports, pending_errors = database._pending_file_retries(layout, inventory)
    inherited_errors.extend(pending_errors)
    fingerprint, fingerprint_errors = database._fingerprint_files(inventory, layout)
    inherited_errors.extend(fingerprint_errors)

    def verify_files() -> None:
        inventory.assert_fingerprint_current(layout, fingerprint)

    state_key = f"file_import:{source_kind}"
    if not inherited_errors:
        unchanged = database._unchanged_files_result(fingerprint, source_kind)
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
            raw_records, _ = database._listing_records(parsed_listing)
            records = [
                candidate
                for raw in raw_records
                if (candidate := database._catalog_record_from_listing(raw)) is not None
            ]
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            records = []

    bug_payloads: dict[str, bytes] = {}
    parsed_payloads: dict[str, Any] = {}
    for value in progress_items(
        records, database._on_progress, "read-bugs", "Reading saved bug details", total=len(records)
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
            if not isinstance(payload, dict) or not isinstance(payload.get("resolutions"), list):
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

    result = database._ingest_snapshot(
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
        with database._transaction() as connection:
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
            result["last_checked_at"] = database._set_last_checked(connection, _utc_now())
    return result


def import_legacy(database: Database, paths: Any) -> dict[str, Any]:
    """Compatibility wrapper for importing an existing repository snapshot."""
    return database.ingest_files(paths, source_kind="legacy")
