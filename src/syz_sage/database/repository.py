"""Public database facade: connection ownership and explicit implementation delegation.

The database package separates SQL, source normalization, read models, retained-file
inspection, and transactional ingestion while this module preserves the API.
"""

from __future__ import annotations

import os
import sqlite3
from collections.abc import Callable, Collection, Iterator, Mapping, Sequence
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from ..project.progress_events import ProgressCallback, report_progress
from ..project.storage import writable_path
from ..retrieval.resolutions import (
    ResolutionTargets,
)
from . import (
    files,
    location_store,
    queries,
    schema,
    schema_v3,
    schema_v4,
    schema_v5,
    snapshot,
    writes,
)
from . import records as record_helpers
from .ingestion import UNPARSED, ArtifactInspection, FileInventory
from .records import _c_reproducer_fields as _c_reproducer_fields
from .schema import _SCHEMA_V1 as _SCHEMA_V1
from .schema import SCHEMA_VERSION as SCHEMA_VERSION


class Database:
    """A migration-aware SQLite repository with a stable public API."""

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
        return schema._validate_v1_schema(connection)

    @staticmethod
    def _put_blob(
        connection: sqlite3.Connection,
        data: bytes,
        media_type: str,
        now: str,
        *,
        digest: str | None = None,
    ) -> tuple[str, bool]:
        return writes._put_blob(connection, data, media_type, now, digest=digest)

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
        return writes._put_document(
            connection,
            kind=kind,
            natural_key=natural_key,
            source_url=source_url,
            blob_sha256=blob_sha256,
            valid=valid,
            error=error,
            run_id=run_id,
        )

    def _start_run(
        self,
        listing_json: bytes,
        listing_html: bytes | None,
        source_url: str,
        listing_error: str | None,
        html_error: str | None,
    ) -> tuple[int, str, str | None, int]:
        return snapshot._start_run(
            self, listing_json, listing_html, source_url, listing_error, html_error
        )

    def _finish_failed(self, run_id: int, summary: dict[str, Any]) -> dict[str, Any]:
        return snapshot._finish_failed(self, run_id, summary)

    @staticmethod
    def _listing_records(payload: Any) -> tuple[list[Any], int | None]:
        return record_helpers._listing_records(payload)

    @staticmethod
    def _catalog_record_from_listing(value: Any) -> dict[str, Any] | None:
        return record_helpers._catalog_record_from_listing(value)

    @staticmethod
    def _prepare_records(records: Sequence[Any]) -> tuple[list[dict[str, Any]], list[str]]:
        return record_helpers._prepare_records(records)

    @staticmethod
    def _prepare_bug_payloads(
        records: Sequence[dict[str, Any]],
        bug_payloads: Mapping[str, bytes],
        parsed_payloads: Mapping[str, Any] | None = None,
        *,
        on_progress: ProgressCallback | None = None,
    ) -> tuple[dict[str, tuple[bytes, dict[str, Any] | None, str | None]], list[str]]:
        return record_helpers._prepare_bug_payloads(
            records, bug_payloads, parsed_payloads, on_progress=on_progress
        )

    @staticmethod
    def _fix_hashes(record: Mapping[str, Any], bug: Mapping[str, Any] | None) -> dict[str, str]:
        return record_helpers._fix_hashes(record, bug)

    @staticmethod
    def _first_report(bug: Mapping[str, Any] | None, dashboard: str) -> tuple[int | None, str]:
        return record_helpers._first_report(bug, dashboard)

    @staticmethod
    def _read_artifact_files(
        directory: Path,
        suffix: str,
    ) -> tuple[dict[str, Path], list[str]]:
        return files._read_artifact_files(directory, suffix)

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
        return files._inspect_artifacts(
            self,
            paths,
            kind=kind,
            inventory=inventory,
            expected_reports=expected_reports,
            payloads=payloads,
            records=records,
            unavailable_reports=unavailable_reports,
        )

    @staticmethod
    def _artifact_source(
        connection: sqlite3.Connection,
        kind: str,
        key: str,
        digest: str,
        supplied: str,
        fallback: str,
    ) -> str:
        return writes._artifact_source(connection, kind, key, digest, supplied, fallback)

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
        return snapshot.ingest_snapshot(
            self,
            listing_json,
            listing_html,
            records,
            bug_payloads,
            reports_dir,
            patches_dir,
            source_url,
            errors=errors,
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
        return snapshot._ingest_snapshot(
            self,
            listing_json=listing_json,
            listing_html=listing_html,
            records=records,
            bug_payloads=bug_payloads,
            reports_dir=reports_dir,
            patches_dir=patches_dir,
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

    def _upsert_commit(self, connection: sqlite3.Connection, commit_hash: str, run_id: int) -> None:
        return writes._upsert_commit(self, connection, commit_hash, run_id)

    @staticmethod
    def _apply_known_resolutions(
        connection: sqlite3.Connection,
        bug_id: int,
        version_id: int,
        *,
        accepted_run_id: int | None = None,
    ) -> None:
        """Enrich a normalized bug version with accepted exact-title resolutions."""
        return writes._apply_known_resolutions(
            connection, bug_id, version_id, accepted_run_id=accepted_run_id
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
        return writes._insert_listing_fixes(
            self, connection, snapshot_id, bug_id, fixes, run_id, now
        )

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
        return writes._insert_bug_children(
            self, connection, version_id, bug, run_id, now, dashboard
        )

    @staticmethod
    def _path_member(paths: Any, names: Sequence[str]) -> Path | None:
        # pathlib.Path has attributes named ``root`` and ``raw`` which are not
        # members of our DataPaths protocol.  Treat path-like inputs solely as
        # a root directory instead of accidentally resolving them to ``/``.
        return files._path_member(paths, names)

    @classmethod
    def _legacy_layout(cls, paths: Any) -> dict[str, Path]:
        return files._legacy_layout(cls, paths)

    def accepted_resolutions(self, targets: ResolutionTargets) -> list[dict[str, Any]]:
        """Read accepted hashes applicable to current title-only fix references.

        This uses the stable v1 tables so an updater can inspect an older
        database read-only before its eventual indexing/migration phase.
        """
        return queries.accepted_resolutions(self, targets)

    def _pending_file_retries(
        self,
        layout: Mapping[str, Path],
        inventory: FileInventory | None = None,
    ) -> tuple[set[str], list[str]]:
        """Block incomplete live work without letting retained history block updates."""
        return files._pending_file_retries(self, layout, inventory)

    @staticmethod
    def _legacy_fingerprint(layout: Mapping[str, Path]) -> tuple[str, list[str]]:
        """Hash only retained input files; databases and analysis outputs are excluded."""
        return files._legacy_fingerprint(layout)

    def _fingerprint_files(
        self, inventory: FileInventory, layout: Mapping[str, Path]
    ) -> tuple[str, list[str]]:
        return files._fingerprint_files(self, inventory, layout)

    @staticmethod
    def _set_last_checked(connection: sqlite3.Connection, checked_at: str) -> str:
        return writes._set_last_checked(connection, checked_at)

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
        return files.check_files_current(self, paths, source_kind=source_kind, inventory=inventory)

    def _unchanged_files_result(self, fingerprint: str, source_kind: str) -> dict[str, Any] | None:
        return files._unchanged_files_result(self, fingerprint, source_kind)

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
        return files.ingest_files(
            self,
            paths,
            errors=errors,
            source_kind=source_kind,
            inventory=inventory,
            source_urls=source_urls,
        )

    def import_legacy(self, paths: Any) -> dict[str, Any]:
        """Compatibility wrapper for importing an existing repository snapshot."""
        return files.import_legacy(self, paths)

    @staticmethod
    def _merge_fix_rows(rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
        """Merge duplicate references without treating a subject as a commit ID.

        Known hashes are grouped first. A title-only reference can enrich one
        unambiguous commit, but remains unresolved when multiple commits share
        the subject and repository (for example, backports).
        """
        return queries._merge_fix_rows(rows)

    def _effective_fixes(
        self,
        *,
        bug_id: int,
        version_id: int,
        snapshot_id: int | None,
    ) -> list[dict[str, Any]]:
        return queries._effective_fixes(
            self, bug_id=bug_id, version_id=version_id, snapshot_id=snapshot_id
        )

    def _current_effective_fixes(self) -> dict[int, list[dict[str, Any]]]:
        return queries._current_effective_fixes(self)

    def status(self) -> dict[str, Any]:
        """Return JSON-serializable coverage and snapshot statistics."""
        return queries.status(self)

    def list_bugs(
        self,
        query: str | None = None,
        limit: int = 20,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """List bugs in the active snapshot, newest listing order first."""
        return queries.list_bugs(self, query, limit, offset)

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
        return queries._filter_terms(values, label)

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
        return queries.filter_bugs(
            self,
            bug_types=bug_types,
            subsystems=subsystems,
            query=query,
            limit=limit,
            offset=offset,
        )

    def filter_values(self) -> dict[str, list[dict[str, Any]]]:
        """Count distinct active bugs for each stored type and exact subsystem tag."""
        return queries.filter_values(self)

    def _list_filtered_rows(
        self,
        where: str,
        parameters: Sequence[Any],
        limit: int | None,
        offset: int,
    ) -> list[dict[str, Any]]:
        return queries._list_filtered_rows(self, where, parameters, limit, offset)

    def _load_json_blob(self, digest: str) -> Any:
        return queries._load_json_blob(self, digest)

    def get_bug(self, key: str) -> dict[str, Any] | None:
        """Return normalized details (and parsed raw JSON) for one bug."""
        return queries.get_bug(self, key)

    def _get_bug(self, key: str) -> dict[str, Any] | None:
        return queries._get_bug(self, key)

    def health_check(self) -> dict[str, Any]:
        """Check SQLite integrity, foreign keys, snapshots, and blob hashes."""
        return queries.health_check(self)


__all__ = ["Database", "SCHEMA_VERSION"]
