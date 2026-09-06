"""Incremental, filesystem-safe Syzbot update orchestration."""

from __future__ import annotations

import contextlib
import importlib
import json
import os
import time
from collections.abc import Callable, Iterator, Mapping, Sequence
from concurrent.futures import CancelledError
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .artifacts import (
    ArtifactResult,
    DownloadJob,
    DownloadReason,
    atomic_write,
    bounded_results,
    fetch_artifact,
    validate_artifact,
)
from .client import FetchError, SyzbotClient
from .config import DataPaths
from .database import Database
from .ingestion import FileInventory
from .parsing import (
    HASH_RE,
    KEY_RE,
    MAX_BUG_KEY_LENGTH,
    PayloadError,
    decode_json_object,
    effective_fixes,
    first_report_url,
    parse_listing,
    parse_subsystem_tags,
    valid_listing_html,
    validate_listing_membership,
)
from .resolutions import (
    ResolutionTargets,
    resolution_identity,
    resolution_matches,
    resolution_targets,
)
from .retry_state import SyncState as _SyncState
from .retry_state import load_sync_state as _load_sync_state
from .retry_state import save_sync_state as _write_sync_state
from .storage import writable_path


@dataclass(frozen=True, slots=True)
class UpdateOptions:
    namespace: str = "upstream"
    status: str = "fixed"
    workers: int = 8
    refresh_details: bool = False
    refresh_artifacts: bool = False
    reports: bool = True
    patches: bool = True
    limit: int | None = None


@dataclass(slots=True)
class UpdateSummary:
    namespace: str
    status: str
    listing_bugs: int = 0
    known_fixed_bugs: int = 0
    new_fixed_bugs: int = 0
    new_fixed_bug_keys: list[str] = field(default_factory=list)
    changed_bugs: int = 0
    changed_bug_keys: list[str] = field(default_factory=list)
    no_longer_listed_bugs: int = 0
    no_longer_listed_bug_keys: list[str] = field(default_factory=list)
    details_downloaded: int = 0
    details_reused: int = 0
    reports_downloaded: int = 0
    reports_reused: int = 0
    reports_unavailable: int = 0
    patches_downloaded: int = 0
    patches_reused: int = 0
    failures: list[dict[str, str]] = field(default_factory=list)
    database: dict[str, Any] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        if self.failures or not self.database:
            return False
        return (
            self.database.get("status") in {"completed", "unchanged"}
            and not self.database.get("failure_count")
            and not self.database.get("failures")
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "namespace": self.namespace,
            "status": self.status,
            "listing_bugs": self.listing_bugs,
            "known_fixed_bugs": self.known_fixed_bugs,
            "new_fixed_bugs": self.new_fixed_bugs,
            "new_fixed_bug_keys": self.new_fixed_bug_keys,
            "changed_bugs": self.changed_bugs,
            "changed_bug_keys": self.changed_bug_keys,
            "no_longer_listed_bugs": self.no_longer_listed_bugs,
            "no_longer_listed_bug_keys": self.no_longer_listed_bug_keys,
            "details_downloaded": self.details_downloaded,
            "details_reused": self.details_reused,
            "reports_downloaded": self.reports_downloaded,
            "reports_reused": self.reports_reused,
            "reports_unavailable": self.reports_unavailable,
            "patches_downloaded": self.patches_downloaded,
            "patches_reused": self.patches_reused,
            "failures": self.failures,
            "database": self.database,
        }


@contextlib.contextmanager
def _exclusive_update_lock(root: Path, *, create: bool = True) -> Iterator[None]:
    """Fail fast on a shared data-root lock, optionally opening an input lock read-only."""

    root = writable_path(root)
    lock_path = writable_path(root / ".syz_sage.update.lock")
    if create:
        root.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+b" if create else "rb") as handle:
        if os.name == "nt":
            locking = importlib.import_module("msvcrt")
            if create:
                handle.seek(0, os.SEEK_END)
                if handle.tell() == 0:
                    handle.write(b"\0")
                    handle.flush()
            # Windows permits locking a byte range beyond EOF. An existing
            # empty input lock therefore needs no initialization write.
            handle.seek(0)
            try:
                locking.locking(handle.fileno(), locking.LK_NBLCK, 1)
            except OSError as exc:
                raise RuntimeError(f"another update owns data root {root}") from exc
            try:
                yield
            finally:
                handle.seek(0)
                locking.locking(handle.fileno(), locking.LK_UNLCK, 1)
        else:
            locking = importlib.import_module("fcntl")
            try:
                locking.flock(handle.fileno(), locking.LOCK_EX | locking.LOCK_NB)
            except OSError as exc:
                raise RuntimeError(f"another update owns data root {root}") from exc
            try:
                yield
            finally:
                locking.flock(handle.fileno(), locking.LOCK_UN)


def _read_valid(
    path: Path, validator: Callable[[bytes], bool], inventory: FileInventory | None = None
) -> bytes | None:
    try:
        payload = inventory.read_bytes(path) if inventory is not None else path.read_bytes()
    except OSError:
        return None
    return payload if validator(payload) else None


def _read_prior_listing(
    path: Path, dashboard: str, inventory: FileInventory
) -> list[dict[str, Any]]:
    """Return a safe incremental baseline, or no records when it is unusable."""

    try:
        return parse_listing(inventory.read_bytes(path), dashboard=dashboard)
    except (OSError, PayloadError):
        return []


def _listing_discrepancies(
    records: list[dict[str, Any]],
    prior_records: list[dict[str, Any]],
) -> tuple[list[str], list[str]]:
    """Return mirror-new keys and metadata-changed existing keys in listing order."""

    prior_by_key = {str(record["key"]): record for record in prior_records}
    mirror_new_keys: list[str] = []
    changed_keys: list[str] = []
    for record in records:
        key = str(record["key"])
        if key not in prior_by_key:
            mirror_new_keys.append(key)
        elif record.get("raw") != prior_by_key[key].get("raw"):
            changed_keys.append(key)
    return mirror_new_keys, changed_keys


def _add_patch_job(
    jobs: dict[str, str | None],
    commit_hash: str,
    repo: str | None,
) -> None:
    """Keep the first useful repository when several sources name one hash."""

    if commit_hash not in jobs or (not jobs[commit_hash] and repo):
        jobs[commit_hash] = repo


def _resolution_patch_jobs(
    path: Path,
    targets: ResolutionTargets,
    selected_keys: set[str],
    inventory: FileInventory | None = None,
    accepted: Sequence[Mapping[str, Any]] = (),
) -> tuple[list[tuple[str, str | None]], list[dict[str, str]]]:
    """Read current resolved hashes without treating retained history as live."""

    jobs = {
        resolution_identity(value): (
            str(value["hash"]).lower(),
            str(value.get("repo") or "") or None,
        )
        for value in accepted
        if str(value["bug_key"]) in selected_keys
    }

    try:
        document = decode_json_object(
            inventory.read_bytes(path) if inventory is not None else path.read_bytes()
        )
    except FileNotFoundError:
        return list(jobs.values()), []
    except (OSError, PayloadError) as exc:
        return list(jobs.values()), [{"kind": "resolution-metadata", "key": "", "error": str(exc)}]

    values = document.get("resolutions")
    if not isinstance(values, list):
        return list(jobs.values()), [
            {
                "kind": "resolution-metadata",
                "key": "",
                "error": "resolution file must contain a resolutions list",
            }
        ]

    failures: list[dict[str, str]] = []
    for index, value in enumerate(values):
        if not isinstance(value, Mapping):
            failures.append(
                {
                    "kind": "resolution-metadata",
                    "key": "",
                    "error": f"resolution[{index}] is not an object",
                }
            )
            continue
        key_value = value["bug_key"] if "bug_key" in value else value.get("key")
        key = key_value if isinstance(key_value, str) else ""
        if len(key) > MAX_BUG_KEY_LENGTH or KEY_RE.fullmatch(key) is None:
            failures.append(
                {
                    "kind": "resolution-metadata",
                    "key": key,
                    "error": f"resolution[{index}] has a missing or unsafe bug key",
                }
            )
            continue
        if not resolution_matches(value, targets):
            continue

        hash_value = value.get("hash")
        if hash_value is None or hash_value == "":
            continue
        if not isinstance(hash_value, str) or HASH_RE.fullmatch(hash_value) is None:
            failures.append(
                {
                    "kind": "resolution-metadata",
                    "key": key,
                    "error": f"resolution[{index}] has an invalid commit hash",
                }
            )
            continue
        repo_value = value.get("repo")
        if repo_value is not None and not isinstance(repo_value, str):
            failures.append(
                {
                    "kind": "resolution-metadata",
                    "key": key,
                    "error": f"resolution[{index}] has a non-string repository",
                }
            )
            continue
        if key in selected_keys:
            jobs[resolution_identity(value)] = (hash_value.lower(), repo_value or None)
    return list(jobs.values()), failures


def _catalog_fields(records: list[dict[str, Any]], source_url: str) -> dict[str, Any]:
    return {
        "source": source_url,
        "source_version": records[0].get("source_version") if records else None,
        "bugs": [
            {
                "key": record["key"],
                "title": record.get("title", ""),
                "bug_url": record.get("bug_url", ""),
                "json_url": record.get("json_url", ""),
                "fix_commits": record.get("fix_commits", []),
                "primary_fix_hash": record.get("primary_fix_hash", ""),
            }
            for record in records
        ],
    }


def write_catalog(
    paths: DataPaths,
    records: list[dict[str, Any]],
    source_url: str,
    inventory: FileInventory | None = None,
) -> bool:
    """Write changed semantic content while preserving a stable generation time."""

    fields = _catalog_fields(records, source_url)
    try:
        current = decode_json_object(
            inventory.read_bytes(paths.catalog)
            if inventory is not None
            else paths.catalog.read_bytes()
        )
    except (OSError, PayloadError):
        current = {}
    if isinstance(current.get("generated_at"), str) and all(
        current.get(name) == value for name, value in fields.items()
    ):
        return False

    payload = {"generated_at": datetime.now(timezone.utc).isoformat(), **fields}
    encoded = (json.dumps(payload, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    atomic_write(paths.catalog, encoded)
    if inventory is not None:
        inventory.verify_saved(paths.catalog, encoded, parsed=payload)
    return True


@dataclass(frozen=True, slots=True)
class UpdatePlan:
    """Validated listing membership and the scope selected for this attempt."""

    records: list[dict[str, Any]]
    selected: list[dict[str, Any]]

    @property
    def live_keys(self) -> set[str]:
        return {str(record["key"]) for record in self.records}


class Updater:
    """Refresh local mirror files, then transactionally index them in SQLite."""

    def __init__(
        self,
        paths: DataPaths,
        database_path: Path,
        client: SyzbotClient | None = None,
        progress: Callable[[str], None] | None = None,
    ) -> None:
        self.paths = paths
        self.database_path = database_path
        self.client = client or SyzbotClient()
        self.progress = progress or (lambda message: None)

    def _phase_progress(self, label: str, total: int) -> Callable[[], None]:
        """Report long batches without printing one line for every download."""
        completed = 0
        last_message = time.monotonic()

        def advance() -> None:
            nonlocal completed, last_message
            completed += 1
            now = time.monotonic()
            if now - last_message >= 5 or (completed == total and total >= 20):
                self.progress(f"{label}: processed {completed:,}/{total:,} downloads.")
                last_message = now

        return advance

    def run(self, options: UpdateOptions | None = None) -> UpdateSummary:
        options = options or UpdateOptions()
        if options.workers < 1:
            raise ValueError("workers must be at least one")
        if options.limit is not None and options.limit < 1:
            raise ValueError("limit must be at least one")
        self.database_path = writable_path(self.database_path)
        self.progress(f"Data directory: {self.paths.root}")
        self.paths.ensure()
        with _exclusive_update_lock(self.paths.root):
            return self._run_locked(options)

    def _run_locked(self, options: UpdateOptions) -> UpdateSummary:
        summary = UpdateSummary(namespace=options.namespace, status=options.status)
        sync_state, sync_state_error = _load_sync_state(self.paths.sync_state)
        if sync_state_error is not None:
            raise PayloadError(
                f"Cannot read sync state {self.paths.sync_state}: {sync_state_error}. "
                "Restore or repair this file before updating; saved retry state was preserved."
            )
        reset = getattr(self.client, "reset_cancellation", None)
        if callable(reset):
            reset()
        inventory = FileInventory()
        source_urls: dict[Path, str] = {}
        plan = self._discover_listing(options, summary, sync_state, inventory)
        details, refreshed = self._fetch_details(
            plan, options, summary, sync_state, inventory, source_urls
        )
        if options.reports:
            self._fetch_reports(
                plan.selected,
                details,
                options,
                summary,
                sync_state=sync_state,
                force_keys=refreshed,
                inventory=inventory,
                source_urls=source_urls,
            )
        if options.patches:
            self._fetch_patches(
                plan.selected,
                details,
                options,
                summary,
                live_keys=plan.live_keys,
                sync_state=sync_state,
                inventory=inventory,
                source_urls=source_urls,
            )
        self._index_candidate(summary, inventory, source_urls)
        return summary

    def _discover_listing(
        self,
        options: UpdateOptions,
        summary: UpdateSummary,
        sync_state: _SyncState,
        inventory: FileInventory,
    ) -> UpdatePlan:
        prior_records = _read_prior_listing(
            self.paths.listing_json,
            self.client.dashboard,
            inventory,
        )

        self.progress(f"Checking {self.client.dashboard}/{options.namespace}/{options.status} ...")
        listing_bytes = self.client.listing_json(options.namespace, options.status)
        records = parse_listing(listing_bytes, dashboard=self.client.dashboard)
        if not records:
            raise PayloadError("live listing contains no bug records")
        summary.listing_bugs = len(records)
        live_keys = {str(record["key"]) for record in records}
        mirror_new_keys, summary.changed_bug_keys = _listing_discrepancies(
            records,
            prior_records,
        )
        summary.changed_bugs = len(summary.changed_bug_keys)
        no_longer_listed = {str(record["key"]) for record in prior_records} - {
            str(record["key"]) for record in records
        }
        self.progress(
            f"Fixed listing: {len(records):,} bugs; {len(mirror_new_keys):,} new, "
            f"{summary.changed_bugs:,} changed, {len(no_longer_listed):,} no longer listed "
            "since the last retained listing."
        )
        # Listing membership is not a download queue: even re-added bugs may
        # already have complete retained files from an earlier fixed listing.
        _write_sync_state(self.paths.sync_state, sync_state)
        source_url = f"{self.client.dashboard}/{options.namespace}/{options.status}?json=1"
        prior_html = _read_valid(self.paths.listing_html, valid_listing_html, inventory)
        try:
            listing_html = self.client.listing_html(options.namespace, options.status)
            if not valid_listing_html(listing_html):
                raise PayloadError("response is not a recognizable HTML listing")
            if not validate_listing_membership(listing_html, tuple(live_keys)):
                raise PayloadError("HTML listing bug keys do not match the JSON listing")
        except (FetchError, PayloadError) as exc:
            listing_html = prior_html or b""
            summary.failures.append({"kind": "listing-html", "key": "", "error": str(exc)})
        else:
            prior_keys = {str(record["key"]) for record in prior_records}
            if prior_html and validate_listing_membership(prior_html, tuple(prior_keys)):
                tags = parse_subsystem_tags(listing_html.decode("utf-8", errors="replace"))
                prior_tags = parse_subsystem_tags(prior_html.decode("utf-8", errors="replace"))
                tag_changes = {
                    key
                    for key in live_keys & prior_keys
                    if tags.get(key, []) != prior_tags.get(key, [])
                }
                if tag_changes:
                    changed_keys = set(summary.changed_bug_keys) | tag_changes
                    summary.changed_bug_keys = [
                        str(record["key"]) for record in records if record["key"] in changed_keys
                    ]
                    summary.changed_bugs = len(summary.changed_bug_keys)
                    self.progress(f"Subsystem tags changed for {len(tag_changes):,} bugs.")
                elif records == prior_records:
                    # Navigation counts and relative display dates can change
                    # without any fixed-bug information changing. Keep the
                    # retained source when the data we index is identical.
                    listing_html = prior_html

        # Only validated JSON reaches the rolling cache.
        atomic_write(self.paths.listing_json, listing_bytes)
        inventory.verify_saved(self.paths.listing_json, listing_bytes)
        if listing_html:
            atomic_write(self.paths.listing_html, listing_html)
            inventory.verify_saved(self.paths.listing_html, listing_html)
        write_catalog(self.paths, records, source_url, inventory)

        selected = records[: options.limit] if options.limit is not None else records
        if len(selected) != len(records):
            summary.failures.append(
                {
                    "kind": "selection",
                    "key": "",
                    "error": (
                        f"retrieval limited to {len(selected)} of {len(records)} bugs; "
                        "candidate snapshot is incomplete"
                    ),
                }
            )
        if not options.reports:
            summary.failures.append(
                {
                    "kind": "reports-skipped",
                    "key": "",
                    "error": "report retrieval was disabled; candidate snapshot is incomplete",
                }
            )
        if not options.patches:
            summary.failures.append(
                {
                    "kind": "patches-skipped",
                    "key": "",
                    "error": "patch retrieval was disabled; candidate snapshot is incomplete",
                }
            )
        return UpdatePlan(records, selected)

    @staticmethod
    def _inspect(
        job: DownloadJob,
        inventory: FileInventory,
    ) -> tuple[ArtifactResult | None, DownloadReason]:
        try:
            payload, _, digest = inventory.read_observation(job.path)
        except OSError:
            return None, "missing"
        try:
            result = validate_artifact(job, payload, digest=digest)
        except PayloadError:
            return None, "invalid"
        if result.detail is not None:
            inventory.remember_json(job.path, result.detail, digest=result.digest)
        return result, "missing"  # Reason is used only when inspection failed.

    def _download(
        self,
        jobs: list[DownloadJob],
        options: UpdateOptions,
        summary: UpdateSummary,
        sync_state: _SyncState,
        inventory: FileInventory,
        source_urls: dict[Path, str],
        *,
        label: str,
        pending: set[str],
        accept: Callable[[ArtifactResult], None],
        failed: Callable[[DownloadJob], None] | None = None,
    ) -> None:
        """Save validated completions and durably advance the existing retry queue."""
        pending.update(job.key for job in jobs)
        _write_sync_state(self.paths.sync_state, sync_state)
        advance = self._phase_progress(label, len(jobs))
        completed = 0
        last_saved = time.monotonic()

        def cancel() -> None:
            stop = getattr(self.client, "cancel", None)
            if callable(stop):
                stop()
            # Persist accepted results before waiting for any in-flight socket
            # operation to finish during generator/executor shutdown.
            _write_sync_state(self.paths.sync_state, sync_state)

        results = bounded_results(
            jobs,
            lambda job: fetch_artifact(self.client, job),
            workers=options.workers,
            cancel=cancel,
        )
        try:
            with contextlib.closing(results):
                for job, future in results:
                    try:
                        result = future.result()
                        atomic_write(job.path, result.payload)
                        if result.detail is not None:
                            inventory.verify_saved(job.path, result.payload, parsed=result.detail)
                        else:
                            inventory.verify_saved(job.path, result.payload)
                        if result.source_url is not None:
                            source_urls[job.path] = result.source_url
                        accept(result)
                    except CancelledError:
                        raise
                    except Exception as exc:
                        if failed is not None:
                            failed(job)
                        summary.failures.append(
                            {"kind": job.kind, "key": job.key, "error": str(exc)}
                        )
                    completed += 1
                    now = time.monotonic()
                    if completed % 8 == 0 or now - last_saved >= 5:
                        _write_sync_state(self.paths.sync_state, sync_state)
                        last_saved = now
                    advance()
        finally:
            # On orderly interruption preserve every saved completion. Abrupt
            # termination can replay only the tail since the last small batch.
            _write_sync_state(self.paths.sync_state, sync_state)

    def _fetch_details(
        self,
        plan: UpdatePlan,
        options: UpdateOptions,
        summary: UpdateSummary,
        sync_state: _SyncState,
        inventory: FileInventory,
        source_urls: dict[Path, str],
    ) -> tuple[dict[str, dict[str, Any]], set[str]]:
        selected_keys = {str(record["key"]) for record in plan.selected}
        details: dict[str, dict[str, Any]] = {}
        refreshed: set[str] = set()
        jobs: list[DownloadJob] = []
        for record in plan.records:
            key = str(record["key"])
            job = DownloadJob(
                "bug-json", key, self.paths.bugs / f"{key}.json", source_url=str(record["json_url"])
            )
            local, reason = self._inspect(job, inventory)
            if local is not None and local.detail is not None:
                details[key] = local.detail
            if key not in selected_keys:
                continue
            if options.refresh_details:
                reason = "refresh"
            elif key in sync_state.pending_details:
                reason = "retry"
            elif local is not None:
                summary.details_reused += 1
                continue
            jobs.append(replace(job, reason=reason))

        def accept(result: ArtifactResult) -> None:
            key = result.job.key
            assert result.detail is not None
            details[key] = result.detail
            refreshed.add(key)
            summary.details_downloaded += 1
            try:
                report_url = first_report_url(result.detail, dashboard=self.client.dashboard)
            except PayloadError:
                # Retain detail retry intent until report metadata is usable.
                return
            if report_url:
                sync_state.pending_reports.add(key)
            else:
                sync_state.pending_reports.discard(key)
            sync_state.pending_details.discard(key)

        def failed(job: DownloadJob) -> None:
            if job.key in details:
                summary.details_reused += 1

        self.progress(
            f"Bug details: downloading {len(jobs):,}, reusing {summary.details_reused:,}."
        )
        self._download(
            jobs,
            options,
            summary,
            sync_state,
            inventory,
            source_urls,
            label="Bug details",
            pending=sync_state.pending_details,
            accept=accept,
            failed=failed,
        )
        return details, refreshed

    def _index_candidate(
        self,
        summary: UpdateSummary,
        inventory: FileInventory,
        source_urls: dict[Path, str],
    ) -> None:
        if not summary.failures and self.database_path.is_file():
            self.progress("Retrieval finished; checking whether SQLite is already current ...")
            with contextlib.closing(Database(self.database_path, read_only=True)) as database:
                summary.database = (
                    database.check_files_current(self.paths, inventory=inventory) or {}
                )
        if summary.database:
            summary.database["skipped"] = True
            self.progress("No data changes; skipping SQLite update.")
        else:
            self.progress("Retrieval finished; updating SQLite from retained files ...")
            with Database(self.database_path) as database:
                database.initialize()
                summary.database = database.ingest_files(
                    self.paths,
                    inventory=inventory,
                    source_urls=source_urls,
                    errors=[
                        f"{failure['kind']} {failure['key']}: {failure['error']}".replace(
                            "  ", " ", 1
                        )
                        for failure in summary.failures
                    ],
                )
            summary.database["skipped"] = False
        summary.known_fixed_bugs = int(summary.database.get("known_fixed_bugs") or 0)
        summary.new_fixed_bugs = int(summary.database.get("new_fixed_bugs") or 0)
        new_fixed_bug_keys = summary.database.get("new_fixed_bug_keys")
        summary.new_fixed_bug_keys = (
            [str(key) for key in new_fixed_bug_keys] if isinstance(new_fixed_bug_keys, list) else []
        )
        summary.no_longer_listed_bugs = int(summary.database.get("no_longer_listed_bugs") or 0)
        no_longer_listed_bug_keys = summary.database.get("no_longer_listed_bug_keys")
        summary.no_longer_listed_bug_keys = (
            [str(key) for key in no_longer_listed_bug_keys]
            if isinstance(no_longer_listed_bug_keys, list)
            else []
        )

    def _fetch_reports(
        self,
        records: list[dict[str, Any]],
        details: Mapping[str, Mapping[str, Any]],
        options: UpdateOptions,
        summary: UpdateSummary,
        *,
        sync_state: _SyncState,
        inventory: FileInventory,
        source_urls: dict[Path, str],
        force_keys: set[str] | None = None,
    ) -> None:
        force_keys = force_keys or set()
        jobs: list[DownloadJob] = []
        for record in records:
            key = str(record["key"])
            try:
                url = first_report_url(details.get(key, {}), dashboard=self.client.dashboard)
            except PayloadError as exc:
                summary.failures.append({"kind": "report-metadata", "key": key, "error": str(exc)})
                continue
            if not url:
                summary.reports_unavailable += 1
                if key in details and key not in sync_state.pending_details:
                    sync_state.pending_reports.discard(key)
                continue
            job = DownloadJob("report", key, self.paths.reports / f"{key}.txt", source_url=url)
            if key in force_keys or options.refresh_artifacts:
                reason: DownloadReason = "refresh"
            elif key in sync_state.pending_reports:
                reason = "retry"
            else:
                local, reason = self._inspect(job, inventory)
                if local is not None:
                    summary.reports_reused += 1
                    continue
            jobs.append(replace(job, reason=reason))

        def accept(result: ArtifactResult) -> None:
            summary.reports_downloaded += 1
            sync_state.pending_reports.discard(result.job.key)

        self.progress(
            f"Crash reports: downloading {len(jobs):,}, reusing {summary.reports_reused:,}."
        )
        self._download(
            jobs,
            options,
            summary,
            sync_state,
            inventory,
            source_urls,
            label="Crash reports",
            pending=sync_state.pending_reports,
            accept=accept,
        )

    def _fetch_patches(
        self,
        records: list[dict[str, Any]],
        details: Mapping[str, Mapping[str, Any]],
        options: UpdateOptions,
        summary: UpdateSummary,
        *,
        live_keys: set[str],
        sync_state: _SyncState,
        inventory: FileInventory,
        source_urls: dict[Path, str],
    ) -> None:
        references: dict[str, str | None] = {}
        for record in records:
            for fix in effective_fixes(record, details.get(str(record["key"]))):
                commit_hash = str(fix.get("hash") or "").lower()
                if HASH_RE.fullmatch(commit_hash):
                    repo_value = fix.get("repo")
                    repo = repo_value if isinstance(repo_value, str) and repo_value else None
                    _add_patch_job(references, commit_hash, repo)
                elif commit_hash:
                    summary.failures.append(
                        {
                            "kind": "patch-metadata",
                            "key": str(record["key"]),
                            "error": f"invalid commit hash {commit_hash!r}",
                        }
                    )
        targets = resolution_targets(records, details)
        accepted: list[dict[str, Any]] = []
        if self.database_path.is_file() and self.database_path.stat().st_size:
            with contextlib.closing(Database(self.database_path, read_only=True)) as database:
                accepted = database.accepted_resolutions(targets)
        resolution_jobs, resolution_failures = _resolution_patch_jobs(
            self.paths.resolutions,
            targets,
            {str(record["key"]) for record in records},
            inventory,
            accepted,
        )
        summary.failures.extend(resolution_failures)
        for commit_hash, repo in resolution_jobs:
            _add_patch_job(references, commit_hash, repo)
        jobs: list[DownloadJob] = []
        for commit_hash, repo in references.items():
            job = DownloadJob(
                "patch", commit_hash, self.paths.patches / f"{commit_hash}.diff", repo=repo
            )
            if options.refresh_artifacts:
                reason: DownloadReason = "refresh"
            elif commit_hash in sync_state.pending_patches:
                reason = "retry"
            else:
                local, reason = self._inspect(job, inventory)
                if local is not None:
                    summary.patches_reused += 1
                    continue
            jobs.append(replace(job, reason=reason))

        def accept(result: ArtifactResult) -> None:
            summary.patches_downloaded += 1
            sync_state.pending_patches.discard(result.job.key)

        self.progress(
            f"Fix patches: downloading {len(jobs):,}, reusing {summary.patches_reused:,}."
        )
        self._download(
            jobs,
            options,
            summary,
            sync_state,
            inventory,
            source_urls,
            label="Fix patches",
            pending=sync_state.pending_patches,
            accept=accept,
        )
