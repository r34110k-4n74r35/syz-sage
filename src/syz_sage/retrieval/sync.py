"""Incremental, filesystem-safe Syzbot update orchestration."""

from __future__ import annotations

import contextlib
import time
from collections.abc import Callable, Mapping
from concurrent.futures import CancelledError
from dataclasses import replace
from pathlib import Path
from typing import Any

from syz_sage.database import Database
from syz_sage.database.ingestion import FileInventory
from syz_sage.parsing.listing import (
    HASH_RE,
    PayloadError,
    effective_fixes,
    first_report_url,
    parse_listing,
    parse_subsystem_tags,
    valid_listing_html,
    validate_listing_membership,
)
from syz_sage.project.config import DataPaths
from syz_sage.project.progress_events import ProgressCallback, ProgressEvent, emit_progress
from syz_sage.project.storage import exclusive_update_lock as _exclusive_update_lock
from syz_sage.project.storage import writable_path

from .artifacts import (
    ArtifactResult,
    DownloadJob,
    DownloadReason,
    atomic_write,
    bounded_results,
    fetch_artifact,
    validate_artifact,
)
from .catalog import _listing_discrepancies, _read_prior_listing, write_catalog
from .client import FetchError, SyzbotClient
from .models import UpdateOptions, UpdatePlan, UpdateSummary
from .resolutions import (
    PatchResolutions,
    load_patch_resolutions,
    resolution_targets,
    unresolved_fix_keys,
)
from .retry_state import SyncState as _SyncState
from .retry_state import load_sync_state as _load_sync_state
from .retry_state import save_sync_state as _write_sync_state


def _read_valid(
    path: Path, validator: Callable[[bytes], bool], inventory: FileInventory | None = None
) -> bytes | None:
    try:
        payload = inventory.read_bytes(path) if inventory is not None else path.read_bytes()
    except OSError:
        return None
    return payload if validator(payload) else None


def _add_patch_job(
    jobs: dict[str, str | None],
    commit_hash: str,
    repo: str | None,
) -> None:
    """Keep the first useful repository when several sources name one hash."""

    if commit_hash not in jobs or (not jobs[commit_hash] and repo):
        jobs[commit_hash] = repo


class Updater:
    """Refresh local mirror files, then transactionally index them in SQLite."""

    def __init__(
        self,
        paths: DataPaths,
        database_path: Path,
        client: SyzbotClient | None = None,
        progress: Callable[[str], None] | None = None,
        *,
        on_progress: ProgressCallback | None = None,
    ) -> None:
        self.paths = paths
        self.database_path = database_path
        self.client = client or SyzbotClient()
        self.progress = progress or (lambda message: None)
        self.on_progress = on_progress

    def _notify(
        self,
        phase: str,
        message: str,
        completed: int | None = None,
        total: int | None = None,
    ) -> None:
        emit_progress(self.on_progress, ProgressEvent(phase, message, completed, total))

    def _phase_progress(
        self, label: str, total: int, *, action: str = "downloading"
    ) -> Callable[[], None]:
        """Report long batches without printing one line for every download."""
        completed = 0
        last_message = time.monotonic()
        phase = "download-" + label.lower().replace(" ", "-")
        message = f"{label}: {action} {total:,}"
        if not total:
            message = f"{label}: no downloads needed"
        self._notify(phase, message, 0, total)

        def advance() -> None:
            nonlocal completed, last_message
            completed += 1
            self._notify(phase, message, completed, total)
            now = time.monotonic()
            if now - last_message >= 5 or (completed == total and total >= 20):
                self.progress(f"{label}: processed {completed:,}/{total:,} requests.")
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
        self._notify("update-lock", "Preparing update")
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
        self._notify("listing", "Checking fixed bugs on syzbot", 0, 2)
        listing_bytes = self.client.listing_json(options.namespace, options.status)
        records = parse_listing(listing_bytes, dashboard=self.client.dashboard)
        if not records:
            raise PayloadError("live listing contains no bug records")
        summary.listing_bugs = len(records)
        self._notify("listing", "Checking subsystem tags on syzbot", 1, 2)
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
        self._notify(
            "listing",
            f"Fixed listing: {len(records):,} bugs; {len(mirror_new_keys):,} new, "
            f"{summary.changed_bugs:,} changed",
            2,
            2,
        )

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
        action: str = "downloading",
    ) -> None:
        """Save validated completions and durably advance the existing retry queue."""
        pending.update(job.key for job in jobs)
        _write_sync_state(self.paths.sync_state, sync_state)
        advance = self._phase_progress(label, len(jobs), action=action)
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
        saved: list[tuple[DownloadJob, bool, DownloadReason]] = []
        for index, record in enumerate(plan.records):
            self._notify("saved-details", "Checking saved bug details", index, len(plan.records))
            key = str(record["key"])
            job = DownloadJob(
                "bug-json", key, self.paths.bugs / f"{key}.json", source_url=str(record["json_url"])
            )
            local, reason = self._inspect(job, inventory)
            if local is not None and local.detail is not None:
                details[key] = local.detail
            if key not in selected_keys:
                continue
            saved.append((job, local is not None, reason))

        discovery_keys: set[str] = set()
        resolutions: PatchResolutions = {}
        if options.recheck_fixes and options.patches and not options.refresh_details:
            # Valid JSON can predate publication of a fix hash. Recheck only
            # those incomplete references when explicitly requested.
            discovery_keys = unresolved_fix_keys(plan.selected, details, {})
            if discovery_keys:
                unresolved_records = [
                    record for record in plan.selected if str(record["key"]) in discovery_keys
                ]
                resolutions, _ = self._patch_resolutions(unresolved_records, details, inventory)
                discovery_keys = unresolved_fix_keys(unresolved_records, details, resolutions)
        discovery_jobs: set[str] = set()
        for job, has_local, reason in saved:
            key = job.key
            if options.refresh_details:
                reason = "refresh"
            elif key in sync_state.pending_details:
                reason = "retry"
            elif has_local and key in discovery_keys:
                reason = "refresh"
                discovery_jobs.add(key)
            elif has_local:
                summary.details_reused += 1
                continue
            jobs.append(replace(job, reason=reason))

        planning_message = (
            f"Saved bug details: {summary.details_reused:,} reused; "
            f"{sum(job.reason in ('missing', 'invalid') for job in jobs):,} missing/invalid; "
            f"{sum(job.reason == 'retry' for job in jobs):,} retries; "
            f"{sum(job.reason == 'refresh' for job in jobs) - len(discovery_jobs):,} "
            f"explicit refreshes; {len(discovery_jobs):,} fix rechecks"
        )
        self._notify(
            "saved-details",
            planning_message,
            len(plan.records),
            len(plan.records),
        )
        self.progress(planning_message)
        # Pending retries can also discover a late hash. Count all cached,
        # unresolved requests, while retaining their original retry behavior.
        recheck_keys = {job.key for job in jobs if job.key in details} & discovery_keys
        accepted_detail_keys: set[str] = set()

        def accept(result: ArtifactResult) -> None:
            key = result.job.key
            assert result.detail is not None
            previous = details.get(key)
            details[key] = result.detail
            summary.details_downloaded += 1
            accepted_detail_keys.add(key)
            try:
                report_url = first_report_url(result.detail, dashboard=self.client.dashboard)
            except PayloadError:
                # Retain detail retry intent until report metadata is usable.
                return
            refresh_report = key not in discovery_jobs
            if not refresh_report:
                try:
                    previous_url = first_report_url(previous or {}, dashboard=self.client.dashboard)
                except PayloadError:
                    refresh_report = True
                else:
                    refresh_report = previous_url != report_url
            if refresh_report:
                refreshed.add(key)
            if report_url and refresh_report:
                sync_state.pending_reports.add(key)
            elif not report_url:
                sync_state.pending_reports.discard(key)
            sync_state.pending_details.discard(key)

        def failed(job: DownloadJob) -> None:
            if job.key in details:
                summary.details_reused += 1

        action = "rechecking" if jobs and all(job.key in details for job in jobs) else "downloading"
        self.progress(f"Bug details: {action} {len(jobs):,}.")
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
            action=action,
        )
        if recheck_keys:
            checked = recheck_keys & accepted_detail_keys
            checked_records = [record for record in plan.selected if str(record["key"]) in checked]
            # New title-only references can match resolutions that were not
            # applicable to the old detail. Use the patch stage's current view.
            if checked_records:
                resolutions, _ = self._patch_resolutions(checked_records, details, inventory)
            still_unresolved = unresolved_fix_keys(checked_records, details, resolutions)
            outcome = (
                f"Fix rechecks: {len(checked):,} checked; "
                f"{len(checked - still_unresolved):,} resolved; "
                f"{len(still_unresolved):,} awaiting hashes; "
                f"{len(recheck_keys - checked):,} failed"
            )
            self._notify("fix-discovery-result", outcome)
            self.progress(outcome)
        return details, refreshed

    def _index_candidate(
        self,
        summary: UpdateSummary,
        inventory: FileInventory,
        source_urls: dict[Path, str],
    ) -> None:
        if not summary.failures and self.database_path.is_file():
            self.progress("Retrieval finished; checking whether SQLite is already current ...")
            self._notify("database-current", "Checking whether SQLite is already current")
            with contextlib.closing(
                Database(self.database_path, read_only=True, on_progress=self.on_progress)
            ) as database:
                summary.database = (
                    database.check_files_current(self.paths, inventory=inventory) or {}
                )
        if summary.database:
            summary.database["skipped"] = True
            self.progress("No data changes; skipping SQLite update.")
            self._notify("database-current", "No data changes; skipping SQLite update", 1, 1)
        else:
            self.progress("Retrieval finished; updating SQLite from retained files ...")
            self._notify("database-index", "Updating SQLite from retained files")
            with Database(self.database_path, on_progress=self.on_progress) as database:
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
        self._notify("database-result", "Database processing finished", 1, 1)
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
        for index, record in enumerate(records):
            self._notify("saved-reports", "Checking saved crash reports", index, len(records))
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

        self._notify(
            "saved-reports",
            f"Saved crash reports: {summary.reports_reused:,} reused; {len(jobs):,} to download",
            len(records),
            len(records),
        )

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

    def _patch_resolutions(
        self,
        records: list[dict[str, Any]],
        details: Mapping[str, Mapping[str, Any]],
        inventory: FileInventory,
    ) -> tuple[PatchResolutions, list[dict[str, str]]]:
        targets = resolution_targets(records, details)
        accepted: list[dict[str, Any]] = []
        if targets and self.database_path.is_file() and self.database_path.stat().st_size:
            with contextlib.closing(Database(self.database_path, read_only=True)) as database:
                accepted = database.accepted_resolutions(targets)
        return load_patch_resolutions(
            self.paths.resolutions,
            targets,
            {str(record["key"]) for record in records},
            inventory,
            accepted,
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
        self._notify("patch-references", "Matching fix commits and resolved patches")
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
        resolutions, resolution_failures = self._patch_resolutions(records, details, inventory)
        summary.failures.extend(resolution_failures)
        for commit_hash, repo in resolutions.values():
            _add_patch_job(references, commit_hash, repo)
        jobs: list[DownloadJob] = []
        for index, (commit_hash, repo) in enumerate(references.items()):
            self._notify("saved-patches", "Checking saved fix patches", index, len(references))
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

        self._notify(
            "saved-patches",
            f"Saved fix patches: {summary.patches_reused:,} reused; {len(jobs):,} to download",
            len(references),
            len(references),
        )

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
