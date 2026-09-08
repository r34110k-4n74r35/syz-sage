"""Fetch explicitly selected evidence from one saved crash, without changing SQLite."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from concurrent.futures import CancelledError
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from syz_sage.parsing.listing import (
    KEY_RE,
    MAX_BUG_KEY_LENGTH,
    PayloadError,
    absolute_syzbot_url,
    valid_report,
    validate_http_url,
)
from syz_sage.project.config import DataPaths
from syz_sage.project.progress_events import ProgressCallback, ProgressEvent, emit_progress
from syz_sage.project.storage import exclusive_update_lock

from .artifacts import atomic_write
from .client import SyzbotClient

_C_MAIN = re.compile(rb"\b(?:int|void)\s+main\s*\(")
_SYZ_CALL = re.compile(rb"(?m)^\s*(?:r\d+\s*=\s*)?[A-Za-z_]\w*(?:\$\w+)?\s*\(")
_CONFIG = re.compile(rb"(?m)^(?:CONFIG_[A-Za-z0-9_]+=|# CONFIG_[A-Za-z0-9_]+ is not set\r?$)")


def _valid_evidence(kind: str, payload: bytes) -> bool:
    if not isinstance(payload, bytes) or not valid_report(payload):
        return False
    if kind == "c-repro":
        return _C_MAIN.search(payload) is not None
    if kind == "syz-repro":
        return _SYZ_CALL.search(payload) is not None
    if kind == "config":
        return _CONFIG.search(payload) is not None
    return True


def _cached(path: Path, kind: str) -> bytes | None:
    try:
        payload = path.read_bytes()
    except OSError:
        return None
    return payload if _valid_evidence(kind, payload) else None


def _select_crash(bug: Mapping[str, Any], ordinal: int | None) -> tuple[dict[str, Any], str]:
    crashes = bug.get("crashes")
    if not isinstance(crashes, list) or not crashes:
        raise ValueError("this bug has no saved crash entries")
    by_ordinal: dict[int, dict[str, Any]] = {}
    for crash in crashes:
        if not isinstance(crash, Mapping):
            raise PayloadError("saved crash entry is not an object")
        position = crash.get("ordinal")
        if type(position) is not int or position < 0 or position in by_ordinal:
            raise PayloadError("saved crash entries have invalid or duplicate ordinals")
        by_ordinal[position] = dict(crash)
    if ordinal is not None:
        if type(ordinal) is not int or ordinal < 0 or ordinal not in by_ordinal:
            raise ValueError(f"no saved crash with ordinal {ordinal!r}; crash ordinals start at 0")
        return by_ordinal[ordinal], "explicit"
    representative = bug.get("report")
    source = representative.get("source_url") if isinstance(representative, Mapping) else None
    ordered = [by_ordinal[position] for position in sorted(by_ordinal)]
    if source:
        for crash in ordered:
            if crash.get("crash_report_url") == source:
                return crash, "representative-report"
    for crash in ordered:
        if crash.get("crash_report_url"):
            return crash, "first-report"
    return ordered[0], "first-crash"


def _representative_cache(paths: DataPaths, bug: Mapping[str, Any], url: str) -> bytes | None:
    report = bug.get("report")
    if not isinstance(report, Mapping) or report.get("source_url") != url:
        return None
    payload = _cached(paths.reports / f"{bug['key']}.txt", "report")
    if payload is not None and hashlib.sha256(payload).hexdigest() == report.get("sha256"):
        return payload
    return None


def fetch_evidence(
    paths: DataPaths,
    bug: Mapping[str, Any],
    *,
    c_repro: bool = False,
    syz_repro: bool = False,
    config: bool = False,
    report: bool = False,
    crash: int | None = None,
    refresh: bool = False,
    client: SyzbotClient | None = None,
    on_progress: ProgressCallback | None = None,
) -> dict[str, Any]:
    """Retain evidence for one active, saved crash; never run its reproducer.

    ``crash`` is the zero-based ordinal returned by ``Database.get_bug``. With
    no ordinal, use the representative report's crash (or the first available
    entry). Missing artifacts never cause selection of another crash/build.
    Files include the URL hash so changed saved metadata cannot reuse another
    crash's bytes. Ordinary ``ss update`` ignores these nested optional files.
    """
    requests: list[tuple[str, str, Path, str]] = []
    if c_repro:
        requests.append(("c-repro", "c_reproducer_url", paths.reproducers, ".c"))
    if syz_repro:
        requests.append(("syz-repro", "syz_reproducer_url", paths.reproducers, ".syz"))
    if config:
        requests.append(("config", "kernel_config_url", paths.configs, ".config"))
    if report:
        requests.append(("report", "crash_report_url", paths.reports, ".txt"))
    if not requests:
        raise ValueError(
            "select at least one artifact: --c-repro, --syz-repro, --config, or --report"
        )
    key = bug.get("key")
    if not isinstance(key, str) or len(key) > MAX_BUG_KEY_LENGTH or KEY_RE.fullmatch(key) is None:
        raise PayloadError("saved bug has an unsafe key")
    if bug.get("in_current_snapshot") is not True:
        raise ValueError("evidence fetch requires a bug from the active database snapshot")
    selected, selection = _select_crash(bug, crash)
    bug_url = bug.get("bug_url")
    validate_http_url(bug_url)
    source = urlsplit(bug_url)
    base_path = source.path[: -len("/bug")] if source.path.endswith("/bug") else ""
    dashboard = urlunsplit((source.scheme, source.netloc, base_path, "", ""))
    client = client or SyzbotClient(dashboard=dashboard)
    validate_http_url(bug_url, same_origin_as=client.dashboard)
    entries: list[dict[str, Any]] = []
    for kind, field, directory, suffix in requests:
        entry: dict[str, Any] = {
            "kind": kind,
            "url": None,
            "path": None,
            "sha256": None,
            "size": 0,
            "status": "pending",
            "available": False,
        }
        link = selected.get(field)
        if link is None or link == "":
            entry.update(status="unavailable", error=f"selected crash has no saved {kind} URL")
        else:
            try:
                if not isinstance(link, str):
                    raise PayloadError(f"saved {kind} URL is not a string")
                url = absolute_syzbot_url(link, dashboard=client.dashboard)
                assert url is not None
                digest = hashlib.sha256(url.encode("utf-8")).hexdigest()
                path = directory / key / f"crash-{selected['ordinal']}-{digest}{suffix}"
                entry.update(url=url, path=str(path))
            except ValueError as exc:
                entry.update(status="failed", error=str(exc))
        entries.append(entry)

    def progress(completed: int) -> None:
        emit_progress(
            on_progress,
            ProgressEvent(
                "selective-evidence", "Fetching selected crash evidence", completed, len(entries)
            ),
        )

    reset = getattr(client, "reset_cancellation", None)
    if callable(reset):
        reset()
    try:
        progress(0)
        if any(entry["status"] == "pending" for entry in entries):
            with exclusive_update_lock(paths.root):
                for completed, entry in enumerate(entries, 1):
                    if entry["status"] == "pending":
                        path = Path(entry["path"])
                        cached = _cached(path, entry["kind"])
                        try:
                            if cached is not None and not refresh:
                                payload = cached
                                state = "reused"
                            else:
                                payload = (
                                    _representative_cache(paths, bug, entry["url"])
                                    if entry["kind"] == "report" and not refresh
                                    else None
                                )
                                if payload is not None:
                                    state = "reused"
                                    entry["cache_source"] = "representative-report"
                                else:
                                    payload = client.get(entry["url"], dashboard_request=True)
                                    if not _valid_evidence(entry["kind"], payload):
                                        raise PayloadError(
                                            f"response is not valid {entry['kind']} evidence"
                                        )
                                    state = "downloaded"
                                atomic_write(path, payload)
                            entry.update(
                                status=state,
                                available=True,
                                sha256=hashlib.sha256(payload).hexdigest(),
                                size=len(payload),
                            )
                        except CancelledError:
                            raise
                        except Exception as exc:
                            entry.update(status="failed", error=str(exc))
                            if cached is not None:
                                entry.update(
                                    available=True,
                                    retained=True,
                                    sha256=hashlib.sha256(cached).hexdigest(),
                                    size=len(cached),
                                )
                    progress(completed)
        else:
            progress(len(entries))
    except (KeyboardInterrupt, CancelledError):
        cancel = getattr(client, "cancel", None)
        if callable(cancel):
            cancel()
        raise
    counts = {
        status: sum(entry["status"] == status for entry in entries)
        for status in ("downloaded", "reused", "unavailable", "failed")
    }
    return {
        "ok": not counts["unavailable"] and not counts["failed"],
        "key": key,
        "bug_url": bug_url,
        "snapshot_id": bug.get("snapshot_id"),
        "crash": selected,
        "selection": selection,
        "artifacts": entries,
        "failures": [entry for entry in entries if entry["status"] == "failed"],
        "reproduction_status": "not_attempted",
        **counts,
    }
