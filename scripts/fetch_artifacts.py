#!/usr/bin/env python3
"""Download Syzbot bug JSON, crash reports, and kernel patches.

Dashboard requests use the shared client's configured limiter and retries.
Patch downloads use the same client with repository-specific URLs.

Default --syzbot mode downloads JSON + crash reports only. Reproducer fields
are not used to select a crash. Existing files are skipped so the run is safe
to interrupt and resume.
"""

from __future__ import annotations

import argparse
import json
import re
import threading
import time
import urllib.parse
from collections.abc import Callable
from concurrent.futures import CancelledError
from pathlib import Path

from syz_sage.parsing.listing import (
    HASH_RE,
    KEY_RE,
    MAX_BUG_KEY_LENGTH,
    PayloadError,
    absolute_syzbot_url,
    effective_fixes,
    first_report_url,
    parse_bug_json,
    valid_bug_json,
    valid_patch,
    valid_report,
)
from syz_sage.project.storage import exclusive_update_lock as _exclusive_update_lock
from syz_sage.retrieval.artifacts import DownloadJob, bounded_results, fetch_artifact
from syz_sage.retrieval.retry_state import SyncState, load_sync_state, save_sync_state

from .common import (
    BUG_JSON,
    CLIENT,
    CONFIGS,
    DASHBOARD,
    PATCHES,
    PROCESSED,
    REPORTS,
    REPROS,
    ensure_dirs,
    writable_path,
    write_bytes,
)

PRINT_LOCK = threading.Lock()
RETRY_LOCK = threading.Lock()
PATCH_LOCKS_GUARD = threading.Lock()
PATCH_LOCKS: dict[str, threading.Lock] = {}


def log(msg: str) -> None:
    with PRINT_LOCK:
        print(msg, flush=True)


def _state() -> SyncState:
    state, error = load_sync_state(PROCESSED / "sync_state.json")
    if error:
        raise PayloadError(f"sync state: {error}")
    return state


def _pending(kind: str, key: str) -> bool:
    with RETRY_LOCK:
        return key in getattr(_state(), f"pending_{kind}")


def _set_pending(kind: str, key: str, pending: bool) -> None:
    with RETRY_LOCK:
        state = _state()
        keys = getattr(state, f"pending_{kind}")
        keys.add(key) if pending else keys.discard(key)
        save_sync_state(PROCESSED / "sync_state.json", state)


def _bug_path(directory: Path, key: str, suffix: str) -> Path:
    if not isinstance(key, str) or len(key) > MAX_BUG_KEY_LENGTH or not KEY_RE.fullmatch(key):
        raise PayloadError(f"unsafe bug key: {key!r}")
    return writable_path(directory / f"{key}{suffix}")


def _patch_path(commit_hash: str) -> Path:
    if not isinstance(commit_hash, str) or not HASH_RE.fullmatch(commit_hash):
        raise PayloadError(f"invalid commit hash: {commit_hash!r}")
    return writable_path(PATCHES / f"{commit_hash.lower()}.diff")


def _config_path(url: str) -> Path:
    tokens = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query, keep_blank_values=True).get(
        "x", []
    )
    if len(tokens) != 1 or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", tokens[0]):
        raise PayloadError("kernel-config URL has no single safe artifact token")
    return writable_path(CONFIGS / f"{tokens[0]}.config")


def _cached_valid(path: Path, validator: Callable[[bytes], bool]) -> bool:
    try:
        return validator(path.read_bytes())
    except OSError:
        return False


def http_get(url: str, dest: Path | None, timeout: int = 60, syzbot: bool = False) -> bytes:
    """Compatibility wrapper for research HTML/text using the shared HTTP client."""
    if dest is not None:
        dest = writable_path(dest)
    payload = CLIENT.get(url, timeout=timeout, dashboard_request=syzbot)
    if dest is not None:
        if not valid_report(payload):
            raise PayloadError("empty or markup text artifact")
        write_bytes(dest, payload)
    return payload


def load_catalog() -> list[dict]:
    payload = json.loads((PROCESSED / "catalog.json").read_bytes())
    if not isinstance(payload, dict) or not isinstance(payload.get("bugs"), list):
        raise PayloadError("catalog must contain a bugs list")
    for record in payload["bugs"]:
        if not isinstance(record, dict) or not isinstance(record.get("key"), str):
            raise PayloadError("catalog contains a record without a bug key")
        _bug_path(BUG_JSON, record["key"], ".json")
    return payload["bugs"]


def abs_syzbot(link: str | None) -> str | None:
    return absolute_syzbot_url(link, dashboard=DASHBOARD)


def report_ok(key: str) -> bool:
    return _cached_valid(_bug_path(REPORTS, key, ".txt"), valid_report)


def json_ok(key: str) -> bool:
    return _cached_valid(_bug_path(BUG_JSON, key, ".json"), valid_bug_json)


def patch_ok(commit_hash: str) -> bool:
    return _cached_valid(_patch_path(commit_hash), valid_patch)


def pick_crash(bug: dict) -> dict | None:
    """Return the first report-bearing crash in Syzbot metadata order."""
    for crash in bug.get("crashes") or []:
        if isinstance(crash, dict) and crash.get("crash-report-link"):
            return crash
    return None


def fetch_bug_json(rec: dict, force: bool = False) -> dict | None:
    key = rec["key"]
    dest = _bug_path(BUG_JSON, key, ".json")
    if not force and not _pending("details", key):
        try:
            return parse_bug_json(dest.read_bytes())
        except (OSError, PayloadError):
            pass
    try:
        _set_pending("details", key, True)
        result = fetch_artifact(CLIENT, DownloadJob("bug-json", key, dest, rec["json_url"]))
        report_url = first_report_url(result.detail or {}, dashboard=DASHBOARD)
        # Persist the need for a matching report before replacing its metadata.
        _set_pending("reports", key, bool(report_url))
        write_bytes(dest, result.payload)
        _set_pending("details", key, False)
        return result.detail
    except CancelledError:
        raise
    except Exception as exc:
        log(f"  json fail {key}: {exc}")
        return None


def fetch_text(url: str | None, dest: Path) -> bool:
    dest = writable_path(dest)
    if not url:
        return False
    is_report = dest.parent == REPORTS
    pending_report = is_report and _pending("reports", dest.stem)
    if not pending_report and _cached_valid(dest, valid_report):
        return True
    try:
        if is_report:
            _bug_path(REPORTS, dest.stem, ".txt")
            _set_pending("reports", dest.stem, True)
            result = fetch_artifact(CLIENT, DownloadJob("report", dest.stem, dest, url))
            payload = result.payload
        else:
            payload = http_get(url, None, syzbot=True)
            if not valid_report(payload):
                raise PayloadError("empty or markup text artifact")
        write_bytes(dest, payload)
        if is_report:
            _set_pending("reports", dest.stem, False)
        return True
    except CancelledError:
        raise
    except Exception as exc:
        log(f"  text fail {dest.name}: {exc}")
        return False


def fetch_patch(commit_hash: str, repo: str | None) -> bool:
    dest = _patch_path(commit_hash)
    commit_hash = commit_hash.lower()
    with PATCH_LOCKS_GUARD:
        lock = PATCH_LOCKS.setdefault(commit_hash, threading.Lock())
    # Several bugs may reference one patch. Inspect, fetch, and update retry
    # intent together so another worker can reuse the first successful result.
    with lock:
        return _fetch_patch(commit_hash, repo, dest)


def _fetch_patch(commit_hash: str, repo: str | None, dest: Path) -> bool:
    if patch_ok(commit_hash) and not _pending("patches", commit_hash):
        return True
    try:
        _set_pending("patches", commit_hash, True)
        result = fetch_artifact(CLIENT, DownloadJob("patch", commit_hash, dest, repo=repo))
        write_bytes(dest, result.payload)
        _set_pending("patches", commit_hash, False)
        return True
    except CancelledError:
        raise
    except Exception as exc:
        log(f"  patch fail {commit_hash[:12]}: {exc}")
        return False


def hashes_from_record(rec: dict) -> list[tuple[str, str | None]]:
    return _fix_hashes(effective_fixes(rec, None))


def hashes_from_bug_json(bug: dict) -> list[tuple[str, str | None]]:
    return _fix_hashes(effective_fixes({}, bug))


def _fix_hashes(fixes: list[dict]) -> list[tuple[str, str | None]]:
    out: list[tuple[str, str | None]] = []
    for fix in fixes:
        commit_hash = fix.get("hash")
        if commit_hash:
            if not isinstance(commit_hash, str) or not HASH_RE.fullmatch(commit_hash):
                raise PayloadError(f"invalid commit hash: {commit_hash!r}")
            repo = fix.get("repo")
            if repo is not None and not isinstance(repo, str):
                raise PayloadError("patch repository must be a string")
            out.append((commit_hash.lower(), repo or None))
    return out


def collect_patch_jobs(bugs: list[dict]) -> list[tuple[str, str | None]]:
    jobs: dict[str, str | None] = {}
    for rec in bugs:
        try:
            bug = parse_bug_json(_bug_path(BUG_JSON, rec["key"], ".json").read_bytes())
        except (OSError, PayloadError):
            bug = {}
        for commit_hash, repo in _fix_hashes(effective_fixes(rec, bug)):
            if commit_hash not in jobs or (not jobs[commit_hash] and repo):
                jobs[commit_hash] = repo
    return list(jobs.items())


def cmd_status(bugs: list[dict]) -> None:
    n = len(bugs)
    n_json = sum(1 for b in bugs if json_ok(b["key"]))
    n_report = sum(1 for b in bugs if report_ok(b["key"]))
    jobs = collect_patch_jobs(bugs)
    n_patch = sum(1 for h, _ in jobs if patch_ok(h))
    n_hash = sum(1 for b in bugs if b.get("primary_fix_hash"))
    print(
        json.dumps(
            {
                "catalog_bugs": n,
                "bug_json": n_json,
                "crash_reports": n_report,
                "missing_reports": n - n_report,
                "bugs_with_fix_hash": n_hash,
                "bugs_without_fix_hash": n - n_hash,
                "unique_fix_hashes": len(jobs),
                "patches_on_disk": n_patch,
                "missing_patches": len(jobs) - n_patch,
            },
            indent=2,
        )
    )


def cmd_patches(bugs: list[dict], limit: int | None) -> None:
    jobs = collect_patch_jobs(bugs)
    jobs = [(h, repo) for h, repo in jobs if not patch_ok(h) or _pending("patches", h)]
    if limit:
        jobs = jobs[:limit]
    print(f"downloading {len(jobs)} missing patches")
    ok = 0
    if not jobs:
        print("patches already complete")
        return
    for done, (_, future) in enumerate(
        bounded_results(jobs, lambda job: fetch_patch(*job), workers=8, cancel=CLIENT.cancel),
        start=1,
    ):
        try:
            if future.result():
                ok += 1
        except CancelledError:
            raise
        except Exception as exc:
            log(f"  patch worker error: {exc}")
        if done % 50 == 0 or done == len(jobs):
            log(f"  patches {done}/{len(jobs)} ok={ok}")
    print(f"patches done ok={ok}/{len(jobs)}")


def process_bug(rec: dict, repros: bool, configs: bool, force_json: bool = False) -> dict:
    """Fetch JSON + crash report and harvest all available patch hashes."""
    out = {
        "key": rec["key"],
        "json": False,
        "report": False,
        "c": False,
        "syz": False,
        "patches": 0,
        "error": None,
    }
    bug = fetch_bug_json(rec, force=force_json)
    if not bug:
        out["error"] = "json"
        return out
    out["json"] = True
    for h, repo in _fix_hashes(effective_fixes(rec, bug)):
        if fetch_patch(h, repo):
            out["patches"] += 1
    crash = pick_crash(bug)
    if not crash:
        _set_pending("reports", rec["key"], False)
        out["error"] = "no-crash-report-link"
        return out
    report_dest = REPORTS / f"{rec['key']}.txt"
    if fetch_text(abs_syzbot(crash.get("crash-report-link")), report_dest):
        out["report"] = report_ok(rec["key"])
        if not out["report"]:
            out["error"] = "empty-report"
    else:
        out["error"] = "report"
    if repros:
        out["c"] = fetch_text(abs_syzbot(crash.get("c-reproducer")), REPROS / f"{rec['key']}.c")
        out["syz"] = fetch_text(
            abs_syzbot(crash.get("syz-reproducer")), REPROS / f"{rec['key']}.syz"
        )
    if configs:
        cfg = crash.get("kernel-config")
        if cfg:
            url = abs_syzbot(cfg)
            if url:
                fetch_text(url, _config_path(url))
    return out


def cmd_syzbot(
    bugs: list[dict],
    limit: int | None,
    configs: bool,
    repros: bool,
    workers: int,
    refresh_missing_hashes: bool,
) -> None:
    def needs_hash_refresh(rec: dict) -> bool:
        path = BUG_JSON / f"{rec['key']}.json"
        if not path.exists():
            fixes = rec.get("fix_commits") or []
            return not fixes or any(not c.get("hash") for c in fixes)
        try:
            local = parse_bug_json(path.read_bytes())
        except (PayloadError, OSError):
            return True
        fixes = local.get("fix-commits") or []
        return not fixes or any(not c.get("hash") for c in fixes)

    state = _state()
    pending_keys = state.pending_details | state.pending_reports
    todo = [
        bug
        for bug in bugs
        if configs
        or repros
        or bug["key"] in pending_keys
        or not report_ok(bug["key"])
        or not json_ok(bug["key"])
    ]
    refresh_keys: set[str] = set()
    if refresh_missing_hashes:
        refresh_keys = {b["key"] for b in bugs if needs_hash_refresh(b)}
        todo_keys = {b["key"] for b in todo}
        todo.extend(b for b in bugs if b["key"] in refresh_keys and b["key"] not in todo_keys)
        # Resolve the previously excluded title-only fixes before the longer
        # missing-report sweep, while preserving resumability for both groups.
        todo.sort(key=lambda rec: (rec["key"] not in refresh_keys, rec["key"]))
    if limit:
        todo = todo[:limit]
    n = len(todo)
    requests, window = CLIENT.limiter.requests, CLIENT.limiter.window
    eta_min = (n * (2 if not repros else 4)) / (requests / window) / 60.0
    log(
        f"fetching syzbot JSON+crash-report for {n} bugs "
        f"(skip {len(bugs) - n} complete local records; "
        f"repros={'yes' if repros else 'no'}; workers={workers}; "
        f"eta ~{eta_min:.0f} min at {requests}/{window:.0f}s)"
    )
    counts = {"json": 0, "report": 0, "fail": 0, "patches": 0}
    t0 = time.time()

    def _one(rec: dict) -> dict:
        return process_bug(
            rec,
            repros=repros,
            configs=configs,
            # A cached record can be the reason a report is still missing: the
            # live record may now expose a crash-report link that was absent in
            # the cached JSON. Refresh every incomplete record before retrying.
            force_json=rec["key"] in refresh_keys or not report_ok(rec["key"]),
        )

    for done, (rec, future) in enumerate(
        bounded_results(todo, _one, workers=workers, cancel=CLIENT.cancel), start=1
    ):
        try:
            res = future.result()
        except CancelledError:
            raise
        except Exception as exc:
            log(f"  worker error {rec['key']}: {exc}")
            res = {"json": False, "report": False, "patches": 0, "error": str(exc)}
        if res.get("json"):
            counts["json"] += 1
        if res.get("report"):
            counts["report"] += 1
        if res.get("error"):
            counts["fail"] += 1
        counts["patches"] += int(res.get("patches") or 0)
        if done % 25 == 0 or done == n:
            elapsed = time.time() - t0
            rate = done / elapsed if elapsed else 0
            remain = (n - done) / rate / 60 if rate else 0
            log(
                f"  syzbot {done}/{n} reports={counts['report']} "
                f"json={counts['json']} fail={counts['fail']} "
                f"new_patches={counts['patches']} "
                f"eta={remain:.0f}m"
            )
    log("syzbot fetch pass complete")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--patches", action="store_true")
    parser.add_argument("--syzbot", action="store_true")
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--status", action="store_true", help="print local coverage and exit")
    parser.add_argument("--configs", action="store_true", help="also download kernel .config files")
    parser.add_argument(
        "--repros",
        action="store_true",
        help="also download C and syz reproducers (off by default)",
    )
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument(
        "--refresh-missing-hashes",
        action="store_true",
        help="re-fetch JSON records whose fix metadata has no commit hash",
    )
    args = parser.parse_args()
    if args.workers < 1 or (args.limit is not None and args.limit < 1):
        parser.error("--workers and --limit must be positive")
    if args.status:
        cmd_status(load_catalog())
        return
    if not (args.patches or args.syzbot or args.all):
        parser.error("specify --patches, --syzbot, --all, or --status")
    with _exclusive_update_lock(PROCESSED.parent):
        CLIENT.reset_cancellation()
        ensure_dirs()
        bugs = load_catalog()
        if args.patches or args.all:
            cmd_patches(bugs, args.limit if args.patches and not args.all else None)
        if args.syzbot or args.all:
            cmd_syzbot(
                bugs,
                args.limit,
                args.configs,
                args.repros,
                args.workers,
                args.refresh_missing_hashes,
            )


if __name__ == "__main__":
    main()
