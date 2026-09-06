#!/usr/bin/env python3
"""Resolve title-only Syzbot fixes against the kernel cgit log.

Syzbot occasionally marks a bug fixed before the fixed listing exposes a commit
hash. This script performs an exact-subject search in the declared repository,
records only unambiguous 40-hex matches, and downloads the matched patch. The
original Syzbot JSON is not modified; resolutions are stored as supplemental,
auditable metadata consumed by the analyzer.
"""

from __future__ import annotations

import argparse
import html
import json
import re
import threading
import urllib.parse
from datetime import datetime, timezone

from syz_sage.artifacts import bounded_results
from syz_sage.client import normalize_patch_repository
from syz_sage.parsing import KEY_RE, PayloadError, parse_bug_json
from syz_sage.sync import _exclusive_update_lock

from .common import BUG_JSON, PROCESSED, normalize_repo_url, writable_path, write_text
from .fetch_artifacts import fetch_patch, http_get

OUTPUT = PROCESSED / "resolved_fix_hashes.json"
PRINT_LOCK = threading.Lock()


def log(message: str) -> None:
    with PRINT_LOCK:
        print(message, flush=True)


def normalize_title(value: str) -> str:
    value = html.unescape(re.sub(r"<[^>]+>", "", value))
    return " ".join(value.split()).strip()


def search_url(repo: str, title: str) -> str:
    host, base = normalize_patch_repository(repo)
    if host != "git.kernel.org":
        raise ValueError("title-only searches require a git.kernel.org cgit repository")
    query = urllib.parse.urlencode({"qt": "grep", "q": title})
    return f"{base}/log/?{query}"


def resolve_one(key: str, fix: dict) -> dict:
    title = normalize_title(fix.get("title") or "")
    repo = fix.get("repo") or "git://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git"
    result = {"bug_key": key, "title": title, "repo": repo, "status": "unresolved"}
    if not title:
        result["reason"] = "empty title"
        return result
    try:
        url = search_url(repo, title)
        result["search_url"] = url
        page = http_get(url, None, timeout=90).decode("utf-8", errors="replace")
    except Exception as exc:
        result["reason"] = f"search failed: {exc}"
        return result

    candidates: dict[str, str] = {}
    for match in re.finditer(
        r"href=['\"][^'\"]*commit/\?id=([0-9a-f]{40})[^'\"]*['\"][^>]*>(.*?)</a>",
        page,
        re.I | re.S,
    ):
        commit_hash, subject = match.group(1).lower(), normalize_title(match.group(2))
        if subject == title:
            candidates[commit_hash] = subject
    if len(candidates) != 1:
        result["reason"] = f"exact matches={len(candidates)}"
        result["candidate_hashes"] = sorted(candidates)
        result["response_excerpt"] = normalize_title(page[:500])[:300]
        return result

    commit_hash = next(iter(candidates))
    result["hash"] = commit_hash
    result["commit_url"] = normalize_repo_url(repo).rstrip("/") + f"/commit/?id={commit_hash}"
    if fetch_patch(commit_hash, repo):
        result["status"] = "resolved"
        result["resolution"] = "exact commit-subject match in declared repository"
    else:
        result["reason"] = "commit matched but patch download failed"
    return result


def load_jobs() -> list[tuple[str, dict]]:
    jobs = []
    for path in sorted(BUG_JSON.glob("*.json")):
        if not KEY_RE.fullmatch(path.stem):
            continue
        try:
            bug = parse_bug_json(path.read_bytes())
        except (PayloadError, OSError):
            continue
        for fix in bug.get("fix-commits") or []:
            if fix.get("title") and not fix.get("hash"):
                jobs.append((path.stem, fix))
    return jobs


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int)
    parser.add_argument("--workers", type=int, default=4)
    args = parser.parse_args()
    if args.workers < 1 or (args.limit is not None and args.limit < 1):
        parser.error("--workers and --limit must be positive")
    writable_path(OUTPUT)
    with _exclusive_update_lock(PROCESSED.parent):
        _run(args)


def _run(args: argparse.Namespace) -> None:
    jobs = load_jobs()
    if args.limit:
        jobs = jobs[: args.limit]
    prior = json.loads(OUTPUT.read_text()) if OUTPUT.exists() else {"resolutions": []}
    if not isinstance(prior, dict) or not isinstance(prior.get("resolutions"), list):
        raise PayloadError("resolution file must contain a resolutions list")
    if any(not isinstance(result, dict) for result in prior["resolutions"]):
        raise PayloadError("resolution file contains a non-object entry")
    by_identity = {
        (result.get("bug_key"), result.get("title"), result.get("repo")): result
        for result in prior["resolutions"]
    }
    log(f"searching {len(jobs)} title-only fix records")
    resolved = 0
    for done, (_, future) in enumerate(
        bounded_results(jobs, lambda job: resolve_one(*job), workers=args.workers), start=1
    ):
        result = future.result()
        by_identity[(result["bug_key"], result["title"], result["repo"])] = result
        resolved += result.get("status") == "resolved"
        if done % 20 == 0 or done == len(jobs):
            log(f"  title resolution {done}/{len(jobs)} resolved={resolved}")
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "method": "exact commit-subject match in declared kernel cgit repository",
        "resolutions": sorted(
            by_identity.values(),
            key=lambda r: (r.get("bug_key", ""), r.get("title", ""), r.get("repo", "")),
        ),
    }
    write_text(OUTPUT, json.dumps(payload, indent=2, ensure_ascii=False) + "\n")
    log(
        json.dumps(
            {
                "output": str(OUTPUT),
                "attempted": len(jobs),
                "resolved_this_run": resolved,
                "resolved_total": sum(
                    r.get("status") == "resolved" for r in payload["resolutions"]
                ),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
