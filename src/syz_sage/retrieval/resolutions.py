"""Match supplemental fix resolutions to current title-only fix references."""

from __future__ import annotations

import html
import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Any

from syz_sage.parsing.listing import (
    HASH_RE,
    KEY_RE,
    MAX_BUG_KEY_LENGTH,
    PayloadError,
    decode_json_object,
    effective_fixes,
)

ResolutionTargets = dict[str, set[tuple[str, str]]]
PatchResolutions = dict[tuple[str, str, str], tuple[str, str | None]]
_TAGS = re.compile(r"<[^>]+>")


if TYPE_CHECKING:
    from syz_sage.database.ingestion import FileInventory


def normalize_fix_title(value: Any) -> str:
    text = "" if value is None else str(value)
    return " ".join(html.unescape(_TAGS.sub("", text)).split())


def resolution_identity(resolution: Mapping[str, Any]) -> tuple[str, str, str]:
    key = resolution.get("bug_key", resolution.get("key"))
    repo = resolution.get("repo")
    return (
        "" if key is None else str(key),
        normalize_fix_title(resolution.get("title")),
        "" if repo is None else str(repo),
    )


def resolution_targets(
    records: Sequence[Mapping[str, Any]],
    details: Mapping[str, Mapping[str, Any]],
) -> ResolutionTargets:
    """Collect exact title/repository identities still lacking a reported hash."""
    targets: ResolutionTargets = {}
    for record in records:
        key = str(record["key"])
        for fix in effective_fixes(record, details.get(key)):
            if fix.get("hash"):
                continue
            _, title, repo = resolution_identity(fix)
            if title:
                targets.setdefault(key, set()).add((title, repo))
    return targets


def resolution_matches(
    resolution: Mapping[str, Any], targets: Mapping[str, set[tuple[str, str]]]
) -> bool:
    key, title, repo = resolution_identity(resolution)
    return (title, repo) in targets.get(key, set())


def load_patch_resolutions(
    path: Path,
    targets: ResolutionTargets,
    selected_keys: set[str],
    inventory: FileInventory | None = None,
    accepted: Sequence[Mapping[str, Any]] = (),
) -> tuple[PatchResolutions, list[dict[str, str]]]:
    """Read current resolved hashes, preserving their bug/title/repository identity."""

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
        return jobs, []
    except (OSError, PayloadError) as exc:
        return jobs, [{"kind": "resolution-metadata", "key": "", "error": str(exc)}]

    values = document.get("resolutions")
    if not isinstance(values, list):
        return jobs, [
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
    return jobs, failures


def unresolved_fix_keys(
    records: Sequence[Mapping[str, Any]],
    details: Mapping[str, Mapping[str, Any]],
    resolutions: Mapping[tuple[str, str, str], tuple[str, str | None]],
) -> set[str]:
    """Find bugs that need another detail check to discover a usable fix hash.

    Listing and cached detail data may name the same fix with and without a
    hash. An unambiguous reported hash or a matching supplemental resolution
    already supplies that reference; a missing patch file is retried separately.
    """
    missing: set[str] = set()
    for record in records:
        key = str(record["key"])
        fixes = effective_fixes(record, details.get(key))
        if not fixes:
            missing.add(key)
            continue
        reported: dict[tuple[str, str], set[str]] = {}
        for fix in fixes:
            commit_hash = str(fix.get("hash") or "").lower()
            if HASH_RE.fullmatch(commit_hash):
                _, title, repo = resolution_identity(fix)
                reported.setdefault((title, repo), set()).add(commit_hash)
        for fix in fixes:
            commit_hash = str(fix.get("hash") or "").lower()
            if HASH_RE.fullmatch(commit_hash):
                continue
            if commit_hash:
                # A malformed reference remains an indexing error even when
                # another source supplies a valid hash for the same title.
                missing.add(key)
                break
            _, title, repo = resolution_identity(fix)
            if title and len(reported.get((title, repo), ())) == 1:
                continue
            if not title or (key, title, repo) not in resolutions:
                missing.add(key)
                break
    return missing
