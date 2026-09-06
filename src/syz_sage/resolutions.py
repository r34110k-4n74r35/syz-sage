"""Match supplemental fix resolutions to current title-only fix references."""

from __future__ import annotations

import html
import re
from collections.abc import Mapping, Sequence
from typing import Any

from .parsing import effective_fixes

ResolutionTargets = dict[str, set[tuple[str, str]]]
_TAGS = re.compile(r"<[^>]+>")


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
