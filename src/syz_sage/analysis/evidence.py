"""Explain observed crash/patch relationships without asserting causation."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import asdict
from typing import Any

from ..parsing.characteristics import classify_characteristics


def location_relationship(crash: Mapping[str, Any], fix: Mapping[str, Any]) -> str:
    """Compare recorded paths and function hints, never cross-version line numbers."""
    path = crash.get("file_path")
    paths = {fix.get("old_file_path"), fix.get("new_file_path")} - {None, ""}
    if not path or not paths:
        return "unknown"
    if path not in paths:
        return "different-file"
    if crash.get("function_name") and crash["function_name"] == fix.get("function_name"):
        return "same-function"
    return "same-file"


def _report_lines(evidence: str, report: str) -> list[dict[str, Any]]:
    """Find the exact evidence lines, keeping original report coordinates."""
    rows = list(enumerate(report.splitlines(), 1))
    found: list[dict[str, Any]] = []
    after = 0
    for line in evidence.splitlines():
        if not line.strip():
            continue
        for number, raw in rows:
            if number > after and raw.strip() == line.strip():
                found.append({"report_line": number, "text": raw})
                after = number
                break
    return found


def _characteristics(bug: Mapping[str, Any], report: str) -> dict[str, dict[str, Any]]:
    classified = asdict(classify_characteristics(str(bug.get("title") or ""), report))
    saved = bug.get("characteristics") or {}
    result: dict[str, dict[str, Any]] = {}
    for name in ("family", "access_mode"):
        item = dict(saved.get(name) or classified[name])
        if item.get("source") == "report":
            item.setdefault("source_sha256", (bug.get("report") or {}).get("sha256"))
            item["report_lines"] = _report_lines(str(item.get("evidence") or ""), report)
        else:
            item.setdefault("source_sha256", None)
            item["report_lines"] = []
        result[name] = item
    return result


def _comparison(crash: Mapping[str, Any], fix: Mapping[str, Any]) -> dict[str, Any]:
    relationship = location_relationship(crash, fix)
    method = {
        "same-function": "equal saved source path and function name; patch function is inferred",
        "same-file": "equal saved source path; enclosing function match is not established",
        "different-file": "recorded crash path differs from both recorded patch paths",
        "unknown": "crash or patch source path is missing",
    }[relationship]
    return {
        "relationship": relationship,
        "method": method,
        # This confidence describes the relationship inference, not the cause.
        "confidence": "unknown" if relationship == "unknown" else "inferred",
        "crash_location": dict(crash),
        "fix_location": dict(fix),
    }


def _manifestation_matches(
    locations: Sequence[Mapping[str, Any]], frames: Sequence[Mapping[str, Any]]
) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    for frame in frames:
        if frame.get("section") != "manifestation" or not frame.get("function_name"):
            continue
        candidates = [
            location
            for location in locations
            if location.get("function_name") == frame["function_name"]
        ]
        if not candidates:
            continue
        exact = any(
            location_relationship(frame, location) == "same-function" for location in candidates
        )
        if (
            not exact
            and frame.get("file_path")
            and all(
                location.get("old_file_path") or location.get("new_file_path")
                for location in candidates
            )
        ):
            continue
        matches.append(
            {
                "frame": dict(frame),
                "method": "same file and function name"
                if exact
                else "function name only; path unavailable",
                "confidence": "inferred" if exact else "low",
            }
        )
    return matches


def _hunk_explanations(
    locations: Sequence[Mapping[str, Any]],
    crash_locations: Sequence[Mapping[str, Any]],
    frames: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    groups: dict[tuple[object, ...], list[dict[str, Any]]] = {}
    identities: set[tuple[object, ...]] = set()
    for item in locations:
        group = (
            item.get("old_file_path"),
            item.get("new_file_path"),
            item.get("hunk_header"),
            item.get("kind"),
        )
        # A fix referenced from two repositories can expose duplicate view rows.
        identity = (
            *group,
            item.get("old_start"),
            item.get("old_count"),
            item.get("new_start"),
            item.get("new_count"),
            item.get("function_name"),
            item.get("function_basis"),
        )
        if identity not in identities:
            groups.setdefault(group, []).append(dict(item))
            identities.add(identity)
    result: list[dict[str, Any]] = []
    for changes in groups.values():
        first = changes[0]
        hints: dict[tuple[object, ...], Mapping[str, Any]] = {}
        for change in changes:
            hints.setdefault(
                (
                    change.get("old_file_path"),
                    change.get("new_file_path"),
                    change.get("function_name"),
                ),
                change,
            )
        comparisons = [
            _comparison(crash, change) for crash in crash_locations for change in hints.values()
        ]
        labels = {item["relationship"] for item in comparisons}
        relationship = (
            "same-function"
            if "same-function" in labels
            else "same-file"
            if "same-file" in labels
            else "different-file"
            if labels == {"different-file"}
            else "unknown"
        )
        result.append(
            {
                "number": len(result) + 1,
                "old_file_path": first.get("old_file_path"),
                "new_file_path": first.get("new_file_path"),
                "hunk_header": first.get("hunk_header") or "",
                "kind": first.get("kind") or "unknown",
                "function_name": first.get("function_name"),
                "function_basis": first.get("function_basis") or "unknown",
                "relationship": relationship,
                "locations": changes,
                "comparisons": comparisons,
                "manifestation_stack_matches": _manifestation_matches(changes, frames),
            }
        )
    return result


def build_explanation(bug: Mapping[str, Any]) -> dict[str, Any]:
    """Build a traceable per-hunk explanation using only the supplied saved bug.

    Paths match exactly, including either side of a rename. Function labels are
    parser hints, not verified boundaries. Allocation/free/origin, other-task and
    unwind stacks never establish membership in the manifestation stack.
    """
    report = bug.get("report") or {}
    text = str(report.get("text") or "")
    characteristics = _characteristics(bug, text)
    crash_locations = [dict(item) for item in bug.get("crash_locations") or []]
    for location in crash_locations:
        location["report_lines"] = _report_lines(str(location.get("evidence") or ""), text)
    fixes: list[dict[str, Any]] = []
    for fix in bug.get("fixes") or bug.get("fix_commits") or []:
        commit_hash = fix.get("commit_hash") or fix.get("hash")
        locations = [
            item
            for item in bug.get("fix_locations") or []
            if commit_hash and item.get("commit_hash") == commit_hash
        ]
        fixes.append(
            {
                "commit_hash": commit_hash,
                "title": fix.get("title") or "",
                "repo": fix.get("repo") or "",
                "link": fix.get("link") or None,
                "patch_available": bool(fix.get("patch_available")),
                "hunks": _hunk_explanations(
                    locations, crash_locations, bug.get("crash_stack") or []
                ),
            }
        )
    return {
        "key": bug.get("key"),
        "title": bug.get("title"),
        "bug_url": bug.get("bug_url"),
        "crash": {
            "family": characteristics["family"],
            "operation": characteristics["access_mode"],
            "report_available": bool(report.get("available")),
            "report_url": report.get("source_url"),
            "report_sha256": report.get("sha256"),
            "locations": crash_locations,
        },
        "fixes": fixes,
        "limitations": [
            "Relationships describe saved paths and inferred function names; "
            "they do not establish causation.",
            "Crash and patch line numbers belong to potentially different kernel "
            "revisions and are not compared.",
            "A hunk heading or definition context is an inferred function hint, "
            "not a verified enclosing function.",
            "Only manifestation frames establish stack membership; allocation, free, "
            "origin, other-task and unwind frames are excluded.",
            "The retained representative report may not describe every crash "
            "recorded for this bug.",
        ],
    }
