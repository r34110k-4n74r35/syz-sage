"""Read-only comparisons and descriptive statistics for current fixed bugs."""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
from statistics import median
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .repository import Database


def _values(rows: Sequence[Mapping[str, Any]], *fields: str) -> set[str]:
    return {str(row[field]) for row in rows for field in fields if row.get(field)}


def _commits(bug: Mapping[str, Any]) -> set[str]:
    return {
        str(commit).lower()
        for fix in bug.get("fixes", [])
        if (commit := fix.get("commit_hash") or fix.get("hash"))
    }


def _connections(left: Mapping[str, Any], right: Mapping[str, Any]) -> list[dict[str, Any]]:
    reasons = []
    for kind, left_values, right_values in (
        ("same-fix-commit", _commits(left), _commits(right)),
        (
            "same-crash-function",
            _values(left.get("crash_locations", []), "function_name"),
            _values(right.get("crash_locations", []), "function_name"),
        ),
        (
            "same-fix-file",
            _values(left.get("fix_locations", []), "old_file_path", "new_file_path"),
            _values(right.get("fix_locations", []), "old_file_path", "new_file_path"),
        ),
        (
            "same-crash-file",
            _values(left.get("crash_locations", []), "file_path"),
            _values(right.get("crash_locations", []), "file_path"),
        ),
    ):
        shared = sorted(left_values & right_values)
        if shared:
            reasons.append({"kind": kind, "values": shared})
    # A broad failure family alone would swamp structural matches. It is an
    # additional observation only, never evidence of a shared cause.
    if (
        reasons
        and left.get("family") not in {None, "unknown"}
        and left["family"] == right.get("family")
    ):
        reasons.append({"kind": "same-failure-pattern", "values": [left["family"]]})
    return reasons


def _case(bug: Mapping[str, Any]) -> dict[str, Any]:
    fields = (
        "key",
        "title",
        "bug_url",
        "bug_type",
        "family",
        "access_mode",
        "subsystems",
        "c_reproducer_status",
        "c_reproducer_urls",
        "patch_urls",
        "fix_file_count",
        "patch_line_count",
        "crash_locations",
        "fix_locations",
        "characteristics",
    )
    result = {name: bug.get(name) for name in fields}
    result["fixes"] = [dict(fix) for fix in bug.get("fixes", [])]
    result["has_report"] = (
        bool(bug["has_report"])
        if "has_report" in bug
        else bool((bug.get("report") or {}).get("available"))
    )
    return result


def related_bugs(database: Database, key: str, *, limit: int = 10) -> dict[str, Any]:
    if type(limit) is not int or limit < 1:
        raise ValueError("--limit must be positive")
    database.initialize()
    with database._read_transaction():
        rows = database.research_rows()
        target = next((row for row in rows if row["key"] == key), None)
        if target is None:
            raise LookupError(f"Bug not found: {key}")
        matches = []
        for row in rows:
            if row["key"] == key:
                continue
            reasons = _connections(target, row)
            if reasons:
                matches.append({"bug": _case(row), "reasons": reasons})
        priorities = ("same-fix-commit", "same-crash-function", "same-fix-file", "same-crash-file")
        matches.sort(
            key=lambda item: (
                *(
                    -int(any(reason["kind"] == kind for reason in item["reasons"]))
                    for kind in priorities
                ),
                item["bug"]["key"],
            )
        )
        return {
            "bug": _case(target),
            "matches": matches[:limit],
            "total": len(matches),
            "limit": limit,
            "method": "Shared commit, crash function, fix file, then crash file; key breaks ties.",
            "interpretation": (
                "Shared evidence does not establish identical bugs or a common root cause."
            ),
        }


def compare_bugs(database: Database, left_key: str, right_key: str) -> dict[str, Any]:
    if left_key == right_key:
        raise ValueError("compare requires two different bug keys")
    database.initialize()
    with database._read_transaction():
        bugs = [database.get_bug(key) for key in (left_key, right_key)]
        for key, bug in zip((left_key, right_key), bugs, strict=True):
            if bug is None:
                raise LookupError(f"Bug not found: {key}")
        left, right = bugs
        assert left is not None and right is not None
        return {
            "left": _case(left),
            "right": _case(right),
            "shared_evidence": _connections(left, right),
            "differences": [
                {"field": field, "left": left.get(field), "right": right.get(field)}
                for field in (
                    "bug_type",
                    "family",
                    "access_mode",
                    "subsystems",
                    "c_reproducer_status",
                )
                if left.get(field) != right.get(field)
            ],
            "interpretation": (
                "Locations refer to each bug's kernel build; "
                "line numbers are not directly comparable across builds."
            ),
        }


def _distribution(values: Sequence[str]) -> list[dict[str, Any]]:
    return [
        {"value": value, "count": count}
        for value, count in sorted(Counter(values).items(), key=lambda item: (-item[1], item[0]))
    ]


def _numeric(values: Sequence[int | None]) -> dict[str, Any]:
    known = [value for value in values if value is not None]
    return {
        "known_bugs": len(known),
        "unknown_bugs": len(values) - len(known),
        "minimum": min(known) if known else None,
        "maximum": max(known) if known else None,
        "median": median(known) if known else None,
    }


def _relationship(bug: Mapping[str, Any]) -> str:
    from ..analysis.evidence import location_relationship

    crashes, fixes = bug.get("crash_locations", []), bug.get("fix_locations", [])
    kinds = {location_relationship(crash, fix) for crash in crashes for fix in fixes}
    for kind in ("same-function", "same-file"):
        if kind in kinds:
            return kind
    # A missing patch/location could conceal a nearer edit. Do not turn an
    # incomplete case into a confident cross-file classification.
    if kinds == {"different-file"} and bug.get("fix_file_count") is not None:
        return "different-file"
    return "unknown"


def statistics(database: Database, **criteria: Any) -> dict[str, Any]:
    """Describe all matches; never apply display pagination to the denominator."""
    if "limit" in criteria or "offset" in criteria:
        raise ValueError("statistics selection does not accept pagination")
    database.initialize()
    with database._read_transaction():
        rows = database.research_rows(**criteria)
        commits = [_commits(row) for row in rows]
        frequencies: dict[str, list[str]] = {
            "bug_types": [row.get("bug_type") or "other" for row in rows],
            "families": [row.get("family") or "unknown" for row in rows],
            "access_modes": [row.get("access_mode") or "unknown" for row in rows],
            "subsystems": [
                tag
                for row in rows
                for tag in sorted({str(tag).casefold() for tag in row.get("subsystems", [])})
            ],
            "crash_functions": [
                value
                for row in rows
                for value in sorted(_values(row.get("crash_locations", []), "function_name"))
            ],
            "fix_functions": [
                value
                for row in rows
                for value in sorted(_values(row.get("fix_locations", []), "function_name"))
            ],
            "fix_files": [
                path
                for row in rows
                for path in sorted(
                    {
                        str(location.get("new_file_path") or location.get("old_file_path"))
                        for location in row.get("fix_locations", [])
                        if location.get("new_file_path") or location.get("old_file_path")
                    }
                )
            ],
            "crash_fix_relationships": [_relationship(row) for row in rows],
        }
        return {
            "total_bugs": len(rows),
            "selection": criteria,
            "distinct_fix_commits": len(set().union(*commits)),
            "bug_commit_links": sum(len(value) for value in commits),
            "bugs_without_known_fix_hash": sum(not value for value in commits),
            "availability": {
                "report_available": sum(bool(row.get("has_report")) for row in rows),
                "report_unavailable": sum(not row.get("has_report") for row in rows),
                "patch_available": sum(bool(row.get("has_patch")) for row in rows),
                "patch_unavailable": sum(not row.get("has_patch") for row in rows),
                "c_reproducer": _distribution(
                    [row.get("c_reproducer_status") or "unknown" for row in rows]
                ),
                "untagged_bugs": sum(not row.get("subsystems") for row in rows),
            },
            "counts": {name: _distribution(values) for name, values in frequencies.items()},
            "fix_size": {
                "files_per_bug": _numeric([row.get("fix_file_count") for row in rows]),
                "changed_lines_per_bug": _numeric([row.get("patch_line_count") for row in rows]),
            },
            "counting_rules": [
                "Each distribution counts distinct bugs per value; "
                "tags, files, and functions may overlap.",
                "Commit totals count known hashes; bug-commit links count each hash once per bug.",
                "Patch size is per bug across its distinct fixes, "
                "excluding unknown/incomplete sizes. "
                "Renames use the new path; deletions use the old.",
                "Relationship counts describe the closest observed file/function match, "
                "not causation; functions may be inferred.",
                "C reproducer availability means a recorded URL, not a successful reproduction.",
                "These counts describe the selected fixed bugs, not subsystem reliability.",
            ],
        }
