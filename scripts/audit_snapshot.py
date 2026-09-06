#!/usr/bin/env python3
"""Audit a local Syzbot fixed-bug snapshot without touching analysis outputs.

The audit is deliberately read-only except for an optional JSON result written
with ``--output``.  It checks the fixed listing/catalog bijection, per-bug JSON
and representative crash reports, and every patch named by the union of live
fix metadata and supplemental exact-title resolutions.

Exit status is zero when the only gaps are intrinsic upstream limitations
(bugs with no report link and fix records that still have only a title) or
retained historical patch files not referenced by today's metadata.  A
missing/corrupt required artifact or snapshot-integrity inconsistency returns
one.
"""

from __future__ import annotations

import argparse
import contextlib
import html
import json
import os
import re
import sys
import tempfile
from collections import Counter
from datetime import date, datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from .common import ROOT, writable_path

KEY_RE = re.compile(r"^(?:extid|id)-[A-Za-z0-9._~%+:-]+$")
HASH_RE = re.compile(r"^[0-9a-fA-F]{40}$")


def file_time_metadata(path: Path, today: date) -> dict[str, Any]:
    """Return UTC/local mtime fields used by the freshness proof."""
    try:
        stat = path.stat()
    except OSError as exc:
        return {
            "size": None,
            "mtime_utc": None,
            "mtime_date_utc": None,
            "mtime_local": None,
            "mtime_date_local": None,
            "mtime_is_today": False,
            "stat_error": str(exc),
        }
    modified_utc = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)
    modified_local = modified_utc.astimezone()
    return {
        "size": stat.st_size,
        "mtime_utc": modified_utc.isoformat(),
        "mtime_date_utc": modified_utc.date().isoformat(),
        "mtime_local": modified_local.isoformat(),
        "mtime_date_local": modified_local.date().isoformat(),
        "mtime_is_today": modified_local.date() == today,
        "stat_error": None,
    }


def generated_time_metadata(value: Any, today: date) -> dict[str, Any]:
    """Parse a JSON generated_at timestamp and compare its local date."""
    result: dict[str, Any] = {
        "generated_at": value,
        "generated_date_utc": None,
        "generated_date_local": None,
        "generated_is_today": False,
        "generated_at_error": None,
    }
    if not isinstance(value, str) or not value.strip():
        result["generated_at_error"] = "missing or not a non-empty string"
        return result
    candidate = value.strip()
    if candidate.endswith("Z"):
        candidate = candidate[:-1] + "+00:00"
    try:
        generated = datetime.fromisoformat(candidate)
    except ValueError as exc:
        result["generated_at_error"] = f"invalid ISO timestamp: {exc}"
        return result
    if generated.tzinfo is None:
        result["generated_at_error"] = "timestamp has no timezone"
        return result
    generated_utc = generated.astimezone(timezone.utc)
    generated_local = generated.astimezone()
    result.update(
        {
            "generated_date_utc": generated_utc.date().isoformat(),
            "generated_date_local": generated_local.date().isoformat(),
            "generated_is_today": generated_local.date() == today,
        }
    )
    return result


def load_json(path: Path) -> tuple[Any | None, str | None]:
    """Return parsed JSON and a stable, human-readable error."""
    if not path.exists():
        return None, "missing"
    if not path.is_file():
        return None, "not a regular file"
    try:
        raw = path.read_bytes()
    except OSError as exc:
        return None, f"read error: {exc}"
    if not raw:
        return None, "empty file"
    try:
        return json.loads(raw.decode("utf-8")), None
    except UnicodeDecodeError as exc:
        return None, f"UTF-8 decode error: {exc}"
    except json.JSONDecodeError as exc:
        return None, f"JSON parse error at line {exc.lineno}, column {exc.colno}: {exc.msg}"


def atomic_write(path: Path, text: str) -> None:
    """Atomically replace *path* with UTF-8 text in the same directory."""
    path = writable_path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            prefix=f".{path.name}.",
            suffix=".tmp",
            dir=path.parent,
            delete=False,
        ) as temporary:
            temporary_name = temporary.name
            temporary.write(text)
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temporary_name, path)
        temporary_name = None
    finally:
        if temporary_name is not None:
            with contextlib.suppress(FileNotFoundError):
                Path(temporary_name).unlink()


def normalize_title(value: str) -> str:
    """Use the resolver's title normalization for cross-source identities."""
    value = html.unescape(re.sub(r"<[^>]+>", "", value))
    return " ".join(value.split()).strip()


def key_from_link(value: Any) -> tuple[str | None, str | None]:
    if not isinstance(value, str) or not value:
        return None, "link is not a non-empty string"
    try:
        candidates = [
            (name, item)
            for name, item in parse_qsl(urlsplit(value).query, keep_blank_values=True)
            if name in {"extid", "id"}
        ]
    except ValueError as exc:
        return None, f"invalid link: {exc}"
    if len(candidates) != 1:
        return None, f"expected exactly one extid/id query key, found {len(candidates)}"
    name, item = candidates[0]
    key = f"{name}-{item}"
    if not item or not KEY_RE.fullmatch(key):
        return None, "invalid extid/id value"
    return key, None


def is_safe_key(value: Any) -> bool:
    return isinstance(value, str) and bool(KEY_RE.fullmatch(value))


def looks_like_html(data: bytes) -> bool:
    stripped = data.lstrip()
    if stripped.startswith(b"\xef\xbb\xbf"):
        stripped = stripped[3:].lstrip()
    prefix = stripped[:16384].lower()
    # Error pages may put an XML declaration or comments before the first HTML
    # element.  Peel those wrappers before testing the leading element.
    xml_declaration = re.match(rb"<\?xml\b.*?\?>", prefix, re.DOTALL)
    if xml_declaration:
        prefix = prefix[xml_declaration.end() :].lstrip()
    while prefix.startswith(b"<!--"):
        end = prefix.find(b"-->")
        if end < 0:
            break
        prefix = prefix[end + 3 :].lstrip()
    return bool(
        re.match(
            rb"(?:<!doctype\s+html\b|<(?:html|head|body|title|meta|link|script|style|"
            rb"div|span|main|section|article|header|footer|nav|form|table|pre|p|a|ul|"
            rb"ol|li|iframe|h[1-6])\b)",
            prefix,
        )
    )


class BugLinkParser(HTMLParser):
    """Collect href attributes from anchors whose URL path is exactly /bug."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.bug_hrefs: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "a":
            return
        href = next((value for name, value in attrs if name.lower() == "href"), None)
        if not href:
            return
        try:
            path = urlsplit(href).path
        except ValueError:
            # Keep syntactically broken anchors that visibly target the bug
            # endpoint so inspect_html_listing can report them precisely.
            if href.startswith("/bug?") or re.match(
                r"^https?://[^/]+/bug(?:[?#]|$)", href, re.IGNORECASE
            ):
                self.bug_hrefs.append(href)
            return
        if path == "/bug":
            self.bug_hrefs.append(href)


def inspect_html_listing(path: Path) -> dict[str, Any]:
    result: dict[str, Any] = {
        "read_error": None,
        "looks_like_html": False,
        "bug_link_count": 0,
        "keys": [],
        "duplicate_keys": [],
        "invalid_bug_links": [],
        "key_container_valid": False,
    }
    if not path.exists():
        result["read_error"] = "missing"
        return result
    if not path.is_file():
        result["read_error"] = "not a regular file"
        return result
    try:
        data = path.read_bytes()
    except OSError as exc:
        result["read_error"] = f"read error: {exc}"
        return result
    if not data.strip():
        result["read_error"] = "empty or whitespace-only"
        return result
    result["looks_like_html"] = looks_like_html(data)
    if not result["looks_like_html"]:
        result["read_error"] = "content does not look like HTML"
        return result
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        result["read_error"] = f"UTF-8 decode error: {exc}"
        return result
    parser = BugLinkParser()
    try:
        parser.feed(text)
        parser.close()
    except Exception as exc:
        result["read_error"] = f"HTML parse error: {exc}"
        return result
    result["bug_link_count"] = len(parser.bug_hrefs)
    keys: list[str] = []
    for index, href in enumerate(parser.bug_hrefs):
        key, error = key_from_link(href)
        if error:
            result["invalid_bug_links"].append({"index": index, "href": href, "error": error})
        else:
            assert key is not None
            keys.append(key)
    counts = Counter(keys)
    result["keys"] = sorted(counts)
    result["duplicate_keys"] = [
        {"key": key, "count": count} for key, count in sorted(counts.items()) if count > 1
    ]
    if not parser.bug_hrefs:
        result["read_error"] = "HTML contains no /bug links"
    result["key_container_valid"] = result["read_error"] is None and not result["invalid_bug_links"]
    return result


def validate_report(path: Path) -> tuple[bool, str | None, int | None]:
    if not path.exists():
        return False, "missing", None
    if not path.is_file():
        return False, "not a regular file", None
    try:
        data = path.read_bytes()
    except OSError as exc:
        return False, f"read error: {exc}", None
    if not data.strip():
        return False, "empty or whitespace-only", len(data)
    if looks_like_html(data):
        return False, "HTML response", len(data)
    return True, None, len(data)


def validate_patch(path: Path) -> tuple[bool, str | None, int | None]:
    if not path.exists():
        return False, "missing", None
    if not path.is_file():
        return False, "not a regular file", None
    try:
        data = path.read_bytes()
    except OSError as exc:
        return False, f"read error: {exc}", None
    if len(data) <= 40:
        return False, "file is not larger than 40 bytes", len(data)
    if looks_like_html(data):
        return False, "HTML response", len(data)
    if b"diff --git" not in data:
        return False, "missing 'diff --git' marker", len(data)
    return True, None, len(data)


def validate_fix_list(
    value: Any,
    *,
    location: str,
    errors: list[dict[str, Any]],
) -> bool:
    if not isinstance(value, list):
        errors.append({"location": location, "error": "must be a list"})
        return False
    valid = True
    for index, fix in enumerate(value):
        item_location = f"{location}[{index}]"
        if not isinstance(fix, dict):
            errors.append({"location": item_location, "error": "must be an object"})
            valid = False
            continue
        if "title" not in fix or not isinstance(fix.get("title"), str):
            errors.append({"location": f"{item_location}.title", "error": "must be a string"})
            valid = False
        for field in ("hash", "repo", "link"):
            if field in fix and fix[field] is not None and not isinstance(fix[field], str):
                errors.append({"location": f"{item_location}.{field}", "error": "must be a string"})
                valid = False
    return valid


def inspect_upstream(payload: Any) -> dict[str, Any]:
    result: dict[str, Any] = {
        "record_count": 0,
        "key_container_valid": False,
        "keys": [],
        "duplicate_keys": [],
        "invalid_records": [],
        "shape_errors": [],
        "titles_by_key": {},
        "records": [],
        "version": None,
    }
    if not isinstance(payload, dict):
        result["shape_errors"].append({"location": "$", "error": "must be an object"})
        return result
    result["version"] = payload.get("version")
    if (
        "version" not in payload
        or isinstance(payload.get("version"), bool)
        or not isinstance(payload.get("version"), (int, str))
    ):
        result["shape_errors"].append(
            {"location": "$.version", "error": "must be a string or integer"}
        )
    if "Bugs" in payload:
        bugs = payload["Bugs"]
        if "bugs" in payload:
            result["shape_errors"].append(
                {"location": "$", "error": "contains both 'Bugs' and 'bugs'"}
            )
    elif "bugs" in payload:
        bugs = payload["bugs"]
    else:
        result["shape_errors"].append({"location": "$", "error": "missing 'Bugs'/'bugs' list"})
        return result
    if not isinstance(bugs, list):
        result["shape_errors"].append({"location": "$.Bugs", "error": "must be a list"})
        return result
    result["key_container_valid"] = "Bugs" not in payload or "bugs" not in payload
    result["record_count"] = len(bugs)
    keys: list[str] = []
    for index, record in enumerate(bugs):
        location = f"$.Bugs[{index}]"
        if not isinstance(record, dict):
            result["invalid_records"].append({"index": index, "error": "record must be an object"})
            continue
        key, key_error = key_from_link(record.get("link"))
        if key_error:
            result["invalid_records"].append({"index": index, "error": key_error})
            continue
        assert key is not None
        title = record.get("title")
        if not isinstance(title, str) or not title:
            result["shape_errors"].append(
                {"location": f"{location}.title", "error": "must be a non-empty string"}
            )
        validate_fix_list(
            record.get("fix-commits"),
            location=f"{location}.fix-commits",
            errors=result["shape_errors"],
        )
        keys.append(key)
        result["titles_by_key"].setdefault(key, []).append(
            title if isinstance(title, str) else None
        )
        result["records"].append((key, record, index))
    counts = Counter(keys)
    result["keys"] = sorted(counts)
    result["duplicate_keys"] = [
        {"key": key, "count": count} for key, count in sorted(counts.items()) if count > 1
    ]
    return result


def inspect_catalog(payload: Any) -> dict[str, Any]:
    result: dict[str, Any] = {
        "record_count": 0,
        "key_container_valid": False,
        "keys": [],
        "duplicate_keys": [],
        "invalid_records": [],
        "shape_errors": [],
        "link_key_mismatches": [],
        "primary_fix_hash_mismatches": [],
        "titles_by_key": {},
        "records": [],
        "source_version": None,
    }
    if not isinstance(payload, dict):
        result["shape_errors"].append({"location": "$", "error": "must be an object"})
        return result
    result["source_version"] = payload.get("source_version")
    if (
        "source_version" not in payload
        or isinstance(payload.get("source_version"), bool)
        or not isinstance(payload.get("source_version"), (int, str))
    ):
        result["shape_errors"].append(
            {"location": "$.source_version", "error": "must be a string or integer"}
        )
    bugs = payload.get("bugs")
    if not isinstance(bugs, list):
        result["shape_errors"].append({"location": "$.bugs", "error": "must be a list"})
        return result
    result["key_container_valid"] = True
    result["record_count"] = len(bugs)
    keys: list[str] = []
    for index, record in enumerate(bugs):
        location = f"$.bugs[{index}]"
        if not isinstance(record, dict):
            result["invalid_records"].append({"index": index, "error": "record must be an object"})
            continue
        key = record.get("key")
        if not is_safe_key(key):
            result["invalid_records"].append(
                {"index": index, "error": "invalid or unsafe key", "value": key}
            )
            continue
        assert isinstance(key, str)
        title = record.get("title")
        if not isinstance(title, str) or not title:
            result["shape_errors"].append(
                {"location": f"{location}.title", "error": "must be a non-empty string"}
            )
        for field in ("bug_url", "json_url"):
            linked_key, link_error = key_from_link(record.get(field))
            if link_error:
                result["shape_errors"].append(
                    {"location": f"{location}.{field}", "error": link_error}
                )
            elif linked_key != key:
                result["link_key_mismatches"].append(
                    {"index": index, "key": key, "field": field, "link_key": linked_key}
                )
        fixes = record.get("fix_commits")
        validate_fix_list(
            fixes,
            location=f"{location}.fix_commits",
            errors=result["shape_errors"],
        )
        primary = record.get("primary_fix_hash")
        if primary is not None and not isinstance(primary, str):
            result["shape_errors"].append(
                {"location": f"{location}.primary_fix_hash", "error": "must be a string"}
            )
        elif isinstance(fixes, list):
            hashes = [
                fix.get("hash")
                for fix in fixes
                if isinstance(fix, dict) and isinstance(fix.get("hash"), str) and fix.get("hash")
            ]
            expected_primary = hashes[0] if hashes else ""
            if (primary or "") != expected_primary:
                result["primary_fix_hash_mismatches"].append(
                    {
                        "index": index,
                        "key": key,
                        "primary_fix_hash": primary,
                        "expected_from_fix_commits": expected_primary,
                    }
                )
        keys.append(key)
        result["titles_by_key"].setdefault(key, []).append(
            title if isinstance(title, str) else None
        )
        result["records"].append((key, record, index))
    counts = Counter(keys)
    result["keys"] = sorted(counts)
    result["duplicate_keys"] = [
        {"key": key, "count": count} for key, count in sorted(counts.items()) if count > 1
    ]
    return result


def validate_bug_shape(key: str, bug: Any) -> list[dict[str, Any]]:
    errors: list[dict[str, Any]] = []
    if not isinstance(bug, dict):
        return [{"location": "$", "error": "must be an object"}]
    title = bug.get("title")
    if not isinstance(title, str) or not title:
        errors.append({"location": "$.title", "error": "must be a non-empty string"})
    validate_fix_list(bug.get("fix-commits"), location="$.fix-commits", errors=errors)
    crashes = bug.get("crashes")
    if not isinstance(crashes, list):
        errors.append({"location": "$.crashes", "error": "must be a list"})
    else:
        for index, crash in enumerate(crashes):
            if not isinstance(crash, dict):
                errors.append({"location": f"$.crashes[{index}]", "error": "must be an object"})
                continue
            link = crash.get("crash-report-link")
            if link is not None and not isinstance(link, str):
                errors.append(
                    {
                        "location": f"$.crashes[{index}].crash-report-link",
                        "error": "must be a string",
                    }
                )
    return errors


def paths_with_suffix(directory: Path, suffix: str) -> dict[str, Path]:
    if not directory.is_dir():
        return {}
    return {
        path.stem: path for path in sorted(directory.glob(f"*{suffix}"), key=lambda item: item.name)
    }


def add_issue(
    issues: list[dict[str, Any]],
    code: str,
    items: list[Any] | None = None,
    *,
    count: int | None = None,
    detail: str | None = None,
) -> None:
    actual_count = count if count is not None else len(items or [])
    if actual_count <= 0:
        return
    issue: dict[str, Any] = {"code": code, "count": actual_count}
    if detail:
        issue["detail"] = detail
    issues.append(issue)


def audit(root: Path) -> dict[str, Any]:
    audit_time_utc = datetime.now(timezone.utc)
    audit_time_local = audit_time_utc.astimezone()
    today_local = audit_time_local.date()
    upstream_path = root / "data/raw/upstream_fixed.json"
    upstream_html_path = root / "data/raw/upstream_fixed.html"
    catalog_path = root / "data/processed/catalog.json"
    resolution_path = root / "data/processed/resolved_fix_hashes.json"
    bug_dir = root / "data/raw/bugs"
    report_dir = root / "data/artifacts/reports"
    patch_dir = root / "data/artifacts/patches"

    actionable: list[dict[str, Any]] = []
    source_state: dict[str, Any] = {}

    upstream_payload, upstream_error = load_json(upstream_path)
    source_state["upstream_fixed"] = {
        "path": str(upstream_path),
        "exists": upstream_path.exists(),
        "parse_error": upstream_error,
        **file_time_metadata(upstream_path, today_local),
    }
    if upstream_error:
        add_issue(actionable, "upstream_fixed_unreadable", count=1, detail=upstream_error)
        upstream = inspect_upstream(None)
    else:
        upstream = inspect_upstream(upstream_payload)
    source_state["upstream_fixed"]["shape_valid"] = not (
        upstream["shape_errors"] or upstream["invalid_records"]
    )
    add_issue(actionable, "upstream_shape_errors", upstream["shape_errors"])
    add_issue(actionable, "upstream_invalid_records", upstream["invalid_records"])
    add_issue(actionable, "upstream_duplicate_keys", upstream["duplicate_keys"])

    catalog_payload, catalog_error = load_json(catalog_path)
    source_state["catalog"] = {
        "path": str(catalog_path),
        "exists": catalog_path.exists(),
        "parse_error": catalog_error,
        **file_time_metadata(catalog_path, today_local),
    }
    if catalog_error:
        add_issue(actionable, "catalog_unreadable", count=1, detail=catalog_error)
        catalog = inspect_catalog(None)
    else:
        catalog = inspect_catalog(catalog_payload)
    source_state["catalog"]["shape_valid"] = not (
        catalog["shape_errors"] or catalog["invalid_records"]
    )
    add_issue(actionable, "catalog_shape_errors", catalog["shape_errors"])
    add_issue(actionable, "catalog_invalid_records", catalog["invalid_records"])
    add_issue(actionable, "catalog_duplicate_keys", catalog["duplicate_keys"])
    add_issue(actionable, "catalog_link_key_mismatches", catalog["link_key_mismatches"])
    add_issue(
        actionable,
        "catalog_primary_fix_hash_mismatches",
        catalog["primary_fix_hash_mismatches"],
    )

    catalog_generated = generated_time_metadata(
        catalog_payload.get("generated_at") if isinstance(catalog_payload, dict) else None,
        today_local,
    )
    source_state["catalog"].update(catalog_generated)

    html_listing = inspect_html_listing(upstream_html_path)
    source_state["upstream_fixed_html"] = {
        "path": str(upstream_html_path),
        "exists": upstream_html_path.exists(),
        "read_error": html_listing["read_error"],
        "looks_like_html": html_listing["looks_like_html"],
        "shape_valid": html_listing["key_container_valid"],
        "bug_link_count": html_listing["bug_link_count"],
        "unique_key_count": len(html_listing["keys"]),
        **file_time_metadata(upstream_html_path, today_local),
    }
    if html_listing["read_error"]:
        add_issue(
            actionable,
            "upstream_fixed_html_unreadable",
            count=1,
            detail=html_listing["read_error"],
        )
    add_issue(
        actionable,
        "upstream_fixed_html_invalid_bug_links",
        html_listing["invalid_bug_links"],
    )
    add_issue(
        actionable,
        "upstream_fixed_html_duplicate_keys",
        html_listing["duplicate_keys"],
    )

    freshness_failures: list[dict[str, Any]] = []
    for source_name in ("upstream_fixed", "upstream_fixed_html", "catalog"):
        state = source_state[source_name]
        if not state["mtime_is_today"]:
            freshness_failures.append(
                {
                    "source": source_name,
                    "field": "mtime",
                    "timestamp_utc": state["mtime_utc"],
                    "date_local": state["mtime_date_local"],
                    "expected_date_local": today_local.isoformat(),
                    "error": state["stat_error"],
                }
            )
    if not catalog_generated["generated_is_today"]:
        freshness_failures.append(
            {
                "source": "catalog",
                "field": "generated_at",
                "timestamp": catalog_generated["generated_at"],
                "date_local": catalog_generated["generated_date_local"],
                "expected_date_local": today_local.isoformat(),
                "error": catalog_generated["generated_at_error"],
            }
        )
    add_issue(actionable, "snapshot_freshness_failures", freshness_failures)

    upstream_keys = set(upstream["keys"])
    catalog_keys = set(catalog["keys"])
    html_keys = set(html_listing["keys"])
    missing_catalog_keys = sorted(upstream_keys - catalog_keys)
    extra_catalog_keys = sorted(catalog_keys - upstream_keys)
    missing_html_keys_from_upstream = sorted(upstream_keys - html_keys)
    extra_html_keys_vs_upstream = sorted(html_keys - upstream_keys)
    missing_html_keys_from_catalog = sorted(catalog_keys - html_keys)
    extra_html_keys_vs_catalog = sorted(html_keys - catalog_keys)
    add_issue(actionable, "keys_missing_from_catalog", missing_catalog_keys)
    add_issue(actionable, "keys_extra_in_catalog", extra_catalog_keys)
    add_issue(
        actionable,
        "keys_missing_from_upstream_fixed_html_vs_json",
        missing_html_keys_from_upstream,
    )
    add_issue(
        actionable,
        "keys_extra_in_upstream_fixed_html_vs_json",
        extra_html_keys_vs_upstream,
    )
    add_issue(
        actionable,
        "keys_missing_from_upstream_fixed_html_vs_catalog",
        missing_html_keys_from_catalog,
    )
    add_issue(
        actionable,
        "keys_extra_in_upstream_fixed_html_vs_catalog",
        extra_html_keys_vs_catalog,
    )

    listing_title_mismatches: list[dict[str, Any]] = []
    for key in sorted(upstream_keys & catalog_keys):
        left = upstream["titles_by_key"].get(key, [])
        right = catalog["titles_by_key"].get(key, [])
        if len(left) == len(right) == 1 and left[0] != right[0]:
            listing_title_mismatches.append(
                {"key": key, "upstream_title": left[0], "catalog_title": right[0]}
            )
    add_issue(actionable, "upstream_catalog_title_mismatches", listing_title_mismatches)

    version_mismatch: dict[str, Any] | None = None
    if (
        upstream_error is None
        and catalog_error is None
        and upstream["version"] != catalog["source_version"]
    ):
        version_mismatch = {
            "upstream_version": upstream["version"],
            "catalog_source_version": catalog["source_version"],
        }
        add_issue(actionable, "source_version_mismatch", count=1)

    json_catalog_bijection_ok = (
        upstream_error is None
        and catalog_error is None
        and upstream["key_container_valid"]
        and catalog["key_container_valid"]
        and not any(
            (
                upstream["duplicate_keys"],
                catalog["duplicate_keys"],
                upstream["invalid_records"],
                catalog["invalid_records"],
                catalog["link_key_mismatches"],
                missing_catalog_keys,
                extra_catalog_keys,
            )
        )
        and upstream["record_count"] == catalog["record_count"]
    )
    bijection_ok = (
        json_catalog_bijection_ok
        and html_listing["key_container_valid"]
        and not html_listing["duplicate_keys"]
        and not missing_html_keys_from_upstream
        and not extra_html_keys_vs_upstream
        and not missing_html_keys_from_catalog
        and not extra_html_keys_vs_catalog
    )

    catalog_record_by_key: dict[str, dict[str, Any]] = {}
    for key, record, _ in catalog["records"]:
        if key not in catalog_record_by_key:
            catalog_record_by_key[key] = record

    local_bug_files = paths_with_suffix(bug_dir, ".json")
    orphan_bug_json = sorted(set(local_bug_files) - catalog_keys)
    missing_bug_json = sorted(catalog_keys - set(local_bug_files))
    corrupt_bug_json: list[str] = []
    corrupt_bug_json_details: list[dict[str, Any]] = []
    # Preserve safely parseable objects for fix-hash harvesting even when a
    # different part of their schema is bad.  The object remains corrupt for
    # acquisition purposes, but no discoverable patch dependency is hidden.
    parsed_bugs: dict[str, dict[str, Any]] = {}
    valid_bugs: dict[str, dict[str, Any]] = {}
    bug_title_mismatches: list[dict[str, Any]] = []
    for key in sorted(catalog_keys & set(local_bug_files)):
        path = local_bug_files[key]
        bug, error = load_json(path)
        if error:
            corrupt_bug_json.append(key)
            corrupt_bug_json_details.append({"key": key, "path": str(path), "error": error})
            continue
        if isinstance(bug, dict):
            parsed_bugs[key] = bug
        shape_errors = validate_bug_shape(key, bug)
        if shape_errors:
            corrupt_bug_json.append(key)
            corrupt_bug_json_details.append(
                {
                    "key": key,
                    "path": str(path),
                    "error": "shape error",
                    "shape_errors": shape_errors,
                }
            )
            continue
        assert isinstance(bug, dict)
        valid_bugs[key] = bug
        catalog_record = catalog_record_by_key.get(key)
        if catalog_record is not None and bug.get("title") != catalog_record.get("title"):
            bug_title_mismatches.append(
                {
                    "key": key,
                    "catalog_title": catalog_record.get("title"),
                    "bug_json_title": bug.get("title"),
                }
            )
    add_issue(actionable, "missing_bug_json", missing_bug_json)
    add_issue(actionable, "corrupt_bug_json", corrupt_bug_json)
    add_issue(actionable, "orphan_bug_json", orphan_bug_json)
    add_issue(actionable, "catalog_bug_json_title_mismatches", bug_title_mismatches)

    local_report_files = paths_with_suffix(report_dir, ".txt")
    no_report_link: list[str] = []
    reports_not_auditable = sorted(catalog_keys - set(valid_bugs))
    expected_report_keys: list[str] = []
    representative_report_links: dict[str, str] = {}
    for key, bug in sorted(valid_bugs.items()):
        selected: str | None = None
        for crash in bug.get("crashes") or []:
            link = crash.get("crash-report-link")
            if isinstance(link, str) and link.strip():
                selected = link.strip()
                break
        if selected is None:
            no_report_link.append(key)
        else:
            expected_report_keys.append(key)
            representative_report_links[key] = selected

    # A report is definitely orphaned if its bug is outside today's catalog or
    # fresh metadata proves that no report link exists.  Files belonging to
    # missing/corrupt bug JSON remain explicitly unclassified until that JSON
    # is reacquired, so the audit never recommends unsafe deletion.
    orphan_reports = sorted(
        (set(local_report_files) - catalog_keys) | (set(local_report_files) & set(no_report_link))
    )
    unclassified_reports = sorted(set(local_report_files) & set(reports_not_auditable))

    missing_reports: list[str] = []
    corrupt_reports: list[str] = []
    corrupt_report_details: list[dict[str, Any]] = []
    valid_reports: list[str] = []
    for key in expected_report_keys:
        path = report_dir / f"{key}.txt"
        valid, reason, size = validate_report(path)
        if valid:
            valid_reports.append(key)
        elif reason == "missing":
            missing_reports.append(key)
        else:
            corrupt_reports.append(key)
            corrupt_report_details.append(
                {"key": key, "path": str(path), "error": reason, "size": size}
            )
    add_issue(actionable, "missing_reports", missing_reports)
    add_issue(actionable, "corrupt_reports", corrupt_reports)
    add_issue(actionable, "orphan_reports", orphan_reports)

    identities: dict[tuple[str, str], dict[str, Any]] = {}
    base_identities: set[tuple[str, str]] = set()
    expected_hashes: set[str] = set()
    effective_hashes_by_bug: dict[str, set[str]] = {}
    hash_sources: dict[str, set[str]] = {}
    malformed_fix_records: list[dict[str, Any]] = []
    invalid_fix_hashes: list[dict[str, Any]] = []
    bugs_with_base_fix: set[str] = set()

    def add_hash(
        raw_hash: Any,
        *,
        source: str,
        bug_key: str,
        title: str,
        location: str,
    ) -> str | None:
        if raw_hash is None or raw_hash == "":
            return None
        if not isinstance(raw_hash, str) or not HASH_RE.fullmatch(raw_hash):
            invalid_fix_hashes.append(
                {
                    "bug_key": bug_key,
                    "title": title,
                    "source": source,
                    "location": location,
                    "value": raw_hash,
                }
            )
            return None
        commit_hash = raw_hash.lower()
        expected_hashes.add(commit_hash)
        effective_hashes_by_bug.setdefault(bug_key, set()).add(commit_hash)
        hash_sources.setdefault(commit_hash, set()).add(source)
        return commit_hash

    def ingest_fix(
        fix: Any,
        *,
        source: str,
        bug_key: str,
        location: str,
        base: bool,
    ) -> tuple[str, str] | None:
        if not isinstance(fix, dict):
            malformed_fix_records.append(
                {
                    "bug_key": bug_key,
                    "source": source,
                    "location": location,
                    "error": "not an object",
                }
            )
            return None
        raw_title = fix.get("title")
        title = normalize_title(raw_title) if isinstance(raw_title, str) else ""
        if not title:
            malformed_fix_records.append(
                {
                    "bug_key": bug_key,
                    "source": source,
                    "location": location,
                    "error": "missing or empty normalized title",
                }
            )
            add_hash(
                fix.get("hash"),
                source=source,
                bug_key=bug_key,
                title="",
                location=f"{location}.hash",
            )
            return None
        identity = (bug_key, title)
        entry = identities.setdefault(
            identity,
            {"bug_key": bug_key, "title": title, "sources": set(), "hashes": set()},
        )
        entry["sources"].add(source)
        commit_hash = add_hash(
            fix.get("hash"),
            source=source,
            bug_key=bug_key,
            title=title,
            location=f"{location}.hash",
        )
        if commit_hash:
            entry["hashes"].add(commit_hash)
        if base:
            base_identities.add(identity)
            bugs_with_base_fix.add(bug_key)
        return identity

    for key, record, index in catalog["records"]:
        fixes = record.get("fix_commits")
        primary_owner_identity: tuple[str, str] | None = None
        if isinstance(fixes, list):
            for fix_index, fix in enumerate(fixes):
                identity = ingest_fix(
                    fix,
                    source="catalog",
                    bug_key=key,
                    location=f"$.bugs[{index}].fix_commits[{fix_index}]",
                    base=True,
                )
                if (
                    primary_owner_identity is None
                    and identity is not None
                    and isinstance(fix, dict)
                    and fix.get("hash")
                ):
                    primary_owner_identity = identity
        primary = record.get("primary_fix_hash")
        if primary:
            title = primary_owner_identity[1] if primary_owner_identity else ""
            commit_hash = add_hash(
                primary,
                source="catalog.primary_fix_hash",
                bug_key=key,
                title=title,
                location=f"$.bugs[{index}].primary_fix_hash",
            )
            if commit_hash and primary_owner_identity:
                identities[primary_owner_identity]["hashes"].add(commit_hash)
                identities[primary_owner_identity]["sources"].add("catalog.primary_fix_hash")
            elif commit_hash:
                malformed_fix_records.append(
                    {
                        "bug_key": key,
                        "source": "catalog.primary_fix_hash",
                        "location": f"$.bugs[{index}].primary_fix_hash",
                        "error": "hash has no titled fix identity",
                    }
                )

    for key, bug in sorted(parsed_bugs.items()):
        fixes = bug.get("fix-commits")
        if isinstance(fixes, list):
            for fix_index, fix in enumerate(fixes):
                ingest_fix(
                    fix,
                    source="bug_json",
                    bug_key=key,
                    location=f"{key}.json:$.fix-commits[{fix_index}]",
                    base=True,
                )

    title_only_before_resolutions = {
        identity for identity in base_identities if not identities[identity]["hashes"]
    }
    resolution_payload: Any | None = None
    resolution_error: str | None = None
    resolution_shape_errors: list[dict[str, Any]] = []
    duplicate_resolution_identities: list[dict[str, Any]] = []
    orphan_resolutions: list[dict[str, Any]] = []
    resolution_identities: set[tuple[str, str]] = set()
    if resolution_path.exists():
        resolution_payload, resolution_error = load_json(resolution_path)
        if resolution_error:
            add_issue(
                actionable,
                "resolved_fix_hashes_unreadable",
                count=1,
                detail=resolution_error,
            )
        elif not isinstance(resolution_payload, dict):
            resolution_shape_errors.append({"location": "$", "error": "must be an object"})
        else:
            resolutions = resolution_payload.get("resolutions")
            if not isinstance(resolutions, list):
                resolution_shape_errors.append(
                    {"location": "$.resolutions", "error": "must be a list"}
                )
            else:
                resolution_counter: Counter[tuple[str, str]] = Counter()
                for index, resolution in enumerate(resolutions):
                    location = f"$.resolutions[{index}]"
                    if not isinstance(resolution, dict):
                        resolution_shape_errors.append(
                            {"location": location, "error": "must be an object"}
                        )
                        continue
                    bug_key = resolution.get("bug_key")
                    raw_title = resolution.get("title")
                    status = resolution.get("status")
                    entry_valid = True
                    if not is_safe_key(bug_key):
                        resolution_shape_errors.append(
                            {"location": f"{location}.bug_key", "error": "invalid or unsafe key"}
                        )
                        entry_valid = False
                    if not isinstance(raw_title, str) or not normalize_title(raw_title):
                        resolution_shape_errors.append(
                            {
                                "location": f"{location}.title",
                                "error": "must normalize to a non-empty string",
                            }
                        )
                        entry_valid = False
                    if not isinstance(status, str) or status not in {"resolved", "unresolved"}:
                        resolution_shape_errors.append(
                            {
                                "location": f"{location}.status",
                                "error": "must be 'resolved' or 'unresolved'",
                            }
                        )
                    if (
                        "hash" in resolution
                        and resolution["hash"] is not None
                        and not isinstance(resolution["hash"], str)
                    ):
                        resolution_shape_errors.append(
                            {"location": f"{location}.hash", "error": "must be a string"}
                        )
                    if status == "resolved" and not resolution.get("hash"):
                        resolution_shape_errors.append(
                            {"location": location, "error": "resolved entry has no hash"}
                        )
                    if not entry_valid:
                        continue
                    assert isinstance(bug_key, str) and isinstance(raw_title, str)
                    title = normalize_title(raw_title)
                    identity = (bug_key, title)
                    resolution_counter[identity] += 1
                    resolution_identities.add(identity)
                    if identity not in base_identities:
                        orphan_resolutions.append({"bug_key": bug_key, "title": title})
                    ingest_fix(
                        {"title": title, "hash": resolution.get("hash")},
                        source="resolved_fix_hashes",
                        bug_key=bug_key,
                        location=location,
                        base=False,
                    )
                duplicate_resolution_identities = [
                    {"bug_key": identity[0], "title": identity[1], "count": count}
                    for identity, count in sorted(resolution_counter.items())
                    if count > 1
                ]
    source_state["resolved_fix_hashes"] = {
        "path": str(resolution_path),
        "exists": resolution_path.exists(),
        "optional": True,
        "parse_error": resolution_error,
        "shape_valid": resolution_error is None and not resolution_shape_errors,
    }
    add_issue(actionable, "resolved_fix_hashes_shape_errors", resolution_shape_errors)
    add_issue(actionable, "duplicate_resolution_identities", duplicate_resolution_identities)
    add_issue(actionable, "orphan_resolutions", orphan_resolutions)
    add_issue(actionable, "malformed_fix_records", malformed_fix_records)
    add_issue(actionable, "invalid_fix_hashes", invalid_fix_hashes)

    unresolved_title_only = [
        {
            "bug_key": identity[0],
            "title": identity[1],
            "sources": sorted(identities[identity]["sources"]),
            "resolution_record_present": identity in resolution_identities,
        }
        for identity in sorted(base_identities)
        if not identities[identity]["hashes"]
    ]
    unattempted_title_only = [
        {"bug_key": identity[0], "title": identity[1]}
        for identity in sorted(title_only_before_resolutions - resolution_identities)
    ]
    identities_with_multiple_hashes = [
        {
            "bug_key": identity[0],
            "title": identity[1],
            "hashes": sorted(entry["hashes"]),
        }
        for identity, entry in sorted(identities.items())
        if len(entry["hashes"]) > 1
    ]
    bugs_without_fix_records = sorted(catalog_keys - bugs_with_base_fix)
    add_issue(actionable, "bugs_without_fix_records", bugs_without_fix_records)

    local_patch_files = paths_with_suffix(patch_dir, ".diff")
    orphan_patches = sorted(set(local_patch_files) - expected_hashes)
    missing_patches: list[str] = []
    corrupt_patches: list[str] = []
    corrupt_patch_details: list[dict[str, Any]] = []
    valid_patches: list[str] = []
    for commit_hash in sorted(expected_hashes):
        path = patch_dir / f"{commit_hash}.diff"
        valid, reason, size = validate_patch(path)
        if valid:
            valid_patches.append(commit_hash)
        elif reason == "missing":
            missing_patches.append(commit_hash)
        else:
            corrupt_patches.append(commit_hash)
            corrupt_patch_details.append(
                {
                    "hash": commit_hash,
                    "path": str(path),
                    "error": reason,
                    "size": size,
                    "sources": sorted(hash_sources.get(commit_hash, set())),
                }
            )
    add_issue(actionable, "missing_patches", missing_patches)
    add_issue(actionable, "corrupt_patches", corrupt_patches)

    valid_patch_set = set(valid_patches)
    identities_by_bug: dict[str, list[tuple[str, str]]] = {key: [] for key in catalog_keys}
    fix_identities_with_valid_patches: list[dict[str, Any]] = []
    for identity in sorted(base_identities):
        bug_key, title = identity
        identities_by_bug.setdefault(bug_key, []).append(identity)
        valid_identity_hashes = sorted(identities[identity]["hashes"] & valid_patch_set)
        if valid_identity_hashes:
            fix_identities_with_valid_patches.append(
                {
                    "bug_key": bug_key,
                    "title": title,
                    "valid_patch_hashes": valid_identity_hashes,
                }
            )

    bugs_without_effective_hash: list[str] = []
    bugs_without_valid_patch: list[str] = []
    bugs_with_unresolved_fix_identities: list[str] = []
    bugs_with_partial_fix_identity_coverage: list[str] = []
    bugs_with_all_fix_identities_covered: list[str] = []
    for bug_key in sorted(catalog_keys):
        bug_identities = identities_by_bug.get(bug_key, [])
        identity_hashes = [identities[identity]["hashes"] for identity in bug_identities]
        identity_valid_patches = [hashes & valid_patch_set for hashes in identity_hashes]
        bug_effective_hashes = effective_hashes_by_bug.get(bug_key, set())
        has_effective_hash = bool(bug_effective_hashes)
        has_valid_patch = bool(bug_effective_hashes & valid_patch_set)
        has_covered_identity = any(identity_valid_patches)
        has_unresolved_identity = any(not hashes for hashes in identity_hashes)
        if not has_effective_hash:
            bugs_without_effective_hash.append(bug_key)
        if not has_valid_patch:
            bugs_without_valid_patch.append(bug_key)
        if has_unresolved_identity:
            bugs_with_unresolved_fix_identities.append(bug_key)
        if has_unresolved_identity and has_covered_identity:
            bugs_with_partial_fix_identity_coverage.append(bug_key)
        if bug_identities and all(identity_valid_patches):
            bugs_with_all_fix_identities_covered.append(bug_key)

    bug_fix_coverage = {
        "definitions": {
            "effective_hash": "a syntactically valid 40-hex hash attributed to the bug by the metadata union",
            "valid_patch": "an effective hash whose local patch passes the patch validator",
            "unresolved_fix_identity": "a normalized (bug_key, title) identity with no effective hash",
            "partial_fix_identity_coverage": "at least one identity has a valid patch and at least one identity is unresolved",
            "all_fix_identities_covered": "the bug has at least one fix identity and every identity has at least one valid patch",
        },
        "current_catalog_bugs_without_any_effective_hash": {
            "count": len(bugs_without_effective_hash),
            "bugs": bugs_without_effective_hash,
        },
        "current_catalog_bugs_without_any_valid_patch": {
            "count": len(bugs_without_valid_patch),
            "bugs": bugs_without_valid_patch,
        },
        "current_catalog_bugs_with_unresolved_fix_identities": {
            "count": len(bugs_with_unresolved_fix_identities),
            "bugs": bugs_with_unresolved_fix_identities,
        },
        "current_catalog_bugs_with_partial_fix_identity_coverage": {
            "count": len(bugs_with_partial_fix_identity_coverage),
            "bugs": bugs_with_partial_fix_identity_coverage,
        },
        "current_catalog_bugs_with_all_fix_identities_covered": {
            "count": len(bugs_with_all_fix_identities_covered),
            "bugs": bugs_with_all_fix_identities_covered,
        },
        "fix_identities_with_valid_patches": {
            "count": len(fix_identities_with_valid_patches),
            "identities": fix_identities_with_valid_patches,
        },
    }

    orphan_lists = {
        "bug_json": orphan_bug_json,
        "reports": orphan_reports,
        "patches": orphan_patches,
        "resolutions": orphan_resolutions,
    }
    missing_lists = {
        "catalog_entries": missing_catalog_keys,
        "html_entries_vs_upstream_json": missing_html_keys_from_upstream,
        "html_entries_vs_catalog": missing_html_keys_from_catalog,
        "bug_json": missing_bug_json,
        "reports": missing_reports,
        "patches": missing_patches,
    }
    corrupt_lists = {
        "bug_json": corrupt_bug_json,
        "reports": corrupt_reports,
        "patches": corrupt_patches,
    }
    actionable_item_count = sum(issue["count"] for issue in actionable)
    result: dict[str, Any] = {
        "schema_version": 2,
        "audited_at": audit_time_utc.isoformat(),
        "root": str(root),
        "status": "ok" if not actionable else "actionable_gaps",
        "ok": not actionable,
        "exit_code": 0 if not actionable else 1,
        "summary": {
            "upstream_records": upstream["record_count"],
            "html_bug_links": html_listing["bug_link_count"],
            "html_unique_keys": len(html_keys),
            "catalog_records": catalog["record_count"],
            "catalog_unique_keys": len(catalog_keys),
            "json_catalog_bijection": json_catalog_bijection_ok,
            "snapshot_key_bijection": bijection_ok,
            "upstream_catalog_bijection": bijection_ok,
            "snapshot_fresh_today": not freshness_failures,
            "bug_json_valid": len(valid_bugs),
            "reports_expected": len(expected_report_keys),
            "reports_valid": len(valid_reports),
            "no_report_link": len(no_report_link),
            "fix_identities": len(base_identities),
            "unique_fix_hashes": len(expected_hashes),
            "patches_valid": len(valid_patches),
            "unresolved_title_only": len(unresolved_title_only),
            "bugs_without_effective_hash": len(bugs_without_effective_hash),
            "bugs_without_valid_patch": len(bugs_without_valid_patch),
            "bugs_with_unresolved_fix_identities": len(bugs_with_unresolved_fix_identities),
            "bugs_with_partial_fix_identity_coverage": len(bugs_with_partial_fix_identity_coverage),
            "bugs_with_all_fix_identities_covered": len(bugs_with_all_fix_identities_covered),
            "fix_identities_with_valid_patches": len(fix_identities_with_valid_patches),
            "actionable_issue_categories": len(actionable),
            "actionable_item_count": actionable_item_count,
        },
        "sources": source_state,
        "freshness": {
            "basis": "local calendar date",
            "audit_time_utc": audit_time_utc.isoformat(),
            "audit_time_local": audit_time_local.isoformat(),
            "required_date_local": today_local.isoformat(),
            "checks": [
                {
                    "source": source_name,
                    "field": "mtime",
                    "timestamp_utc": source_state[source_name]["mtime_utc"],
                    "date_utc": source_state[source_name]["mtime_date_utc"],
                    "date_local": source_state[source_name]["mtime_date_local"],
                    "is_today": source_state[source_name]["mtime_is_today"],
                }
                for source_name in ("upstream_fixed", "upstream_fixed_html", "catalog")
            ]
            + [
                {
                    "source": "catalog",
                    "field": "generated_at",
                    "timestamp": catalog_generated["generated_at"],
                    "date_utc": catalog_generated["generated_date_utc"],
                    "date_local": catalog_generated["generated_date_local"],
                    "is_today": catalog_generated["generated_is_today"],
                    "error": catalog_generated["generated_at_error"],
                }
            ],
            "ok": not freshness_failures,
            "failures": freshness_failures,
        },
        "upstream_catalog": {
            "bijection": bijection_ok,
            "json_catalog_bijection": json_catalog_bijection_ok,
            "upstream_record_count": upstream["record_count"],
            "catalog_record_count": catalog["record_count"],
            "upstream_duplicate_keys": upstream["duplicate_keys"],
            "catalog_duplicate_keys": catalog["duplicate_keys"],
            "upstream_invalid_records": upstream["invalid_records"],
            "catalog_invalid_records": catalog["invalid_records"],
            "upstream_shape_errors": upstream["shape_errors"],
            "catalog_shape_errors": catalog["shape_errors"],
            "catalog_link_key_mismatches": catalog["link_key_mismatches"],
            "catalog_primary_fix_hash_mismatches": catalog["primary_fix_hash_mismatches"],
            "missing_from_catalog": missing_catalog_keys,
            "extra_in_catalog": extra_catalog_keys,
            "title_mismatches": listing_title_mismatches,
            "source_version_mismatch": version_mismatch,
        },
        "html_listing": {
            "path": str(upstream_html_path),
            "valid": html_listing["key_container_valid"],
            "looks_like_html": html_listing["looks_like_html"],
            "read_error": html_listing["read_error"],
            "bug_link_count": html_listing["bug_link_count"],
            "unique_key_count": len(html_keys),
            "duplicate_keys": html_listing["duplicate_keys"],
            "invalid_bug_links": html_listing["invalid_bug_links"],
            "missing_vs_upstream_json": missing_html_keys_from_upstream,
            "extra_vs_upstream_json": extra_html_keys_vs_upstream,
            "missing_vs_catalog": missing_html_keys_from_catalog,
            "extra_vs_catalog": extra_html_keys_vs_catalog,
        },
        "bug_json": {
            "expected_count": len(catalog_keys),
            "valid_count": len(valid_bugs),
            "missing": missing_bug_json,
            "corrupt": corrupt_bug_json,
            "corrupt_details": corrupt_bug_json_details,
            "title_mismatches": bug_title_mismatches,
            "orphans": orphan_bug_json,
        },
        "reports": {
            "expected_count": len(expected_report_keys),
            "valid_count": len(valid_reports),
            "missing": missing_reports,
            "corrupt": corrupt_reports,
            "corrupt_details": corrupt_report_details,
            "no_report_link": no_report_link,
            "not_auditable_due_to_bug_json": reports_not_auditable,
            "unclassified_local_files_due_to_bug_json": unclassified_reports,
            "representative_selection": "first crash with a non-empty crash-report-link",
            "orphans": orphan_reports,
        },
        "fixes": {
            "identity_rule": "(bug_key, normalized_title)",
            "identity_count": len(base_identities),
            "unique_hash_count": len(expected_hashes),
            "unresolved_title_only": unresolved_title_only,
            "unattempted_title_only": unattempted_title_only,
            "bugs_without_fix_records": bugs_without_fix_records,
            "identities_with_multiple_hashes": identities_with_multiple_hashes,
            "invalid_hashes": invalid_fix_hashes,
            "malformed_records": malformed_fix_records,
            "resolution_shape_errors": resolution_shape_errors,
            "duplicate_resolution_identities": duplicate_resolution_identities,
            "orphan_resolutions": orphan_resolutions,
            "identities_with_valid_patches_count": len(fix_identities_with_valid_patches),
        },
        "bug_fix_coverage": bug_fix_coverage,
        "patches": {
            "validation": "size > 40 bytes, non-HTML, contains 'diff --git'",
            "expected_count": len(expected_hashes),
            "valid_count": len(valid_patches),
            "missing": missing_patches,
            "corrupt": corrupt_patches,
            "corrupt_details": corrupt_patch_details,
            "orphans": orphan_patches,
            "orphans_actionable": False,
        },
        "missing": missing_lists,
        "corrupt": corrupt_lists,
        "orphans": {
            "counts": {name: len(items) for name, items in orphan_lists.items()},
            "lists": orphan_lists,
        },
        "intrinsic_non_actionable": {
            "no_report_link": no_report_link,
            "unresolved_title_only": unresolved_title_only,
        },
        "retained_non_actionable": {
            "orphan_patches": orphan_patches,
            "reason": "historical supplemental patches are retained but not required by today's fix-hash union",
        },
        "actionable_issues": actionable,
    }
    return result


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=ROOT,
        help="project root (default: root containing this script)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="also atomically write the audit JSON to this path",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    root = args.root.resolve()
    result = audit(root)
    if args.output is not None:
        output_path = args.output
        if not output_path.is_absolute():
            output_path = Path.cwd() / output_path
        try:
            serialized = json.dumps(result, indent=2, ensure_ascii=False, sort_keys=True) + "\n"
            atomic_write(output_path, serialized)
        except (OSError, ValueError) as exc:
            result["actionable_issues"].append(
                {"code": "output_write_failed", "count": 1, "detail": str(exc)}
            )
            result["status"] = "actionable_gaps"
            result["ok"] = False
            result["exit_code"] = 1
            result["summary"]["actionable_issue_categories"] += 1
            result["summary"]["actionable_item_count"] += 1
    print(json.dumps(result, indent=2, ensure_ascii=False, sort_keys=True))
    return int(result["exit_code"])


if __name__ == "__main__":
    sys.exit(main())
