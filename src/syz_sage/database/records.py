"""Pure normalization and validation of retrieved source records."""

from __future__ import annotations

import html
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from ..parsing.listing import (
    PayloadError,
    absolute_syzbot_url,
    validate_http_url,
)
from ..project.progress_events import ProgressCallback, progress_items
from .ingestion import UNPARSED

_MAX_BUG_KEY_LENGTH = 128


_HASH_RE = re.compile(r"^[0-9a-fA-F]{7,128}$")


_BUG_KEY_RE = re.compile(r"^(?:extid|id)-[A-Za-z0-9_%+~-](?:[A-Za-z0-9._%+~-]*[A-Za-z0-9_%+~-])?$")


_TAG_RE = re.compile(r"<[^>]+>")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _json_text(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


def _json_bytes(value: Any) -> bytes:
    return _json_text(value).encode("utf-8")


def _coerce_bytes(value: Any) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, memoryview):
        return value.tobytes()
    if isinstance(value, str):
        return value.encode("utf-8")
    return _json_bytes(value)


def _as_mapping(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    if is_dataclass(value) and not isinstance(value, type):
        dataclass_values = asdict(value)
        if isinstance(dataclass_values, dict):
            return dataclass_values
    try:
        attribute_values: dict[str, Any] | None = vars(value)
    except TypeError:
        attribute_values = None
    if attribute_values is not None:
        return {key: item for key, item in attribute_values.items() if not key.startswith("_")}
    fields = ("key", "title", "bug_url", "json_url", "fix_commits", "raw")
    out = {name: getattr(value, name) for name in fields if hasattr(value, name)}
    if out:
        return out
    raise TypeError(f"record is not mapping-like: {type(value).__name__}")


def _field(mapping: Mapping[str, Any], *names: str, default: Any = "") -> Any:
    for name in names:
        if name in mapping:
            value = mapping[name]
            return default if value is None else value
    return default


def _text(value: Any) -> str:
    if value is None:
        return ""
    return value if isinstance(value, str) else str(value)


def _normal_title(value: Any) -> str:
    cleaned = html.unescape(_TAG_RE.sub("", _text(value)))
    return " ".join(cleaned.split()).strip()


def _safe_file_key(value: str) -> bool:
    return len(value) <= _MAX_BUG_KEY_LENGTH and _BUG_KEY_RE.fullmatch(value) is not None


def _looks_like_html(data: bytes) -> bool:
    prefix = data.lstrip().lower()[:4096]
    if prefix.startswith(b"\xef\xbb\xbf"):
        prefix = prefix[3:].lstrip()
    return prefix.startswith((b"<!doctype html", b"<html", b"<head", b"<body", b"<?xml"))


def _validate_listing_html(data: bytes) -> str | None:
    if not data.strip():
        return "empty or whitespace-only HTML listing"
    if not _looks_like_html(data):
        return "listing does not look like HTML"
    lowered = data.lower()
    if b"<html" not in lowered or b"</html>" not in lowered:
        return "listing is missing a complete html element"
    return None


def _validate_report(data: bytes) -> str | None:
    if not data.strip():
        return "empty or whitespace-only report"
    if _looks_like_html(data):
        return "report response is HTML"
    return None


def _validate_patch(data: bytes) -> str | None:
    if len(data) <= 40:
        return "patch is not larger than 40 bytes"
    if _looks_like_html(data):
        return "patch response is HTML"
    if b"diff --git" not in data:
        return "patch is missing 'diff --git' marker"
    return None


def _key_from_link(link: Any) -> str:
    if not isinstance(link, str) or not link:
        return ""
    try:
        candidates = [
            (name, value)
            for name, value in parse_qsl(urlsplit(link).query, keep_blank_values=True)
            if name in {"id", "extid"}
        ]
    except ValueError:
        return ""
    if len(candidates) != 1 or not candidates[0][1]:
        return ""
    key = f"{candidates[0][0]}-{candidates[0][1]}"
    return key if _safe_file_key(key) else ""


def _absolute_syzbot_url(link: Any, dashboard: str = "https://syzkaller.appspot.com") -> str:
    value = _text(link)
    if not value:
        return ""
    if value.startswith(("http://", "https://")):
        return value
    return dashboard.rstrip("/") + "/" + value.lstrip("/")


def _dashboard_from_bug_url(value: Any) -> str:
    try:
        parsed = urlsplit(_text(value))
    except ValueError:
        return "https://syzkaller.appspot.com"
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return "https://syzkaller.appspot.com"
    path = parsed.path
    if path.endswith("/bug"):
        path = path[: -len("/bug")]
    return f"{parsed.scheme}://{parsed.netloc}{path.rstrip('/')}"


def _c_reproducer_fields(raw: Any, payload_kind: str, dashboard: str) -> dict[str, Any]:
    """Summarize recorded C links across this version's crashes without fetching.

    The original payload distinguishes missing metadata from an explicit crash
    list with no C link, and lets older databases reject malformed values that
    their permissive URL normalization may have converted into plausible URLs.
    """
    urls: list[str] = []
    unknown = (
        payload_kind != "bug-json"
        or not isinstance(raw, Mapping)
        or not isinstance(raw.get("crashes"), list)
    )
    if not unknown:
        for crash in raw["crashes"]:
            if not isinstance(crash, Mapping):
                unknown = True
                continue
            value = crash.get("c-reproducer")
            if value is None or value == "":
                continue
            if not isinstance(value, str):
                unknown = True
                continue
            try:
                url = absolute_syzbot_url(value, dashboard)
            except PayloadError:
                unknown = True
                continue
            if url and url not in urls:
                urls.append(url)
    return {
        "c_reproducer_status": "available" if urls else "unknown" if unknown else "not_provided",
        "c_reproducer_urls": urls,
    }


def _patch_urls(fixes: Sequence[Mapping[str, Any]]) -> list[str]:
    """Collect recorded patch sources, falling back to saved fix commit links."""
    urls: list[str] = []
    for fix in fixes:
        for candidate in (fix.get("patch_source_url"), fix.get("link")):
            if not isinstance(candidate, str):
                continue
            try:
                url = validate_http_url(candidate)
            except PayloadError:
                continue
            if url not in urls:
                urls.append(url)
            break
    return urls


def _listing_records(payload: Any) -> tuple[list[Any], int | None]:
    if isinstance(payload, list):
        return payload, None
    if not isinstance(payload, Mapping):
        return [], None
    value = payload.get("Bugs", payload.get("bugs", []))
    if isinstance(value, list):
        return list(value), payload.get("version")
    return [], payload.get("version")


def _catalog_record_from_listing(value: Any) -> dict[str, Any] | None:
    try:
        raw = _as_mapping(value)
    except TypeError:
        return None
    link = _text(raw.get("link"))
    key = _key_from_link(link)
    if not key:
        return None
    bug_url = _absolute_syzbot_url(link)
    separator = "&" if "?" in bug_url else "?"
    return {
        "key": key,
        "title": _text(raw.get("title")),
        "bug_url": bug_url,
        "json_url": f"{bug_url}{separator}json=1",
        "fix_commits": raw.get("fix-commits", []),
        "raw": raw,
    }


def _prepare_records(records: Sequence[Any]) -> tuple[list[dict[str, Any]], list[str]]:
    prepared: list[dict[str, Any]] = []
    errors: list[str] = []
    seen: set[str] = set()
    for index, value in enumerate(records):
        try:
            item = _as_mapping(value)
        except (TypeError, ValueError) as exc:
            errors.append(f"record[{index}]: {exc}")
            continue
        key = _text(_field(item, "key"))
        if not _safe_file_key(key):
            errors.append(f"record[{index}]: missing or unsafe bug key")
            continue
        if key in seen:
            errors.append(f"record[{index}]: duplicate bug key {key}")
            continue
        seen.add(key)
        raw_value = item.get("raw", item)
        try:
            raw_bytes = _coerce_bytes(raw_value)
        except (TypeError, ValueError) as exc:
            errors.append(f"record[{index}] {key}: cannot serialize raw record: {exc}")
            continue
        fixes_value = _field(item, "fix_commits", "fix-commits", default=[])
        if not isinstance(fixes_value, Sequence) or isinstance(fixes_value, (str, bytes)):
            errors.append(f"record[{index}] {key}: fix_commits is not a sequence")
            fixes_value = []
        fixes: list[dict[str, Any]] = []
        for fix_index, fix in enumerate(fixes_value):
            try:
                fixes.append(_as_mapping(fix))
            except TypeError as exc:
                errors.append(f"record[{index}] {key} fix[{fix_index}]: {exc}")
        prepared.append(
            {
                "key": key,
                "title": _text(_field(item, "title")),
                "bug_url": _text(_field(item, "bug_url", "bug-url")),
                "json_url": _text(_field(item, "json_url", "json-url")),
                "fix_commits": fixes,
                "raw_bytes": raw_bytes,
            }
        )
    return prepared, errors


def _prepare_bug_payloads(
    records: Sequence[dict[str, Any]],
    bug_payloads: Mapping[str, bytes],
    parsed_payloads: Mapping[str, Any] | None = None,
    *,
    on_progress: ProgressCallback | None = None,
) -> tuple[dict[str, tuple[bytes, dict[str, Any] | None, str | None]], list[str]]:
    out: dict[str, tuple[bytes, dict[str, Any] | None, str | None]] = {}
    errors: list[str] = []
    for record in progress_items(
        records, on_progress, "prepare-bugs", "Validating bug details", total=len(records)
    ):
        key = record["key"]
        value = bug_payloads.get(key)
        if value is None:
            continue
        try:
            raw = _coerce_bytes(value)
        except (TypeError, ValueError) as exc:
            errors.append(f"bug JSON {key}: cannot convert to bytes: {exc}")
            continue
        try:
            decoded = (parsed_payloads or {}).get(key, UNPARSED)
            if decoded is UNPARSED:
                decoded = json.loads(raw.decode("utf-8"))
            if not isinstance(decoded, dict):
                raise ValueError("top-level value is not an object")
            if not (
                decoded.get("title") or decoded.get("id") or decoded.get("crashes") is not None
            ):
                raise ValueError("object does not look like a syzbot bug payload")
            for field in ("fix-commits", "crashes", "discussions"):
                if field in decoded and not isinstance(decoded[field], list):
                    raise ValueError(f"{field} is not a list")
            for field in ("fix-commits", "crashes"):
                if any(not isinstance(item, Mapping) for item in decoded.get(field, [])):
                    raise ValueError(f"{field} contains a non-object entry")
            if any(
                not isinstance(item, str) or not item.strip()
                for item in decoded.get("discussions", [])
            ):
                raise ValueError("discussions contains a non-string or empty entry")
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            out[key] = (raw, None, str(exc))
            errors.append(f"bug JSON {key}: {exc}")
        else:
            out[key] = (raw, decoded, None)
    return out, errors


def _fix_hashes(record: Mapping[str, Any], bug: Mapping[str, Any] | None) -> dict[str, str]:
    hashes: dict[str, str] = {}
    sources: list[Any] = list(record.get("fix_commits", []))
    if bug is not None:
        fixes = bug.get("fix-commits", [])
        if isinstance(fixes, list):
            sources.extend(fixes)
    for value in sources:
        try:
            fix = _as_mapping(value)
        except TypeError:
            continue
        commit_hash = _text(fix.get("hash")).lower()
        if _HASH_RE.fullmatch(commit_hash):
            hashes.setdefault(commit_hash, _text(fix.get("link")))
    return hashes


def _first_report(bug: Mapping[str, Any] | None, dashboard: str) -> tuple[int | None, str]:
    if bug is None:
        return None, ""
    crashes = bug.get("crashes", [])
    if not isinstance(crashes, list):
        return None, ""
    for ordinal, value in enumerate(crashes):
        if not isinstance(value, Mapping):
            continue
        link = _text(value.get("crash-report-link"))
        if link:
            return ordinal, _absolute_syzbot_url(link, dashboard)
    return None, ""
