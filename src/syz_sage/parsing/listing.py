"""Parsing and validation for Syzbot's JSON and text responses."""

from __future__ import annotations

import json
import re
from collections.abc import Collection, Mapping, Sequence
from html.parser import HTMLParser
from typing import Any
from urllib.parse import SplitResult, parse_qsl, urlsplit

DEFAULT_DASHBOARD = "https://syzkaller.appspot.com"
MAX_BUG_KEY_LENGTH = 128
# Bug keys become filenames in the retained mirror. Keep the accepted query
# alphabet conservative and portable: Windows forbids ``:`` and trailing
# dots, while the ``extid-``/``id-`` prefix prevents reserved device names.
KEY_RE = re.compile(r"^(?:extid|id)-[A-Za-z0-9_%+~-](?:[A-Za-z0-9._%+~-]*[A-Za-z0-9_%+~-])?$")
HASH_RE = re.compile(r"^[0-9a-fA-F]{40}$")


class PayloadError(ValueError):
    """Raised when a remote payload cannot be safely interpreted."""


class _SubsystemParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.tags: dict[str, set[str]] = {}
        self.keys: set[str] = set()
        self.labels: set[str] = set()
        self.in_row = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "tr":
            self.keys, self.labels = set(), set()
            self.in_row = True
        if tag != "a" or not self.in_row:
            return
        href = dict(attrs).get("href") or ""
        try:
            parsed = urlsplit(href)
            if parsed.path == "/bug":
                self.keys.add(key_from_link(href))
            for name, value in parse_qsl(parsed.query):
                if name == "label" and value.startswith("subsystems:"):
                    label = value.removeprefix("subsystems:").strip()
                    if label:
                        self.labels.add(label)
        except ValueError:
            return

    def handle_endtag(self, tag: str) -> None:
        if tag == "tr" and self.in_row:
            # Never assign labels across ambiguous or malformed rows.
            if len(self.keys) == 1:
                self.tags.setdefault(next(iter(self.keys)), set()).update(self.labels)
            self.in_row = False


def parse_subsystem_tags(listing_html: str) -> dict[str, list[str]]:
    """Read syzbot subsystem labels from each listing row, excluding other tags."""
    parser = _SubsystemParser()
    parser.feed(listing_html)
    parser.close()
    return {key: sorted(tags) for key, tags in parser.tags.items()}


class _ListingKeyParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.keys: set[str] = set()
        self.invalid = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag != "a":
            return
        href = dict(attrs).get("href") or ""
        try:
            if urlsplit(href).path == "/bug":
                self.keys.add(key_from_link(href))
        except ValueError:
            self.invalid = True


def validate_listing_membership(payload: bytes, expected_keys: Collection[str]) -> bool:
    """Reject error pages and separately fetched listings describing different bugs."""
    if not valid_listing_html(payload):
        return False
    parser = _ListingKeyParser()
    try:
        parser.feed(payload.decode("utf-8-sig"))
        parser.close()
    except (UnicodeDecodeError, ValueError):
        return False
    return not parser.invalid and bool(parser.keys) and parser.keys == set(expected_keys)


def _http_url_parts(url: str) -> SplitResult:
    if not isinstance(url, str) or not url or url != url.strip():
        raise PayloadError("HTTP URL is empty or contains surrounding whitespace")
    if url.startswith("//"):
        raise PayloadError("scheme-relative URLs are not allowed")
    if any(
        character.isspace() or ord(character) < 0x20 or 0x7F <= ord(character) <= 0x9F
        for character in url
    ):
        raise PayloadError("HTTP URL contains whitespace or control characters")
    try:
        parsed = urlsplit(url)
        _ = parsed.port
    except ValueError as exc:
        raise PayloadError(f"invalid HTTP URL: {exc}") from exc
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
        raise PayloadError("URL must use http or https and include a host")
    if parsed.hostname is None:
        raise PayloadError("HTTP URL has no hostname")
    if parsed.username is not None or parsed.password is not None:
        raise PayloadError("HTTP URL must not contain user information")
    if parsed.fragment:
        raise PayloadError("HTTP URL must not contain a fragment")
    return parsed


def _origin(parsed: SplitResult) -> tuple[str, str, int]:
    scheme = parsed.scheme.lower()
    assert parsed.hostname is not None
    port = parsed.port or (443 if scheme == "https" else 80)
    return scheme, parsed.hostname.lower(), port


def validate_http_url(url: str, *, same_origin_as: str | None = None) -> str:
    """Validate a fetchable HTTP(S) URL and optionally enforce an origin."""

    parsed = _http_url_parts(url)
    if same_origin_as is not None:
        reference = _http_url_parts(same_origin_as)
        if _origin(parsed) != _origin(reference):
            raise PayloadError("dashboard resource URL must use the configured dashboard origin")
    return url


def decode_json_object(payload: bytes | str | Mapping[str, Any]) -> dict[str, Any]:
    if isinstance(payload, Mapping):
        return dict(payload)
    try:
        value = json.loads(payload)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise PayloadError(f"invalid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise PayloadError("expected a JSON object")
    return value


def key_from_link(link: str) -> str:
    """Extract and validate a stable ``extid-*`` or ``id-*`` bug key."""

    if not isinstance(link, str) or not link:
        raise PayloadError("bug link is empty")
    try:
        candidates = [
            (name, value)
            for name, value in parse_qsl(urlsplit(link).query, keep_blank_values=True)
            if name in {"extid", "id"}
        ]
    except ValueError as exc:
        raise PayloadError(f"invalid bug link: {exc}") from exc
    if len(candidates) != 1 or not candidates[0][1]:
        raise PayloadError("bug link must contain exactly one non-empty extid or id")
    key = f"{candidates[0][0]}-{candidates[0][1]}"
    if len(key) > MAX_BUG_KEY_LENGTH or not KEY_RE.fullmatch(key):
        raise PayloadError(f"unsafe bug key: {key!r}")
    return key


def absolute_syzbot_url(link: str | None, dashboard: str = DEFAULT_DASHBOARD) -> str | None:
    if not link:
        return None
    dashboard_parts = _http_url_parts(dashboard)
    if dashboard_parts.query or dashboard_parts.fragment:
        raise PayloadError("dashboard URL must not contain a query or fragment")
    try:
        parsed_link = urlsplit(link)
        _ = parsed_link.port
    except ValueError as exc:
        raise PayloadError(f"invalid syzbot URL: {exc}") from exc
    if link.startswith("//"):
        raise PayloadError("scheme-relative syzbot URLs are not allowed")
    if parsed_link.scheme or parsed_link.netloc:
        return validate_http_url(link, same_origin_as=dashboard)
    if not link.startswith("/"):
        raise PayloadError(f"invalid relative syzbot URL: {link!r}")
    result = dashboard.rstrip("/") + link
    return validate_http_url(result, same_origin_as=dashboard)


def parse_listing(
    payload: bytes | str | Mapping[str, Any], dashboard: str = DEFAULT_DASHBOARD
) -> list[dict[str, Any]]:
    """Parse a Syzbot dashboard listing into stable, serializable records."""

    document = decode_json_object(payload)
    raw_bugs = document.get("Bugs", document.get("bugs"))
    if not isinstance(raw_bugs, list):
        raise PayloadError("listing has no Bugs array")
    records: list[dict[str, Any]] = []
    seen: set[str] = set()
    for position, raw in enumerate(raw_bugs):
        if not isinstance(raw, dict):
            raise PayloadError(f"listing bug at position {position} is not an object")
        link = raw.get("link")
        if not isinstance(link, str):
            raise PayloadError(f"listing bug at position {position} has no string link")
        key = key_from_link(link)
        if key in seen:
            raise PayloadError(f"duplicate bug key in listing: {key}")
        seen.add(key)
        bug_url = absolute_syzbot_url(link, dashboard)
        assert bug_url is not None
        separator = "&" if "?" in bug_url else "?"
        fixes = raw.get("fix-commits", [])
        if fixes is None:
            fixes = []
        if not isinstance(fixes, list):
            raise PayloadError(f"fix-commits for {key} is not an array")
        if any(not isinstance(item, Mapping) for item in fixes):
            raise PayloadError(f"fix-commits for {key} contains a non-object entry")
        normalized_fixes = [dict(item) for item in fixes]
        primary_fix_hash = next(
            (str(item["hash"]) for item in normalized_fixes if item.get("hash")),
            "",
        )
        records.append(
            {
                "key": key,
                "position": position,
                "title": str(raw.get("title") or ""),
                "bug_url": bug_url,
                "json_url": f"{bug_url}{separator}json=1",
                "fix_commits": normalized_fixes,
                "primary_fix_hash": primary_fix_hash,
                "raw": dict(raw),
                "source_version": document.get("version"),
            }
        )
    return records


def choose_bug_payload(
    listing_record: Mapping[str, Any], detail: Mapping[str, Any] | None
) -> dict[str, Any]:
    """Combine listing identity/URLs with the richer per-bug document."""

    result = dict(detail or {})
    result["key"] = listing_record["key"]
    result["bug_url"] = listing_record.get("bug_url")
    result["json_url"] = listing_record.get("json_url")
    if not result.get("title"):
        result["title"] = listing_record.get("title", "")
    if not result.get("fix-commits"):
        result["fix-commits"] = list(listing_record.get("fix_commits") or [])
    return result


def first_report_url(detail: Mapping[str, Any], dashboard: str = DEFAULT_DASHBOARD) -> str | None:
    crashes = detail.get("crashes") or []
    if not isinstance(crashes, Sequence) or isinstance(crashes, (str, bytes)):
        return None
    for crash in crashes:
        if isinstance(crash, Mapping) and crash.get("crash-report-link"):
            return absolute_syzbot_url(str(crash["crash-report-link"]), dashboard)
    return None


def effective_fixes(
    listing_record: Mapping[str, Any], detail: Mapping[str, Any] | None
) -> list[dict[str, Any]]:
    """Return the lossless union of listing and detail fix references."""

    fixes: list[dict[str, Any]] = []
    identities: set[tuple[str, str, str]] = set()
    for source, values in (
        ("listing", listing_record.get("fix_commits") or []),
        ("bug", (detail or {}).get("fix-commits") or []),
    ):
        if not isinstance(values, Sequence) or isinstance(values, (str, bytes)):
            continue
        for value in values:
            if not isinstance(value, Mapping):
                continue
            item = dict(value)
            identity = (
                str(item.get("hash") or "").lower(),
                str(item.get("title") or ""),
                str(item.get("repo") or ""),
            )
            if identity in identities:
                continue
            identities.add(identity)
            item["source"] = source
            fixes.append(item)
    return fixes


def _payload_prefix(payload: bytes, limit: int = 4096) -> bytes:
    prefix = payload.lstrip()
    if prefix.startswith(b"\xef\xbb\xbf"):
        prefix = prefix[3:].lstrip()
    return prefix[:limit].lower()


def _looks_like_markup(payload: bytes) -> bool:
    return _payload_prefix(payload).startswith(
        (b"<!doctype html", b"<html", b"<head", b"<body", b"<?xml")
    )


def valid_report(payload: bytes) -> bool:
    return bool(_payload_prefix(payload)) and not _looks_like_markup(payload)


def valid_listing_html(payload: bytes) -> bool:
    prefix = _payload_prefix(payload)
    if not prefix.startswith((b"<!doctype html", b"<html", b"<head", b"<body")):
        return False
    lowered = payload.lower()
    return b"<html" in lowered and b"</html>" in lowered


def valid_patch(payload: bytes) -> bool:
    if len(payload) <= 40:
        return False
    if _looks_like_markup(payload):
        return False
    return b"diff --git" in payload


def parse_bug_json(payload: bytes) -> dict[str, Any]:
    """Validate a detail response and return its single decoded representation."""
    value = decode_json_object(payload)
    if not (value.get("title") or value.get("id") or value.get("crashes") is not None):
        raise PayloadError("bug JSON has no title, id, or crashes")
    for field in ("fix-commits", "crashes", "discussions"):
        if field in value and not isinstance(value[field], list):
            raise PayloadError(f"bug JSON {field} is not an array")
    for field in ("fix-commits", "crashes"):
        if any(not isinstance(item, Mapping) for item in value.get(field, [])):
            raise PayloadError(f"bug JSON {field} contains a non-object entry")
    if any(not isinstance(item, str) or not item.strip() for item in value.get("discussions", [])):
        raise PayloadError("bug JSON discussions contains an invalid link")
    return value


def valid_bug_json(payload: bytes) -> bool:
    try:
        parse_bug_json(payload)
    except PayloadError:
        return False
    return True
