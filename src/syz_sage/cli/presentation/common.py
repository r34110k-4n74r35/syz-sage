"""Shared semantic formatting and console diagnostics for human CLI views."""

from __future__ import annotations

import re
import sys
from collections.abc import Sequence
from datetime import datetime

from ..terminal import fields as _fields
from ..terminal import paragraph, safe_text, style


def value_tone(label: str, value: object) -> str:
    """Color the meaning of values while leaving the displayed text intact."""
    text = str(value).lower()
    if text.startswith(
        ("unknown", "unavailable", "unresolved", "partial", "not yet", "not recorded")
    ):
        return "warning"
    if re.search(r"\b[1-9][\d,]* (?:missing|invalid)\b", text):
        return "warning"
    if label in {"SQLite", "Foreign keys", "Blob hashes", "Snapshots"}:
        return "success" if text in {"ok", "0 errors"} else "error"
    if label in {"Status", "Saved status", "Result"}:
        if text.startswith(("failed", "error")):
            return "error"
        if "not activated" in text:
            return "warning"
        if text.startswith(("fixed", "complete", "unchanged")):
            return "success"
    if label in {"Patch", "Representative report", "C reproducer"}:
        return "success" if text.startswith("available") else "warning"
    if label == "Confidence":
        return "success" if text == "high" else "warning"
    if label == "Unavailable":
        return "warning" if text != "0" else "muted"
    if label == "Downloaded":
        return "success" if text != "0" else "muted"
    if label == "Reused":
        return "accent" if text != "0" else "muted"
    if label in {"Bug type", "Types", "Subsystems", "Subsystem tags"}:
        return "tag"
    if label == "Function":
        return "function"
    if label in {"Commit", "Kernel commit"}:
        return "hash"
    if label in {"URL", "Report URL", "Repository", "C repro URL"}:
        return "link"
    if label in {"Key", "File", "Database", "Retained files", "Role"}:
        return "accent"
    if label in {"First crash", "Last crash", "Fix time", "Close time", "Finished", "Last checked"}:
        return "date"
    if label.endswith("keys") or label in {"Changes", "No longer listed", "Migration"}:
        return "accent"
    if re.match(r"^\d", text):
        return "number"
    return "strong"


def fields(rows: Sequence[tuple[str, object]], *, indent: int = 2) -> None:
    _fields(rows, indent=indent, tones={label: value_tone(label, value) for label, value in rows})


_TITLE_PREFIX = re.compile(
    r"^(?P<number>\d+\.\s+)?"
    r"(?P<category>(?:BUG:\s*)?"
    r"(?:KASAN|KMSAN|KCSAN|UBSAN|KFENCE|WARNING|INFO|kernel BUG|kernel panic|BUG|"
    r"general protection fault|unable to handle kernel paging request):?)(?=\s|$)",
    re.I,
)


def title_colors(line: str) -> str:
    """Distinguish the reported diagnostic prefix without rewriting its title."""
    match = _TITLE_PREFIX.match(line)
    if not match:
        return style(line, tone="strong")
    return (
        style(match["number"] or "", tone="strong")
        + style(match["category"], tone="tag")
        + style(line[match.end() :], tone="strong")
    )


def format_date(value: object) -> str:
    raw = str(value or "unknown")
    try:
        date = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        return date.isoformat(sep=" ", timespec="seconds").replace("+00:00", " UTC")
    except ValueError:
        return raw


def bug_type_label(value: object) -> str:
    label = str(value or "other")
    if label in {
        "kasan",
        "kmsan",
        "ubsan",
        "kcsan",
        "kfence",
        "warning",
        "info",
        "bug",
        "rcu",
        "vfs",
    }:
        return label.upper()
    return label.replace("-", " ").capitalize()


def c_reproducer_label(status: object) -> str:
    return {
        "available": "available (URL recorded)",
        "not_provided": "not provided in saved crash metadata",
    }.get(str(status), "unknown (metadata missing or invalid)")


def progress(message: str) -> None:
    destination = sys.stderr
    label, separator, rest = safe_text(message).partition(": ")
    prefix = style("  > ", tone="accent", stream=destination)
    if separator and len(label) < 30:
        rest = re.sub(
            r"\b\d[\d,]*(?:/[\d,]+)?\b",
            lambda match: style(match.group(), tone="number", stream=destination),
            rest,
        )
        rendered = style(label + ":", tone="strong", stream=destination) + " " + rest
    else:
        rendered = safe_text(message)
    print(prefix + rendered, file=destination, flush=True)


def error(message: object) -> None:
    paragraph("Error: " + str(message), tone="error", stream=sys.stderr)
