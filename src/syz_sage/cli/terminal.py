"""Small, dependency-free helpers for readable terminal output."""

from __future__ import annotations

import os
import shutil
import sys
import textwrap
import unicodedata
from collections.abc import Callable, Mapping, Sequence
from typing import TextIO


def terminal_width(stream: TextIO | None = None) -> int:
    width = shutil.get_terminal_size(fallback=(96, 24)).columns
    destination = stream if stream is not None else sys.stdout
    # Progress can remain interactive on stderr when stdout is redirected.
    # Honor an explicit COLUMNS setting, otherwise size the actual destination.
    if not os.environ.get("COLUMNS"):
        try:
            if destination.isatty():
                width = os.get_terminal_size(destination.fileno()).columns
        except (AttributeError, OSError, ValueError):
            pass
    return max(24, min(110, width))


def style(value: str, *, tone: str = "heading", stream: TextIO | None = None) -> str:
    destination = stream if stream is not None else sys.stdout
    if not destination.isatty() or "NO_COLOR" in os.environ or os.environ.get("TERM") == "dumb":
        return value
    codes = {
        "heading": "1;36",
        "accent": "36",
        "muted": "2",
        "strong": "1",
        "success": "32",
        "warning": "33",
        "error": "31",
        "number": "1;36",
        "tag": "1;35",
        "function": "35",
        "hash": "33",
        "link": "4;94",
        "date": "94",
    }
    return f"\x1b[{codes[tone]}m{value}\x1b[0m"


def safe_text(value: object, *, multiline: bool = False) -> str:
    """Escape source controls before styling; full reports retain line breaks."""
    output: list[str] = []
    for character in str(value):
        if multiline and character in {"\n", "\t"}:
            output.append(character)
        elif unicodedata.category(character) in {"Cc", "Cf"}:
            codepoint = ord(character)
            output.append(f"\\x{codepoint:02x}" if codepoint <= 0xFF else f"\\u{codepoint:04x}")
        else:
            output.append(character)
    return "".join(output)


def paragraph(
    value: object,
    *,
    indent: int = 0,
    hanging: int = 0,
    tone: str | None = None,
    highlight: Callable[[str], str] | None = None,
    stream: TextIO | None = None,
) -> None:
    destination = stream if stream is not None else sys.stdout
    prefix = " " * indent
    lines = textwrap.wrap(
        safe_text(value),
        width=max(12, terminal_width(destination) - indent),
        subsequent_indent=" " * hanging,
        break_long_words=False,
        break_on_hyphens=False,
    ) or [""]
    for line in lines:
        rendered = (
            highlight(line)
            if highlight
            else style(line, tone=tone, stream=destination)
            if tone
            else line
        )
        print(prefix + rendered, file=destination)


def section(title: str, *, count: int | None = None) -> None:
    suffix = f" ({count:,})" if count is not None else ""
    print()
    paragraph(title + suffix, tone="heading")


def fields(
    rows: Sequence[tuple[str, object]],
    *,
    indent: int = 2,
    tones: Mapping[str, str] | None = None,
) -> None:
    """Align labels within a group and wrap values with a hanging indent."""
    if not rows:
        return
    label_width = max(len(label) for label, _ in rows) + 2
    # Narrow terminals use a value on the following line instead of squeezing it.
    stacked = terminal_width() - label_width - indent < 24
    for label, value in rows:
        tone = tones.get(label) if tones else None
        prefix = " " * indent + f"{label}:".ljust(label_width)
        text = safe_text(value)
        # Long links get a dedicated, intact line for selection and copying.
        if stacked or (tone == "link" and len(text) > terminal_width() - len(prefix)):
            print(" " * indent + style(label + ":", tone="muted"))
            paragraph(value, indent=indent + 2, tone=tone)
            continue
        lines = textwrap.wrap(
            text,
            width=terminal_width() - len(prefix),
            break_long_words=False,
            break_on_hyphens=False,
        ) or [""]
        rendered = [style(line, tone=tone) if tone else line for line in lines]
        print(style(prefix, tone="muted") + rendered[0])
        for line in rendered[1:]:
            print(" " * len(prefix) + line)
