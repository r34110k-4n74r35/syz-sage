"""Deterministic diagnostic types derived only from syzbot bug titles.

These labels describe report markers, not inferred root causes. In particular,
WARNING and INFO retain their own types even when they mention another detector.
"""

from __future__ import annotations

import re

BUG_TYPES: tuple[str, ...] = (
    "kasan",
    "kmsan",
    "kcsan",
    "kfence",
    "ubsan",
    "warning",
    "info",
    "bug",
    "panic",
    "general-protection-fault",
    "deadlock",
    "memory-leak",
    "inconsistent-lock-state",
    "divide-error",
    "rcu",
    "unregister-netdevice",
    "stack-segment-fault",
    "internal-error",
    "vfs",
    "invalid-opcode",
    "unexpected-reboot",
    "lost-connection",
    "build-error",
    "boot-error",
    "test-error",
    "other",
)

_DUPLICATE_SUFFIX = re.compile(r"(?:\s*\(\d+\))+$")
_MANAGER_ERROR = re.compile(
    r"[a-z0-9][a-z0-9._+/-]* (?P<stage>build|boot|test) error"
    r"\s*(?::\s*(?P<detail>.*))?"
)
_SANITIZER = re.compile(r"^(kasan|kmsan|kcsan|kfence|ubsan)\s*:")
_MARKERS = tuple(
    (re.compile(rf"^(?:{marker})(?=\s|:|$)"), kind)
    for marker, kind in (
        ("warning", "warning"),
        ("info", "info"),
        (r"(?:kernel )?bug", "bug"),
        (r"(?:kernel )?panic", "panic"),
        ("general protection fault", "general-protection-fault"),
        ("possible deadlock", "deadlock"),
        ("memory leak", "memory-leak"),
        ("inconsistent lock state", "inconsistent-lock-state"),
        ("divide error", "divide-error"),
        ("suspicious rcu usage", "rcu"),
        ("unregister_netdevice", "unregister-netdevice"),
        ("stack segment fault", "stack-segment-fault"),
        ("internal error", "internal-error"),
        ("vfs", "vfs"),
        ("invalid opcode", "invalid-opcode"),
        ("unexpected kernel reboot", "unexpected-reboot"),
        ("lost connection to test machine", "lost-connection"),
    )
)


def _classify_marker(title: str) -> str:
    sanitizer = _SANITIZER.match(title)
    if sanitizer:
        return sanitizer.group(1)
    for pattern, kind in _MARKERS:
        if pattern.match(title):
            return kind
    return "other"


def classify_bug_type(title: str) -> str:
    """Return a canonical title type without inspecting reports or subsystem tags.

    Manager boot/test errors expose their underlying diagnostic when recognized;
    otherwise they retain the stage type. Build errors always remain build errors.
    Manager names are structurally validated so new managers need no allowlist.
    """
    normalized = _DUPLICATE_SUFFIX.sub("", " ".join(title.split()).casefold()).strip()
    wrapper = _MANAGER_ERROR.fullmatch(normalized)
    if wrapper:
        stage = wrapper.group("stage")
        if stage == "build":
            return "build-error"
        kind = _classify_marker(wrapper.group("detail") or "")
        return f"{stage}-error" if kind == "other" else kind
    return _classify_marker(normalized)
