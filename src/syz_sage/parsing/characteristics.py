"""Conservative failure families and access modes, separate from diagnostic types."""

from __future__ import annotations

import re
from dataclasses import dataclass

from .crash import split_manifestation_report

BUG_FAMILIES = (
    "unknown",
    "use-after-free",
    "use-after-scope",
    "use-after-return",
    "out-of-bounds",
    "uninitialized-value",
    "double-free",
    "invalid-free",
    "null-dereference",
    "data-race",
    "deadlock",
    "memory-leak",
    "integer-overflow",
    "shift-out-of-bounds",
    "divide-by-zero",
    "alignment",
    "hang",
)
ACCESS_MODES = ("unknown", "read", "write", "read-write")


@dataclass(frozen=True)
class Characteristic:
    value: str
    method: str
    evidence: str
    source: str


@dataclass(frozen=True)
class Characteristics:
    family: Characteristic
    access_mode: Characteristic


_FAMILY_PATTERNS = (
    ("use-after-free", r"\buse[- ]after[- ]free\b"),
    ("use-after-scope", r"\buse[- ]after[- ]scope\b"),
    ("use-after-return", r"\buse[- ]after[- ]return\b"),
    ("double-free", r"\bdouble[- ]free\b"),
    ("invalid-free", r"\b(?:invalid|bad)[- ]free\b"),
    ("shift-out-of-bounds", r"\bshift[- ]out[- ]of[- ]bounds\b|\bshift exponent .+ too large\b"),
    ("out-of-bounds", r"\bout[- ]of[- ]bounds\b|\b(?:buffer|stack|heap)[- ]overflow\b"),
    ("uninitialized-value", r"\buninit(?:ialized)?[- ](?:value|memory|variable)\b"),
    ("null-dereference", r"\bnull(?: pointer)?[- ]dereference\b|\bnull[- ]ptr[- ]deref\b"),
    ("data-race", r"\bdata[- ]race\b"),
    ("deadlock", r"\b(?:deadlock|circular locking dependency)\b"),
    ("memory-leak", r"\bmemory[- ]leak\b"),
    ("integer-overflow", r"\b(?:signed|unsigned)[- ]integer[- ]overflow\b|\binteger[- ]overflow\b"),
    ("divide-by-zero", r"\b(?:divide|division)[- ]by[- ]zero\b"),
    ("alignment", r"\b(?:misaligned address|alignment[- ]assumption|unaligned access)\b"),
    ("hang", r"\b(?:task hung|blocked for more than|soft lockup|hard lockup)\b"),
)
_DIAGNOSTIC = re.compile(
    r"^\s*(?:\[[^]]+\]\s*)?(?:BUG:|WARNING:|INFO:|KASAN:|KMSAN:|KCSAN:|KFENCE:|UBSAN:|"
    r"kernel BUG|general protection fault|Unable to handle|divide error)",
    re.I,
)


def _summary(text: str) -> str:
    """Function names and source paths are not evidence of a failure family."""
    return re.split(r"\s+(?:in|at)\s+", text, maxsplit=1, flags=re.I)[0]


def classify_characteristics(title: str, report: str | None = None) -> Characteristics:
    main = split_manifestation_report(report or "")[0]
    diagnostics = [line.strip() for line in main.splitlines() if _DIAGNOSTIC.match(line)]
    unknown = Characteristic("unknown", "no explicit evidence", "", "unknown")
    family = unknown
    for source, evidence in [("report", line) for line in diagnostics] + [("title", title)]:
        summary = _summary(evidence)
        matches = {name for name, pattern in _FAMILY_PATTERNS if re.search(pattern, summary, re.I)}
        # The shift-specific family necessarily also matches generic out-of-bounds.
        if "shift-out-of-bounds" in matches:
            matches.discard("out-of-bounds")
        if len(matches) == 1:
            family = Characteristic(matches.pop(), "explicit failure wording", evidence, source)
            break
        if matches:
            family = Characteristic("unknown", "conflicting failure wording", evidence, source)
            break

    access = unknown
    modes: set[str] = set()
    evidence_lines: list[str] = []
    for line in main.splitlines():
        matched = re.match(
            r"^\s*(?:\[[^]]+\]\s*)?(read-write|read|write)(?:\s+\([^)]+\))?"
            r"\s+(?:of size\b|to .+\bby (?:task|interrupt)\b)",
            line,
            re.I,
        )
        if matched:
            modes.update(matched[1].lower().split("-"))
            evidence_lines.append(line.strip())
    if modes:
        access = Characteristic(
            "read-write" if len(modes) == 2 else next(iter(modes)),
            "explicit access diagnostic",
            "\n".join(evidence_lines),
            "report",
        )
    else:
        summary = _summary(title)
        title_modes = set(re.findall(r"\b(read-write|read|write)\b", summary, re.I))
        modes = {part for mode in title_modes for part in mode.lower().split("-")}
        if modes and family.value not in {"unknown", "deadlock", "hang", "memory-leak"}:
            access = Characteristic(
                "read-write" if len(modes) == 2 else next(iter(modes)),
                "explicit title access",
                title,
                "title",
            )
    return Characteristics(family, access)
