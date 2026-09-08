"""Shared selection options for filtering and descriptive statistics."""

from __future__ import annotations

import argparse
from typing import Any

from ..parsing.characteristics import ACCESS_MODES, BUG_FAMILIES

SEQUENCE_CRITERIA = (
    "bug_types",
    "subsystems",
    "families",
    "access_modes",
    "crash_files",
    "fix_files",
    "crash_functions",
    "fix_functions",
)
OPTIONAL_CRITERIA = (
    "query",
    "has_c_repro",
    "has_report",
    "has_patch",
    "max_fix_files",
    "max_patch_lines",
)


def _pattern(value: str) -> str:
    if not value.strip() or any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise argparse.ArgumentTypeError("patterns must be nonempty and contain no controls")
    return value.strip()


def add_research_filters(parser: argparse.ArgumentParser) -> None:
    evidence = parser.add_argument_group("Failure patterns and source evidence")
    for flag, dest, choices, help_text in (
        ("--family", "families", BUG_FAMILIES, "observed failure patterns; unknown is explicit"),
        ("--access", "access_modes", ACCESS_MODES, "reported memory access mode"),
    ):
        evidence.add_argument(
            flag,
            dest=dest,
            nargs="+",
            action="extend",
            type=str.casefold,
            choices=choices,
            metavar="VALUE",
            help=help_text,
        )
    for flag, dest, label in (
        ("--crash-file", "crash_files", "crash source paths"),
        ("--fix-file", "fix_files", "old or new changed paths"),
        ("--crash-function", "crash_functions", "crash function names"),
        ("--fix-function", "fix_functions", "inferred patch function names"),
    ):
        evidence.add_argument(
            flag,
            dest=dest,
            nargs="+",
            action="extend",
            type=_pattern,
            metavar="PATTERN",
            help=f"case-sensitive globs for {label}",
        )
    for name, dest, label in (
        ("c-repro", "has_c_repro", "C reproducer URL in saved metadata"),
        ("report", "has_report", "saved representative report"),
        ("patch", "has_patch", "at least one saved referenced patch"),
    ):
        group = evidence.add_mutually_exclusive_group()
        group.add_argument(
            f"--has-{name}",
            dest=dest,
            action="store_const",
            const=True,
            default=None,
            help=f"require {label}",
        )
        group.add_argument(
            f"--no-{name}",
            dest=dest,
            action="store_const",
            const=False,
            help=f"exclude bugs with {label}",
        )
    evidence.add_argument(
        "--max-fix-files",
        type=int,
        metavar="N",
        help="maximum distinct changed paths across fixes; excludes unknown sizes",
    )
    evidence.add_argument(
        "--max-patch-lines",
        type=int,
        metavar="N",
        help="maximum added + removed lines across fixes; excludes unknown sizes",
    )


def selection(args: argparse.Namespace) -> dict[str, Any]:
    values = {name: getattr(args, name, None) or [] for name in SEQUENCE_CRITERIA}
    values.update(
        {
            name: getattr(args, name, None)
            for name in OPTIONAL_CRITERIA
            if getattr(args, name, None) is not None
        }
    )
    return values


def validate_research_filters(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    for name in ("max_fix_files", "max_patch_lines"):
        value = getattr(args, name, None)
        if value is not None and value < 0:
            parser.error("--" + name.replace("_", "-") + " must be non-negative")
