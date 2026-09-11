"""CLI argument definitions and validation, independent of command execution."""

from __future__ import annotations

import argparse
from pathlib import Path

from .. import __version__
from ..parsing.bug_types import BUG_TYPES
from ..project.config import DATABASE_ENV
from .help import HelpParser
from .research_arguments import (
    OPTIONAL_CRITERIA,
    SEQUENCE_CRITERIA,
    add_research_filters,
    validate_research_filters,
)


def _filter_text(value: str) -> str:
    value = value.strip()
    if not value:
        raise argparse.ArgumentTypeError("filter criteria must not be blank")
    return value


def _filter_type(value: str) -> str:
    value = _filter_text(value).casefold()
    if value not in BUG_TYPES:
        raise argparse.ArgumentTypeError(
            f"unknown bug type {value!r}; choose from: {', '.join(BUG_TYPES)}"
        )
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = HelpParser(
        prog="ss",
        description="Syz Sage: retrieve fixed syzbot bugs and inspect crash and fix evidence.",
        epilog=(
            "Examples:\n"
            "  ss update\n"
            "  ss list --query use-after-free\n"
            "  ss filter --type kasan --subsystem net\n"
            "  ss show extid-0a884bc2d304ce4af70f --stack\n\n"
            "Run ss COMMAND --help for command options.\n"
            "Aliases: syz-sage and python -m syz_sage."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
        help="show the installed version and exit",
    )
    paths = parser.add_argument_group(
        "Paths", "Place these options before COMMAND. Explicit paths may be anywhere."
    )
    paths.add_argument(
        "--data-dir",
        type=Path,
        metavar="DIR",
        help="data root (default: SYZ_SAGE_DATA_DIR or this checkout's data/)",
    )
    paths.add_argument(
        "--database",
        type=Path,
        metavar="FILE",
        help=f"SQLite file (default: {DATABASE_ENV} or DATA_DIR/db/syz_sage.sqlite3)",
    )
    commands = parser.add_subparsers(
        title="Commands",
        dest="command",
        metavar="COMMAND",
        required=True,
    )

    update = commands.add_parser(
        "update",
        help="check for new fixed bugs and index retained data",
        description=(
            "Check syzbot's upstream/fixed listing, fetch missing bug details, reports, "
            "and patches, then update SQLite. Valid saved files are reused. Unchanged "
            "data leaves the database untouched."
        ),
        epilog=(
            "Examples:\n"
            "  ss update\n"
            "  ss update --quiet\n"
            "  ss update --workers 4 --json\n\n"
            "Partial runs retain downloads and preserve any previous active snapshot. "
            "Run ss update again to resume."
        ),
    )
    retrieval = update.add_argument_group("Retrieval")
    retrieval.add_argument(
        "--workers",
        type=int,
        default=8,
        metavar="N",
        help="concurrent network workers (default: 8)",
    )
    retrieval.add_argument(
        "--limit",
        type=int,
        metavar="N",
        help="select the first N listing entries (default: all; smaller selections are partial)",
    )
    refresh = update.add_argument_group("Refresh saved files")
    refresh.add_argument(
        "--refresh-details",
        action="store_true",
        help="re-fetch selected bug JSON and its representative reports",
    )
    refresh.add_argument(
        "--refresh-artifacts",
        action="store_true",
        help="re-fetch saved reports and patches",
    )
    partial = update.add_argument_group("Partial runs")
    partial.add_argument(
        "--no-reports",
        action="store_true",
        help="skip crash reports; keep candidate partial",
    )
    partial.add_argument(
        "--no-patches",
        action="store_true",
        help="skip fix patches; keep candidate partial",
    )
    partial.add_argument(
        "--allow-partial",
        action="store_true",
        help="return success for a partial candidate without activating it",
    )
    output = update.add_argument_group("Output")
    output.add_argument("--json", action="store_true", help="print JSON without progress or color")
    output.add_argument(
        "--quiet",
        action="store_true",
        help="hide progress; keep the summary and issues",
    )

    show = commands.add_parser(
        "show",
        help="inspect one bug, its locations, crash stack, and fix patches",
        description=(
            "Read one bug from the active SQLite snapshot, including subsystem tags, "
            "crash locations, and changed fix lines. Bug URLs are looked up locally."
        ),
        epilog=(
            "Examples:\n"
            "  ss show extid-0a884bc2d304ce4af70f\n"
            "  ss show extid-0a884bc2d304ce4af70f --stack\n"
            "  ss show extid-0a884bc2d304ce4af70f --stack --diff\n"
            "  ss show extid-0a884bc2d304ce4af70f --json\n\n"
            "JSON always includes the extracted stack. All saved patch bodies require --diff."
        ),
    )
    show.add_argument("key", metavar="KEY_OR_URL", help="extid-* / id-* key or syzbot /bug URL")
    content = show.add_argument_group("Report content")
    content.add_argument(
        "--stack",
        action="store_true",
        help="display all extracted representative-report frames",
    )
    patches = content.add_mutually_exclusive_group()
    patches.add_argument(
        "--diff",
        action="store_true",
        help="include all saved fix patches with per-file diffstat; combines with --stack",
    )
    patches.add_argument(
        "--patch", metavar="HASH", help="display the saved diff for this fix commit"
    )
    content.add_argument(
        "--file",
        dest="patch_file",
        metavar="PATTERN",
        help="case-sensitive file glob within --patch",
    )
    content.add_argument(
        "--explain",
        action="store_true",
        help="explain observed crash-to-fix relationships with source evidence",
    )
    show.add_argument_group("Output").add_argument(
        "--json",
        action="store_true",
        help="print structured bug data without color",
    )

    listing = commands.add_parser(
        "list",
        help="search and browse bugs in the active snapshot",
        description="List bugs in active listing order. Search matches the title or bug key.",
        epilog=(
            "Examples:\n"
            "  ss list --query use-after-free\n"
            "  ss list --limit 10 --offset 10\n"
            "  ss list --json"
        ),
    )
    selection = listing.add_argument_group("Filter and pagination")
    selection.add_argument("--query", metavar="TEXT", help="case-insensitive title/key substring")
    selection.add_argument(
        "--limit", type=int, default=20, metavar="N", help="maximum rows to return (default: 20)"
    )
    selection.add_argument(
        "--offset", type=int, default=0, metavar="N", help="rows to skip (default: 0)"
    )
    listing.add_argument_group("Output").add_argument(
        "--json",
        action="store_true",
        help="print rows as JSON",
    )

    filtering = commands.add_parser(
        "filter",
        help="filter active fixed bugs by diagnostic type and subsystem",
        description=(
            "Filter the active SQLite snapshot offline. Values match case-insensitively: "
            "OR within each category, AND between types, subsystem tags, and query. "
            "Subsystem tags match exactly; fs does not include ext4 or btrfs."
        ),
        epilog=(
            "Examples:\n"
            "  ss filter --type kasan kmsan --subsystem fs mm\n"
            "  ss filter --list-values\n"
            "  ss filter --type kasan --all --urls-only\n"
            "  ss filter --subsystem net --limit 10 --offset 10 --json\n\n"
            "With no criteria, browse all active fixed bugs. Repeat --type or --subsystem "
            "to add values. --list-values shows values present in the active snapshot.\n\n"
            "Supported types:\n  " + ", ".join(BUG_TYPES)
        ),
    )
    criteria = filtering.add_argument_group("Selection")
    criteria.add_argument(
        "--type",
        "--bug-type",
        dest="bug_types",
        action="extend",
        nargs="+",
        type=_filter_type,
        metavar="TYPE",
        help="diagnostic types, e.g. kasan kmsan (repeatable)",
    )
    criteria.add_argument(
        "--subsystem",
        dest="subsystems",
        action="extend",
        nargs="+",
        type=_filter_text,
        metavar="TAG",
        help="exact saved subsystem tags (repeatable)",
    )
    criteria.add_argument(
        "--query", type=_filter_text, metavar="TEXT", help="case-insensitive title/key substring"
    )
    criteria.add_argument(
        "--list-values",
        action="store_true",
        help="show active types and subsystem tags with counts; use alone or with --json",
    )
    add_research_filters(filtering)
    pagination = filtering.add_argument_group("Pagination")
    page_size = pagination.add_mutually_exclusive_group()
    page_size.add_argument(
        "--limit", type=int, metavar="N", help="maximum rows to return (default: 20)"
    )
    page_size.add_argument(
        "--all", action="store_true", help="return every match after the selected offset"
    )
    pagination.add_argument(
        "--offset", type=int, metavar="N", help="matching rows to skip (default: 0)"
    )
    filter_output = filtering.add_argument_group("Output").add_mutually_exclusive_group()
    filter_output.add_argument(
        "--json", action="store_true", help="print structured results without color"
    )
    filter_output.add_argument(
        "--urls-only", action="store_true", help="print only complete bug URLs, one per line"
    )

    stats = commands.add_parser(
        "stats",
        help="describe selected bugs, evidence, and fix sizes",
        description="Offline statistics; all matches form the denominator.",
    )
    stats.add_argument(
        "--type",
        "--bug-type",
        dest="bug_types",
        action="extend",
        nargs="+",
        type=_filter_type,
        metavar="TYPE",
        help="diagnostic types (repeatable)",
    )
    stats.add_argument(
        "--subsystem",
        dest="subsystems",
        action="extend",
        nargs="+",
        type=_filter_text,
        metavar="TAG",
        help="exact saved subsystem tags",
    )
    stats.add_argument("--query", type=_filter_text, metavar="TEXT", help="title/key substring")
    add_research_filters(stats)
    stats.add_argument(
        "--top",
        type=int,
        default=10,
        metavar="N",
        help="maximum entries per human table (default: 10); JSON includes all",
    )
    stats.add_argument("--json", action="store_true", help="print complete structured statistics")

    related = commands.add_parser(
        "related",
        help="find bugs sharing fixes or affected code",
        description="Explain concrete shared evidence; bugs are never merged.",
    )
    related.add_argument("key", metavar="KEY_OR_URL", help="bug to find related cases for")
    related.add_argument(
        "--limit", type=int, default=10, metavar="N", help="maximum matches (default: 10)"
    )
    related.add_argument("--json", action="store_true", help="print structured matches and reasons")

    compare = commands.add_parser("compare", help="compare the evidence of two fixed bugs")
    compare.add_argument("keys", nargs=2, metavar="KEY_OR_URL", help="two different bugs")
    compare.add_argument("--json", action="store_true", help="print structured comparison")

    fetch = commands.add_parser(
        "fetch",
        help="download selected evidence for one saved crash",
        description="Explicitly fetch one bug's crash-specific evidence; no code is executed.",
    )
    fetch.add_argument("key", metavar="KEY_OR_URL", help="active bug whose evidence to fetch")
    for flag, label in (
        ("c-repro", "C reproducer"),
        ("syz-repro", "syz reproducer"),
        ("config", "kernel configuration"),
        ("report", "crash report"),
    ):
        fetch.add_argument(
            "--" + flag, action="store_true", help="retrieve the selected crash's " + label
        )
    fetch.add_argument(
        "--crash",
        type=int,
        metavar="N",
        help="zero-based saved crash ordinal (default: representative crash)",
    )
    fetch.add_argument(
        "--refresh", action="store_true", help="refresh selected evidence even if cached"
    )
    fetch.add_argument(
        "--json", action="store_true", help="print structured results without progress"
    )
    fetch.add_argument("--quiet", action="store_true", help="hide progress; retain result summary")

    status = commands.add_parser(
        "status",
        help="summarize local coverage and synchronization state",
        description="Read current database coverage and the latest synchronization result offline.",
        epilog="Examples:\n  ss status\n  ss status --json",
    )
    status.add_argument(
        "--json", action="store_true", help="include detailed counts and snapshot metadata"
    )

    check = commands.add_parser(
        "check",
        help="verify SQLite integrity and saved content hashes",
        description=(
            "Check database integrity, foreign keys, snapshot associations, and every stored "
            "blob hash without writing data. Large databases can take a few seconds."
        ),
        epilog=(
            "Examples:\n  ss check\n  ss check --json\n\nReturns 0 when checks pass, 1 on failure."
        ),
    )
    check_output = check.add_argument_group("Output")
    check_output.add_argument("--json", action="store_true", help="print all check results as JSON")
    check_output.add_argument(
        "--quiet", action="store_true", help="hide progress; keep the check results"
    )

    legacy = commands.add_parser(
        "import-legacy",
        help="index a saved filesystem mirror offline",
        description=(
            "Import retained listings, bug JSON, reports, and patches into SQLite. "
            "Downloaded source files are preserved and no network requests are made."
        ),
        epilog=(
            "Examples:\n"
            "  ss import-legacy ./data\n"
            "  ss --database data/db/archive.sqlite3 import-legacy ./data\n\n"
            "The source directory must exist. Explicit paths may be anywhere."
        ),
    )
    legacy.add_argument(
        "source",
        nargs="?",
        type=Path,
        metavar="DIR",
        help="saved data root (default: selected data directory)",
    )
    legacy_output = legacy.add_argument_group("Output")
    legacy_output.add_argument(
        "--json", action="store_true", help="print the import result as JSON"
    )
    legacy_output.add_argument(
        "--quiet", action="store_true", help="hide progress; keep the summary and issues"
    )

    migrate = commands.add_parser(
        "migrate",
        help="upgrade the database and re-index derived locations",
        description=(
            "Upgrade an existing database using its stored source blobs. "
            "Original payloads are preserved and no download is needed."
        ),
        epilog=(
            "Examples:\n  ss migrate\n  ss check\n\nBack up valuable databases before upgrading."
        ),
    )
    migrate_output = migrate.add_argument_group("Output")
    migrate_output.add_argument(
        "--json", action="store_true", help="print the resulting database status"
    )
    migrate_output.add_argument(
        "--quiet", action="store_true", help="hide progress; keep the migration summary"
    )
    return parser


def validate_filter(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    validate_research_filters(parser, args)
    if args.list_values and (
        any(getattr(args, name, None) for name in SEQUENCE_CRITERIA)
        or any(getattr(args, name, None) is not None for name in OPTIONAL_CRITERIA)
        or args.limit is not None
        or args.offset is not None
        or args.all
        or args.urls_only
    ):
        parser.error("--list-values cannot be combined with selection, pagination, or --urls-only")
    if (args.limit is not None and args.limit < 1) or (args.offset is not None and args.offset < 0):
        parser.error("--limit must be positive and --offset cannot be negative")
    args.bug_types = list(dict.fromkeys(args.bug_types or []))
    args.subsystems = list(dict.fromkeys(value.casefold() for value in args.subsystems or []))
    args.limit = None if args.all else (20 if args.limit is None else args.limit)
    args.offset = 0 if args.offset is None else args.offset
