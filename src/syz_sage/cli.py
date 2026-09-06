"""Command-line interface for Syz Sage."""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
from collections.abc import Sequence
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from . import __version__
from .bug_types import BUG_TYPES
from .config import DATA_DIR_ENV, DATABASE_ENV, DataPaths
from .database import Database
from .display import (
    error,
    human_filter,
    human_filter_values,
    human_import,
    human_migrate,
)
from .display import (
    human_bug as _human_bug,
)
from .display import (
    human_check as _human_check,
)
from .display import (
    human_list as _human_list,
)
from .display import (
    human_status as _human_status,
)
from .display import (
    human_update as _human_update,
)
from .display import (
    progress as _update_progress,
)
from .parsing import KEY_RE, MAX_BUG_KEY_LENGTH, absolute_syzbot_url, key_from_link
from .storage import writable_path
from .sync import UpdateOptions, Updater, _exclusive_update_lock
from .terminal import safe_text


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


def _parser() -> argparse.ArgumentParser:
    from .help import HelpParser

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
        help="inspect one bug, its locations, and crash stack",
        description=(
            "Read one bug from the active SQLite snapshot, including subsystem tags, "
            "crash locations, and changed fix lines. Bug URLs are looked up locally."
        ),
        epilog=(
            "Examples:\n"
            "  ss show extid-0a884bc2d304ce4af70f\n"
            "  ss show extid-0a884bc2d304ce4af70f --stack\n"
            "  ss show extid-0a884bc2d304ce4af70f --json --report\n\n"
            "JSON always includes the extracted stack. Report text requires --report."
        ),
    )
    show.add_argument("key", metavar="KEY_OR_URL", help="extid-* / id-* key or syzbot /bug URL")
    content = show.add_argument_group("Report content")
    content.add_argument(
        "--stack",
        action="store_true",
        help="display all extracted representative-report frames",
    )
    content.add_argument(
        "--report",
        action="store_true",
        help="include the full representative crash report",
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
    check.add_argument("--json", action="store_true", help="print all check results as JSON")

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
    legacy.add_argument("--json", action="store_true", help="print the import result as JSON")

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
    migrate.add_argument("--json", action="store_true", help="print the resulting database status")
    return parser


def _paths(args: argparse.Namespace) -> tuple[DataPaths, Path]:
    # Resolve explicit configuration before looking for a default checkout.
    # A database-only command does not need an implicit download directory.
    database_override = args.database
    if database_override is None and args.data_dir is None:
        configured = os.environ.get(DATABASE_ENV)
        if configured:
            database_override = Path(configured)
    data_override = args.data_dir or os.environ.get(DATA_DIR_ENV)
    needs_data_root = args.command == "update" or (
        args.command == "import-legacy" and args.source is None
    )
    if data_override:
        paths = DataPaths.from_root(data_override)
    elif database_override is not None and not needs_data_root:
        paths = DataPaths.from_root(writable_path(database_override).parent)
    else:
        paths = DataPaths.default()
    database = database_override if database_override is not None else paths.database
    return paths, writable_path(database)


def _dump(value: Any) -> None:
    print(json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True))


def _show_key(value: str) -> str:
    if len(value) <= MAX_BUG_KEY_LENGTH and KEY_RE.fullmatch(value):
        return value
    try:
        url = absolute_syzbot_url(value)
        if url is not None and urlsplit(url).path == "/bug":
            return key_from_link(url)
    except ValueError:
        pass
    raise ValueError("show expects an extid-* or id-* key, or a syzbot /bug URL")


def _import_lock_root(source: DataPaths, destination: DataPaths) -> Path:
    # Coordinate with an existing mirror's updater, wherever that mirror lives.
    # A separate archive without a lock is only read; do not create files in it.
    if source.root == destination.root or (source.root / ".syz_sage.update.lock").is_file():
        return source.root
    return destination.root


def _validate_filter(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    if args.list_values and (
        args.bug_types
        or args.subsystems
        or args.query is not None
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


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI and return a process-compatible status code."""

    parser = _parser()
    try:
        args = parser.parse_args(list(argv) if argv is not None else None)
        if args.command == "filter":
            _validate_filter(parser, args)
        paths, database_path = _paths(args)

        if args.command == "update":
            if args.workers < 1:
                parser.error("--workers must be at least 1")
            if args.limit is not None and args.limit < 1:
                parser.error("--limit must be at least 1")
            summary = Updater(
                paths,
                database_path,
                progress=None if args.json or args.quiet else _update_progress,
            ).run(
                UpdateOptions(
                    workers=args.workers,
                    limit=args.limit,
                    refresh_details=args.refresh_details,
                    refresh_artifacts=args.refresh_artifacts,
                    reports=not args.no_reports,
                    patches=not args.no_patches,
                )
            )
            payload = summary.as_dict()
            if args.json:
                _dump(payload)
            else:
                _human_update(summary, paths.root, database_path)
            partial_allowed = args.allow_partial and summary.database.get("status") == "partial"
            return 0 if summary.ok or partial_allowed else 1

        if args.command == "import-legacy":
            source = DataPaths.from_root(args.source or paths.root)
            if not source.root.is_dir():
                raise ValueError(f"Legacy source directory does not exist: {source.root}")
            lock_root = _import_lock_root(source, paths)
            existing_source_lock = (
                lock_root == source.root and (lock_root / ".syz_sage.update.lock").is_file()
            )
            with (
                _exclusive_update_lock(lock_root, create=not existing_source_lock),
                Database(database_path) as database,
            ):
                database.initialize()
                result = database.import_legacy(source)
            if args.json:
                _dump(result)
            else:
                human_import(result, database_path)
            return 0 if not result.get("failures") else 1

        if not database_path.is_file():
            error(
                f"Database does not exist: {database_path}. "
                "Run 'ss update' or 'ss import-legacy SOURCE' first."
            )
            return 2

        if args.command == "migrate":
            with _exclusive_update_lock(paths.root), Database(database_path) as database:
                result = database.status()
            if args.json:
                _dump(result)
            else:
                human_migrate(result, database_path)
            return 0

        with Database(database_path, read_only=True) as database:
            database.initialize()
            if args.command == "status":
                result = database.status()
                _dump(result) if args.json else _human_status(result)
                return 0
            if args.command == "check":
                result = database.health_check()
                _dump(result) if args.json else _human_check(result, database_path)
                return 0 if result.get("ok") else 1
            if args.command == "list":
                if args.limit < 1 or args.offset < 0:
                    parser.error("--limit must be positive and --offset cannot be negative")
                rows = database.list_bugs(args.query, args.limit, args.offset)
                _dump(rows) if args.json else _human_list(rows, offset=args.offset)
                return 0
            if args.command == "filter":
                if args.list_values:
                    values = database.filter_values()
                    _dump(values) if args.json else human_filter_values(values)
                    return 0
                result = database.filter_bugs(
                    bug_types=args.bug_types,
                    subsystems=args.subsystems,
                    query=args.query,
                    limit=args.limit,
                    offset=args.offset,
                )
                if args.json:
                    _dump(result)
                elif args.urls_only:
                    for bug in result["bugs"]:
                        if bug.get("bug_url"):
                            print(safe_text(bug["bug_url"]))
                else:
                    human_filter(result, query=args.query)
                return 0
            if args.command == "show":
                key = _show_key(args.key)
                bug = database.get_bug(key)
                if bug is None:
                    error(f"Bug not found in the active snapshot: {key}")
                    return 3
                if not args.report and bug.get("report"):
                    bug["report"].pop("text", None)
                _dump(bug) if args.json else _human_bug(bug, args.report, args.stack)
                return 0
    except KeyboardInterrupt:
        error("Interrupted.")
        return 130
    except (OSError, sqlite3.Error, ValueError, RuntimeError) as exc:
        error(exc)
        return 1
    return 0
