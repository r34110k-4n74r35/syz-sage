"""Command-line interface for Syz Sage."""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import sqlite3
from collections.abc import Sequence
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from ..database import Database
from ..parsing.listing import KEY_RE, MAX_BUG_KEY_LENGTH, absolute_syzbot_url, key_from_link
from ..project.config import DATA_DIR_ENV, DATABASE_ENV, DataPaths
from ..project.progress_events import ProgressEvent
from ..project.storage import exclusive_update_lock as _exclusive_update_lock
from ..project.storage import writable_path
from ..retrieval.models import UpdateOptions
from ..retrieval.sync import Updater
from .arguments import build_parser as _parser
from .arguments import validate_filter
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
from .progress import ProgressDisplay
from .terminal import safe_text


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


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI and return a process-compatible status code."""

    parser = _parser()
    try:
        args = parser.parse_args(list(argv) if argv is not None else None)
        if args.command == "filter":
            validate_filter(parser, args)
        paths, database_path = _paths(args)

        if args.command == "update":
            if args.workers < 1:
                parser.error("--workers must be at least 1")
            if args.limit is not None and args.limit < 1:
                parser.error("--limit must be at least 1")
            enabled = not (args.json or args.quiet)
            with ProgressDisplay("Updating fixed bugs", enabled=enabled) as progress:
                summary = Updater(
                    paths,
                    database_path,
                    progress=None,
                    on_progress=progress if enabled else None,
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
                progress.finish(success=summary.ok)
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
            enabled = not (args.json or args.quiet)
            with (
                ProgressDisplay("Importing saved data", enabled=enabled) as progress,
                _exclusive_update_lock(lock_root, create=not existing_source_lock),
                Database(database_path, on_progress=progress if enabled else None) as database,
            ):
                database.initialize()
                result = database.import_legacy(source)
                progress.finish(success=not result.get("failures"))
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
            enabled = not (args.json or args.quiet)
            with (
                ProgressDisplay("Migrating database", enabled=enabled) as progress,
                _exclusive_update_lock(paths.root),
                contextlib.closing(
                    Database(database_path, on_progress=progress if enabled else None)
                ) as database,
            ):
                progress(ProgressEvent("schema", "Checking database schema"))
                prior_schema = int(database.connection.execute("PRAGMA user_version").fetchone()[0])
                database.initialize()
                result = database.status()
            if args.json:
                _dump(result)
            else:
                human_migrate(result, database_path, prior_schema=prior_schema)
            return 0

        if args.command == "check":
            enabled = not (args.json or args.quiet)
            with (
                ProgressDisplay("Checking database", enabled=enabled) as progress,
                Database(
                    database_path, read_only=True, on_progress=progress if enabled else None
                ) as database,
            ):
                result = database.health_check()
                progress.finish(success=bool(result.get("ok")))
            _dump(result) if args.json else _human_check(result, database_path)
            return 0 if result.get("ok") else 1

        with Database(database_path, read_only=True) as database:
            database.initialize()
            if args.command == "status":
                result = database.status()
                _dump(result) if args.json else _human_status(result)
                return 0
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
