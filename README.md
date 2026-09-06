# Syz Sage

Syz Sage retrieves fixed Linux kernel bugs from
[syzbot](https://syzkaller.appspot.com/upstream/fixed), saves the source data
inside this project by default, and makes it searchable offline with SQLite.

Each bug can include its title, diagnostic type, syzbot URL, subsystem tags, crash metadata,
representative report and full extracted stack, fix commits, and crash/fix
source locations. Original downloaded payloads remain available as evidence.

## Quick start

Requirements: **Python 3.10+ with SQLite**. The application has no third-party
runtime dependencies. Retrieval needs network access; inspection and migration
work offline.

From this project's root, create and activate a local environment:

```console
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
```

The editable installation uses the source directly; routine development needs
no wheel build. If `.venv` already exists, activate it instead of recreating it.
Python and installation tools use their normal cache and temporary-file behavior.

You can also run directly from the checkout without installation:

```console
PYTHONPATH=src python3 -m syz_sage --help
```

Choose the starting point that matches your local data:

| Local state | Command |
|---|---|
| Database already exists | `ss status` |
| Inspection says the schema needs an upgrade | `ss migrate` |
| Downloads exist in `data/`, but the database does not | `ss import-legacy ./data` |
| Starting fresh, or checking for newly fixed bugs | `ss update` |

For everyday use:

```console
ss update
ss filter --type kasan --subsystem fs
ss list --query use-after-free --limit 5
ss show extid-0a884bc2d304ce4af70f
ss show extid-0a884bc2d304ce4af70f --stack
ss check
```

Replace the example bug key with one returned by `ss list`. `ss show` also
accepts a quoted syzbot bug URL. Run `ss COMMAND --help` for options and examples.
`ss` and `syz-sage` are aliases; if Linux's socket utility occupies `ss` on your
`PATH`, use `syz-sage` or `python -m syz_sage` instead.

Filter fixed bugs by diagnostic type and the saved subsystem tags:

```console
ss filter --type kasan kmsan --subsystem fs usb
ss filter --list-values
ss filter --type warning --subsystem mm --all --urls-only
```

Results include titles, bug URLs, patch links, C reproducer URLs and availability,
types, tags, and crash/fix/report summaries. Links come from saved metadata;
filtering does not download files.
Filters are case-insensitive: multiple values within a category match any of
those values, and the type and subsystem categories must both match. Tags are
exact syzbot labels; `fs` does not automatically include `ext4` or `btrfs`.
See [filtering](docs/usage.md#filter-fixed-bugs) for pagination and JSON output.
For a database created by an older version, run `ss migrate` once to backfill
bug types and repair crash-stack interpretation from stored evidence. No download is needed.

## Documentation

| Guide | What it covers |
|---|---|
| [Usage](docs/usage.md) | Commands, incremental updates, retries, JSON, colors, paths, and configuration. |
| [Database and provenance](docs/database.md) | Tables, exact raw-data sources, crash/fix interpretation, SQL queries, and migrations. |
| [Research and maintenance scripts](docs/scripts.md) | Script inputs/outputs, optional report/workbook generation, and mirror maintenance. |
| [Development](docs/development.md) | Source layout, module responsibilities, data flow, and checks for future changes. |

## How updates and coverage work

`ss update` checks the fixed-bug listing, reuses valid saved details and
artifacts, and downloads new or missing content. An unchanged mirror leaves
SQLite untouched. Existing metadata changes, repaired artifacts, and unfinished
downloads can still require indexing even when no new bugs appear.

Only a complete candidate becomes active. Failed or deliberately limited
updates retain their downloads and preserve the previous complete snapshot;
rerun `ss update` to resume. `show` and `list` read that active snapshot offline.

Routine retrieval saves **one representative crash report per bug**, plus
metadata for every supplied crash. Configs and reproducers are recorded as
URLs. Subsystem tags come from the saved syzbot listing; missing tags and
coordinates remain unknown. Extracted locations carry their method and evidence,
and inferred patch functions are labeled as such. See the
[database guide](docs/database.md#interpreting-locations) for interpretation limits.

## Project layout

```text
README.md                Start here
pyproject.toml           Package metadata, CLI entry points, and tool settings
src/syz_sage/            Application and shared Python modules
scripts/                 Checkout-local research and maintenance commands
tests/                   Regression tests and small fixtures
docs/                    Usage, database, scripts, and development guides
data/
  db/syz_sage.sqlite3     SQLite database
  raw/                   Saved listings and per-bug JSON
  artifacts/reports/     Representative crash reports
  artifacts/patches/     Fix patches, named by commit hash
  processed/             Catalog, fix resolutions, and retry state
outputs/                 Optional results from explicitly run analysis/export commands
```

`data/` and `outputs/` are ignored by Git. Inspection prints to the terminal;
analysis and export files are written to explicitly requested destinations.
Tests use self-cleaning `.syz-sage-tmp-*` directories inside the project.
Normal Python `__pycache__/` directories are ignored; the application does not
require mypy or its separate type-checking cache.

The default database is `data/db/syz_sage.sqlite3`, with downloads under
`data/raw/` and `data/artifacts/`. Explicit input/output paths and configuration
overrides may use any location permitted by the operating system. Syz Sage
does not automatically create its own hidden or system application-data folder
outside the checkout. See
[paths and write boundaries](docs/usage.md#paths-and-write-boundaries) for
configuration precedence and SQLite sidecar files.
