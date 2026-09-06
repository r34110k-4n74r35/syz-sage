# Research and maintenance scripts

[Project overview](../README.md) · [CLI usage](usage.md) · [Development](development.md)

The top-level `scripts/` directory contains checkout-local tools for analysis,
exports, and maintaining the downloaded mirror. They share application code
from `src/syz_sage/` and are separate from the installed CLI package.

Use `ss update` for routine retrieval. These scripts operate on retained files;
they do not automatically update SQLite or select the active database snapshot.
The mirror can contain newer partial data than `ss show` displays.

## Running a script

Run from the project root after the [editable installation](../README.md#quick-start):

```console
python -m scripts.analyze_fixed_bugs --help
```

Without installation, prefix the command with `PYTHONPATH=src`:

```console
PYTHONPATH=src python3 -m scripts.audit_snapshot --help
```

Use the module form (`python -m scripts.NAME`) so relative imports work. Explicit
input and output paths may be inside or outside this project, subject to normal
filesystem permissions. Files under `outputs/` are created only when you
explicitly request an analysis or export there.

## Tools at a glance

| Module | Main input | Result or destination | Network |
|---|---|---|---|
| `scripts.audit_snapshot` | Retained files under `data/` | Prints coverage and gaps; optional JSON file with `--output` | No |
| `scripts.analyze_fixed_bugs` | Catalog, detail JSON, reports, patches, resolutions | Required `--output` analysis JSON | No |
| `scripts.build_fixed_bug_report` | Analysis JSON | Markdown report at the requested path | No |
| `scripts.build_fixed_bug_workbook` | Analysis JSON | Workbook and preview images at the requested paths | No retrieval |
| `scripts.download_listings` | syzbot fixed listing | `data/raw/upstream_fixed.json` and `.html` | Yes |
| `scripts.build_catalog` | Saved listing JSON | `data/processed/catalog.json` | No |
| `scripts.fetch_artifacts` | Catalog and saved per-bug JSON | Detail JSON, reports, patches, optional configs/reproducers; prints fetch status | Yes, except `--status` |
| `scripts.resolve_title_only_fixes` | Saved detail JSON with title-only fixes | `data/processed/resolved_fix_hashes.json` and matched patches | Yes |

`common.py` supplies project paths and the shared `SyzbotClient`; its URL
helpers and atomic writes delegate to the application modules. Detail, report,
and patch retrieval uses the same artifact validation and bounded worker
helper as the CLI. `project_paths.mjs` supplies JavaScript path resolution, and
`workbook_values.mjs` validates dates and elapsed-time values for export.
The `.mjs` workbook builder sits beside its Python launcher. These helper files
are not separate user commands.

## Inspect mirror coverage without saving a report

```console
python -m scripts.audit_snapshot
python -m scripts.fetch_artifacts --status
```

The audit prints JSON with coverage, malformed files, missing artifacts, and
other actionable gaps. It exits unsuccessfully when it finds actionable gaps.
It does not repair downloads or migrate the database. `fetch_artifacts --status`
prints local coverage without retrieval or creating missing data directories.
Neither command automatically saves a status/audit report.

The audit and analyzer accept `--root PATH`; this means the project root
containing `data/`, not the data directory itself. Most maintenance helpers use
the checkout's fixed `data/` paths from `scripts/common.py`; they do not inherit
the CLI's `--data-dir`, `--database`, or `SYZ_SAGE_*` overrides.

## Create an analysis and Markdown report

When you want saved research results:

```console
python -m scripts.analyze_fixed_bugs --output outputs/analysis.json
python -m scripts.build_fixed_bug_report outputs/analysis.json outputs/report.md
```

The analyzer selects bugs with a retained nonempty report and a downloaded
patch for a known fix hash from the current catalog. A catalog is required;
retained bugs absent from it are excluded from both statistics and the cohort
manifest. Fix references combine listing and detail metadata, match supplemental
resolutions by bug, subject, and repository, and count each patch hash once.
Its JSON includes bug results, patch hunks, a cohort
manifest, and coverage/exclusion information. The Markdown builder consumes
that analysis rather than rerunning retrieval.

The analyzer accepts saved syzbot `YYYY/MM/DD` timestamps and ISO timestamps.
Exported calendar dates use `YYYY-MM-DD`; elapsed days use the complete timestamps
so the workbook and report agree. Missing or invalid dates remain blank, as do
intervals whose timestamps have incompatible timezone information.

Crash-to-fix classifications and distance estimates are research heuristics.
Review their evidence and exclusions before drawing conclusions; path-based
classifications in research outputs do not replace syzbot's subsystem tags
in SQLite. The [database guide](database.md) explains the core fields and their
sources.

## Optional workbook export

The workbook exporter additionally needs Node.js and a locally available
`@oai/artifact-tool` package. Neither is required for the CLI or Markdown reports.

```console
python -m scripts.build_fixed_bug_workbook outputs/analysis.json outputs/workbook.xlsx outputs/previews
```

The Python launcher calls the adjacent JavaScript builder. The workbook and
previews are written to the requested destinations. The renderer and its
dependencies use their normal cache and temporary-file behavior; the launcher
does not override their environment. Renderer/dependency availability is
separate from the core application's regression checks.

## Maintain or enrich the mirror

Use these commands only when you deliberately want to run individual stages:

```console
python -m scripts.download_listings
python -m scripts.build_catalog
python -m scripts.fetch_artifacts --patches
python -m scripts.resolve_title_only_fixes --workers 4
```

Listing and catalog commands refresh their corresponding files. The artifact
helper can retrieve bug JSON/reports with `--syzbot`, or both patch and syzbot
work with `--all`. See its `--help` for optional `--configs`, `--repros`, and
`--refresh-missing-hashes`. Its selection and limit behavior differs from
`ss update`; it does not index or activate a database snapshot.

The listing helper validates a nonempty JSON listing and matching HTML bug
membership before writing either source. The artifact helper validates cached
files before reusing them and shares `processed/sync_state.json` with the CLI.
A failed report or patch stays pending even if an older valid file exists;
updated detail JSON also records the need for its matching representative
report. Files are replaced atomically only after validation, and identical
bytes are left untouched. Optional configs/reproducers keep their existing
plain-text formats and filenames. Their `data/artifacts/configs/` and
`data/artifacts/repros/` directories are created only when an optional artifact
is saved. Fetch results print to the terminal; no `fetch_status.json` report is
written automatically. The separate `processed/sync_state.json` file remains
necessary for retry recovery.

Patch selection combines fix hashes from the catalog and saved bug details.
When several selected bugs share a patch, per-hash coordination serializes its
download and retry state, and later requests reuse the successful saved file.

`--configs` and `--repros` include bugs whose ordinary JSON/report is already
complete, so optional artifacts can be added later:

```console
python -m scripts.fetch_artifacts --syzbot --configs --repros --limit 5
```

The title resolver searches declared repositories for an unambiguous exact
commit subject and downloads the matched patch. Original bug JSON remains
unchanged; supplemental results retain unsuccessful and ambiguous searches
as well as resolved commits. A failed refresh preserves a previously successful
resolution instead of removing its known hash. Repository identity remains part of a resolution,
so equal titles in different repositories stay separate. The cgit title-search
workflow supports `git.kernel.org` repositories; an unsupported search source
is retained as unresolved instead of being searched as though it were cgit.

`download_listings`, retrieval modes of `fetch_artifacts`, and
`resolve_title_only_fixes` acquire the same data-root lock as `ss update`.
`build_catalog` should be run separately from mirror writers. To index
completed, deliberate mirror changes afterward:

```console
ss import-legacy ./data
```

Import still checks completeness and pending refresh state. See
[offline imports](usage.md#import-retained-files-offline) and
[update recovery](usage.md#recover-interrupted-or-partial-updates).
