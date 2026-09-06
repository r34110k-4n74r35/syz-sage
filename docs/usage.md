# Command-line usage

Follow the [quick start](../README.md#quick-start) to prepare the checkout.
The examples below run from the project root. `ss`, `syz-sage`, and
`python -m syz_sage` invoke the same application. If your shell selects the
Linux socket utility named `ss`, use `syz-sage` instead.

## Contents

- [Command reference](#command-reference)
- [Inspect bugs](#inspect-bugs)
- [Filter fixed bugs](#filter-fixed-bugs)
- [Update fixed bugs](#update-fixed-bugs)
- [Recover interrupted or partial updates](#recover-interrupted-or-partial-updates)
- [Import retained files offline](#import-retained-files-offline)
- [Migrate and check the database](#migrate-and-check-the-database)
- [JSON and automation](#json-and-automation)
- [Terminal display](#terminal-display)
- [Paths and write boundaries](#paths-and-write-boundaries)

## Command reference

```console
ss --help
ss update --help
ss show --help
ss filter --help
ss --version
```

Each command supports `--json` and `--help`. Global path options precede the
command; command-specific options follow it.

| Command | Purpose | Network / database writes |
|---|---|---|
| `update` | Check the fixed listing, retrieve missing content, and index it. | Network; database writes when indexing or migration is needed. |
| `list` | Search and paginate active bugs. | Offline, read-only. |
| `filter` | Select fixed bugs by diagnostic type, subsystem tags, and optional title/key text. | Offline, read-only. |
| `show KEY_OR_URL` | Inspect one active bug and its saved evidence. | Offline, read-only. |
| `status` | Summarize coverage and the latest synchronization. | Offline, read-only. |
| `check` | Verify database consistency and stored content hashes. | Offline, read-only. |
| `import-legacy [DIR]` | Index a retained filesystem mirror. | Offline; database writes when needed. |
| `migrate` | Upgrade an existing database from stored source blobs. | Offline; writes an older database during migration. |

`show`, `list`, and `filter` use the **active complete snapshot**. Retained historical
bugs or bugs present only in a partial candidate do not appear in these
commands. `status` shows active coverage and the latest run; `status --json`
also exposes stored-history counts and snapshot metadata.

## Inspect bugs

Find a bug by title or key, then inspect its evidence:

```console
ss status
ss list --query 'use-after-free' --limit 10
ss list --limit 10 --offset 10
ss show extid-0a884bc2d304ce4af70f
ss show 'https://syzkaller.appspot.com/bug?extid=0a884bc2d304ce4af70f'
```

`list --query TEXT` matches a case-insensitive substring of the title or stable
bug key. It does not search source paths or filter subsystem tags. Results
follow active listing order. `--limit N` defaults to 20 and must be positive;
`--offset N` defaults to 0 and must be non-negative.

`show` accepts an `extid-*` / `id-*` key or a syzbot `/bug` URL. Both forms
perform the same local lookup. Quote URLs containing `&` so the shell passes
one argument.

The default display includes the title, bug type, bug URL, subsystem tags, C reproducer
availability and URLs, timeline, crash coordinates, fix commits and their
changed locations, and saved evidence. Crash locations include file, function,
line/column, kernel commit, and extraction method/confidence when available. Fix ranges describe
removed and added lines in the patch's old and new trees. Missing values
remain unknown; inferred functions retain their extraction basis.

```console
ss show extid-0a884bc2d304ce4af70f --stack
ss show extid-0a884bc2d304ce4af70f --report
ss show extid-0a884bc2d304ce4af70f --json --report
```

| Show option | Effect |
|---|---|
| `--stack` | Display every extracted frame from the representative report, including inline and allocation/free traces. |
| `--report` | Include the complete saved representative report text. |
| `--json` | Return structured metadata and the extracted stack; include the report body only with `--report`. |

Routine retrieval saves **one representative crash report per bug**, plus
metadata for every crash entry supplied by syzbot. Kernel configs and C/syz
reproducers are recorded as URLs; their contents and other historical crash
reports are not downloaded by `ss update`. See the
[database guide](database.md) for coverage, location interpretation, and the
mapping from source files to database fields.

### C reproducer availability

`ss show KEY` summarizes C reproducer links across **all crash entries** in the
active bug's saved detail JSON, including crashes beyond the representative
report. It displays up to three distinct URLs and a hint to use `--json` for
the complete list.

`ss show KEY --json` exposes `c_reproducer_status` and `c_reproducer_urls`:

| Status | Meaning |
|---|---|
| `available` | At least one valid C reproducer URL is recorded in the saved crash metadata. |
| `not_provided` | The saved detail has a valid crash list, including an empty list, and supplies no C reproducer links. |
| `unknown` | No valid link was found, and detail/crash metadata is missing or malformed, or a supplied URL is invalid. |

The URL list removes duplicates while preserving crash order. A valid link
makes the status `available` even if another crash entry is malformed.
Availability describes what the saved data reports; it does not mean a C
reproducer has been downloaded locally or its URL has been checked over HTTP.
These fields are derived during the read-only lookup, so existing indexed
bugs need no migration, re-import, or download to display them. See
[C reproducer sources](database.md#c-reproducer-metadata) for field provenance.

## Filter fixed bugs

```console
ss filter --type kasan --subsystem fs
ss filter --type kasan kmsan --subsystem fs usb
ss filter --type warning --subsystem mm --query 'use-after-free'
ss filter --subsystem ext4 btrfs --limit 10 --offset 10
ss filter --list-values
```

`--type` and `--subsystem` accept one or more values and can be repeated. Values
are case-insensitive. Several types match **any selected type**, and several
subsystems match **any selected tag**. When both categories are supplied, a bug
must match both. Omitting a category leaves it unrestricted; `ss filter` alone
browses the first page of active bugs. `--query` adds a literal case-insensitive
substring match against the title or key.

Subsystem tags match exactly. For example, `fs` selects bugs tagged `fs`; use
`--subsystem fs ext4 btrfs` to include those three distinct labels. No inferred
filesystem hierarchy or source-path classification is applied. Untagged bugs
remain visible without a subsystem constraint. `--list-values` shows the types
and tags actually present in the active database, with their bug counts.
Use it alone or with `--json`; selection and pagination options do not apply
to value discovery.

Bug types describe the leading diagnostic in the saved title, such as `kasan`,
`kmsan`, `ubsan`, `warning`, or `info`. Additional supported markers include
`kcsan`, `kfence`, `bug`, `panic`, and `general-protection-fault`; unrecognized
titles are `other`. A manager boot/test wrapper is handled separately from the
underlying diagnostic. This is a derived title classification, not a root-cause
or vulnerability classification. See [bug type provenance](database.md#bug-types).

The human display includes each full title and URL, bug key, stored type, all
subsystem tags, saved status, crash/fix counts, and representative-report availability.
Each result also includes all distinct recorded patch links and C reproducer
URLs, printed in full for copying. Patch links prefer the saved download source;
when that is unavailable, they use the saved fix commit link. A patch link may
therefore open a commit page instead of a raw diff. No URL is guessed from a hash.
Missing patch links are marked as not recorded. C reproducer availability uses
the [same saved-metadata rules as `show`](#c-reproducer-availability), across all
crash entries. These links are not downloaded or checked over the network.
It also shows the total matching count and the current page. Results follow
active listing order, even when a bug matches several selected tags.
Fixed-bug membership comes from that listing. The saved status text comes
from cached detail JSON and can still describe an earlier reporting state.

```console
ss filter --type kasan --subsystem fs --all --json
ss filter --subsystem usb --all --urls-only
ss filter --type kmsan --all --json > /path/to/matches.json
```

`--limit` defaults to 20 and must be positive; `--offset` defaults to 0 and
must be non-negative. `--all` returns every match after the offset and cannot
be combined with an explicit `--limit`. JSON includes `bugs`, the pre-pagination
`total`, `limit` (`null` with `--all`), `offset`, `bug_types`, and `subsystems`.
Each bug includes `key`, `title`, `bug_url`, `bug_type`, tags, and summary fields,
plus `patch_urls`, `c_reproducer_status`, and `c_reproducer_urls`. URL arrays are
empty when no usable links were recorded. Existing indexed data needs no
migration or re-import for these additional fields.
`--urls-only` prints one complete **bug URL** per line with no heading or color;
use `--json` to export patch and reproducer URLs too. Both
output formats respect pagination; add `--all` to export the whole selection.
JSON and URL-only modes are mutually exclusive. No matches is a successful
empty result; URL-only mode prints nothing.

Filtering reads SQLite only. It does not retrieve bugs, download artifacts,
create export files on its own, or migrate a database during inspection. Run
`ss migrate` once if an older database reports that schema migration is needed.

## Update fixed bugs

```console
ss update
```

An ordinary update proceeds as follows:

1. Acquire the data-root lock and check the live `upstream/fixed` JSON/HTML.
2. Compare the listing with the retained copy and save relevant listing changes.
3. Retrieve missing or invalid bug detail JSON and pending detail retries.
4. Retrieve missing or invalid representative reports and fix patches, including
   new fix hashes and pending artifact retries.
5. Compare retained content with SQLite, then skip unchanged ingestion or index
   a candidate snapshot. A complete candidate becomes active.

Valid saved details are reused, including for bugs that reappear in the fixed
listing. Changes to a listing title, subsystem tags, or fix references are
indexed without automatically downloading that bug's detail JSON again. A new
fix hash can require a new patch for an existing bug.

When the updater confirms that database ingestion can be skipped, the final
result says it is up to date. The JSON result has `database.status: "unchanged"` and
`database.skipped: true`. No new database rows or sync runs are added, and the
database's `last_checked_at` does not advance. The command still checks the
website and may rewrite local listing/catalog/retry files.

Zero newly discovered bugs alone does not imply zero database work. Changed
tags or other metadata, repaired artifacts, unindexed downloads, a previous
partial run, or an older schema can require indexing or migration. Changes
to unrelated HTML navigation counts or display dates are ignored when the
indexed listing and subsystem tags are unchanged.

| Update option | Effect |
|---|---|
| `--workers N` | Set concurrent network workers; default 8, minimum 1. |
| `--quiet` | Hide progress and retain the final summary and issues. |
| `--json` | Emit the structured summary without progress messages. |
| `--refresh-details` | Re-fetch selected bug JSON and its representative reports. |
| `--refresh-artifacts` | Re-fetch reports and patches while reusing valid saved detail JSON. |
| `--limit N` | Select the first N listing entries; minimum 1, default all entries. |
| `--no-reports` | Disable report retrieval and keep the candidate partial. |
| `--no-patches` | Disable patch retrieval and keep the candidate partial. |
| `--allow-partial` | Return success for a partial result without activating it. |

Use the refresh flags when you explicitly want new versions of saved content:

```console
ss update --refresh-details
ss update --refresh-artifacts
```

Without a limit, these can re-download the corresponding content for the whole
live listing. Ordinary incremental updates need neither flag. A validated
refresh can replace a same-name mirror file; SQLite retains indexed versions.
Bugs leaving the live listing do not trigger deletion of saved downloads or
database history.

Listing progress compares with the previous filesystem listing. Final
new/no-longer-listed counts compare with the active database snapshot;
changed-entry counts come from the retained listing comparison. Following a
partial attempt, a file can already exist for a bug that is still new to the
active database. The report table's unavailable count means no report URL was
available for a selected bug; request failures are listed under issues.

## Recover interrupted or partial updates

Successful downloads stay on disk. Pending detail, report, and patch work is
recorded in `data/processed/sync_state.json` under the selected data root.
Resume with the ordinary command:

```console
ss update
```

The updater saves successful results as downloads finish and periodically
persists completed work in that existing retry file. An abrupt termination can
re-download the last small batch of saved completions; it does not require
restarting the whole download phase. No separate recovery files are needed.

Partial candidates preserve the last complete active snapshot and its
associated report/patch versions. Failed refreshes remain pending even when an
older valid file exists. On a first-ever partial run, there is no active
snapshot for `show` or `list` yet.

`--limit N` selects the **first N listing entries**, not N missing bugs. A
limit smaller than the listing, `--no-reports`, or `--no-patches` makes the
candidate partial even if some skipped content already exists locally:

```console
ss update --limit 5 --allow-partial --json
```

`--allow-partial` changes the partial result's exit code to 0; it does not
relax completeness checks or activate the candidate. A failed run still exits
unsuccessfully. Check `database.status` and `database.activated` in automation,
then run a full `ss update` when ready to complete retrieval.

Only one update can own a data root at a time. A concurrent invocation reports
an error. The persistent `.syz_sage.update.lock` file can remain after the
process exits; its presence alone does not indicate a running updater. Retain
the downloaded files and retry state when recovering from transient failures.

## Import retained files offline

If the downloads exist but the database does not, import them without network
access. The source directory must already exist:

```console
ss import-legacy ./data
ss --database ./data/db/research.sqlite3 import-legacy ./data
ss import-legacy ./data --json
ss --database /path/to/research.sqlite3 import-legacy /path/to/saved-mirror
```

Omitting `DIR` uses the selected data root. The import reads retained listings,
bug JSON, reports, patches, and supporting metadata without rewriting those
source files. Repeating a successful unchanged import adds no data. Missing
or invalid required content yields a partial candidate; inspect the result
before assuming it became active.

Import uses the source root's update lock when it is also the destination data
root or already has a mirror lock. Otherwise, it locks the destination data
root, or the database's parent directory when only a database path was supplied.
Existing source locks are opened read-only. A separate static archive without
an existing lock receives no new lock file.
An explicit source plus `--database FILE` works without a checkout; omitting
the source still requires a selected or default data root.

Imports honor pending refreshes in saved retry state. An older valid artifact
cannot make an unfinished refresh complete. Run `ss --data-dir DIR update` to
finish retrieval in the selected mirror, whether it is inside or outside the
checkout. For deliberate mirror maintenance and research workflows, see
[the scripts guide](scripts.md).

## Migrate and check the database

Use stored source blobs to upgrade an older database, then verify its local
consistency:

```console
ss migrate
ss check
ss check --json
ss --database /path/to/research.sqlite3 migrate
```

Migration runs offline and preserves original downloaded bytes. It does not
rewrite the mirror or create a sync run. Schema version 3 records explicit
snapshot report/patch associations and re-extracts derived crash/fix locations;
corrected parsing can change previously displayed coordinates or function
names. `ss migrate --json` returns the resulting database status.

Schema version 4 stores bug types for every retained snapshot using its saved
titles. It does not change original JSON, reports, or patches.

Read-only `show`, `list`, `filter`, `status`, and `check` report when migration is
required. Run `ss migrate` before retrying them. Writable opens during update
or import can perform the upgrade automatically. See
[database migrations](database.md#migration-and-subsequent-updates) for the
schema history and limits of older artifact associations.

`check` verifies SQLite integrity, foreign keys, stored blob hashes, and
snapshot consistency, including retained history. It returns 0 when checks
pass and 1 when they find problems. It may take longer than `status`. These
checks establish local consistency; they do not measure live website coverage
or establish the semantic correctness of a derived crash location.

Back up valuable databases before upgrading or making manual changes; choose
any suitable backup destination. SQLite's `-wal` and `-shm` files belong to its
write-ahead log and connection coordination. Do not remove them while
connections are open.
Use SQLite's backup API for an open database, or copy the main database after
all connections close and the log has been checkpointed.

## JSON and automation

Update progress goes to stderr; summaries and JSON results go to stdout.
`update --quiet` suppresses progress while preserving the human summary and
issues. `--json` suppresses progress and preserves structured results, including
the full retrieval failure list and available database failure details. Human
update summaries show at most five distinct issues.

```console
ss update --quiet
ss update --json
ss status --json
ss show extid-0a884bc2d304ce4af70f --json --report
ss filter --type kasan --subsystem fs --all --json
```

JSON `show` includes `crash_stack` without `--stack`; only `--report` adds the
report body. JSON preserves source strings and field values independently of
terminal presentation. It is the stable interface for scripts; human columns,
wrapping, and labels can change.

Errors before a result is constructed go to stderr and may leave stdout
empty. Check the exit status before parsing stdout.

| Exit code | Meaning |
|---|---|
| `0` | Success; also a partial update explicitly allowed by `--allow-partial`. |
| `1` | Retrieval, database, path, or validation failure; partial update by default; failed consistency check. |
| `2` | Invalid CLI arguments, or a missing database for inspection/migration. |
| `3` | `show` did not find the requested bug in the active snapshot. |
| `130` | Interrupted with Ctrl-C. |

An invalid `show` key/URL is a validation failure (`1`). A valid identifier
absent from the active snapshot returns `3`. When using `--allow-partial`,
inspect the result as well as the process exit status.

## Terminal display

Help groups related options and includes examples. Human summaries wrap to the
terminal width; narrow terminals use individual records instead of wide
tables. Bug inspection groups each fix commit with its changed locations and
numbers stack frames when `--stack` is used.

Colors are enabled independently for interactive stdout and stderr. `NO_COLOR`
(even an empty value) or `TERM=dumb` disables them. Redirected output and JSON
contain no application-added color sequences:

```console
NO_COLOR=1 ss show extid-0a884bc2d304ce4af70f --stack
NO_COLOR=1 ss update
```

Cyan highlights counts and source paths; magenta marks tags and functions;
blue marks links and dates. Green denotes success or available content, while
yellow marks unavailable or uncertain values. Fix ranges use red for old
lines and green for new lines; failures are also red. Written labels carry
the same meaning when color is disabled.

Human output escapes source terminal-control characters. `--report` preserves
report line breaks and tabs while escaping other controls. For original
evidence, use the stored source files/blobs described in the
[database guide](database.md#where-each-field-comes-from).

## Paths and write boundaries

Without overrides, the data root is this checkout's `data/` and SQLite is
`data/db/syz_sage.sqlite3`. With the checkout's editable installation, these
defaults stay anchored to the project when invoked from another directory.
Explicit paths may be anywhere permitted by the operating system. Relative
paths resolve from the current working directory, and `~` is expanded to the
user's home directory.

```console
ss --data-dir ./data update
ss --data-dir /path/to/mirror update
ss --database /path/to/research.sqlite3 status
ss --data-dir /path/to/mirror --database /path/to/research.sqlite3 check
```

The data root is selected by `--data-dir`, then `SYZ_SAGE_DATA_DIR`, then the
checkout default. The database path is selected in this order:

1. Explicit `--database FILE`.
2. `DIR/db/syz_sage.sqlite3` when `--data-dir DIR` was explicitly provided.
3. `SYZ_SAGE_DATABASE` when set.
4. `db/syz_sage.sqlite3` beneath the selected data root.

Thus an explicit `--data-dir` takes precedence over an ambient
`SYZ_SAGE_DATABASE` for SQLite selection; explicit `--database` takes precedence
over both. Downloaded files continue to use the selected data root. Global path
options must precede the command.

`--data-dir`, `--database`, `SYZ_SAGE_DATA_DIR`, and `SYZ_SAGE_DATABASE` are
explicit user configuration and may point outside the checkout. Source paths,
script output paths, and backup destinations follow the same rule. Symlinks
and ordinary filesystem permissions are handled normally.

If no owning checkout can be found, commands that need a data root require
`--data-dir DIR` or `SYZ_SAGE_DATA_DIR`. Database-only commands can instead use
an explicit `--database FILE` or `SYZ_SAGE_DATABASE`: `status`, `list`, `filter`, `show`,
`check`, and `migrate` all work without a source checkout. A migration without
a selected data root places its lock beside the selected database. An update
still needs a selected or default data root; a database path alone does not
choose where to save downloads. Syz Sage does not fall back to automatically
creating `~/.syz-sage`,
`~/Library/Application Support/syz-sage`, or another external application-data
directory.

This controls where Syz Sage chooses its own data defaults; it does not confine
all process writes to the checkout. Python bytecode, SQLite sidecars and
temporary storage, installer caches, type-checker caches, and export-library
temporary files use normal tool behavior. Atomic artifact replacements create
temporary files beside their explicit destinations. Tests deliberately use
self-cleaning `.syz-sage-tmp-*` directories inside the checkout. See
[development guidance](development.md) and [the scripts guide](scripts.md) for
tool usage and explicitly requested research outputs.
