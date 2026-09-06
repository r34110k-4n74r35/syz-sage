# Development

Use the project virtual environment from the
[quick start](../README.md#quick-start). For command examples, see
[usage](usage.md); for research tools, see [scripts](scripts.md). The
[database guide](database.md) describes the schema and the source of each field.

## Code organization

Application code lives in `src/syz_sage/`. Source and tests use the same five
main groups, making the corresponding implementation or tests easy to find:

| Source package | Matching tests | Responsibility |
|---|---|---|
| `src/syz_sage/cli/` | `tests/cli/` | Command dispatch, arguments, help, views, and terminal progress |
| `src/syz_sage/database/` | `tests/database/` | Connections, imports, snapshots, queries, schema, and migrations |
| `src/syz_sage/retrieval/` | `tests/retrieval/` | HTTP, update orchestration, artifact downloads, catalogs, and retries |
| `src/syz_sage/parsing/` | `tests/parsing/` | Listings, diagnostic types, crash stacks, and patch locations |
| `src/syz_sage/project/` | `tests/project/` | Configuration, filesystem paths, locking, and shared progress events |

Top-level `scripts/` maps to `tests/workflows/`, since those tools live outside
the application package. `tests/fixtures/` and test support modules hold test
inputs and helpers. Individual tests may exercise several packages; match the
main responsibility rather than forcing a separate test file for every module.
Only package metadata and `__main__.py` remain at the source package root.

| Application responsibility | Modules |
|---|---|
| CLI dispatch, paths, JSON output, and exit codes | [cli/commands.py](../src/syz_sage/cli/commands.py) |
| Argument definitions and validation | [cli/arguments.py](../src/syz_sage/cli/arguments.py), [cli/help.py](../src/syz_sage/cli/help.py) |
| Update orchestration and download selection | [retrieval/sync.py](../src/syz_sage/retrieval/sync.py) |
| Update options, listing scope, and result contracts | [retrieval/models.py](../src/syz_sage/retrieval/models.py) |
| Retained listing comparison and catalog generation | [retrieval/catalog.py](../src/syz_sage/retrieval/catalog.py) |
| Artifact validation, atomic saves, bounded workers | [retrieval/artifacts.py](../src/syz_sage/retrieval/artifacts.py) |
| File observations, fingerprints, and bounded in-memory caches | [database/ingestion.py](../src/syz_sage/database/ingestion.py) |
| Durable retry queues and applicable fix resolutions | [retrieval/retry_state.py](../src/syz_sage/retrieval/retry_state.py), [retrieval/resolutions.py](../src/syz_sage/retrieval/resolutions.py) |
| HTTP requests, retries, rate limiting, patch-source URLs | [retrieval/client.py](../src/syz_sage/retrieval/client.py) |
| Listing/detail validation, URLs, and subsystem tags | [parsing/listing.py](../src/syz_sage/parsing/listing.py) |
| Bug-type, crash-stack, and patch interpretation | [parsing/bug_types.py](../src/syz_sage/parsing/bug_types.py), [parsing/crash.py](../src/syz_sage/parsing/crash.py), [parsing/patch.py](../src/syz_sage/parsing/patch.py) |
| Path defaults, explicit destinations, and data-root locking | [project/config.py](../src/syz_sage/project/config.py), [project/storage.py](../src/syz_sage/project/storage.py) |

`database/repository.py` owns connections and transactions. The package exports
the stable `syz_sage.database.Database` API. Its explicit delegates keep implementation responsibilities
inside `database/`:

| Persistence responsibility | Modules |
|---|---|
| Public database API and migration dispatch | [database/repository.py](../src/syz_sage/database/repository.py) |
| Base SQL schema, version, and schema validation | [database/schema.py](../src/syz_sage/database/schema.py) |
| Source normalization and metadata extraction | [database/records.py](../src/syz_sage/database/records.py) |
| Retained-file imports, artifact inspection, and no-op checks | [database/files.py](../src/syz_sage/database/files.py) |
| Transactional snapshot ingestion and activation | [database/snapshot.py](../src/syz_sage/database/snapshot.py) |
| Blob/document writes and normalized child records | [database/writes.py](../src/syz_sage/database/writes.py) |
| Bug/filter queries, coverage, and integrity checks | [database/queries.py](../src/syz_sage/database/queries.py) |
| Derived-location indexing and v2 migration | [database/location_store.py](../src/syz_sage/database/location_store.py) |
| Subsequent schema migrations | [database/schema_v3.py](../src/syz_sage/database/schema_v3.py), [database/schema_v4.py](../src/syz_sage/database/schema_v4.py), [database/schema_v5.py](../src/syz_sage/database/schema_v5.py), [database/schema_v6.py](../src/syz_sage/database/schema_v6.py) |

The snapshot transaction stays together so its validation, source retention,
and activation rules can be reviewed as one operation. The smaller preparation,
query, and write modules can be maintained independently. Implementation modules
use type-only references to `Database`, avoiding runtime import cycles.

| Presentation responsibility | Modules |
|---|---|
| Public human-output functions | [cli/display.py](../src/syz_sage/cli/display.py) |
| Bug details, fix locations, and stacks | [cli/presentation/bug_detail.py](../src/syz_sage/cli/presentation/bug_detail.py) |
| Listing, filtering, and available filter values | [cli/presentation/browsing.py](../src/syz_sage/cli/presentation/browsing.py) |
| Update, import, migration, status, and check summaries | [cli/presentation/maintenance.py](../src/syz_sage/cli/presentation/maintenance.py) |
| Semantic formatting shared by views | [cli/presentation/common.py](../src/syz_sage/cli/presentation/common.py) |
| Escaping, wrapping, terminal capabilities, and colors | [cli/terminal.py](../src/syz_sage/cli/terminal.py) |
| Observable work events and live progress rendering | [project/progress_events.py](../src/syz_sage/project/progress_events.py), [cli/progress.py](../src/syz_sage/cli/progress.py) |

Views consume structured results and `retrieval/models.py` contracts. They do
not fetch data or open a database. `cli/display.py` gathers the human view
functions; new rendering code belongs in `cli/presentation/`. Imports between
packages use their new module paths. The `cli` package exports `main`, preserving
both console entry points; the `database` package exports `Database` and
`SCHEMA_VERSION`.

[`pyproject.toml`](../pyproject.toml) discovers the application package under
`src/` and declares both console entry points, `ss` and `syz-sage`, as
`syz_sage.cli:main`. [`__main__.py`](../src/syz_sage/__main__.py) supports
`python -m syz_sage`; [`__init__.py`](../src/syz_sage/__init__.py) defines the
package version. An editable installation uses this checkout's source.
Routine development and testing do not require building a wheel.

Top-level `scripts/` contains checkout tools for auditing, analysis, reporting,
and older retrieval workflows. They can import shared application code but are
not installed `syz_sage` modules or additional CLI subcommands. See the
[scripts guide](scripts.md) for their inputs and outputs.

## Data flow and boundaries

```text
ss update
  -> discover and validate listing membership
  -> plan missing/invalid/retry/refresh download jobs
  -> fetch and validate with a bounded worker pool
  -> save each completion atomically; advance durable retry state
  -> compare retained content with the indexed snapshot
       unchanged -> skip SQLite ingestion
       changed   -> validate sources; prepare a bounded amount of derived data
                 -> stream evidence and index a candidate transactionally
                       complete -> activate the new snapshot
                       partial  -> keep the previous active snapshot

ss show / ss list / ss filter -> read active SQLite data -> display or JSON
ss status / ss check -> read coverage or consistency results -> display or JSON
```

`retrieval/sync.py` coordinates discovery, detail retrieval, report/patch retrieval, and
candidate indexing as separate stages. `retrieval/artifacts.py` supplies the shared
fetch/validate/save operations. `database/repository.py` reads retained evidence, preserves
source bytes in content-addressed blobs, and decides whether a candidate can
activate. Offline import also checks retry state so an unfinished refresh cannot
be mistaken for complete data. `location_store.py` connects prepared parser
results to report, crash, and patch versions. No parser needs a network
connection to derive a location.

Dashboard requests validate their HTTP(S) origin both at the initial URL and
before every redirect. Patch and research requests permit HTTP(S) redirects to
other origins. Redirects keep cancellation checks active and release rejected
response bodies.

The rolling mirror can contain successful downloads from a partial attempt
while inspection still uses the previous complete snapshot. Keep that
distinction when adding a query or research workflow. Raw payloads are evidence;
derived functions, coordinates, and confidence are interpretations. Schema
migrations and parser revisions must preserve that provenance. See
[database migration details](database.md#migration-and-subsequent-updates).

Presentation is separate from retrieval and storage. `cli/display.py` produces
human views; `cli/terminal.py` handles escaping, wrapping, and optional ANSI colors.
`project/progress_events.py` defines observational phase/count events shared by sync
and database work. `cli/progress.py` renders those events on stderr with live
terminal bars or sparse plain lines for redirected output. Report actual
processed counts, and use an unknown total for work that cannot be measured.
Finishing a phase does not imply successful validation or a committed snapshot.
JSON and quiet modes attach no progress listener. Ordinary listener failures
must not change database results; cancellation still propagates.
JSON is emitted directly from structured results in `cli/commands.py`, without terminal
decoration. Format plain text before applying color so ANSI sequences cannot
change wrapping or column alignment.

## Download and indexing contracts

`UpdatePlan` contains the validated listing and selected retrieval scope.
`DownloadJob` identifies one detail/report/patch resource, its destination,
optional source URL/repository, and selection reason: missing, invalid, retry,
or explicit refresh. Workers return `ArtifactResult` with validated original
bytes, a SHA-256 digest, the successful endpoint, and parsed detail JSON when
applicable. The coordinator saves results and updates retry state; workers do
not write SQLite.

`bounded_results()` schedules at most twice the worker count at a time. Its
consumer handles completed results before scheduling another batch, preventing
completed payloads and submitted futures from accumulating for the whole corpus.
The shared atomic writer leaves identical bytes untouched and replaces changed
files only after the temporary file is fully written and flushed. These
temporary files sit beside their destinations so replacement remains atomic.

Pending jobs are written to the existing retry-state file before download.
Completions are flushed after eight processed jobs, or when a completion arrives
at least five seconds after the last flush. The phase's `finally` block also
persists state. An orderly interruption preserves processed completions; an
abrupt termination may replay saved work from the last unflushed batch. Failed
downloads remain pending, including when a valid older artifact still exists.

`FileInventory` shares observations between retrieval, the unchanged-data check,
and ingestion during one run. It tracks file identity/timestamps/size, SHA-256,
and parsed JSON. Its raw-byte LRU is limited to 32 MiB by default; parsed JSON
and prepared extraction metadata are separate, so this is not a total process
memory limit. Changed file stamps invalidate observations. The fingerprint
keeps the existing exact-content algorithm, so reuse does not change what
counts as an unchanged mirror.

The input membership and file stamps are checked against that fingerprint
before indexing and before candidate activation. An external edit during
ingestion prevents a stale fingerprint from being recorded for different data.
`show`, `filter`, `status`, `check`, and unchanged-import summaries hold a read
transaction across related queries so a concurrent update cannot mix metadata,
locations, or counts from different snapshots.

After saving a downloaded file, the coordinator verifies the on-disk bytes
before recording its parsed representation. An external edit between save and
inspection therefore cannot be cached as the downloaded payload. Reused local
files share their checked observations without this extra save-verification read.

Artifact inspection validates files before the writer transaction. New report
and patch extractions are prepared in advance within an 8 MiB source-byte
budget for each artifact type; larger cold imports parse the remaining
artifacts during indexing instead of retaining every stack/range in memory.
Already indexed source/parser combinations reuse their existing extraction.
`ArtifactInspection` retains the source stamp and digest, checks that the file
still matches before insertion, and lets ingestion read report/patch payloads
one at a time. This reduces whole-corpus byte accumulation while keeping
snapshot activation transactional.

These objects and caches are in memory only. They introduce no new downloaded
artifact format, persistent inventory, SQLite schema version, or auxiliary
checkpoint files. Retained JSON, reports, and diffs keep their original bytes
and existing paths. The existing retry-state file continues to carry pending
work across invocations.

Download endpoint metadata is passed to ingestion alongside the inventory.
A successful patch endpoint can be stored in the existing `documents.source_url`
when ingestion runs. A raw cached file alone cannot identify which fallback
served its bytes. The no-op path still avoids database writes even after an
explicit refresh returns identical bytes; it does not write solely to retain
new endpoint metadata. See [source provenance](database.md#where-each-field-comes-from)
for the resulting limits.

## Where to make the next change

| Change | Start with | Test area |
|---|---|---|
| Download selection, retries, or unchanged updates | `retrieval/sync.py`, `retrieval/catalog.py`, `retrieval/artifacts.py`, `retrieval/retry_state.py` | `tests/retrieval/` |
| File observations, fingerprints, or imports | `database/ingestion.py`, `database/files.py`, `database/snapshot.py` | `tests/database/` and `tests/retrieval/` |
| HTTP behavior | `retrieval/client.py` | `tests/retrieval/` |
| Listing validation or crash/patch interpretation | `parsing/listing.py`, `parsing/crash.py`, `parsing/patch.py` | `tests/parsing/` and `tests/database/` |
| Stored fields, associations, or queries | `database/schema.py`, `database/writes.py`, `database/queries.py`, migration modules | `tests/database/` |
| Bug-type classification and filtering | `parsing/bug_types.py`, `database/queries.py`, `cli/presentation/browsing.py` | `tests/parsing/`, `tests/database/`, `tests/cli/` |
| CLI options, human output, JSON, or progress | `cli/arguments.py`, `cli/commands.py`, `cli/presentation/`, `cli/terminal.py`, `cli/progress.py` | `tests/cli/` |
| Paths, defaults, locking, or packaging | `project/config.py`, `project/storage.py`, `pyproject.toml` | `tests/project/` and `tests/retrieval/` |
| Research calculations or exports | `scripts/` | `tests/workflows/` |

For a parser correction, add a small regression fixture for the actual format.
Check the database indexing path as well as the pure parser. Existing derived
rows are versioned by parser revision; changing the parser alone does not
repair a user's already indexed data. Provide an explicit transactional
reindexing/migration path when stored interpretation changes.

Report and patch parsers have separate revision constants. Schema v6 uses
report revision 4 and patch revision 2; a report-only repair does not reindex
unchanged patch locations.

For an ingestion change, preserve complete-snapshot activation, retries across
interruption, unchanged-update behavior, and exact raw evidence. For a new
field, document its source and what an unknown value means. Keep storage and
network operations out of terminal formatting helpers.

Types are stored per snapshot from the same title displayed by query commands.
Subsystem filters match retained tags exactly; do not infer a parent hierarchy
from tag names or source paths. Combine multiple values with OR within each
filter category and AND across categories. Count matches before pagination,
use parameterized SQL, and enrich only the selected result page. Filtering and
value discovery must remain read-only, including for older schemas that need
an explicit migration before inspection.

Group new code by responsibility. When a concern becomes large enough to
maintain independently, extract it with its tests and update imports together.
Keep console entry points and script launch paths working across any module move.

## Test organization

`tests/` mirrors the five source package names. The additional `workflows/`
group covers the top-level `scripts/` directory:

```text
tests/
  cli/          Arguments, command results, human views, and progress
  database/     Ingestion, snapshots, queries, migrations, and stored evidence
  retrieval/    HTTP, downloads, update stages, retries, and locking
  parsing/      Listing, title, crash, and patch interpretation
  project/      Paths, configuration, packaging, and JavaScript path helpers
  workflows/    Checkout research and maintenance scripts
  fixtures/     Small retained-data examples
  support.py    Shared project and fixture roots
```

Large update, database, and CLI suites are split by scenario. Concern-specific
`support.py` modules contain fixture setup and helpers; they contain no test
cases of their own. Keep tests in `test_*.py` modules and add `__init__.py` to
new test directories so unittest discovery includes them. Import shared fixtures
through `tests.support` instead of deriving their location from each test file.
This keeps fixture paths stable when a suite moves. Keep reusable setup free of
`test_*` methods so cases are not collected multiple times through inheritance.

The `-t .` option below keeps test module names rooted at `tests`. The JavaScript
suite remains a separate Node command. Optional `pytest` also uses the same
`tests/` tree through the existing configuration in `pyproject.toml`.

## Run checks

Run commands from the project root in the project virtual environment. Optional
development tools are declared in `pyproject.toml`:

```console
python -m pip install -e '.[dev]'
```

Start with tests relevant to the change:

```console
PYTHONPATH=src python -m unittest discover -s tests/retrieval -t . -q
PYTHONPATH=src python -m unittest discover -s tests/database -t . -q
PYTHONPATH=src python -m unittest discover -s tests/parsing -t . -q
PYTHONPATH=src python -m unittest discover -s tests/cli -t . -q
```

Before finishing a behavioral change, run the full suite and existing checks:

```console
PYTHONPATH=src python -m unittest discover -s tests -t . -q
node --test tests/project/test_project_paths.mjs tests/workflows/test_workbook_values.mjs
ruff check src tests scripts
ruff format --check src tests scripts
```

The Python suite uses small fixtures and mocked network responses rather than
the downloaded corpus or live syzbot service. Python 3.10 needs the `tomli`
dependency from the development extra for packaging metadata tests. The Node
tests exercise JavaScript path resolution and workbook date values without
requiring the optional workbook-export dependency. Strict type checking covers application modules;
research scripts have their own runtime checks.

For optional static type checking:

```console
PYTHONPATH=src python -m mypy src/syz_sage
```

`.mypy_cache/` belongs only to the optional mypy type checker; Python and the
application do not need it. Python, pip, mypy, Ruff, SQLite, and export libraries
use their normal cache and temporary-file settings. No cache redirection or
bytecode suppression is required. Standard Python `__pycache__/` directories
and the usual development-tool caches inside the checkout are ignored by Git.

Tests create self-cleaning `.syz-sage-tmp-*` directories directly under the
project root. Git ignores these temporary directories if a process is abruptly
stopped before cleanup. Tests do not need a persistent `outputs/` directory.
Keep test inputs synthetic and write assertions against copied fixtures or
temporary databases, never the real corpus under `data/`.

Automatic application data defaults must stay under the owning checkout's
`data/`. Do not add a fallback that silently creates a Syz Sage folder in a home
directory or system application-data location. Without a checkout, require an
explicit data path; database-only commands can use an explicit database path.
User-supplied paths may be anywhere permitted by the operating system. This
policy does not restrict normal interpreter, database, or development-tool
caches and temporary files. See [path configuration](usage.md#paths-and-write-boundaries).
