# Development

Use the project virtual environment from the
[quick start](../README.md#quick-start). For command examples, see
[usage](usage.md); for research tools, see [scripts](scripts.md). The
[database guide](database.md) describes the schema and the source of each field.

## Code organization

Application code lives in `src/syz_sage/`. The current flat package keeps related
modules easy to find without introducing extra import layers. Tests and
checkout-specific scripts remain top-level directories. Downloaded data defaults
to `data/`, separate from source code; explicit configuration can select another
location.

| Responsibility | Modules |
|---|---|
| Command arguments, dispatch, and exit codes | [cli.py](../src/syz_sage/cli.py) |
| Help layout | [help.py](../src/syz_sage/help.py) |
| Human-readable views and terminal formatting | [display.py](../src/syz_sage/display.py), [terminal.py](../src/syz_sage/terminal.py) |
| Listing discovery, download selection, completion handling, update lock | [sync.py](../src/syz_sage/sync.py) |
| Download contracts, artifact validation, atomic saves, bounded workers | [artifacts.py](../src/syz_sage/artifacts.py) |
| Per-run file inventory and exact-content fingerprints | [ingestion.py](../src/syz_sage/ingestion.py) |
| Durable retry queues shared with offline ingestion | [retry_state.py](../src/syz_sage/retry_state.py) |
| HTTP requests, retries, rate limiting, patch-source URLs | [client.py](../src/syz_sage/client.py) |
| Listing/detail validation, URL rules, subsystem tags | [parsing.py](../src/syz_sage/parsing.py) |
| Deterministic title diagnostic classification | [bug_types.py](../src/syz_sage/bug_types.py) |
| Crash coordinates and ordered stack extraction | [locations.py](../src/syz_sage/locations.py) |
| Changed file/range extraction and function hints | [patch_locations.py](../src/syz_sage/patch_locations.py) |
| SQLite connections, ingestion, queries, and integrity checks | [database.py](../src/syz_sage/database.py) |
| Derived-location indexing and the v2 migration | [location_store.py](../src/syz_sage/location_store.py) |
| Snapshot artifact associations and the v3 migration | [schema_v3.py](../src/syz_sage/schema_v3.py) |
| Stored bug types and the v4 migration | [schema_v4.py](../src/syz_sage/schema_v4.py) |
| Crash/origin interpretation repair in v5 | [schema_v5.py](../src/syz_sage/schema_v5.py) |
| Current fix subject/repository matching | [resolutions.py](../src/syz_sage/resolutions.py) |
| Data-root defaults and explicit path resolution | [config.py](../src/syz_sage/config.py), [storage.py](../src/syz_sage/storage.py) |

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

`sync.py` coordinates discovery, detail retrieval, report/patch retrieval, and
candidate indexing as separate stages. `artifacts.py` supplies the shared
fetch/validate/save operations. `database.py` reads retained evidence, preserves
source bytes in content-addressed blobs, and decides whether a candidate can
activate. Offline import also checks retry state so an unfinished refresh cannot
be mistaken for complete data. `location_store.py` connects prepared parser
results to report, crash, and patch versions. No parser needs a network
connection to derive a location.

The rolling mirror can contain successful downloads from a partial attempt
while inspection still uses the previous complete snapshot. Keep that
distinction when adding a query or research workflow. Raw payloads are evidence;
derived functions, coordinates, and confidence are interpretations. Schema
migrations and parser revisions must preserve that provenance. See
[database migration details](database.md#migration-and-subsequent-updates).

Presentation is separate from retrieval and storage. `display.py` produces
human views; `terminal.py` handles escaping, wrapping, and optional ANSI colors.
`progress_events.py` defines observational phase/count events shared by sync
and database work. `progress.py` renders those events on stderr with live
terminal bars or sparse plain lines for redirected output. Report actual
processed counts, and use an unknown total for work that cannot be measured.
Finishing a phase does not imply successful validation or a committed snapshot.
JSON and quiet modes attach no progress listener. Ordinary listener failures
must not change database results; cancellation still propagates.
JSON is emitted directly from structured results in `cli.py`, without terminal
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
`show` and `filter` hold a read transaction across related queries so a concurrent
update cannot mix metadata and locations from different snapshots.

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

| Change | Start with | Relevant tests |
|---|---|---|
| Download selection, retries, or no-op updates | `sync.py`, `artifacts.py`, `retry_state.py` | `test_sync.py`, `test_artifacts.py`, `test_ingest_retry.py` |
| Cached file inspection, fingerprints, or streamed ingestion | `ingestion.py`, `database.py` | `test_ingestion.py`, `test_database.py` |
| HTTP behavior or response validation | `client.py`, `parsing.py` | `test_client.py`, `test_parsing.py` |
| Crash, stack, or patch interpretation | `locations.py`, `patch_locations.py` | `test_locations.py`, `test_location_store.py` |
| New stored fields, associations, or queries | `database.py`, location/migration modules | `test_database.py`, `test_schema_v3.py` |
| Bug-type classification and combined filtering | `bug_types.py`, `schema_v4.py`, `database.py` | `test_bug_types.py`, `test_schema_v4.py`, `test_filter_database.py`, `test_filter_cli.py` |
| Command options, human output, or JSON behavior | `cli.py`, `help.py`, `display.py`, `terminal.py` | `test_cli.py`, `test_help.py` |
| Path resolution or default locations | `config.py`, `storage.py` | `test_config.py`, `test_storage.py`, `test_project_paths.mjs` |
| Research-only calculations or exports | `scripts/` | `test_scripts.py` and focused script checks |

For a parser correction, add a small regression fixture for the actual format.
Check the database indexing path as well as the pure parser. Existing derived
rows are versioned by parser revision; changing the parser alone does not
repair a user's already indexed data. Provide an explicit transactional
reindexing/migration path when stored interpretation changes.

Report and patch parsers have separate revision constants. Schema v5 uses
report revision 3 and patch revision 2; a report-only repair does not reindex
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

## Run checks

Run commands from the project root in the project virtual environment. Optional
development tools are declared in `pyproject.toml`:

```console
python -m pip install -e '.[dev]'
```

Start with tests relevant to the change:

```console
PYTHONPATH=src python -m unittest tests.test_artifacts tests.test_sync tests.test_ingest_retry
PYTHONPATH=src python -m unittest tests.test_ingestion tests.test_database
PYTHONPATH=src python -m unittest tests.test_locations tests.test_location_store
PYTHONPATH=src python -m unittest tests.test_database tests.test_schema_v3
PYTHONPATH=src python -m unittest tests.test_cli tests.test_help
```

Before finishing a behavioral change, run the full suite and existing checks:

```console
PYTHONPATH=src python -m unittest discover -s tests -q
node --test tests/test_project_paths.mjs
ruff check src tests scripts
ruff format --check src tests scripts
```

The Python suite uses small fixtures and mocked network responses rather than
the downloaded corpus or live syzbot service. Python 3.10 needs the `tomli`
dependency from the development extra for packaging metadata tests. The Node
test exercises JavaScript path resolution without requiring the optional
workbook-export dependency. Strict type checking covers application modules;
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
