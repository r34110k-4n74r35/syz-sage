# Fixed-bug records

[Project overview](../README.md) · [CLI usage](usage.md) · [Development](development.md)

## Contents

- [Where each field comes from](#where-each-field-comes-from)
- [Bug types](#bug-types)
- [C reproducer metadata](#c-reproducer-metadata)
- [Following a value back to its stored source](#following-a-value-back-to-its-stored-source)
- [Interpreting locations](#interpreting-locations)
- [Querying the active data](#querying-the-active-data)
- [Migration and subsequent updates](#migration-and-subsequent-updates)

## Overview

The default database is `data/db/syz_sage.sqlite3` in the owning checkout.
An explicit `--database` or data-root override can select another location;
see [path configuration](usage.md#paths-and-write-boundaries).
Schema version 5 keeps titles, diagnostic types,
subsystem tags, crash sites, complete extracted stacks, and fix sites queryable.
The original downloaded JSON, reports, and patches remain in `blobs`.

| Content | Table | Main fields |
|---|---|---|
| Bug title and identity | `bugs`, `bug_versions`, `snapshot_bugs` | `key`, `title`, version and snapshot IDs |
| Bug diagnostic type | `snapshot_bugs` | `bug_type`, also exposed by `current_bug_rows` |
| Bug URLs | `bugs`, `snapshot_bugs` | `bug_url` (syzbot web page), `json_url` (JSON endpoint); also exposed by `current_bug_rows` |
| Subsystem tags | `bug_subsystems` | `snapshot_id`, `bug_id`, `tag`, `source_blob_sha256` |
| C reproducer links per crash | `crashes` | `bug_version_id`, `ordinal`, `c_reproducer_url`; bug-level availability is derived from the retained detail JSON |
| Report selected by a snapshot | `snapshot_reports` | `snapshot_id`, `bug_id`, `report_version_id`, `crash_id`, `source_url` |
| Patches used by a snapshot | `snapshot_patches` | `snapshot_id`, `commit_hash`, `patch_version_id`, `source_url` |
| Crash sites | `crash_locations` | `report_version_id`, `crash_id`, `role`, `file_path`, `function_name`, `line_number`, `column_number`, `confidence`, `method`, `evidence` |
| Full extracted crash stack | `crash_stack_frames` | `report_version_id`, `ordinal`, `section`, `report_line`, `function_name`, `file_path`, `line_number`, `column_number`, `is_inline`, `raw_line` |
| Fix sites | `fix_locations` | `patch_version_id`, `ordinal`, old/new file paths and changed ranges, `function_name`, `function_basis`, `hunk_header`, `kind` |

One bug can have multiple subsystem tags and crash locations. One fix commit
can change multiple files and multiple separate ranges in each file. A patch
shared by several bugs is indexed once per patch version. Extraction records
include `parser_version` so their interpretation can be identified later.

`bug_url` stores the full syzbot page URL, for example
`https://syzkaller.appspot.com/bug?extid=0a0e5f37746013dc7476`.
`ss show KEY` displays it on the `URL:` line; `ss show KEY --json` includes
both `bug_url` and `json_url`.

Subsystem tags come from syzbot's `subsystems:` labels in the saved fixed-bug
listing HTML. Other labels such as priority are excluded. Tags belong to a
snapshot: an incomplete update cannot replace the active tags. An empty tag
list means the saved page supplies none; path-based guesses are not substituted.

## Where each field comes from

The paths below are relative to the selected data root (the checkout's `data/`
by default).
`KEY` is the stable filename key, such as `extid-0a884bc2d304ce4af70f`.
`HASH` is the fix commit hash. Reports are joined by bug key; patches are joined
by the commit hash referenced by that bug. Similar filename prefixes do not
establish a relationship between a report, patch, and bug.

| Database content | Retrieved or processed source | How the value is obtained |
|---|---|---|
| `bugs.key` | `raw/upstream_fixed.json`, `Bugs[].link` | `/bug?extid=X` becomes `extid-X`; `/bug?id=X` becomes `id-X`. |
| Active `title` in `current_bug_rows` / `ss show` | Listing `Bugs[].title`, normally carried through `processed/catalog.json`, `bugs[].title` | Import uses the catalog when available; otherwise it builds records from the listing. A missing record title falls back to the detail JSON title, then the bug key. |
| `snapshot_bugs.bug_type` / active `bug_type` | The corresponding stored `snapshot_bugs.title` | Classify its leading diagnostic marker with `bug_types.classify_bug_type`; store the normalized lowercase result. No crash-report parsing or additional retrieval is used. |
| `bug_versions.title`, `bugs.syzbot_id` | `raw/bugs/KEY.json`, top-level `title` and `id` | Copied from the detail response. Its internal `id` can differ from the `extid` used in the filename and URL. |
| `bug_url`, `json_url` | Listing `Bugs[].link`, normally carried through the catalog's `bug_url` and `json_url` | The dashboard origin is added to relative links; `json=1` selects the JSON endpoint. These URLs are not taken from the detail JSON's internal `id`. |
| `status`, `first_crash_at`, `last_crash_at`, `fix_time`, `close_time` | `raw/bugs/KEY.json`: `status`, `first-crash`, `last-crash`, `fix-time`, `close-time` | Copied from the named JSON fields. |
| `bug_subsystems.tag` | `raw/upstream_fixed.html` | In the table row linking to this bug, decode anchor query parameters such as `label=subsystems%3Anet` into the tag `net`. Keep all subsystem tags in that row; exclude priority and other labels. |
| `crashes` metadata and kernel build | `raw/bugs/KEY.json`, `crashes[]` | Store each crash's `title`, `kernel-source-git`, `kernel-source-commit`, syzkaller revision, report/config/reproducer URLs, and reproduction options. Relative artifact URLs are expanded against the dashboard origin. |
| `crashes.c_reproducer_url`; `ss show` / `ss filter` C reproducer fields | Detail JSON `crashes[].c-reproducer` | The per-crash column stores the expanded URL. `c_reproducer_status` and `c_reproducer_urls` are computed from the active version's original detail blob, validating supplied values and collecting distinct links across all crashes. |
| Representative report bytes and report URL | `artifacts/reports/KEY.txt`; detail JSON `crashes[].crash-report-link` | The selected crash is the first entry with a nonempty report link. Its saved report is retained in `blobs` through `reports` / `report_versions`. |
| `crash_locations` | The saved representative report, plus the selected crash's title (falling back to the detail title) | The parser chooses explicit source diagnostics or a matching symbolized frame, with lower-confidence fallbacks. It records file, function, line/column, `method`, `confidence`, and the supporting `evidence` text. These are derived fields, not dedicated fields supplied in the bug JSON. |
| `crash_stack_frames` | `artifacts/reports/KEY.txt` | Parse frames in report order. `report_line` is the 1-based line number in the report text; `line_number` is the kernel source line. Preserve `raw_line`, inline markers, and section labels inferred from report headings. |
| `fix_commits` and `listing_fix_commits` | Detail JSON `fix-commits[]` and listing JSON `Bugs[].fix-commits[]` | Copy `title`, `hash`, `repo`, `branch`, `link`, author fields, and `date`. Inspection merges references from both sources. |
| `resolved_hash` / `fix_resolutions` | `processed/resolved_fix_hashes.json`, `resolutions[]` | Import retained title-only fix resolutions. These are results of the resolution workflow, separate from hashes directly reported by syzbot. |
| Patch bytes | `artifacts/patches/HASH.diff` | The filename hash joins the patch to a referenced or resolved fix commit. Its bytes are retained through `patches` / `patch_versions` and `blobs`. |
| Patch download provenance | Current download metadata, stored in `documents.source_url` and artifact associations when indexing runs | Use the actual successful endpoint, including a fallback, when supplied by this run. Otherwise retain a known URL for the same patch bytes, or use the legacy fix-reference fallback. A raw `.diff` file alone does not identify its download endpoint. |
| `ss filter` patch links (`patch_urls`) | Active `snapshot_patches.source_url`, falling back to merged listing/detail fix `link` | For each effective fix, use the snapshot's valid patch association and its recorded HTTP(S) source URL; otherwise use its saved HTTP(S) commit link. Deduplicate in fix order. Legacy source URLs may themselves be commit pages. Do not infer endpoints from hashes or include unrelated retained patches. |
| `fix_locations` file paths and changed ranges | The patch's `diff --git`, `---` / `+++`, `@@` headers, and body | Track old/new line counters, collecting actual `-` and `+` edits. Context lines advance counters but are excluded from changed ranges. |
| `fix_locations.function_name` | Text after the closing `@@` in the patch hunk header, or a leading unchanged function definition | Infer a function name when the heading or definition supplies one. Store the heading and `function_basis`. Calls in the patch body are not treated as enclosing function definitions. |
| `cause_commits`, `discussions` | Detail JSON `cause-commit` and `discussions[]`, when present | Copy the supplied metadata and discussion URLs. |
| Local IDs, ingestion times, hashes, and extraction metadata | Generated by Syz Sage / SQLite | Row IDs, synchronization status, SHA-256 digests, `parser_version`, confidence, and ingestion timestamps are local metadata. In particular, `fetched_at` records indexing time; it is not a syzbot crash timestamp. |

`processed/catalog.json` is a local normalized copy of the listing, not an
independent upstream source. If the detail JSON is unavailable, a bug version
can instead have `payload_kind = 'listing-record'`; detail-only fields then
remain unavailable. Current subsystem tags come from listing HTML, not from
the research script's path-based subsystem classification.

The current downloader retains **one representative report per bug**, although
it stores metadata for every entry in `crashes[]`. Consequently, the full
extracted stack means the frames in that saved report, including its auxiliary
traces; it does not mean reports for every observed crash have been downloaded.
Unrecognized report text is still preserved in the original report blob.

### Bug types

`snapshot_bugs.bug_type` stores the diagnostic category for each snapshot's
displayed title. This keeps a bug's historical classifications tied to the
matching historical titles. A partial candidate cannot change the active
type. Both `Database.get_bug()` and listing/filter query rows expose `bug_type`.

Classification ignores case and redundant whitespace, and matches the start
of a title rather than arbitrary words in a function name or description.
Examples:

| Saved title | Stored type |
|---|---|
| `KASAN: slab-use-after-free Read in example` | `kasan` |
| `WARNING in example` | `warning` |
| `INFO: task hung in example` | `info` |
| `kernel BUG at example.c:42` | `bug` |
| `general protection fault in example` | `general-protection-fault` |
| `upstream boot error: KMSAN: uninit-value in example` | `kmsan` |

Other recognized markers include KCSAN, KFENCE, UBSAN, panic, deadlock, memory
leaks, and several architecture/locking diagnostics. Recognized manager
`build error:` titles use `build-error`; boot/test errors use an underlying
recognized diagnostic where available, otherwise `boot-error` or `test-error`.
Unknown titles use `other`. `ss filter --help` identifies supported type values;
`ss filter --list-values` lists values actually present in the active snapshot.

This field is derived locally, not a dedicated syzbot JSON field and not a
claim about severity, exploitability, or root cause. The original title remains
unchanged. The classifier lives in [parsing/bug_types.py](../src/syz_sage/parsing/bug_types.py);
classification changes that affect retained rows require a migration/backfill,
not merely a change to the helper.

Subsystem tags remain separate and flat. An `fs` filter matches the stored
`fs` tag; it does not imply `ext4`, `btrfs`, or every path under `fs/`.

### C reproducer metadata

The raw source is `crashes[].c-reproducer` in `raw/bugs/KEY.json`, retained for
the indexed version through `bug_versions.raw_sha256` → `blobs`. Relative
links are expanded using the bug's dashboard URL. The existing
`crashes.c_reproducer_url` column keeps the URL for each crash; the bug-level
summary does not need a duplicate status column.

`Database.get_bug()` and the listing/filter query rows derive two fields from
the active version's saved detail blob. They are exposed in `ss show KEY --json`
and each bug in `ss filter --json` (also `ss list --json`):

| Field | Derivation |
|---|---|
| `c_reproducer_urls` | Collect valid C reproducer URLs from every crash entry, retaining first-occurrence order after URL expansion and removing duplicates. |
| `c_reproducer_status` | `available` if any valid URL exists; otherwise `not_provided` for a valid crash list with no supplied links, or `unknown` when metadata is missing or invalid. |

An explicit empty `crashes` list means `not_provided`. Missing detail data,
a `listing-record` payload, a missing or malformed crash list, non-object
crash entries, or malformed/non-string/off-dashboard C links produce
`unknown` when no valid link exists. Missing, null, or empty `c-reproducer`
fields mean that crash supplies no C link. Reading the original values also
avoids treating permissively normalized values in older per-crash rows as
proof of availability.

This is availability **reported by saved metadata**, independent of which
representative report was retained. No reproducer contents are fetched or
checked for local existence, and no HTTP request verifies the URLs. Existing
indexed data needs no migration or re-import for the summary. The
[CLI guide](usage.md#c-reproducer-availability) describes its display.

### Following a value back to its stored source

| Value being inspected | Link to its source in SQLite |
|---|---|
| Original listing JSON/HTML | `snapshots.listing_json_sha256` / `listing_html_sha256` → `blobs.sha256` |
| Detail JSON version | `bug_versions.raw_sha256` → `blobs.sha256`; check `payload_kind` |
| Bug type | `snapshot_bugs.bug_type` derives from that same row's `title`; `listing_record_sha256` identifies the retained source record, with title fallback described above |
| Subsystem tag | `bug_subsystems.source_blob_sha256` → the listing HTML in `blobs` |
| Crash location or stack frame | `report_version_id` → `report_versions.blob_sha256` → `blobs` |
| Kernel build associated with a crash location | `crash_locations.crash_id` → `crashes`; `crashes.raw_sha256` identifies the serialized crash object |
| C reproducer URL per crash | `crashes.c_reproducer_url`; `crashes.raw_sha256` identifies the crash object containing `c-reproducer` |
| Fix location | `patch_version_id` → `patch_versions.blob_sha256` → `blobs` |
| Artifact version used by a snapshot | `snapshot_reports` / `snapshot_patches` → the corresponding version and blob; `source_url` retains the URL for that association |

Complete downloaded files retain their original bytes in `blobs`. Individual
JSON objects extracted from a listing or detail response are also stored as
serialized JSON blobs; their whitespace and key order need not match the
downloaded document. Files on disk can later be refreshed, so the database's
version-specific blob is the definitive source for an older indexed value.

Successful download URLs travel in memory with their validated bytes until
ingestion. No new provenance sidecar is written beside a report or patch.
If the process stops before indexing, the saved file may survive without that
endpoint metadata. An identical-byte refresh can also take the unchanged-data
path, which intentionally performs no database write solely to record a URL.
Treat older fallback/source-reference URLs as retained metadata rather than
proof of the exact HTTP endpoint that supplied a historical file.

The implementation entry points are `Database.ingest_files()` and
`Database._insert_bug_children()` in [database/repository.py](../src/syz_sage/database/repository.py).
Their implementations are in [database/files.py](../src/syz_sage/database/files.py),
[database/snapshot.py](../src/syz_sage/database/snapshot.py), and
[database/writes.py](../src/syz_sage/database/writes.py). Parsing starts with
`parse_subsystem_tags()` in [parsing/listing.py](../src/syz_sage/parsing/listing.py),
`locate_crash_site()` / `extract_stack_frames()` in
[parsing/crash.py](../src/syz_sage/parsing/crash.py), and `extract_fix_locations()` in
[parsing/patch.py](../src/syz_sage/parsing/patch.py).
[location_store.py](../src/syz_sage/database/location_store.py) connects these extractions
to their report, patch, and snapshot versions;
[schema_v3.py](../src/syz_sage/database/schema_v3.py) defines snapshot artifact associations
and their ownership constraints.
[database/ingestion.py](../src/syz_sage/database/ingestion.py) shares per-run file observations,
fingerprints, and prepared artifact inspections. These are in-memory helpers;
the database schema and downloaded artifact formats remain unchanged.

### Example: `extid-0a884bc2d304ce4af70f`

For the [detail JSON](../data/raw/bugs/extid-0a884bc2d304ce4af70f.json):

- Top-level `title` is `WARNING in __dev_queue_xmit (5)`.
- The matching row in [upstream_fixed.html](../data/raw/upstream_fixed.html)
  contains `label=subsystems%3Anet`, supplying the `net` tag.
- `crashes[0].crash-report-link` identifies the retained
  [report](../data/artifacts/reports/extid-0a884bc2d304ce4af70f.txt).
  That crash's kernel revision is `c2ee9f594da826bea183ed14f2cc029c719bf4da`.
- `fix-commits[0].hash` is `5eb70dbebf32c2fd1f2814c654ae17fc47d6e859`,
  selecting [this patch](../data/artifacts/patches/5eb70dbebf32c2fd1f2814c654ae17fc47d6e859.diff).
  It changes `net/core/netdev-genl.c` at old/new lines 433 and 436.
- The patch heading is `@@ -430,10 +430,10 @@ static int`. Its leading unchanged
  definition identifies `netdev_nl_queue_fill`, recorded with
  `function_basis = 'inferred from definition context'`.
- The primary crash location is the inline helper `skb_assert_len` at
  `include/linux/skbuff.h:2679`. Its caller `__dev_queue_xmit` at
  `net/core/dev.c:4345` remains a separate stack entry.
- The detail JSON contains 41 crash records. Only the selected representative
  report supplies the extracted stack; `--stack` displays that complete extraction.

Parser revision 2 corrects the earlier function/file mismatch in this warning:
revision 1 paired the outer caller with the inline helper's file and line.
Schema migration repairs those derived rows from the retained report bytes.

## Interpreting locations

Crash coordinates refer to the kernel build recorded by the associated crash
(`crashes.kernel_source_git` and `kernel_source_commit`), not today's kernel.
Explicit sanitizer source coordinates take precedence over grouping titles,
which can name an outer function instead of the inlined failing operation.
An explicit diagnostic line does not establish a function from a different
source line, even if both occur in the same file.
Both conflicting KCSAN access sites are retained. Evidence and confidence
distinguish reported coordinates from heuristic frame selection. Missing
coordinates are SQL `NULL`; an allocation/free line is never substituted for
a missing crash line.

Stack frames preserve report order, inline frames, and separate manifestation,
allocation, free, origin, and other-task sections when those headings are
available. KMSAN's `Uninit was stored to memory at:` traces are origin history;
`page last allocated` and `page last free stack trace` identify page history.
These frames cannot supply a missing crash coordinate. Unsymbolized frames
keep their raw text and unknown fields. The
complete report text remains the source of truth for unusual formats and is
available through `ss show KEY --report` or JSON with `--report`.

Fix coordinates refer to the patch's old tree and new tree. `old_start` with
`old_count` describes removed lines; `new_start` with `new_count` describes
added lines. These are contiguous edits, excluding unchanged hunk context.
Counts greater than zero cover `start` through `start + count - 1` inclusive.
A zero count denotes an insertion/deletion anchor **after** `start`; zero
means before the first line. Renamed paths retain both names, and a missing
side of an added/deleted file has a NULL path. Binary, file-only, and malformed
changes have unknown line coordinates rather than invented ranges.

Function names inferred from Git hunk headings have
`function_basis = 'inferred from hunk heading'`. A leading unchanged function
definition can instead supply `function_basis = 'inferred from definition context'`.
Patches alone do not always
identify the enclosing function or which individual edit caused the fix.
All changed ranges are retained for review; unknown function names stay NULL.

## Querying the active data

The views `current_bug_subsystems`, `current_crash_locations`,
`current_crash_stack_frames`, and `current_fix_locations` join each derived row
to its active bug. `current_bug_rows` contains every active bug, including those
with no available report, patch, or subsystem label. Raw tables retain previous
artifact versions when the corresponding artifact changes. Parser upgrades can
replace derived extractions; the original source blobs remain intact.

The active location views follow `snapshot_reports` and `snapshot_patches`, so
a newer or partial artifact cannot silently change the locations of the active
snapshot. The `reports` and `patches` tables retain legacy current pointers;
inspection reads snapshot associations. These record the exact version, report
crash/build, and source URL. Composite keys prevent duplicate associations;
foreign keys and insert/update triggers reject associations with the wrong bug,
crash version, or commit.

```sql
-- Titles and subsystem tags, including bugs without tags.
SELECT b.key, b.title, b.bug_url, group_concat(t.tag, ', ') AS subsystem_tags
FROM current_bug_rows b
LEFT JOIN current_bug_subsystems t ON t.bug_id = b.bug_id
GROUP BY b.bug_id, b.key, b.title, b.bug_url;

SELECT key, file_path, function_name, line_number, column_number,
       kernel_source_commit, confidence, method
FROM current_crash_locations;

SELECT key, commit_hash, old_file_path, old_start, old_count,
       new_file_path, new_start, new_count, function_name, function_basis
FROM current_fix_locations;

SELECT ordinal, section, function_name, file_path, line_number, raw_line
FROM current_crash_stack_frames
WHERE key = 'extid-0a0e5f37746013dc7476'
ORDER BY ordinal;
```

```console
ss migrate
ss check
ss show extid-0a0e5f37746013dc7476 --stack
ss show extid-0a0e5f37746013dc7476 --json
```

## Migration and subsequent updates

Migrations use stored rows and blobs, so no redownload or filesystem mirror is required.
The v1-to-v2 migration backfills subsystem tags and location tables. The
transactional v2-to-v3 migration adds artifact associations and re-extracts
locations using parser revision 2. The v3-to-v4 migration adds and backfills
`snapshot_bugs.bug_type` for every retained snapshot from its stored title and
indexes the field for filtering. It leaves source blobs, artifact associations,
active-snapshot selection, and synchronization history intact. A failure rolls back the schema and data
changes in that migration. Back up a valuable database before running `ss migrate`;
the command does not automatically create a backup.

The v4-to-v5 migration repairs crash locations and stack sections with report
parser revision 3. It reparses current and historical report/crash associations
from stored blobs in one transaction. Patch extraction remains at revision 2;
raw reports, patches, snapshot membership, and synchronization history are
unchanged. Read-only commands require an explicit `ss migrate` before opening
an older database.

Version 2 did not retain artifact pointers for every historical snapshot.
Migration backfills associations for the active snapshot where ownership can
be established, and keeps older source versions and derived rows. It does not
invent historical report/build associations. Every snapshot ingested under
version 3 or later records its own available artifact versions.

New ingestion validates retained artifacts and prepares a bounded amount of
new location extraction before opening the snapshot transaction. It streams
report/patch bytes into the existing tables and indexes the remaining
extractions as needed inside that transaction. Partial candidates retain their
derived data, while active views
continue to expose the last complete candidate. Repeated unchanged updates
add no rows or synchronization history and perform no location reindexing.

The durable download queues in `processed/sync_state.json` also apply to offline
imports. A pending live detail, report, or referenced patch download prevents
activation, even when an older cached file exists. Pending report/detail bytes
are preserved without falsely assigning them to a newly selected crash or URL.
Historical jobs unrelated to the current listing do not block activation.
Required resolution patches are matched to current fix subjects and repositories,
including applicable accepted resolutions already stored in SQLite. Obsolete
resolution records remain history without becoming download requirements.
Malformed retry state stops online updates without overwriting its bytes; offline
imports retain it as a completeness error. HTML whose bug membership disagrees
with the JSON listing produces a partial candidate. Missing HTML cannot erase
existing subsystem tags.

Title-only fix resolutions are accepted only from a complete import. A partial
candidate retains its resolution source document but cannot change the active
resolution lookup. Resolutions enrich normalized fix references, including
older references; the original reported values remain recoverable from blobs.
Distinct commit hashes are kept separate even when their subjects match. A
title-only reference is merged for inspection only when the matching commit
is unambiguous.

`ss check` verifies SQLite structure, foreign keys, blob sizes and SHA-256
hashes, active membership counts, stored bug types against snapshot titles,
and artifact ownership/extraction consistency.
It reads the database without modifying it. It does not validate against the
current syzbot website or prove that every possible report format was parsed.
