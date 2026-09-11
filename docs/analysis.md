# Find and study fixed bugs

[Project overview](../README.md) · [CLI usage](usage.md) · [Database](database.md)

`filter`, `show`, `related`, `compare`, and `stats` use saved data offline and do
not write SQLite. Only `fetch` downloads additional evidence, and only for the
selected bug and crash. No reproducer is compiled or executed.

For an existing database, run `ss migrate` once to add schema 7's failure-pattern
and access-mode fields from retained titles and representative reports. Migration
needs no downloads and preserves the original source bytes.

## Filter by failure pattern and source evidence

```console
ss filter --type kasan --family use-after-free --subsystem fs
ss filter --crash-file 'fs/ext4/*' --has-c-repro
ss filter --fix-function example_function --has-patch
ss filter --access write read-write --max-fix-files 1 --max-patch-lines 20
ss filter --family unknown --all --json
ss filter --list-values
```

Diagnostic type and failure pattern are separate. `kasan` identifies a diagnostic;
`use-after-free` describes explicit failure wording, not an inferred ownership or
synchronization mistake. JSON includes each classification's method, evidence,
and source under `characteristics`.

Families include use-after-free, use-after-scope, use-after-return, out-of-bounds,
uninitialized-value, double-free, invalid-free, null-dereference, data-race,
deadlock, memory-leak, integer-overflow, shift-out-of-bounds, divide-by-zero,
alignment, hang, and unknown. Access modes are read, write, read-write, and unknown.
Explicit manifestation diagnostics take precedence over grouping-title wording.
Auxiliary stacks do not supply the observed access mode. Unrecognized or conflicting
evidence stays unknown. The representative report may not describe every crash.

| Option | Selection rule |
|---|---|
| `--family VALUE...` | Exact failure patterns, case-insensitive. |
| `--access VALUE...` | Exact observed access modes, case-insensitive. |
| `--crash-file PATTERN...` | Match recorded crash source paths. |
| `--fix-file PATTERN...` | Match either old or new changed source paths. |
| `--crash-function PATTERN...` | Match recorded crash function names. |
| `--fix-function PATTERN...` | Match inferred patch function names. |
| `--has-c-repro` / `--no-c-repro` | C reproducer URL recorded / known not provided; unknown metadata matches neither. |
| `--has-report` / `--no-report` | Valid representative report saved / none associated. |
| `--has-patch` / `--no-patch` | At least one valid referenced patch saved / none associated. |
| `--max-fix-files N` | At most N distinct changed paths across the bug's fixes. |
| `--max-patch-lines N` | At most N added plus removed lines across the bug's fixes. |

Source patterns are case-sensitive, match the entire value, and support `*`, `?`,
and `[abc]`. `*` also matches `/`. Quote patterns to prevent shell expansion.
Without wildcards, the value is an exact match. Missing coordinates never match.
Patch function names remain inferred even when a function filter matches.

Values within a category match any value; different categories must all match.
Subsystems remain exact syzbot tags: `fs` does not include `ext4`. Existing `--query`,
pagination, `--all`, `--json`, and `--urls-only` options remain available.
`--list-values` must be used without selection or pagination; it now also lists
observed families and access modes.

Each result includes its timeline, representative crash coordinates, fix commits
and changed source ranges, report URL/size, and stack-frame count. Colors distinguish
source paths, functions, hashes, dates, and evidence availability. Use `--limit 5`
for a shorter page or `--json` for the structured details. See the
[filter output reference](usage.md#filter-fixed-bugs) for field definitions.

Patch-size filters count each known fix hash once. Renames use the new path,
deletions the old path. Sizes are unknown when required fixes are unresolved,
patches are missing, or their contents are binary or incompletely parsed. Those
bugs do not pass maximum-size filters. Availability describes saved evidence,
not whether additional content exists online.

## Read saved patches

Append all saved fix patches to the bug details, or select one commit:

```console
ss show KEY --diff
ss show KEY --stack --diff
ss show KEY --diff --json
ss show KEY --patch HASH
ss show KEY --patch HASH --file 'net/core/*'
ss show KEY --patch HASH --json
```

Replace `KEY` and `HASH` with an actual bug key and full 40-character commit hash.
Use ordinary `ss show KEY` to find its fix hashes; a selected hash must belong to
that bug. `--diff` includes per-file insertion/deletion summaries and full saved
text for every fix. Diff lines remain unwrapped; human output colors additions,
deletions, file headers, and hunk headings. Combine `--stack --diff` to read the
full numbered stack and all patches together. `--explain` can also be included.

`--diff` and `--patch HASH` are mutually exclusive. `--file` follows the same glob
rules and matches either side of a rename. It requires `--patch`; an unmatched
path is an error.

Inspection reads retained patch bytes from the active SQLite snapshot, even when
artifact files are missing, and never downloads patches. Unresolved fix references
and missing patches are reported explicitly. Binary or incomplete patches have
unknown line counts; their available text is still displayed.

JSON `--diff` adds a `patches` array; `--patch HASH` adds a single `patch` object.
Each entry includes commit metadata, source URL, SHA-256, file sections, hunks,
and saved text. Its `diffstat` contains `files_changed`, `insertions`, `deletions`,
and `complete`; file sections also include `insertions` and `deletions`. Unknown
line counts are `null`, and `complete` is false when counts are incomplete.
The hash/size describe the full retained patch even when displayed text is
filtered; counts describe the selected files. A fix without saved bytes returns
`available: false`, with `text` and `diffstat` set to `null`. Ordinary `show --json`
omits patch bodies.

## Explain crash-to-fix relationships

```console
ss show KEY --explain
ss show KEY --explain --patch HASH
ss show KEY --stack --diff --explain
ss show KEY --explain --json
```

Explanations connect failure/access wording and crash coordinates to report evidence,
then examine each available fix hunk. Labels are same-function, same-file,
different-file, or unknown. Same-function requires equal source paths and function
names, but remains inferred because patch functions come from headings or definition
context. Individual edits are retained rather than reduced to one causal score.

Stack matches include their report lines. Allocation/free/origin, other-task, and
unwind frames cannot establish manifestation stack membership. No match means none
was found in this saved stack; it does not prove a function was never executed.
Crash and patch line numbers are not compared across different source revisions.
These are observed relationships, not proof of causation. No external AI service
or source-code execution is used.

JSON adds `explanation`, keeps report metadata, and always omits full report text.
Normal `--stack` and `--diff` views can be combined with `--explain`.

## Find related cases and compare bugs

```console
ss related KEY --limit 10
ss related KEY --json
ss compare KEY1 KEY2
ss compare KEY1 KEY2 --json
```

Related results explain shared fix commits, crash function names, changed paths,
and crash paths. Ranking prefers those signals in that order, then the bug key.
A shared failure pattern supplies context only when there is also a concrete
commit/function/path connection. Results exclude the selected bug itself;
`total` counts matches before `--limit`.

Comparison shows each bug's diagnostic, family, access, tags, crash locations,
fixes, and reproducer availability, followed by shared evidence and differing
metadata. Keys and syzbot URLs are accepted. Equal names or shared patches do not
establish identical bugs or a common root cause; no records are merged.

## Describe selected bugs

```console
ss stats --type kasan --subsystem fs
ss stats --family use-after-free --has-c-repro --top 20
ss stats --fix-file 'net/*' --json
```

`stats` accepts the same selection criteria as `filter`, without pagination or
`--list-values`. Every match contributes to the denominator. `--top N` limits each
human table (default 10); JSON includes all values.

Results include diagnostic/family/access distributions, subsystem tags, frequently
changed paths/functions, evidence availability, fix-size ranges and medians, and
the closest observed file/function relationship per bug.

- Each distribution counts a bug at most once per value. Tags, paths, and functions
  overlap, so those tables need not sum to the selected bug count.
- Distinct fix commits and bug–commit links are separate. Two bugs sharing one
  known commit produce one distinct commit and two links. Unresolved references
  are not invented hashes.
- Fix sizes use complete known evidence; unknown counts are shown separately.
  Renames use their new name, deletions their old name.
- Same-function/file means an observed match. Different-file requires complete
  known fix evidence. These are not root-cause classifications.
- A reproducer URL does not establish successful reproduction.

These statistics describe the selected fixed bugs, not subsystem reliability.
Empty selections succeed with zero counts and unknown size summaries.

## Fetch additional evidence for one crash

```console
ss show KEY --json
ss fetch KEY --c-repro --config
ss fetch KEY --crash 1 --report --syz-repro
ss fetch KEY --crash 1 --c-repro --refresh --json
ss --data-dir /path/to/evidence --database /path/to/bugs.sqlite3 fetch KEY --config
```

`show --json` lists crash entries and their zero-based `ordinal` values.
`--crash N` selects one entry. By default, selection uses the crash matching the
representative report URL, then the first report-bearing crash, then the first
saved crash. Every requested artifact comes from that entry; missing URLs never
cause borrowing from another crash/build.

At least one of `--c-repro`, `--syz-repro`, `--config`, or `--report` is required.
Valid local files are reused; `--refresh` requests fresh bytes. `--json` and
`--quiet` suppress progress. Missing requested URLs and failed downloads return
nonzero status while retaining successes. Failed refreshes preserve valid older
files and report that they were retained.

Downloads preserve plain source/report/config formats under the selected data root:

```text
artifacts/repros/KEY/crash-N-URL_SHA256.c
artifacts/repros/KEY/crash-N-URL_SHA256.syz
artifacts/configs/KEY/crash-N-URL_SHA256.config
artifacts/reports/KEY/crash-N-URL_SHA256.txt
```

Directories are created only when needed. The URL digest avoids reusing files for
different resources. JSON reports the URL, selected crash/build, path, content
SHA-256, and downloaded/reused/unavailable/failed status. Additional files do not
replace representative reports or change SQLite. Routine updates and imports
ignore these nested optional files. Existing artifact formats stay unchanged.

Fetching checks URLs and basic content format; it does not verify kernel
compatibility, compile/execute reproducers, or claim successful reproduction.
