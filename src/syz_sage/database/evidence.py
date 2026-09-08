"""Read retained patches belonging to one bug in the active fixed listing."""

from __future__ import annotations

import re
from dataclasses import asdict
from fnmatch import fnmatchcase
from typing import TYPE_CHECKING, Any

from ..parsing.patch import extract_fix_locations

if TYPE_CHECKING:
    from .repository import Database


_HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


def _file_sections(text: str) -> tuple[str, list[str]]:
    """Keep exact file blocks, without mistaking removed source for a header."""
    lines = text.splitlines(keepends=True)
    starts = [index for index, line in enumerate(lines) if line.startswith("diff --git ")]
    if not starts:
        old_left = new_left = 0
        for index, line in enumerate(lines):
            if old_left or new_left:
                old_left -= int(line.startswith((" ", "-")) and old_left > 0)
                new_left -= int(line.startswith((" ", "+")) and new_left > 0)
                continue
            match = _HUNK.match(line)
            if match:
                old_left, new_left = int(match[2] or 1), int(match[4] or 1)
            elif (
                line.startswith("--- ")
                and index + 1 < len(lines)
                and lines[index + 1].startswith("+++ ")
            ):
                starts.append(index)
    if not starts:
        return text, []
    return "".join(lines[: starts[0]]), [
        "".join(lines[start:stop])
        for start, stop in zip(starts, [*starts[1:], len(lines)], strict=True)
    ]


def _hunks(text: str) -> list[dict[str, Any]]:
    lines = text.splitlines(keepends=True)
    hunks: list[dict[str, Any]] = []
    prefix: str | None = None
    index = 0
    while index < len(lines):
        match = _HUNK.match(lines[index])
        if not match:
            index += 1
            continue
        if prefix is None:
            prefix = "".join(lines[:index])
        start = index
        old_left, new_left = int(match[2] or 1), int(match[4] or 1)
        index += 1
        while index < len(lines):
            line = lines[index]
            if line.startswith("\\ No newline at end of file"):
                index += 1
                continue
            if not (old_left or new_left) or line[:1] not in {" ", "+", "-"}:
                break
            old_left -= int(line.startswith((" ", "-")))
            new_left -= int(line.startswith((" ", "+")))
            index += 1
            if old_left < 0 or new_left < 0:
                break
        hunk_text = "".join(lines[start:index])
        hunks.append(
            {
                "header": lines[start].rstrip("\r\n"),
                "text": hunk_text,
                "locations": [
                    asdict(location) for location in extract_fix_locations(prefix + hunk_text)
                ],
            }
        )
    return hunks


def _patch_files(text: str) -> tuple[str, list[dict[str, Any]]]:
    preamble, sections = _file_sections(text)
    files: list[dict[str, Any]] = []
    for block in sections:
        locations = extract_fix_locations(block)
        first = locations[0] if locations else None
        kinds = {location.kind for location in locations}
        files.append(
            {
                "old_file_path": first.old_file_path if first else None,
                "new_file_path": first.new_file_path if first else None,
                "kind": "text" if "text" in kinds else first.kind if first else "unparsed",
                "text": block,
                "hunks": _hunks(block),
            }
        )
    return preamble, files


def patch_view(
    database: Database,
    key: str,
    commit_hash: str,
    file_pattern: str | None = None,
) -> dict[str, Any] | None:
    """Return a selected saved patch, never a different bug's or newer patch.

    A full commit hash is required. File selection matches either full old or
    new path using case-sensitive shell wildcards; it never reads a source tree.
    Missing bugs return None; an unrelated hash or unmatched file raises ValueError.
    A known fix without retained bytes returns metadata with available=False.
    """
    commit_hash = commit_hash.strip().lower()
    if re.fullmatch(r"[0-9a-f]{40}", commit_hash) is None:
        raise ValueError("--patch requires a full 40-character hexadecimal commit hash")
    if file_pattern is not None:
        file_pattern = file_pattern.strip()
        if not file_pattern or any(ord(character) < 32 for character in file_pattern):
            raise ValueError("--file requires a nonempty source path or glob without controls")
    database.initialize()
    with database._read_transaction():
        bug = database.connection.execute(
            """SELECT key, title, bug_url, bug_id, bug_version_id, snapshot_id
               FROM current_bug_rows WHERE key = ?""",
            (key,),
        ).fetchone()
        if bug is None:
            return None
        fixes = database._effective_fixes(
            bug_id=bug["bug_id"],
            version_id=bug["bug_version_id"],
            snapshot_id=bug["snapshot_id"],
        )
        fix = next((item for item in fixes if item["commit_hash"] == commit_hash), None)
        if fix is None:
            raise ValueError(f"commit {commit_hash} is not a recorded fix for {key}")
        row = database.connection.execute(
            """SELECT sp.source_url, pv.blob_sha256, b.content, b.size_bytes
               FROM snapshot_patches sp JOIN patch_versions pv ON pv.id = sp.patch_version_id
               JOIN blobs b ON b.sha256 = pv.blob_sha256
               WHERE sp.snapshot_id = ? AND sp.commit_hash = ? AND pv.is_valid = 1""",
            (bug["snapshot_id"], commit_hash),
        ).fetchone()
        text = bytes(row["content"]).decode("utf-8", errors="replace") if row else None
        preamble, files = _patch_files(text) if text is not None else ("", [])
        total_files = len(files)
        if file_pattern is not None and text is not None:
            files = [
                item
                for item in files
                if any(
                    path and fnmatchcase(path, file_pattern)
                    for path in (item["old_file_path"], item["new_file_path"])
                )
            ]
            if not files:
                raise ValueError(f"no saved patch file matches {file_pattern!r}")
            text = preamble + "".join(item["text"] for item in files)
        return {
            "key": bug["key"],
            "title": bug["title"],
            "bug_url": bug["bug_url"],
            "commit_hash": commit_hash,
            "fix": fix,
            "available": row is not None,
            "source_url": row["source_url"] if row else fix.get("link") or None,
            "sha256": row["blob_sha256"] if row else None,
            "size": row["size_bytes"] if row else 0,
            "file_pattern": file_pattern,
            "files": files,
            "total_files": total_files,
            "text": text,
        }
