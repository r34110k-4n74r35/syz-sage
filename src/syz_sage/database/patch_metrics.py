"""Conservative completeness checks for cached patch size measurements."""

from __future__ import annotations

import re
import sqlite3

_HUNK = re.compile(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(?:.*)$")


def complete_text(patch: str) -> bool:
    """Reject binary, malformed, extra or truncated hunk bodies.

    File-only mode changes and pure renames have known zero changed text lines.
    Existing parsed locations separately establish whether paths are known.
    """
    lines = patch.splitlines()
    in_diff = False
    hunk_seen = False
    text_header = False
    metadata: set[str] = set()

    def file_complete() -> bool:
        if text_header:
            return hunk_seen
        return hunk_seen or any(
            required <= metadata
            for required in (
                {"old mode", "new mode"},
                {"rename from", "rename to"},
                {"copy from", "copy to"},
                {"new file mode"},
                {"deleted file mode"},
            )
        )

    i = 0
    while i < len(lines):
        line = lines[i]
        if line.startswith(("GIT binary patch", "Binary files ")):
            return False
        if line.startswith("diff --git "):
            if in_diff and not file_complete():
                return False
            in_diff = True
            hunk_seen = text_header = False
            metadata.clear()
        elif line.startswith(("--- ", "+++ ")):
            if line.startswith("--- ") and text_header and hunk_seen:
                hunk_seen = False
                metadata.clear()
            in_diff = True
            text_header = True
        elif line.startswith("@@"):
            match = _HUNK.fullmatch(line)
            if match is None:
                return False
            hunk_seen = True
            old_left, new_left = int(match[2] or 1), int(match[4] or 1)
            i += 1
            while old_left or new_left:
                if i == len(lines):
                    return False
                body = lines[i]
                if body.startswith("\\ No newline at end of file"):
                    i += 1
                    continue
                if not body or body[0] not in " +-":
                    return False
                old_left -= body[0] in " -"
                new_left -= body[0] in " +"
                if old_left < 0 or new_left < 0:
                    return False
                i += 1
            continue
        elif in_diff and line and line[0] in " +-" and line != "-- ":
            # The location parser may ignore extra edit lines after a declared
            # hunk ends. They make a complete line-count claim unsafe.
            return False
        else:
            for prefix in (
                "old mode",
                "new mode",
                "rename from",
                "rename to",
                "copy from",
                "copy to",
                "new file mode",
                "deleted file mode",
            ):
                if line.startswith(prefix + " "):
                    metadata.add(prefix)
        i += 1
    return in_diff and file_complete()


def index_patch(
    connection: sqlite3.Connection, patch_version_id: int, *, payload: bytes | None = None
) -> None:
    if connection.execute(
        "SELECT 1 FROM patch_metric_coverage WHERE patch_version_id=?", (patch_version_id,)
    ).fetchone():
        return
    if payload is None:
        row = connection.execute(
            "SELECT b.content FROM patch_versions pv JOIN blobs b ON b.sha256=pv.blob_sha256 "
            "WHERE pv.id=?",
            (patch_version_id,),
        ).fetchone()
        if row is None:
            return
        payload = bytes(row[0])
    connection.execute(
        "INSERT INTO patch_metric_coverage(patch_version_id,is_complete) VALUES(?,?)",
        (patch_version_id, int(complete_text(payload.decode("utf-8", errors="replace")))),
    )
