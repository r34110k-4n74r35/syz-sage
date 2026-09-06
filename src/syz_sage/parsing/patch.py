"""Exact changed ranges from unified diffs; function names are inferred hints."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class FixLocation:
    old_file_path: str | None
    new_file_path: str | None
    old_start: int | None
    old_count: int
    new_start: int | None
    new_count: int
    function_name: str | None
    hunk_header: str
    kind: str
    function_basis: str = "unknown"


def _file_path(value: str, *, strip_prefix: bool = True) -> str | None:
    value = value.split("\t", 1)[0].strip()
    if value.startswith('"'):
        try:
            decoded = ast.literal_eval(value)
            if isinstance(decoded, str):
                value = decoded
        except (SyntaxError, ValueError):
            return None
    if value == "/dev/null":
        return None
    return value[2:] if strip_prefix and value.startswith(("a/", "b/")) else value


def _function_hint(context: str) -> str | None:
    # Git's hunk heading is a hint, not proof of the enclosing function.
    match = re.search(r"\bfn\s+([A-Za-z_]\w*)", context)
    if match:
        return match.group(1)
    match = re.search(r"\b([A-Za-z_]\w*)\s*\(", context)
    if match and match.group(1) not in {"if", "for", "while", "switch", "sizeof"}:
        return match.group(1)
    return None


def _edit_location(
    old_path: str | None,
    new_path: str | None,
    old_line: int,
    removed: int,
    new_line: int,
    added: int,
    function: str | None,
    header: str,
    function_basis: str,
) -> FixLocation:
    return FixLocation(
        old_path,
        new_path,
        old_line if removed else max(0, old_line - 1),
        removed,
        new_line if added else max(0, new_line - 1),
        added,
        function,
        header,
        "text",
        function_basis,
    )


def _definition_hint(heading: str, lines: list[str], start: int) -> str | None:
    """Recognize a declaration followed by a body in unchanged leading context.

    Do not turn a call inside a function or a changed declaration into the
    enclosing function. This intentionally leaves complicated macros unknown.
    """
    context = [heading.strip()] if heading.strip() else []
    for raw in lines[start : start + 12]:
        if not raw.startswith(" "):
            break
        context.append(raw[1:].strip())
        if "{" in raw or ";" in raw:
            break
    signature = " ".join(context)
    match = re.fullmatch(
        r"(?:[A-Za-z_]\w*\s+)+\**\s*([A-Za-z_]\w*)\s*\([^;{}]*\)\s*\{",
        signature,
    )
    return match[1] if match and "=" not in signature else None


def extract_fix_locations(patch: str) -> list[FixLocation]:
    """One row per contiguous edit, excluding unchanged hunk context.

    A zero count uses the diff convention: start is the preceding line (zero
    means before line one). Non-text changes retain file names with NULL lines.
    Malformed/truncated hunks retain their file with unknown line coordinates.
    """
    locations: list[FixLocation] = []
    lines = patch.splitlines()
    old_path: str | None = None
    new_path: str | None = None
    file_has_locations = False
    file_kind = "file-only"

    def finish_file() -> None:
        if not file_has_locations and (old_path or new_path):
            locations.append(
                FixLocation(
                    old_path,
                    new_path,
                    None,
                    0,
                    None,
                    0,
                    None,
                    "",
                    file_kind,
                )
            )

    i = 0
    while i < len(lines):
        line = lines[i]
        if line.startswith("diff --git "):
            finish_file()
            old_path = new_path = None
            file_has_locations = False
            file_kind = "file-only"
            match = re.match(r'diff --git (".*?"|a/.*?) (".*?"|b/.*)$', line)
            if match:
                old_path, new_path = _file_path(match[1]), _file_path(match[2])
        elif line.startswith("rename from "):
            old_path, file_kind = _file_path(line[12:], strip_prefix=False), "rename"
        elif line.startswith("rename to "):
            new_path, file_kind = _file_path(line[10:], strip_prefix=False), "rename"
        elif line.startswith("new file mode "):
            old_path = None
        elif line.startswith("deleted file mode "):
            new_path = None
        elif line.startswith("--- "):
            # Also support plain unified diffs containing more than one file.
            if file_has_locations:
                finish_file()
                file_has_locations = False
            old_path = _file_path(line[4:])
        elif line.startswith("+++ "):
            new_path = _file_path(line[4:])
        elif line.startswith(("GIT binary patch", "Binary files ")):
            file_kind = "binary"
        else:
            match = re.match(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(.*)", line)
            if match:
                old_total, new_total = int(match[2] or 1), int(match[4] or 1)
                old_line = int(match[1]) + (old_total == 0)
                new_line = int(match[3]) + (new_total == 0)
                old_seen = new_seen = 0
                removed = added = 0
                edit_old, edit_new = old_line, new_line
                function = _function_hint(match[5])
                basis = "inferred from hunk heading" if function else "unknown"
                if not function:
                    function = _definition_hint(match[5], lines, i + 1)
                    if function:
                        basis = "inferred from definition context"
                edits: list[FixLocation] = []

                i += 1
                while i < len(lines) and (old_seen < old_total or new_seen < new_total):
                    body = lines[i]
                    if body.startswith("\\"):
                        i += 1
                        continue
                    if not body or body[0] not in " +-":
                        break
                    if body.startswith(" "):
                        if removed or added:
                            edits.append(
                                _edit_location(
                                    old_path,
                                    new_path,
                                    edit_old,
                                    removed,
                                    edit_new,
                                    added,
                                    function,
                                    line,
                                    basis,
                                )
                            )
                        removed = added = 0
                        old_line += 1
                        new_line += 1
                        old_seen += 1
                        new_seen += 1
                    else:
                        if not removed and not added:
                            edit_old, edit_new = old_line, new_line
                        if body.startswith("-"):
                            removed += 1
                            old_line += 1
                            old_seen += 1
                        else:
                            added += 1
                            new_line += 1
                            new_seen += 1
                    i += 1
                if removed or added:
                    edits.append(
                        _edit_location(
                            old_path,
                            new_path,
                            edit_old,
                            removed,
                            edit_new,
                            added,
                            function,
                            line,
                            basis,
                        )
                    )
                if old_seen == old_total and new_seen == new_total and (old_path or new_path):
                    locations.extend(edits)
                    file_has_locations = file_has_locations or bool(edits)
                else:
                    locations.append(
                        FixLocation(
                            old_path,
                            new_path,
                            None,
                            0,
                            None,
                            0,
                            None,
                            line,
                            "unparsed",
                        )
                    )
                    file_has_locations = True
                continue
        i += 1
    finish_file()
    return locations
