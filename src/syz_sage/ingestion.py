"""Per-run, stat-validated inspection of a retained filesystem mirror.

Nothing here writes files or persists a cache. Artifact bytes use a bounded
LRU; metadata, parsed JSON and fingerprints can be reused within one update.
"""

from __future__ import annotations

import hashlib
import json
from collections import OrderedDict
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

UNPARSED = object()
FileStamp = tuple[int, int, int, int, int]


def file_stamp(path: Path) -> FileStamp:
    stat = path.stat()
    return stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns


@dataclass
class _ObservedFile:
    stamp: FileStamp
    digest: str
    parsed: Any = UNPARSED


@dataclass
class ArtifactInspection:
    path: Path
    stamp: FileStamp
    digest: str
    error: str | None
    prepared: Any = None

    def read(self, inventory: FileInventory) -> bytes:
        if file_stamp(self.path) != self.stamp:
            raise OSError(f"artifact changed after preparation: {self.path}")
        payload = inventory.read_bytes(self.path)
        if file_stamp(self.path) != self.stamp or inventory.digest(self.path) != self.digest:
            raise OSError(f"artifact changed after preparation: {self.path}")
        return payload


class FileInventory:
    """Share validated observations between retrieval, no-op checks and ingestion.

    Call ``observe`` after a successful write or a verified local read. As with
    the updater lock, stat validation handles ordinary concurrent edits, not
    adversarial replacement that defeats filesystem metadata checks.
    """

    def __init__(self, *, max_bytes: int = 32 * 1024 * 1024) -> None:
        if max_bytes < 0:
            raise ValueError("max_bytes must not be negative")
        self.max_bytes = max_bytes
        self._files: dict[Path, _ObservedFile] = {}
        self._payloads: OrderedDict[Path, bytes] = OrderedDict()
        self._cached_bytes = 0
        self._fingerprint: tuple[object, str, list[str]] | None = None

    @property
    def cached_bytes(self) -> int:
        return self._cached_bytes

    @staticmethod
    def _path(path: Path) -> Path:
        return path.absolute()

    def invalidate(self, path: Path | None = None) -> None:
        self._fingerprint = None
        if path is None:
            self._files.clear()
            self._payloads.clear()
            self._cached_bytes = 0
            return
        path = self._path(path)
        self._files.pop(path, None)
        self._cached_bytes -= len(self._payloads.pop(path, b""))

    def _current(self, path: Path) -> _ObservedFile | None:
        known = self._files.get(path)
        if known is not None:
            try:
                if file_stamp(path) == known.stamp:
                    return known
            except OSError:
                pass
            self.invalidate(path)
        return None

    def observe(
        self,
        path: Path,
        payload: bytes,
        parsed: Any = UNPARSED,
        *,
        digest: str | None = None,
        expected_stamp: FileStamp | None = None,
    ) -> None:
        path = self._path(path)
        stamp = file_stamp(path)
        if stamp[2] != len(payload) or (expected_stamp is not None and stamp != expected_stamp):
            self.invalidate(path)
            raise OSError(f"file changed while observing {path}")
        known = self._current(path)
        digest = digest or hashlib.sha256(payload).hexdigest()
        if known is None or known.digest != digest:
            self._fingerprint = None
        if parsed is UNPARSED and known is not None and known.digest == digest:
            parsed = known.parsed
        self._files[path] = _ObservedFile(stamp, digest, parsed)
        self._cached_bytes -= len(self._payloads.pop(path, b""))
        if len(payload) <= self.max_bytes:
            self._payloads[path] = payload
            self._cached_bytes += len(payload)
            while self._cached_bytes > self.max_bytes:
                _, evicted = self._payloads.popitem(last=False)
                self._cached_bytes -= len(evicted)

    def read_bytes(self, path: Path) -> bytes:
        path = self._path(path)
        if self._current(path) is not None and path in self._payloads:
            self._payloads.move_to_end(path)
            return self._payloads[path]
        before = file_stamp(path)
        payload = path.read_bytes()
        if file_stamp(path) != before:
            self.invalidate(path)
            raise OSError(f"file changed while reading {path}")
        self.observe(path, payload, expected_stamp=before)
        return payload

    def remember_json(self, path: Path, parsed: Any, *, digest: str) -> None:
        """Attach a parsed value only to the exact, still-current observation."""
        path = self._path(path)
        known = self._current(path)
        if known is None or known.digest != digest:
            raise OSError(f"file changed while parsing {path}")
        known.parsed = parsed

    def read_observation(self, path: Path) -> tuple[bytes, FileStamp, str]:
        """Read bytes and their matching metadata without accepting a later edit."""
        payload = self.read_bytes(path)
        known = self._current(self._path(path))
        if known is None:
            raise OSError(f"file changed while reading {path}")
        return payload, known.stamp, known.digest

    def verify_saved(self, path: Path, payload: bytes, parsed: Any = UNPARSED) -> None:
        """Verify a completed write before caching its downloaded representation.

        A writer returning successfully does not imply the path still names its
        bytes: another process can replace it before observation. Re-read saved
        files once, pairing their bytes with a checked stamp, instead of giving
        an external edit the downloaded payload's digest or parsed JSON.
        """
        self.invalidate(path)
        saved, _, digest = self.read_observation(path)
        if saved != payload:
            self.invalidate(path)
            raise OSError(f"file changed after save: {path}")
        if parsed is not UNPARSED:
            self.remember_json(path, parsed, digest=digest)

    def read_json(self, path: Path, *, payload: bytes | None = None) -> Any:
        path = self._path(path)
        known = self._current(path)
        if payload is not None and self._payloads.get(path) is not payload:
            # A caller can retain source bytes after their observation expires
            # or is evicted. Always decode those bytes, never a newer file.
            return json.loads(payload)
        if known is not None and known.parsed is not UNPARSED:
            return known.parsed
        payload, _, digest = self.read_observation(path)
        parsed = json.loads(payload)
        self.remember_json(path, parsed, digest=digest)
        return parsed

    def digest(self, path: Path) -> str:
        path = self._path(path)
        known = self._current(path)
        if known is None:
            self.read_bytes(path)
            known = self._files[path]
        return known.digest

    @staticmethod
    def artifact_paths(directory: Path, suffix: str) -> tuple[dict[str, Path], list[str]]:
        try:
            entries = sorted(directory.iterdir()) if directory.is_dir() else []
            return {
                path.stem: path for path in entries if path.suffix == suffix and path.is_file()
            }, []
        except OSError as exc:
            return {}, [f"cannot list {directory}: {exc}"]

    def fingerprint(self, layout: Mapping[str, Path]) -> tuple[str, list[str]]:
        """Keep the legacy exact-content fingerprint; reuse it only for stable inputs."""
        candidates = [
            layout[name]
            for name in ("listing_json", "listing_html", "catalog", "resolutions")
            if layout[name].is_file()
        ]
        errors: list[str] = []
        for name, suffix in (("bugs", ".json"), ("reports", ".txt"), ("patches", ".diff")):
            paths, failures = self.artifact_paths(layout[name], suffix)
            candidates.extend(paths.values())
            errors.extend(failures)
        candidates.sort(key=str)
        stamps: list[tuple[str, FileStamp]] = []
        for path in candidates:
            try:
                stamps.append((str(path.absolute()), file_stamp(path)))
            except OSError as exc:
                errors.append(f"cannot fingerprint {path}: {exc}")
        identity = (str(layout["root"].absolute()), tuple(stamps))
        if not errors and self._fingerprint is not None and self._fingerprint[0] == identity:
            return self._fingerprint[1], list(self._fingerprint[2])
        digest = hashlib.sha256()
        for path in candidates:
            try:
                label = str(path.relative_to(layout["root"]))
            except ValueError:
                label = str(path)
            digest.update(label.encode("utf-8", errors="surrogateescape"))
            digest.update(b"\x00")
            try:
                digest.update(self.read_bytes(path))
            except OSError as exc:
                errors.append(f"cannot fingerprint {path}: {exc}")
            digest.update(b"\x00")
        value = digest.hexdigest()
        if not errors:
            self._fingerprint = (identity, value, [])
        return value, errors
