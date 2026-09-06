"""Checkout-local defaults and unrestricted user-selected filesystem paths."""

from __future__ import annotations

import contextlib
import importlib
import os
import tempfile
from collections.abc import Iterator
from pathlib import Path


def project_root() -> Path:
    """Find the checkout owning this installation or the current working directory.

    Used only for implicit application defaults and project test scratch space.
    Explicit input/output paths do not need a checkout. Never invent a default
    application data directory under the user's home or a system location.
    """
    for start in (Path(__file__).resolve().parent, Path.cwd().resolve()):
        for root in (start, *start.parents):
            if (root / "pyproject.toml").is_file() and (root / "src" / "syz_sage").is_dir():
                return root
    raise ValueError(
        "cannot find a Syz Sage source checkout for default paths; "
        "specify --data-dir, or --database for database commands"
    )


def writable_path(path: str | os.PathLike[str]) -> Path:
    """Normalize a chosen destination; the filesystem enforces write permissions.

    User-selected paths may be anywhere, including symlinks and hard links.
    Validate downloaded identifiers separately before using them as filenames.
    This function does not create files or change cache/environment settings.
    """
    return Path(path).expanduser().resolve()


def make_directory(path: str | os.PathLike[str]) -> Path:
    destination = writable_path(path)
    destination.mkdir(parents=True, exist_ok=True)
    return destination


def temporary_directory_root() -> Path:
    """Parent for self-cleaning temporary directories, independent of system TMPDIR.

    Callers use TemporaryDirectory under this existing directory so no empty
    shared scratch root remains after their cleanup.
    """
    return project_root()


def temporary_directory() -> tempfile.TemporaryDirectory[str]:
    """Create self-cleaning scratch space inside the project, ignoring system TMPDIR.

    The hidden prefix also identifies interrupted runs for manual cleanup;
    there is no persistent shared temporary directory.
    """
    return tempfile.TemporaryDirectory(prefix=".syz-sage-tmp-", dir=temporary_directory_root())


def write_bytes(path: str | os.PathLike[str], payload: bytes) -> None:
    destination = writable_path(path)
    make_directory(destination.parent)
    destination.write_bytes(payload)


def write_text(path: str | os.PathLike[str], payload: str) -> None:
    destination = writable_path(path)
    make_directory(destination.parent)
    destination.write_text(payload, encoding="utf-8")


@contextlib.contextmanager
def exclusive_update_lock(root: Path, *, create: bool = True) -> Iterator[None]:
    """Fail fast on a shared data-root lock, optionally opening an input lock read-only."""

    root = writable_path(root)
    lock_path = writable_path(root / ".syz_sage.update.lock")
    if create:
        root.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+b" if create else "rb") as handle:
        if os.name == "nt":
            locking = importlib.import_module("msvcrt")
            if create:
                handle.seek(0, os.SEEK_END)
                if handle.tell() == 0:
                    handle.write(b"\0")
                    handle.flush()
            # Windows permits locking a byte range beyond EOF. An existing
            # empty input lock therefore needs no initialization write.
            handle.seek(0)
            try:
                locking.locking(handle.fileno(), locking.LK_NBLCK, 1)
            except OSError as exc:
                raise RuntimeError(f"another update owns data root {root}") from exc
            try:
                yield
            finally:
                handle.seek(0)
                locking.locking(handle.fileno(), locking.LK_UNLCK, 1)
        else:
            locking = importlib.import_module("fcntl")
            try:
                locking.flock(handle.fileno(), locking.LOCK_EX | locking.LOCK_NB)
            except OSError as exc:
                raise RuntimeError(f"another update owns data root {root}") from exc
            try:
                yield
            finally:
                locking.flock(handle.fileno(), locking.LOCK_UN)
