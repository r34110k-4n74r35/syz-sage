"""Checkout-local defaults and unrestricted user-selected filesystem paths."""

from __future__ import annotations

import os
import tempfile
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
