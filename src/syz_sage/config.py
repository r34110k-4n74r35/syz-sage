"""Filesystem configuration for Syz Sage."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from .storage import project_root, writable_path

DATA_DIR_ENV = "SYZ_SAGE_DATA_DIR"
DATABASE_ENV = "SYZ_SAGE_DATABASE"


def default_data_root() -> Path:
    """Use this checkout's data directory or an explicit override anywhere.

    An explicit ``SYZ_SAGE_DATA_DIR`` still takes precedence. A checkout stays
    anchored to its own data even when the command runs from another directory.
    """

    configured = os.environ.get(DATA_DIR_ENV)
    if configured:
        return writable_path(configured)
    return writable_path(project_root() / "data")


@dataclass(frozen=True, slots=True)
class DataPaths:
    """All mutable paths used by an update, rooted at one directory."""

    root: Path

    @classmethod
    def from_root(cls, root: str | os.PathLike[str]) -> DataPaths:
        return cls(Path(root).expanduser().resolve())

    @classmethod
    def default(cls) -> DataPaths:
        return cls.from_root(default_data_root())

    @property
    def raw(self) -> Path:
        return self.root / "raw"

    @property
    def processed(self) -> Path:
        return self.root / "processed"

    @property
    def artifacts(self) -> Path:
        return self.root / "artifacts"

    @property
    def bugs(self) -> Path:
        return self.raw / "bugs"

    @property
    def reports(self) -> Path:
        return self.artifacts / "reports"

    @property
    def patches(self) -> Path:
        return self.artifacts / "patches"

    @property
    def reproducers(self) -> Path:
        return self.artifacts / "repros"

    @property
    def configs(self) -> Path:
        return self.artifacts / "configs"

    @property
    def database_dir(self) -> Path:
        return self.root / "db"

    @property
    def database(self) -> Path:
        return self.database_dir / "syz_sage.sqlite3"

    @property
    def listing_json(self) -> Path:
        return self.raw / "upstream_fixed.json"

    @property
    def listing_html(self) -> Path:
        return self.raw / "upstream_fixed.html"

    @property
    def catalog(self) -> Path:
        return self.processed / "catalog.json"

    @property
    def resolutions(self) -> Path:
        return self.processed / "resolved_fix_hashes.json"

    @property
    def sync_state(self) -> Path:
        """Durable updater retry state, kept outside database fingerprints."""

        return self.processed / "sync_state.json"

    def ensure(self) -> None:
        directories = (
            self.root,
            self.database_dir,
            self.raw,
            self.processed,
            self.artifacts,
            self.bugs,
            self.reports,
            self.patches,
        )
        # Optional artifact writers create their own parents only when needed.
        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)
