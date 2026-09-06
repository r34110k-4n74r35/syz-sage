"""Validated durable download intent shared by retrieval and offline ingestion."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from syz_sage.parsing.listing import (
    HASH_RE,
    KEY_RE,
    MAX_BUG_KEY_LENGTH,
    PayloadError,
    decode_json_object,
)

from .artifacts import atomic_write


@dataclass(slots=True)
class SyncState:
    """Download retries that remain pending across listing rollover."""

    pending_details: set[str] = field(default_factory=set)
    pending_reports: set[str] = field(default_factory=set)
    pending_patches: set[str] = field(default_factory=set)


def save_sync_state(path: Path, state: SyncState) -> None:
    """Atomically preserve the shared v2 retry queues at the selected data path."""
    document = {
        "version": 2,
        "pending_details": sorted(state.pending_details),
        "pending_reports": sorted(state.pending_reports),
        "pending_patches": sorted(state.pending_patches),
    }
    atomic_write(path, (json.dumps(document, indent=2, ensure_ascii=False) + "\n").encode("utf-8"))


def load_sync_state(path: Path) -> tuple[SyncState, str | None]:
    """Read v1/v2 queues without accepting unsafe keys or commit hashes."""
    try:
        document = decode_json_object(path.read_bytes())
        version = document.get("version")
        if type(version) is not int or version not in (1, 2):
            raise PayloadError("sync state has an unsupported or missing version")

        def keys_for(name: str) -> set[str]:
            values = document.get(name)
            if not isinstance(values, list):
                raise PayloadError(f"sync state {name} must be a list")
            keys: set[str] = set()
            for value in values:
                if (
                    not isinstance(value, str)
                    or len(value) > MAX_BUG_KEY_LENGTH
                    or KEY_RE.fullmatch(value) is None
                ):
                    raise PayloadError(f"sync state {name} contains an unsafe bug key")
                keys.add(value)
            return keys

        patches: set[str] = set()
        if version == 2:
            values = document.get("pending_patches")
            if not isinstance(values, list):
                raise PayloadError("sync state pending_patches must be a list")
            for value in values:
                if not isinstance(value, str) or HASH_RE.fullmatch(value) is None:
                    raise PayloadError("sync state pending_patches contains an invalid hash")
                patches.add(value.lower())
        return SyncState(keys_for("pending_details"), keys_for("pending_reports"), patches), None
    except FileNotFoundError:
        return SyncState(), None
    except (OSError, PayloadError) as exc:
        return SyncState(), str(exc)
