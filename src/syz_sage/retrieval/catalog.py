"""Retained fixed-listing comparison and stable catalog generation."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from syz_sage.parsing.listing import PayloadError, decode_json_object, parse_listing
from syz_sage.project.config import DataPaths

from .artifacts import atomic_write

if TYPE_CHECKING:
    from syz_sage.database.ingestion import FileInventory


def _read_prior_listing(
    path: Path, dashboard: str, inventory: FileInventory
) -> list[dict[str, Any]]:
    """Return a safe incremental baseline, or no records when it is unusable."""

    try:
        return parse_listing(inventory.read_bytes(path), dashboard=dashboard)
    except (OSError, PayloadError):
        return []


def _listing_discrepancies(
    records: list[dict[str, Any]],
    prior_records: list[dict[str, Any]],
) -> tuple[list[str], list[str]]:
    """Return mirror-new keys and metadata-changed existing keys in listing order."""

    prior_by_key = {str(record["key"]): record for record in prior_records}
    mirror_new_keys: list[str] = []
    changed_keys: list[str] = []
    for record in records:
        key = str(record["key"])
        if key not in prior_by_key:
            mirror_new_keys.append(key)
        elif record.get("raw") != prior_by_key[key].get("raw"):
            changed_keys.append(key)
    return mirror_new_keys, changed_keys


def _catalog_fields(records: list[dict[str, Any]], source_url: str) -> dict[str, Any]:
    return {
        "source": source_url,
        "source_version": records[0].get("source_version") if records else None,
        "bugs": [
            {
                "key": record["key"],
                "title": record.get("title", ""),
                "bug_url": record.get("bug_url", ""),
                "json_url": record.get("json_url", ""),
                "fix_commits": record.get("fix_commits", []),
                "primary_fix_hash": record.get("primary_fix_hash", ""),
            }
            for record in records
        ],
    }


def write_catalog(
    paths: DataPaths,
    records: list[dict[str, Any]],
    source_url: str,
    inventory: FileInventory | None = None,
) -> bool:
    """Write changed semantic content while preserving a stable generation time."""

    fields = _catalog_fields(records, source_url)
    try:
        current = decode_json_object(
            inventory.read_bytes(paths.catalog)
            if inventory is not None
            else paths.catalog.read_bytes()
        )
    except (OSError, PayloadError):
        current = {}
    if isinstance(current.get("generated_at"), str) and all(
        current.get(name) == value for name, value in fields.items()
    ):
        return False

    payload = {"generated_at": datetime.now(timezone.utc).isoformat(), **fields}
    encoded = (json.dumps(payload, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    atomic_write(paths.catalog, encoded)
    if inventory is not None:
        inventory.verify_saved(paths.catalog, encoded, parsed=payload)
    return True
