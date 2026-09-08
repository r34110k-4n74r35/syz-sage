"""Persist conservative interpretations tied to each snapshot's saved evidence."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import asdict
from typing import Any

from ..parsing.characteristics import classify_characteristics
from ..project.progress_events import ProgressCallback, progress_items
from .records import _c_reproducer_fields, _dashboard_from_bug_url

CLASSIFIER_VERSION = 1


def index_snapshot(
    connection: sqlite3.Connection, snapshot_id: int, *, on_progress: ProgressCallback | None = None
) -> None:
    rows = connection.execute(
        """SELECT sb.bug_id, sb.title, sb.bug_url, sb.listing_record_sha256,
                  bv.payload_kind, bv.raw_sha256, raw.content AS detail, listing.content AS listing,
                  rv.blob_sha256 AS report_sha256, report.content AS report
           FROM snapshot_bugs sb JOIN bug_versions bv ON bv.id=sb.bug_version_id
           JOIN blobs raw ON raw.sha256=bv.raw_sha256
           JOIN blobs listing ON listing.sha256=sb.listing_record_sha256
           LEFT JOIN snapshot_reports sr ON sr.snapshot_id=sb.snapshot_id AND sr.bug_id=sb.bug_id
           LEFT JOIN report_versions rv ON rv.id=sr.report_version_id AND rv.is_valid=1
           LEFT JOIN blobs report ON report.sha256=rv.blob_sha256
           WHERE sb.snapshot_id=? ORDER BY sb.position""",
        (snapshot_id,),
    )
    for row in progress_items(rows, on_progress, "classify-bugs", "Classifying bug evidence"):
        report = (
            bytes(row["report"]).decode("utf-8", errors="replace")
            if row["report"] is not None
            else None
        )
        classification = classify_characteristics(row["title"], report)
        try:
            raw = json.loads(bytes(row["detail"]))
        except (ValueError, UnicodeDecodeError):
            raw = None
        repro = _c_reproducer_fields(
            raw, row["payload_kind"], _dashboard_from_bug_url(row["bug_url"])
        )
        try:
            listing = json.loads(bytes(row["listing"]))
        except (ValueError, UnicodeDecodeError):
            listing = None
        title_sha = (
            row["listing_record_sha256"]
            if isinstance(listing, dict) and listing.get("title") == row["title"]
            else row["raw_sha256"]
            if isinstance(raw, dict) and raw.get("title") == row["title"]
            else None
        )
        evidence: dict[str, Any] = {}
        for key, value in (
            ("family", classification.family),
            ("access_mode", classification.access_mode),
        ):
            evidence[key] = {
                **asdict(value),
                "source_sha256": row["report_sha256"]
                if value.source == "report"
                else title_sha
                if value.source == "title"
                else None,
            }
        connection.execute(
            """INSERT INTO snapshot_bug_characteristics(
               snapshot_id,bug_id,family,access_mode,evidence_json,c_reproducer_status,
               c_reproducer_urls_json,classifier_version
               ) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(snapshot_id,bug_id) DO UPDATE SET
               family=excluded.family, access_mode=excluded.access_mode,
               evidence_json=excluded.evidence_json,c_reproducer_status=excluded.c_reproducer_status,
               c_reproducer_urls_json=excluded.c_reproducer_urls_json,
               classifier_version=excluded.classifier_version""",
            (
                snapshot_id,
                row["bug_id"],
                classification.family.value,
                classification.access_mode.value,
                json.dumps(evidence, sort_keys=True),
                repro["c_reproducer_status"],
                json.dumps(repro["c_reproducer_urls"]),
                CLASSIFIER_VERSION,
            ),
        )


def fields(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    return {
        "family": row["family"],
        "access_mode": row["access_mode"],
        "characteristics": json.loads(row["evidence_json"]),
    }
