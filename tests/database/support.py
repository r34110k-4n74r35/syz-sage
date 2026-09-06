from __future__ import annotations

import json
import shutil
from pathlib import Path

from syz_sage.database import Database
from syz_sage.project.storage import temporary_directory
from tests.support import (
    FIXTURES,
)


class DatabaseFixture:
    """Reusable fixture setup only; concrete tests live in concern modules."""

    def setUp(self) -> None:
        self.temporary = temporary_directory()
        self.root = Path(self.temporary.name)
        self.legacy = self.root / "legacy"
        shutil.copytree(FIXTURES, self.legacy)
        self.database_path = self.root / "store" / "syz-sage.sqlite3"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def import_fixture(self, database: Database) -> object:
        database.initialize()
        return database.import_legacy(self.legacy)

    def direct_inputs(self) -> tuple[dict[str, object], dict[str, bytes]]:
        catalog = json.loads((self.legacy / "processed" / "catalog.json").read_text())
        payloads = {
            path.stem: path.read_bytes() for path in (self.legacy / "raw" / "bugs").glob("*.json")
        }
        return catalog, payloads

    def ingest_direct(
        self,
        database: Database,
        *,
        records: object | None = None,
        listing_json: bytes | None = None,
        listing_html: bytes | None = None,
        errors: tuple[str, ...] = (),
    ) -> dict[str, object]:
        catalog, payloads = self.direct_inputs()
        selected_records = catalog["bugs"] if records is None else records
        return database.ingest_snapshot(
            listing_json=(
                (self.legacy / "raw" / "upstream_fixed.json").read_bytes()
                if listing_json is None
                else listing_json
            ),
            listing_html=(
                (self.legacy / "raw" / "upstream_fixed.html").read_bytes()
                if listing_html is None
                else listing_html
            ),
            records=selected_records,
            bug_payloads=payloads,
            reports_dir=self.legacy / "artifacts" / "reports",
            patches_dir=self.legacy / "artifacts" / "patches",
            source_url=str(catalog["source"]),
            errors=errors,
        )
