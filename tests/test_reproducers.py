from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import shutil
import unittest
from pathlib import Path
from unittest import mock

from syz_sage.cli import main
from syz_sage.database import SCHEMA_VERSION, Database, _c_reproducer_fields
from syz_sage.storage import temporary_directory

FIXTURES = Path(__file__).parent / "fixtures" / "legacy_data"
DASHBOARD = "https://syzkaller.appspot.com"
C_URL = f"{DASHBOARD}/text?tag=ReproC&x=alpha"


class CReproducerTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = temporary_directory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.mirror = self.root / "data"
        shutil.copytree(FIXTURES, self.mirror)
        self.path = self.root / "database.sqlite3"
        self.alpha_path = self.mirror / "raw/bugs/extid-alpha123.json"
        self.alpha = json.loads(self.alpha_path.read_bytes())

    def save_alpha(self) -> None:
        self.alpha_path.write_text(json.dumps(self.alpha))

    def import_mirror(self, **kwargs) -> dict:
        with Database(self.path) as database:
            return database.ingest_files(self.mirror, **kwargs)

    def get_alpha(self) -> dict:
        with Database(self.path, read_only=True) as database:
            return database.get_bug("extid-alpha123")

    def invoke(self, *args: str) -> tuple[int, str]:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(["--database", str(self.path), "show", "extid-alpha123", *args])
        return code, output.getvalue()

    def test_existing_persisted_links_work_without_network_or_schema_change(self) -> None:
        self.assertEqual(self.import_mirror()["status"], "completed")
        before = hashlib.sha256(self.path.read_bytes()).hexdigest()
        modified = self.path.stat().st_mtime_ns
        # Inspection must work solely from SQLite, even without the mirror.
        shutil.rmtree(self.mirror)
        with mock.patch(
            "syz_sage.client.SyzbotClient.get", side_effect=AssertionError("no network")
        ):
            bug = self.get_alpha()
            code, text = self.invoke()
            json_code, output = self.invoke("--json")
        self.assertEqual((code, json_code), (0, 0))
        self.assertEqual(bug["c_reproducer_status"], "available")
        self.assertEqual(bug["c_reproducer_urls"], [C_URL])
        self.assertEqual(bug["crashes"][0]["c_reproducer_url"], C_URL)
        self.assertIn("available (URL recorded)", text)
        self.assertIn(C_URL, text)
        self.assertEqual(json.loads(output)["c_reproducer_urls"], [C_URL])
        self.assertNotIn("\x1b[", output)
        with Database(self.path, read_only=True) as database:
            self.assertEqual(
                database.connection.execute("PRAGMA user_version").fetchone()[0], SCHEMA_VERSION
            )
        self.assertEqual(hashlib.sha256(self.path.read_bytes()).hexdigest(), before)
        self.assertEqual(self.path.stat().st_mtime_ns, modified)

    def test_all_crashes_contribute_unique_urls_in_metadata_order(self) -> None:
        self.alpha["crashes"][0].pop("c-reproducer")
        self.alpha["crashes"].extend(
            {"title": "another crash", "c-reproducer": value}
            for value in (
                "/text?tag=ReproC&x=second",
                f"{DASHBOARD}/text?tag=ReproC&x=second",
                "/text?tag=ReproC&x=third",
            )
        )
        self.save_alpha()
        self.assertEqual(self.import_mirror()["status"], "completed")
        bug = self.get_alpha()
        self.assertEqual(bug["c_reproducer_status"], "available")
        self.assertEqual(
            bug["c_reproducer_urls"],
            [
                f"{DASHBOARD}/text?tag=ReproC&x=second",
                f"{DASHBOARD}/text?tag=ReproC&x=third",
            ],
        )

    def test_missing_and_invalid_c_links_are_not_mistaken_for_available(self) -> None:
        for value, expected in (
            (None, "not_provided"),
            ("", "not_provided"),
            (False, "unknown"),
            (42, "unknown"),
            ([], "unknown"),
            ("   ", "unknown"),
            ("javascript:alert(1)", "unknown"),
            ("https://elsewhere.invalid/repro.c", "unknown"),
        ):
            with self.subTest(value=value):
                self.alpha["crashes"][0]["c-reproducer"] = value
                self.save_alpha()
                self.assertEqual(self.import_mirror()["status"], "completed")
                bug = self.get_alpha()
                self.assertEqual(bug["c_reproducer_status"], expected)
                self.assertEqual(bug["c_reproducer_urls"], [])
        # A syz reproducer by itself does not imply C reproducer availability.
        self.alpha["crashes"][0].pop("c-reproducer")
        self.save_alpha()
        self.import_mirror()
        self.assertEqual(self.get_alpha()["c_reproducer_status"], "not_provided")
        self.assertIn("not provided in saved crash metadata", self.invoke()[1])

    def test_missing_crash_metadata_differs_from_explicit_empty_list(self) -> None:
        self.alpha.pop("crashes")
        self.save_alpha()
        self.assertEqual(self.import_mirror()["status"], "completed")
        self.assertEqual(self.get_alpha()["c_reproducer_status"], "unknown")
        self.assertIn("unknown (metadata missing or invalid)", self.invoke()[1])
        self.alpha["crashes"] = []
        self.save_alpha()
        self.assertEqual(self.import_mirror()["status"], "completed")
        self.assertEqual(self.get_alpha()["c_reproducer_status"], "not_provided")

    def test_partial_refresh_does_not_change_active_reproducer_status(self) -> None:
        self.import_mirror()
        self.alpha["crashes"][0].pop("c-reproducer")
        self.save_alpha()
        partial = self.import_mirror(errors=["planned incomplete refresh"])
        self.assertEqual(partial["status"], "partial")
        self.assertEqual(self.get_alpha()["c_reproducer_urls"], [C_URL])
        self.assertEqual(self.import_mirror()["status"], "completed")
        bug = self.get_alpha()
        self.assertEqual(bug["c_reproducer_status"], "not_provided")
        self.assertEqual(bug["c_reproducer_urls"], [])
        with Database(self.path, read_only=True) as database:
            self.assertEqual(
                database.connection.execute(
                    "SELECT COUNT(*) FROM crashes WHERE c_reproducer_url = ?",
                    (C_URL,),
                ).fetchone()[0],
                1,
            )

    def test_console_limits_urls_and_json_retains_every_link(self) -> None:
        self.alpha["crashes"].extend(
            {"title": "another crash", "c-reproducer": f"/text?tag=ReproC&x=extra{index}"}
            for index in range(4)
        )
        self.save_alpha()
        self.import_mirror()
        _, text = self.invoke()
        self.assertIn("2 more C reproducer URLs; use --json to display all.", text)
        self.assertNotIn("extra3", text)
        _, output = self.invoke("--json")
        self.assertEqual(len(json.loads(output)["c_reproducer_urls"]), 5)

    def test_status_and_url_have_semantic_terminal_colors(self) -> None:
        self.import_mirror()
        output = io.StringIO()
        with (
            contextlib.redirect_stdout(output),
            mock.patch.object(output, "isatty", return_value=True),
            mock.patch.dict(os.environ, {"TERM": "xterm"}, clear=True),
        ):
            code = main(["--database", str(self.path), "show", "extid-alpha123"])
        self.assertEqual(code, 0)
        self.assertIn("\x1b[32mavailable (URL recorded)\x1b[0m", output.getvalue())
        self.assertIn("\x1b[4;34m", output.getvalue())

    def test_unknown_sources_and_custom_dashboard_resolution(self) -> None:
        for raw, kind in ((None, "bug-json"), ({"crashes": []}, "listing-record")):
            self.assertEqual(
                _c_reproducer_fields(raw, kind, DASHBOARD),
                {
                    "c_reproducer_status": "unknown",
                    "c_reproducer_urls": [],
                },
            )
        result = _c_reproducer_fields(
            {
                "crashes": [
                    {"c-reproducer": 42},
                    {"c-reproducer": "/text?tag=ReproC&x=custom"},
                ]
            },
            "bug-json",
            "https://mirror.invalid/syzbot",
        )
        self.assertEqual(
            result,
            {
                "c_reproducer_status": "available",
                "c_reproducer_urls": ["https://mirror.invalid/syzbot/text?tag=ReproC&x=custom"],
            },
        )


if __name__ == "__main__":
    unittest.main()
