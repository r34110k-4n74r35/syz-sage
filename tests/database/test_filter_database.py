from __future__ import annotations

import html
import json
import shutil
import unittest
from pathlib import Path
from unittest import mock

from syz_sage.database import Database
from syz_sage.project.storage import temporary_directory
from tests.support import ALPHA_HASH, BETA_HASH, FIXTURES


class FilterDatabaseTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = temporary_directory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.data = self.root / "data"
        self.path = self.root / "store.sqlite3"
        shutil.copytree(FIXTURES, self.data)
        self.listing_path = self.data / "raw/upstream_fixed.json"
        self.catalog_path = self.data / "processed/catalog.json"
        self.listing = json.loads(self.listing_path.read_bytes())
        self.catalog = json.loads(self.catalog_path.read_bytes())
        self.tags = {
            "extid-alpha123": ["net", "mm"],
            "id-beta456": ["fs", "ext4"],
            "id-gamma": ["ext4"],
            "id-delta": ["net", "Net"],
            "id-epsilon": [],
        }
        for name, title in (
            ("gamma", "KASAN: use-after-free in gamma"),
            ("delta", "INFO: 100% ready_under_score"),
            ("epsilon", "BUG: unable to handle page fault"),
        ):
            key = f"id-{name}"
            link = f"/bug?id={name}"
            self.listing["Bugs"].append({"title": title, "link": link, "fix-commits": []})
            self.catalog["bugs"].append(
                {
                    "key": key,
                    "title": title,
                    "bug_url": f"https://syzkaller.appspot.com{link}",
                    "json_url": f"https://syzkaller.appspot.com{link}&json=1",
                    "fix_commits": [],
                }
            )
            (self.data / "raw/bugs" / f"{key}.json").write_text(
                json.dumps({"title": title, "crashes": [], "status": ""})
            )
        self.save_metadata()

    def save_metadata(self) -> None:
        self.listing_path.write_text(json.dumps(self.listing))
        self.catalog_path.write_text(json.dumps(self.catalog))
        rows = []
        for record in self.catalog["bugs"]:
            labels = "".join(
                f'<a href="/upstream/fixed?label=subsystems%3A{html.escape(tag)}">{tag}</a>'
                for tag in self.tags[record["key"]]
            )
            rows.append(f'<tr><td><a href="{record["bug_url"]}">bug</a>{labels}</td></tr>')
        (self.data / "raw/upstream_fixed.html").write_text(
            "<!doctype html><html><body><table>" + "".join(rows) + "</table></body></html>"
        )

    def import_data(self, database: Database) -> dict:
        result = database.ingest_files(self.data)
        self.assertEqual(result["status"], "completed", result)
        return result

    def set_alpha_fixes(self, fixes: list[dict]) -> None:
        self.listing["Bugs"][0]["fix-commits"] = fixes
        self.catalog["bugs"][0]["fix_commits"] = fixes
        path = self.data / "raw/bugs/extid-alpha123.json"
        payload = json.loads(path.read_bytes())
        payload["fix-commits"] = fixes
        path.write_text(json.dumps(payload))
        self.save_metadata()

    @staticmethod
    def keys(result: dict) -> list[str]:
        return [bug["key"] for bug in result["bugs"]]

    def test_filters_or_within_categories_and_and_between_categories(self) -> None:
        with Database(self.path) as database:
            self.import_data(database)
            result = database.filter_bugs(
                bug_types=[" KASAN ", "info", "kasan"], subsystems=[" NET ", "net"]
            )
            self.assertEqual(self.keys(result), ["extid-alpha123", "id-delta"])
            self.assertEqual(result["bug_types"], ["kasan", "info"])
            self.assertEqual(result["subsystems"], ["net"])
            result = database.filter_bugs(bug_types=["kasan"], subsystems=["fs", "ext4"])
            self.assertEqual(self.keys(result), ["id-gamma"])
            self.assertEqual(result["bugs"][0]["status"], "")
            self.assertEqual(self.keys(database.filter_bugs(subsystems=["FS"])), ["id-beta456"])
            self.assertEqual(
                database.filter_bugs(bug_types=["kasan"], subsystems=["fs"])["total"], 0
            )

    def test_page_count_and_enrichment_only_apply_to_selected_rows(self) -> None:
        with Database(self.path) as database:
            self.import_data(database)
            with (
                mock.patch.object(
                    database, "_effective_fixes", wraps=database._effective_fixes
                ) as fixes,
                mock.patch.object(
                    database, "_load_json_blob", wraps=database._load_json_blob
                ) as payloads,
            ):
                result = database.filter_bugs(bug_types=["kasan"], limit=1, offset=1)
            self.assertEqual(result["total"], 2)
            self.assertEqual((result["limit"], result["offset"]), (1, 1))
            self.assertEqual(self.keys(result), ["id-gamma"])
            self.assertEqual(fixes.call_count, 1)
            self.assertEqual(payloads.call_count, 1)
            all_remaining = database.filter_bugs(limit=None, offset=2)
            self.assertEqual(all_remaining["total"], 5)
            self.assertEqual(self.keys(all_remaining), ["id-gamma", "id-delta", "id-epsilon"])
            empty_page = database.filter_bugs(limit=0)
            self.assertEqual((empty_page["total"], empty_page["bugs"]), (5, []))

    def test_filter_values_count_distinct_bugs_for_case_variants(self) -> None:
        with Database(self.path) as database:
            self.import_data(database)
            values = database.filter_values()
        self.assertEqual(
            values["bug_types"],
            [
                {"value": kind, "count": count}
                for kind, count in (("bug", 1), ("info", 1), ("kasan", 2), ("warning", 1))
            ],
        )
        self.assertEqual(
            values["subsystems"],
            [
                {"value": tag, "count": count}
                for tag, count in (("ext4", 2), ("fs", 1), ("mm", 1), ("net", 2))
            ],
        )

    def test_filter_query_uses_literal_parameterized_key_or_title_substrings(self) -> None:
        with Database(self.path) as database:
            self.import_data(database)
            for query in ("%", "_", "DELTA"):
                self.assertEqual(self.keys(database.filter_bugs(query=query)), ["id-delta"])
            self.assertEqual(database.filter_bugs(query="' OR 1=1 --")["total"], 0)
            self.assertEqual(database.filter_bugs(subsystems=["net')OR(1=1)--"])["total"], 0)
            self.assertEqual(database.filter_bugs(bug_types=["kasan"], query="beta")["total"], 0)

    def test_type_follows_snapshot_title_and_partial_candidate_stays_inactive(self) -> None:
        with Database(self.path) as database:
            first = self.import_data(database)
            self.listing["Bugs"][0]["title"] = "INFO: renamed alpha"
            self.catalog["bugs"][0]["title"] = "INFO: renamed alpha"
            self.save_metadata()
            partial = database.ingest_files(self.data, errors=["planned incomplete candidate"])
            self.assertEqual(partial["status"], "partial")
            self.assertEqual(database.get_bug("extid-alpha123")["bug_type"], "kasan")
            complete = self.import_data(database)
            current = database.get_bug("extid-alpha123")
            self.assertEqual(
                (current["bug_type"], current["title"]), ("info", "INFO: renamed alpha")
            )
            self.assertEqual(current["raw"]["title"], "KASAN: use-after-free in alpha")
            self.assertEqual(
                database.connection.execute(
                    "SELECT bug_type FROM snapshot_bugs WHERE snapshot_id=? AND position=0",
                    (first["snapshot_id"],),
                ).fetchone()[0],
                "kasan",
            )
            self.assertNotEqual(first["snapshot_id"], complete["snapshot_id"])
            self.assertEqual(database.list_bugs()[0]["bug_type"], "info")

    def test_removed_bugs_remain_history_but_disappear_from_filters_and_values(self) -> None:
        with Database(self.path) as database:
            self.import_data(database)
            self.listing["Bugs"].pop(2)
            self.catalog["bugs"].pop(2)
            self.save_metadata()
            self.import_data(database)
            self.assertEqual(
                self.keys(database.filter_bugs(bug_types=["kasan"])), ["extid-alpha123"]
            )
            self.assertEqual(database.filter_bugs()["total"], 4)
            self.assertIn({"value": "ext4", "count": 1}, database.filter_values()["subsystems"])
            self.assertEqual(
                database.connection.execute("SELECT COUNT(*) FROM bugs").fetchone()[0], 5
            )

    def test_invalid_filters_are_rejected_and_unknown_tags_match_nothing(self) -> None:
        with Database(self.path) as database:
            self.import_data(database)
            for arguments in (
                {"bug_types": ["not-a-type"]},
                {"bug_types": [""]},
                {"bug_types": "kasan"},
                {"subsystems": [" "]},
                {"subsystems": ["net\x1b"]},
                {"subsystems": ["net core"]},
                {"limit": -1},
                {"limit": 1.5},
                {"limit": True},
                {"offset": -1},
            ):
                with self.subTest(arguments=arguments), self.assertRaises(ValueError):
                    database.filter_bugs(**arguments)
            self.assertEqual(database.filter_bugs(subsystems=["unknown-tag"])["total"], 0)

    def test_read_only_filters_preserve_database_and_match_list_rows(self) -> None:
        with Database(self.path) as database:
            self.import_data(database)
        before = self.path.read_bytes(), self.path.stat().st_mtime_ns
        with Database(self.path, read_only=True) as database:
            result = database.filter_bugs()
            self.assertEqual(result["bugs"], database.list_bugs())
            first = result["bugs"][0]
            self.assertEqual(first["bug_url"], "https://syzkaller.appspot.com/bug?extid=alpha123")
            self.assertEqual(
                (first["fix_count"], first["crash_count"], first["has_report"]), (1, 1, True)
            )
            self.assertEqual(first["subsystems"], ["mm", "net"])
            self.assertTrue(first["fix_time"])
            database.filter_values()
        self.assertEqual((self.path.read_bytes(), self.path.stat().st_mtime_ns), before)

    def test_patch_urls_use_snapshot_source_and_exclude_orphan_artifacts(self) -> None:
        patch = self.data / "artifacts/patches" / f"{ALPHA_HASH}.diff"
        orphan = patch.with_name(f"{BETA_HASH}.diff")
        orphan.write_bytes(patch.read_bytes())
        captured = "https://patch.example/actual-alpha.diff"
        with Database(self.path) as database:
            result = database.ingest_files(
                self.data,
                source_urls={patch: captured, orphan: "https://patch.example/orphan.diff"},
            )
            self.assertEqual(result["status"], "completed", result)
            database.connection.execute(
                "UPDATE patches SET source_url='https://patch.example/global'"
            )
            database.connection.execute(
                "UPDATE patch_versions SET source_url='https://patch.example/first'"
            )
            rows = database.filter_bugs()["bugs"]
            self.assertEqual(rows[0]["patch_urls"], [captured])
            self.assertTrue(all(not row["patch_urls"] for row in rows[1:]))
            self.assertEqual(
                database.connection.execute("SELECT COUNT(*) FROM snapshot_patches").fetchone()[0],
                2,
            )

    def test_patch_urls_fall_back_to_fix_link_and_skip_invalid_or_missing_links(self) -> None:
        fallback = f"https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id={ALPHA_HASH}"
        with Database(self.path) as database:
            self.import_data(database)
            for source in (
                "",
                "javascript:alert(1)",
                "https://[broken",
                "https://host.invalid/has space",
            ):
                database.connection.execute("UPDATE snapshot_patches SET source_url=?", (source,))
                self.assertEqual(database.filter_bugs()["bugs"][0]["patch_urls"], [fallback])
            for link in ("", "file:///tmp/fix.patch", "https://[broken"):
                database.connection.execute("UPDATE fix_commits SET link=?", (link,))
                database.connection.execute("UPDATE listing_fix_commits SET link=?", (link,))
                self.assertEqual(database.filter_bugs()["bugs"][0]["patch_urls"], [])

    def test_title_only_fix_link_is_returned_without_saved_patch(self) -> None:
        link = "https://commits.example/fix/alpha"
        self.set_alpha_fixes([{"title": "fix alpha", "link": link}])
        (self.data / "artifacts/patches" / f"{ALPHA_HASH}.diff").unlink()
        with Database(self.path) as database:
            self.import_data(database)
            row = database.filter_bugs()["bugs"][0]
            self.assertEqual(row["patch_urls"], [link])
            self.assertEqual(
                database.connection.execute("SELECT COUNT(*) FROM snapshot_patches").fetchone()[0],
                0,
            )
            self.assertFalse(database.get_bug("extid-alpha123")["fixes"][0]["patch_available"])

    def test_resolved_fix_uses_recorded_resolution_patch_url(self) -> None:
        link = f"https://commits.example/beta/{BETA_HASH}"
        path = self.data / "processed/resolved_fix_hashes.json"
        payload = json.loads(path.read_bytes())
        payload["resolutions"][0].update(status="resolved", hash=BETA_HASH, commit_url=link)
        path.write_text(json.dumps(payload))
        patches = self.data / "artifacts/patches"
        (patches / f"{BETA_HASH}.diff").write_bytes((patches / f"{ALPHA_HASH}.diff").read_bytes())
        with Database(self.path) as database:
            self.import_data(database)
            row = database.filter_bugs(query="id-beta456")["bugs"][0]
            self.assertEqual(row["patch_urls"], [link])
            self.assertEqual(database.get_bug("id-beta456")["fixes"][0]["resolved_hash"], BETA_HASH)

    def test_multiple_fix_hashes_keep_order_and_duplicate_urls_are_removed(self) -> None:
        first, second = "https://patch.example/first.diff", "https://patch.example/second.diff"
        self.set_alpha_fixes(
            [
                {"title": "same subject", "hash": BETA_HASH, "repo": "repo"},
                {"title": "same subject", "hash": ALPHA_HASH, "repo": "repo"},
                {"title": "another reference", "link": second},
            ]
        )
        patches = self.data / "artifacts/patches"
        alpha, beta = patches / f"{ALPHA_HASH}.diff", patches / f"{BETA_HASH}.diff"
        beta.write_bytes(alpha.read_bytes())
        with Database(self.path) as database:
            result = database.ingest_files(self.data, source_urls={beta: first, alpha: second})
            self.assertEqual(result["status"], "completed", result)
            row = database.filter_bugs()["bugs"][0]
            self.assertEqual(row["patch_urls"], [first, second])
            self.assertEqual(row["fix_count"], 3)

    def test_c_reproducer_fields_match_show_across_all_crashes_and_unknown_metadata(self) -> None:
        path = self.data / "raw/bugs/extid-alpha123.json"
        payload = json.loads(path.read_bytes())
        payload["crashes"].extend(
            [
                {"c-reproducer": "/text?tag=ReproC&x=second"},
                {"c-reproducer": "/text?tag=ReproC&x=alpha"},
            ]
        )
        path.write_text(json.dumps(payload))
        path = self.data / "raw/bugs/id-delta.json"
        payload = json.loads(path.read_bytes())
        payload.pop("crashes")
        path.write_text(json.dumps(payload))
        path = self.data / "raw/bugs/id-epsilon.json"
        payload = json.loads(path.read_bytes())
        payload["crashes"] = [{"c-reproducer": True}]
        path.write_text(json.dumps(payload))
        with Database(self.path) as database:
            self.import_data(database)
            rows = database.filter_bugs()["bugs"]
            for row in rows:
                shown = database.get_bug(row["key"])
                for field in ("c_reproducer_status", "c_reproducer_urls"):
                    self.assertEqual(row[field], shown[field])
            self.assertEqual(rows[0]["c_reproducer_status"], "available")
            self.assertEqual(
                rows[0]["c_reproducer_urls"],
                [
                    "https://syzkaller.appspot.com/text?tag=ReproC&x=alpha",
                    "https://syzkaller.appspot.com/text?tag=ReproC&x=second",
                ],
            )
            self.assertEqual(rows[2]["c_reproducer_status"], "not_provided")
            self.assertEqual(rows[3]["c_reproducer_status"], "unknown")
            self.assertEqual(rows[4]["c_reproducer_status"], "unknown")

    def test_partial_candidate_c_and_patch_urls_cannot_replace_active_snapshot_links(self) -> None:
        patch = self.data / "artifacts/patches" / f"{ALPHA_HASH}.diff"
        old, new = "https://patch.example/old.diff", "https://patch.example/new.diff"
        with Database(self.path) as database:
            first = database.ingest_files(self.data, source_urls={patch: old})
            self.assertEqual(first["status"], "completed", first)
            before = database.filter_bugs()["bugs"][0]
            path = self.data / "raw/bugs/extid-alpha123.json"
            payload = json.loads(path.read_bytes())
            payload["crashes"][0]["c-reproducer"] = "/text?tag=ReproC&x=new"
            path.write_text(json.dumps(payload))
            patch.write_bytes(patch.read_bytes() + b"\nnew patch version metadata\n")
            partial = database.ingest_files(
                self.data, errors=["planned partial"], source_urls={patch: new}
            )
            self.assertEqual(partial["status"], "partial", partial)
            after = database.filter_bugs()["bugs"][0]
            for field in ("patch_urls", "c_reproducer_status", "c_reproducer_urls"):
                self.assertEqual(after[field], before[field])
            self.import_data(database)
            latest = database.filter_bugs()["bugs"][0]
            self.assertEqual(latest["patch_urls"], [new])
            self.assertEqual(
                latest["c_reproducer_urls"], ["https://syzkaller.appspot.com/text?tag=ReproC&x=new"]
            )

    def test_count_page_and_tags_share_snapshot_while_updater_commits(self) -> None:
        with Database(self.path) as writer:
            self.import_data(writer)
            self.assertEqual(writer.connection.execute("PRAGMA journal_mode").fetchone()[0], "wal")
            with Database(self.path, read_only=True) as reader:
                original = reader._list_filtered_rows

                def activate_after_count(*args: object) -> list[dict]:
                    self.listing["Bugs"].pop(2)
                    self.catalog["bugs"].pop(2)
                    self.tags["extid-alpha123"] = ["usb"]
                    self.save_metadata()
                    self.import_data(writer)
                    return original(*args)

                with mock.patch.object(
                    reader, "_list_filtered_rows", side_effect=activate_after_count
                ):
                    result = reader.filter_bugs()
                self.assertEqual(result["total"], 5)
                self.assertEqual(len(result["bugs"]), 5)
                self.assertEqual(result["bugs"][0]["subsystems"], ["mm", "net"])
                self.assertIn("id-gamma", self.keys(result))
                latest = reader.filter_bugs()
                self.assertEqual(latest["total"], 4)
                self.assertEqual(latest["bugs"][0]["subsystems"], ["usb"])
                self.assertEqual(reader.connection.total_changes, 0)

    def test_filters_reuse_callers_read_transaction_without_committing_it(self) -> None:
        with Database(self.path) as database:
            self.import_data(database)
            with database._transaction("DEFERRED"):
                self.assertEqual(database.filter_bugs()["total"], 5)
                self.assertEqual(len(database.filter_values()["bug_types"]), 4)
                self.assertTrue(database.connection.in_transaction)

    def test_empty_database_returns_empty_filter_results(self) -> None:
        with Database(self.path) as database:
            self.assertEqual(database.filter_bugs()["total"], 0)
            self.assertEqual(database.filter_bugs()["bugs"], [])
            self.assertEqual(database.filter_values(), {"bug_types": [], "subsystems": []})


if __name__ == "__main__":
    unittest.main()
