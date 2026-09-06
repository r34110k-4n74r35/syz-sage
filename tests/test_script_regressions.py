from __future__ import annotations

import argparse
import contextlib
import io
import json
import shutil
import sys
import unittest
from concurrent.futures import CancelledError
from pathlib import Path
from unittest import mock

from scripts import analyze_fixed_bugs, audit_snapshot, resolve_title_only_fixes
from syz_sage.storage import temporary_directory

FIXTURES = Path(__file__).resolve().parent / "fixtures/legacy_data"
ALPHA = "extid-alpha123"
ALPHA_HASH = "a" * 40
BETA_HASH = "b" * 40
TORVALDS = "git://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git"
STABLE = "git://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git"


class ResearchScriptRegressions(unittest.TestCase):
    def setUp(self) -> None:
        temporary = temporary_directory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.data = self.root / "data"
        shutil.copytree(FIXTURES, self.data)
        self.catalog_path = self.data / "processed/catalog.json"
        self.resolution_path = self.data / "processed/resolved_fix_hashes.json"
        self.alpha_path = self.data / "raw/bugs" / f"{ALPHA}.json"

    @staticmethod
    def read_json(path: Path) -> dict:
        return json.loads(path.read_bytes())

    @staticmethod
    def write_json(path: Path, payload: dict) -> None:
        path.write_text(json.dumps(payload))

    def analyze(self) -> dict:
        with (
            mock.patch.object(
                sys,
                "argv",
                [
                    "analyzer",
                    "--root",
                    str(self.root),
                    "--output",
                    str(self.root / "analysis.json"),
                ],
            ),
            mock.patch.object(analyze_fixed_bugs, "write_text") as write,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            analyze_fixed_bugs.main()
        self.assertFalse((self.root / "analysis.json").exists())
        return json.loads(write.call_args.args[1])

    def add_patch(self, commit_hash: str) -> None:
        patches = self.data / "artifacts/patches"
        shutil.copyfile(patches / f"{ALPHA_HASH}.diff", patches / f"{commit_hash}.diff")

    def repository_scoped_fixes(self) -> list[dict]:
        fixes = [{"title": "same fix title", "repo": repo} for repo in (TORVALDS, STABLE)]
        detail = self.read_json(self.alpha_path)
        detail["fix-commits"] = fixes
        self.write_json(self.alpha_path, detail)
        catalog = self.read_json(self.catalog_path)
        catalog["bugs"][0]["fix_commits"] = fixes
        catalog["bugs"][0]["primary_fix_hash"] = ""
        self.write_json(self.catalog_path, catalog)
        resolutions = [
            {
                **fix,
                "bug_key": ALPHA,
                "status": "resolved",
                "hash": commit_hash,
                "commit_url": repo.replace("git://", "https://") + f"/commit/?id={commit_hash}",
            }
            for fix, repo, commit_hash in zip(
                fixes, (TORVALDS, STABLE), (ALPHA_HASH, BETA_HASH), strict=True
            )
        ]
        self.write_json(self.resolution_path, {"resolutions": resolutions})
        self.add_patch(BETA_HASH)
        return resolutions

    def test_resolutions_match_repository_in_analysis_and_missing_detail_manifest(self) -> None:
        resolutions = self.repository_scoped_fixes()
        result = self.analyze()
        alpha = next(row for row in result["bugs"] if row["bug_key"] == ALPHA)
        self.assertEqual(alpha["fix_hashes"].split("; "), [ALPHA_HASH, BETA_HASH])
        self.assertEqual(alpha["fix_commit_count"], 2)
        self.assertEqual(
            alpha["fix_commit_urls"].split("; "), [record["commit_url"] for record in resolutions]
        )
        self.alpha_path.unlink()
        result = self.analyze()
        alpha = next(row for row in result["manifest"] if row["bug_key"] == ALPHA)
        self.assertEqual(alpha["fix_commits_with_hash"], 2)
        self.assertEqual(alpha["patches_available"], 2)
        self.assertFalse(alpha["included"])
        self.assertIn("bug JSON unavailable", alpha["exclusion_reason"])

    def test_retained_bugs_outside_catalog_do_not_enter_current_cohort(self) -> None:
        catalog = self.read_json(self.catalog_path)
        catalog["bugs"] = catalog["bugs"][1:]
        self.write_json(self.catalog_path, catalog)
        result = self.analyze()
        self.assertEqual(result["bugs"], [])
        self.assertEqual([row["bug_key"] for row in result["manifest"]], ["id-beta456"])
        self.assertEqual(result["completeness"]["live_fixed_listing"], 1)
        self.assertEqual(result["completeness"]["local_bug_json"], 1)
        self.assertTrue(self.alpha_path.exists())
        self.assertTrue((self.data / "artifacts/patches" / f"{ALPHA_HASH}.diff").exists())

    def test_empty_catalog_does_not_fall_back_to_retained_raw_files(self) -> None:
        self.write_json(self.catalog_path, {"bugs": []})
        result = self.analyze()
        self.assertEqual(result["manifest"], [])
        self.assertEqual(result["bugs"], [])
        self.assertEqual(result["completeness"]["live_fixed_listing"], 0)

    def test_missing_catalog_cannot_claim_a_current_cohort(self) -> None:
        self.catalog_path.unlink()
        errors = io.StringIO()
        with contextlib.redirect_stderr(errors), self.assertRaises(SystemExit) as raised:
            self.analyze()
        self.assertEqual(raised.exception.code, 2)
        self.assertIn("current catalog is required", errors.getvalue())

    def test_listing_only_fix_is_included_when_detail_has_no_fix(self) -> None:
        detail = self.read_json(self.alpha_path)
        detail["fix-commits"] = []
        self.write_json(self.alpha_path, detail)
        result = self.analyze()
        alpha = next(row for row in result["bugs"] if row["bug_key"] == ALPHA)
        self.assertEqual(alpha["fix_hashes"], ALPHA_HASH)
        self.assertEqual(alpha["fix_commit_count"], 1)

    def test_fix_union_keeps_extra_listing_patch_without_double_counting_shared_patch(self) -> None:
        baseline = self.analyze()["bugs"][0]
        catalog = self.read_json(self.catalog_path)
        catalog["bugs"][0]["fix_commits"].append(
            {"title": "another listing fix", "hash": BETA_HASH, "repo": STABLE}
        )
        self.write_json(self.catalog_path, catalog)
        self.add_patch(BETA_HASH)
        result = self.analyze()
        alpha = next(row for row in result["bugs"] if row["bug_key"] == ALPHA)
        self.assertEqual(alpha["fix_hashes"].split("; "), [ALPHA_HASH, BETA_HASH])
        self.assertEqual(alpha["fix_commit_count"], 2)
        self.assertEqual(alpha["fix_hunk_count"], baseline["fix_hunk_count"] * 2)
        detail = self.read_json(self.alpha_path)
        self.assertEqual(alpha["fix_commit_urls"].split("; ")[0], detail["fix-commits"][0]["link"])

    def test_audit_distinguishes_repository_resolutions_and_preserves_partial_coverage(
        self,
    ) -> None:
        resolutions = self.repository_scoped_fixes()
        result = audit_snapshot.audit(self.root)
        self.assertEqual(result["fixes"]["duplicate_resolution_identities"], [])
        self.assertEqual(result["fixes"]["orphan_resolutions"], [])
        self.assertEqual(result["fixes"]["identities_with_multiple_hashes"], [])
        self.write_json(self.resolution_path, {"resolutions": resolutions[:1]})
        result = audit_snapshot.audit(self.root)
        unresolved = [
            row for row in result["fixes"]["unresolved_title_only"] if row["bug_key"] == ALPHA
        ]
        self.assertEqual([row["repo"] for row in unresolved], [STABLE])
        self.assertFalse(unresolved[0]["resolution_record_present"])
        coverage = result["bug_fix_coverage"][
            "current_catalog_bugs_with_partial_fix_identity_coverage"
        ]
        self.assertIn(ALPHA, coverage["bugs"])

    def test_audit_still_detects_duplicate_resolution_in_same_repository(self) -> None:
        resolutions = self.repository_scoped_fixes()
        self.write_json(self.resolution_path, {"resolutions": resolutions + resolutions[:1]})
        result = audit_snapshot.audit(self.root)
        self.assertEqual(
            result["fixes"]["duplicate_resolution_identities"],
            [{"bug_key": ALPHA, "title": "same fix title", "repo": TORVALDS, "count": 2}],
        )

    def run_resolver(self, previous: dict, result: dict) -> tuple[dict, str]:
        self.write_json(self.resolution_path, {"resolutions": [previous]})
        output = io.StringIO()
        with (
            mock.patch.object(resolve_title_only_fixes, "OUTPUT", self.resolution_path),
            mock.patch.object(resolve_title_only_fixes, "load_jobs", return_value=[(ALPHA, {})]),
            mock.patch.object(resolve_title_only_fixes, "resolve_one", return_value=result),
            contextlib.redirect_stdout(output),
        ):
            resolve_title_only_fixes._run(argparse.Namespace(limit=None, workers=1))
        return self.read_json(self.resolution_path)["resolutions"][0], output.getvalue()

    def test_failed_refresh_preserves_previous_successful_resolution(self) -> None:
        previous = {
            "bug_key": ALPHA,
            "title": "fix alpha",
            "repo": TORVALDS,
            "status": "resolved",
            "hash": ALPHA_HASH,
            "commit_url": "saved URL",
        }
        failed = {
            key: value for key, value in previous.items() if key not in {"hash", "commit_url"}
        }
        failed.update(status="unresolved", reason="search failed: timeout")
        result, output = self.run_resolver(previous, failed)
        self.assertEqual(result, previous)
        self.assertIn('"preserved_previous_resolutions": 1', output)
        self.assertIn('"resolved_this_run": 0', output)

    def test_successful_refresh_can_replace_previous_resolution(self) -> None:
        previous = {
            "bug_key": ALPHA,
            "title": "fix alpha",
            "repo": TORVALDS,
            "status": "resolved",
            "hash": ALPHA_HASH,
        }
        current = {**previous, "hash": BETA_HASH}
        result, output = self.run_resolver(previous, current)
        self.assertEqual(result, current)
        self.assertIn('"preserved_previous_resolutions": 0', output)

    def test_failed_refresh_does_not_preserve_malformed_prior_hash(self) -> None:
        previous = {
            "bug_key": ALPHA,
            "title": "fix alpha",
            "repo": TORVALDS,
            "status": "resolved",
            "hash": "invalid",
        }
        failed = {
            "bug_key": ALPHA,
            "title": "fix alpha",
            "repo": TORVALDS,
            "status": "unresolved",
            "reason": "search failed: timeout",
        }
        result, _ = self.run_resolver(previous, failed)
        self.assertEqual(result, failed)

    def test_resolver_resets_cancellation_and_propagates_interrupt(self) -> None:
        before = self.resolution_path.read_bytes()
        client = mock.Mock()
        with (
            mock.patch.object(resolve_title_only_fixes, "OUTPUT", self.resolution_path),
            mock.patch.object(resolve_title_only_fixes, "CLIENT", client),
            mock.patch.object(resolve_title_only_fixes, "load_jobs", return_value=[(ALPHA, {})]),
            mock.patch.object(
                resolve_title_only_fixes, "bounded_results", side_effect=KeyboardInterrupt
            ) as results,
            contextlib.redirect_stdout(io.StringIO()),
            self.assertRaises(KeyboardInterrupt),
        ):
            resolve_title_only_fixes._run(argparse.Namespace(limit=None, workers=1))
        client.reset_cancellation.assert_called_once_with()
        self.assertEqual(results.call_args.kwargs["cancel"], client.cancel)
        self.assertEqual(self.resolution_path.read_bytes(), before)

    def test_cancelled_title_search_does_not_become_an_unresolved_result(self) -> None:
        with (
            mock.patch.object(resolve_title_only_fixes, "http_get", side_effect=CancelledError),
            self.assertRaises(CancelledError),
        ):
            resolve_title_only_fixes.resolve_one(ALPHA, {"title": "fix alpha", "repo": TORVALDS})


if __name__ == "__main__":
    unittest.main()
