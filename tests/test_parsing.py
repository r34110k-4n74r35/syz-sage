from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from syz_sage.parsing import (
    PayloadError,
    absolute_syzbot_url,
    choose_bug_payload,
    key_from_link,
    parse_listing,
    valid_bug_json,
    valid_listing_html,
    valid_patch,
    valid_report,
)

FIXTURE = Path(__file__).parent / "fixtures" / "legacy_data" / "raw" / "upstream_fixed.json"
ALPHA_HASH = "a" * 40


class KeyFromLinkTests(unittest.TestCase):
    def test_extracts_extid_from_relative_link(self) -> None:
        self.assertEqual(key_from_link("/bug?extid=alpha123"), "extid-alpha123")

    def test_extracts_id_from_absolute_link_with_other_parameters(self) -> None:
        link = "https://syzkaller.appspot.com/bug?foo=1&id=beta456&json=1"
        self.assertEqual(key_from_link(link), "id-beta456")

    def test_decodes_query_values(self) -> None:
        self.assertEqual(key_from_link("/bug?extid=a%2Bb"), "extid-a+b")

    def test_rejects_unusable_link(self) -> None:
        with self.assertRaises(PayloadError):
            key_from_link("/bug?foo=bar")

    def test_rejects_traversal_and_windows_unsafe_filename_characters(self) -> None:
        unsafe_links = [
            "/bug?extid=..",
            "/bug?extid=trailing.",
            "/bug?extid=alpha%3Abeta",
            "/bug?extid=alpha%2Fbeta",
            "/bug?extid=alpha%5Cbeta",
            "/bug?extid=alpha%00beta",
            "/bug?extid=alpha%3Cbeta%3E",
            "/bug?extid=alpha%22beta",
            "/bug?extid=alpha%7Cbeta",
            "/bug?extid=alpha%3Fbeta",
            "/bug?extid=alpha%2Abeta",
            f"/bug?extid={'a' * 129}",
        ]

        for link in unsafe_links:
            with self.subTest(link=link), self.assertRaises(PayloadError):
                key_from_link(link)


class ParseListingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.payload = json.loads(FIXTURE.read_text(encoding="utf-8"))

    def test_normalizes_listing_records(self) -> None:
        records = parse_listing(self.payload)

        self.assertEqual(len(records), 2)
        alpha = records[0]
        self.assertEqual(alpha["key"], "extid-alpha123")
        self.assertEqual(alpha["title"], "KASAN: use-after-free in alpha")
        self.assertEqual(
            alpha["bug_url"],
            "https://syzkaller.appspot.com/bug?extid=alpha123",
        )
        self.assertEqual(
            alpha["json_url"],
            "https://syzkaller.appspot.com/bug?extid=alpha123&json=1",
        )
        self.assertEqual(alpha["primary_fix_hash"], ALPHA_HASH)
        self.assertEqual(alpha["fix_commits"][0]["hash"], ALPHA_HASH)

        beta = records[1]
        self.assertEqual(beta["key"], "id-beta456")
        self.assertEqual(beta["primary_fix_hash"], "")

    def test_accepts_lowercase_bugs_key(self) -> None:
        records = parse_listing({"version": 1, "bugs": self.payload["Bugs"][:1]})
        self.assertEqual([record["key"] for record in records], ["extid-alpha123"])

    def test_primary_fix_hash_is_the_first_nonempty_hash(self) -> None:
        payload = copy.deepcopy(self.payload)
        fixes = payload["Bugs"][0]["fix-commits"]
        fixes.insert(0, {"title": "metadata-only fix", "hash": ""})
        fixes.append({"title": "later fix", "hash": "b" * 40})

        record = parse_listing(payload)[0]

        self.assertEqual(record["primary_fix_hash"], ALPHA_HASH)

    def test_primary_fix_hash_is_empty_when_no_fix_has_a_hash(self) -> None:
        record = parse_listing(self.payload)[1]
        self.assertEqual(record["primary_fix_hash"], "")

    def test_rejects_records_without_a_stable_bug_key(self) -> None:
        payload = copy.deepcopy(self.payload)
        payload["Bugs"].append({"title": "broken", "link": "/bug?foo=bar"})
        with self.assertRaises(PayloadError):
            parse_listing(payload)

    def test_rejects_non_object_fix_entries(self) -> None:
        payload = copy.deepcopy(self.payload)
        payload["Bugs"][0]["fix-commits"].append("silently lossy metadata")

        with self.assertRaisesRegex(PayloadError, "non-object"):
            parse_listing(payload)

    def test_rejects_falsy_non_array_fix_metadata(self) -> None:
        for malformed in ({}, "", 0):
            payload = copy.deepcopy(self.payload)
            payload["Bugs"][0]["fix-commits"] = malformed
            with (
                self.subTest(malformed=malformed),
                self.assertRaisesRegex(PayloadError, "not an array"),
            ):
                parse_listing(payload)

    def test_does_not_mutate_input(self) -> None:
        original = copy.deepcopy(self.payload)
        parse_listing(self.payload)
        self.assertEqual(self.payload, original)


class ChooseBugPayloadTests(unittest.TestCase):
    def setUp(self) -> None:
        listing = json.loads(FIXTURE.read_text(encoding="utf-8"))
        self.record = parse_listing(listing)[0]
        detail_path = FIXTURE.parent / "bugs" / "extid-alpha123.json"
        self.detail = json.loads(detail_path.read_text(encoding="utf-8"))

    def test_wraps_detailed_payload_with_stable_listing_identity(self) -> None:
        selected = choose_bug_payload(self.record, self.detail)

        self.assertEqual(selected["key"], "extid-alpha123")
        self.assertEqual(selected["bug_url"], self.record["bug_url"])
        self.assertEqual(selected["json_url"], self.record["json_url"])
        self.assertEqual(selected["title"], self.detail["title"])
        self.assertEqual(selected["status"], self.detail["status"])
        self.assertEqual(selected["fix-commits"][0]["hash"], ALPHA_HASH)

    def test_falls_back_to_listing_when_detail_is_unavailable(self) -> None:
        selected = choose_bug_payload(self.record, None)

        self.assertEqual(selected["key"], "extid-alpha123")
        self.assertEqual(selected["title"], self.record["title"])
        self.assertEqual(selected["fix-commits"][0]["hash"], ALPHA_HASH)

    def test_does_not_mutate_either_input(self) -> None:
        record_before = copy.deepcopy(self.record)
        detail_before = copy.deepcopy(self.detail)
        choose_bug_payload(self.record, self.detail)
        self.assertEqual(self.record, record_before)
        self.assertEqual(self.detail, detail_before)


class UrlPolicyTests(unittest.TestCase):
    def test_resolves_relative_links_under_a_custom_dashboard_path_and_port(self) -> None:
        self.assertEqual(
            absolute_syzbot_url(
                "/bug?extid=alpha123",
                "https://mirror.example.invalid:8443/syzbot/",
            ),
            "https://mirror.example.invalid:8443/syzbot/bug?extid=alpha123",
        )

    def test_accepts_absolute_links_on_the_same_normalized_origin(self) -> None:
        self.assertEqual(
            absolute_syzbot_url(
                "https://mirror.example.invalid:443/bug?extid=alpha123",
                "https://mirror.example.invalid/syzbot",
            ),
            "https://mirror.example.invalid:443/bug?extid=alpha123",
        )

    def test_rejects_unfetchable_or_cross_origin_dashboard_links(self) -> None:
        unsafe = [
            "//mirror.example.invalid/bug?extid=alpha123",
            "https://other.example.invalid/bug?extid=alpha123",
            "http://mirror.example.invalid/bug?extid=alpha123",
            "https://mirror.example.invalid:444/bug?extid=alpha123",
            "https://user@mirror.example.invalid/bug?extid=alpha123",
            "file:///tmp/bug?extid=alpha123",
            "https://mirror.example.invalid/bug?extid=alpha123#json",
            "https://mirror.example.invalid/bug?extid=alpha 123",
            "https://mirror.example.invalid/bug?extid=alpha\u2003123",
            "https://[bad/bug?extid=alpha123",
        ]

        for link in unsafe:
            with self.subTest(link=link), self.assertRaises(PayloadError):
                absolute_syzbot_url(link, "https://mirror.example.invalid/syzbot")


class PayloadValidatorTests(unittest.TestCase):
    def test_markup_detection_is_bom_aware_for_reports_and_patches(self) -> None:
        self.assertFalse(valid_report(b"\xef\xbb\xbf<html><body>error</body></html>"))
        self.assertFalse(valid_report(b"\xef\xbb\xbf<?xml version='1.0'?><error/>"))
        self.assertFalse(
            valid_patch(b"\xef\xbb\xbf<html><body>diff --git a/a b/a upstream error</body></html>")
        )
        self.assertFalse(
            valid_patch(b"\xef\xbb\xbf<?xml version='1.0'?><error>diff --git a/a b/a</error>")
        )
        self.assertTrue(valid_report(b"\xef\xbb\xbfplain crash report"))

    def test_listing_html_requires_a_complete_html_element(self) -> None:
        self.assertTrue(
            valid_listing_html(b"\xef\xbb\xbf<!doctype html><html><body>ok</body></html>")
        )
        self.assertFalse(valid_listing_html(b"<html><body>truncated"))

    def test_bug_json_rejects_malformed_structured_collections(self) -> None:
        valid = {
            "title": "bug",
            "fix-commits": [],
            "crashes": [],
            "discussions": ["https://example.invalid/thread"],
        }
        self.assertTrue(valid_bug_json(json.dumps(valid).encode()))

        malformed = [
            {**valid, "fix-commits": ["not an object"]},
            {**valid, "crashes": [1]},
            {**valid, "fix-commits": {}},
            {**valid, "crashes": {}},
            {**valid, "discussions": {}},
            {**valid, "discussions": [123]},
            {**valid, "discussions": [""]},
        ]
        for payload in malformed:
            with self.subTest(payload=payload):
                self.assertFalse(valid_bug_json(json.dumps(payload).encode()))


if __name__ == "__main__":
    unittest.main()
