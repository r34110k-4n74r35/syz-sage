from __future__ import annotations

import http.client
import io
import unittest
import urllib.error
from unittest import mock

from syz_sage.client import FetchError, RetryPolicy, SyzbotClient


class PatchUrlTests(unittest.TestCase):
    def test_accepts_and_normalizes_a_full_hexadecimal_commit_hash(self) -> None:
        commit_hash = "ABCDEF12" * 5

        urls = SyzbotClient.patch_urls(commit_hash, "https://github.com/example/linux.git")

        self.assertEqual(
            urls[0],
            f"https://github.com/example/linux/commit/{commit_hash.lower()}.diff",
        )
        self.assertTrue(all(commit_hash.lower() in url for url in urls))

    def test_rejects_hashes_that_cannot_safely_name_a_patch_file(self) -> None:
        unsafe = [
            "a" * 39,
            "g" * 40,
            "../escaped-" + "a" * 29,
            "a" * 39 + "/",
        ]

        for commit_hash in unsafe:
            with self.subTest(commit_hash=commit_hash), self.assertRaises(ValueError):
                SyzbotClient.patch_urls(commit_hash, None)

    def test_normalizes_only_trusted_kernel_and_github_repositories(self) -> None:
        commit_hash = "a" * 40
        cases = {
            "git://git.kernel.org/pub/scm/linux/kernel/git/example/linux.git": (
                "https://git.kernel.org/pub/scm/linux/kernel/git/example/"
                f"linux.git/patch/?id={commit_hash}"
            ),
            "http://github.com/example/linux.git": (
                f"https://github.com/example/linux/commit/{commit_hash}.diff"
            ),
        }

        for repository, expected in cases.items():
            with self.subTest(repository=repository):
                self.assertEqual(SyzbotClient.patch_urls(commit_hash, repository)[0], expected)

    def test_rejects_untrusted_or_ambiguous_patch_repositories(self) -> None:
        commit_hash = "a" * 40
        unsafe = [
            "file:///tmp/linux.git",
            "ssh://git.kernel.org/linux.git",
            "https://example.invalid/linux.git",
            "https://github.com.evil.invalid/linux.git",
            "https://user@github.com/example/linux.git",
            "https://github.com:443/example/linux.git",
            "https://github.com/example/linux.git?format=diff",
            "https://github.com/example/linux.git#fragment",
            "https://github.com/example/linux repo.git",
            "https://github.com/example/linux\u2003repo.git",
        ]

        for repository in unsafe:
            with self.subTest(repository=repository), self.assertRaises(ValueError):
                SyzbotClient.patch_urls(commit_hash, repository)


class ClientUrlPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        response = mock.MagicMock()
        response.read.return_value = b"ok"
        response.__enter__.return_value = response
        self.opener = mock.MagicMock()
        self.opener.open.return_value = response
        self.client = SyzbotClient(
            dashboard="https://mirror.example.invalid/syzbot",
            opener=self.opener,
            retry=RetryPolicy(attempts=1),
        )

    def test_dashboard_get_allows_only_the_configured_normalized_origin(self) -> None:
        result = self.client.get(
            "https://mirror.example.invalid:443/syzbot/bug?extid=alpha",
            dashboard_request=True,
        )

        self.assertEqual(result, b"ok")
        self.opener.open.assert_called_once()

        unsafe = [
            "//mirror.example.invalid/syzbot/bug?extid=alpha",
            "https://other.example.invalid/syzbot/bug?extid=alpha",
            "http://mirror.example.invalid/syzbot/bug?extid=alpha",
            "https://mirror.example.invalid:444/syzbot/bug?extid=alpha",
            "https://user@mirror.example.invalid/syzbot/bug?extid=alpha",
            "https://mirror.example.invalid/syzbot/bug?extid=alpha#json",
        ]
        for url in unsafe:
            with self.subTest(url=url), self.assertRaises(ValueError):
                self.client.get(url, dashboard_request=True)
        self.opener.open.assert_called_once()

    def test_custom_dashboard_port_is_part_of_the_trusted_origin(self) -> None:
        client = SyzbotClient(
            dashboard="https://mirror.example.invalid:8443/base",
            opener=self.opener,
            retry=RetryPolicy(attempts=1),
        )

        self.assertEqual(
            client.get(
                "https://mirror.example.invalid:8443/base/bug?extid=alpha",
                dashboard_request=True,
            ),
            b"ok",
        )
        with self.assertRaises(ValueError):
            client.get(
                "https://mirror.example.invalid/base/bug?extid=alpha",
                dashboard_request=True,
            )

    def test_generic_get_rejects_non_http_userinfo_and_whitespace(self) -> None:
        unsafe = [
            "file:///tmp/resource",
            "ftp://example.invalid/resource",
            "https://user@example.invalid/resource",
            "https://example.invalid/resource#fragment",
            "https://example.invalid/a b",
            "https://example.invalid/a\u2003b",
        ]

        for url in unsafe:
            with self.subTest(url=url), self.assertRaises(ValueError):
                self.client.get(url)
        self.opener.open.assert_not_called()

    def test_patch_revalidates_generated_urls_before_fetching(self) -> None:
        with (
            mock.patch.object(
                SyzbotClient,
                "patch_urls",
                return_value=["https://github.com.evil.invalid/example/linux.diff"],
            ),
            self.assertRaises(ValueError),
        ):
            self.client.patch("a" * 40)

        self.opener.open.assert_not_called()


class ClientRetryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.response = mock.MagicMock()
        self.response.read.return_value = b"complete response"
        self.response.__enter__.return_value = self.response
        self.opener = mock.MagicMock()
        self.sleep = mock.Mock()
        self.limiter = mock.Mock()
        self.client = SyzbotClient(
            opener=self.opener,
            limiter=self.limiter,
            retry=RetryPolicy(attempts=2, rate_limit_delay=45),
            sleep=self.sleep,
        )

    def test_patch_rate_limit_waits_before_retry_and_closes_response(self) -> None:
        body = io.BytesIO(b"rate limited")
        error = urllib.error.HTTPError("https://github.com/test", 429, "slow down", {}, body)
        self.opener.open.side_effect = [error, self.response]

        result = self.client.get("https://github.com/test")

        self.assertEqual(result, b"complete response")
        self.assertTrue(body.closed)
        self.assertEqual(self.opener.open.call_count, 2)
        self.assertEqual(self.sleep.call_args_list[0], mock.call(45))
        self.limiter.acquire.assert_not_called()

    def test_dashboard_rate_limit_is_shared_with_other_workers(self) -> None:
        error = urllib.error.HTTPError(
            "https://syzkaller.appspot.com/test", 429, "slow down", {}, io.BytesIO()
        )
        self.opener.open.side_effect = [error, self.response]

        self.client.get("https://syzkaller.appspot.com/test", dashboard_request=True)

        self.limiter.penalize.assert_called_once_with(45)
        self.assertEqual(self.limiter.acquire.call_count, 2)

    def test_truncated_http_body_is_retried_without_returning_partial_bytes(self) -> None:
        broken = mock.MagicMock()
        broken.__enter__.return_value = broken
        broken.read.side_effect = http.client.IncompleteRead(b"partial", 100)
        self.opener.open.side_effect = [broken, self.response]

        result = self.client.get("https://syzkaller.appspot.com/test", dashboard_request=True)

        self.assertEqual(result, b"complete response")
        self.assertEqual(self.opener.open.call_count, 2)
        broken.__exit__.assert_called_once()

    def test_nonretryable_error_closes_response_and_exits_without_sleep(self) -> None:
        body = io.BytesIO(b"not found")
        error = urllib.error.HTTPError("https://github.com/test", 404, "not found", {}, body)
        self.opener.open.side_effect = error

        with self.assertRaises(FetchError):
            self.client.get("https://github.com/test")

        self.assertTrue(body.closed)
        self.opener.open.assert_called_once()
        self.sleep.assert_not_called()


if __name__ == "__main__":
    unittest.main()
