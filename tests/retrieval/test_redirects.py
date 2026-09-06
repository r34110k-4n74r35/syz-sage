from __future__ import annotations

import io
import unittest
import urllib.request
from concurrent.futures import CancelledError
from email.message import Message
from unittest import mock
from urllib.response import addinfourl

from syz_sage.parsing.listing import PayloadError
from syz_sage.retrieval.client import FetchError, RetryPolicy, SyzbotClient


class MemoryHTTP(urllib.request.BaseHandler):
    """Serve redirects through urllib's real processing without opening sockets."""

    handler_order = 100

    def __init__(self, redirects: list[str]) -> None:
        self.redirects = redirects
        self.requests: list[str] = []
        self.responses: list[addinfourl] = []
        self.before_response = lambda: None

    def https_open(self, request: urllib.request.Request) -> addinfourl:
        self.requests.append(request.full_url)
        headers = Message()
        index = len(self.requests) - 1
        redirected = index < len(self.redirects)
        if redirected:
            headers["Location"] = self.redirects[index]
        result = addinfourl(
            io.BytesIO(b"redirect" if redirected else b"complete report"),
            headers,
            request.full_url,
            302 if redirected else 200,
        )
        result.msg = "Found" if redirected else "OK"
        self.responses.append(result)
        self.before_response()
        return result

    http_open = https_open


class RedirectPolicyTests(unittest.TestCase):
    def client(self, transport: MemoryHTTP) -> SyzbotClient:
        return SyzbotClient(
            dashboard="https://mirror.example.invalid",
            opener=urllib.request.build_opener(transport),
            retry=RetryPolicy(attempts=1),
        )

    def test_dashboard_redirect_chain_retains_same_origin_policy(self) -> None:
        transport = MemoryHTTP(["/second", "https://mirror.example.invalid:443/final"])
        result = self.client(transport).report("https://mirror.example.invalid/start")
        self.assertEqual(result, b"complete report")
        self.assertEqual(
            transport.requests,
            [
                "https://mirror.example.invalid/start",
                "https://mirror.example.invalid/second",
                "https://mirror.example.invalid:443/final",
            ],
        )
        self.assertTrue(all(response.closed for response in transport.responses))

    def test_dashboard_rejects_redirect_before_requesting_another_origin(self) -> None:
        for target in (
            "https://other.example.invalid/report",
            "http://mirror.example.invalid/report",
            "https://mirror.example.invalid:8443/report",
            "https://user@mirror.example.invalid/report",
        ):
            with self.subTest(target=target):
                transport = MemoryHTTP([target])
                with self.assertRaises(PayloadError):
                    self.client(transport).report("https://mirror.example.invalid/start")
                self.assertEqual(transport.requests, ["https://mirror.example.invalid/start"])
                self.assertTrue(transport.responses[0].closed)

    def test_later_redirect_cannot_drop_the_original_request_policy(self) -> None:
        transport = MemoryHTTP(["/second", "https://other.example.invalid/final"])
        with self.assertRaises(PayloadError):
            self.client(transport).report("https://mirror.example.invalid/start")
        self.assertEqual(len(transport.requests), 2)
        self.assertTrue(all(response.closed for response in transport.responses))

    def test_generic_research_download_keeps_its_existing_cross_origin_policy(self) -> None:
        transport = MemoryHTTP(["https://cdn.example.invalid/final"])
        self.assertEqual(
            self.client(transport).get("https://source.example.invalid/start"),
            b"complete report",
        )
        self.assertEqual(transport.requests[-1], "https://cdn.example.invalid/final")

    def test_generic_redirect_still_rejects_user_information(self) -> None:
        transport = MemoryHTTP(["https://user@cdn.example.invalid/final"])
        with self.assertRaises(PayloadError):
            self.client(transport).get("https://source.example.invalid/start")
        self.assertEqual(len(transport.requests), 1)
        self.assertTrue(transport.responses[0].closed)

    def test_malformed_redirect_location_closes_its_response(self) -> None:
        transport = MemoryHTTP(["https://[broken"])
        with self.assertRaises(ValueError):
            self.client(transport).report("https://mirror.example.invalid/start")
        self.assertEqual(len(transport.requests), 1)
        self.assertTrue(transport.responses[0].closed)

    def test_unsupported_redirect_scheme_closes_without_fetching_target(self) -> None:
        for target, exception in (
            ("file:///not-requested", FetchError),
            ("ftp://other.example.invalid/not-requested", PayloadError),
        ):
            with self.subTest(target=target):
                transport = MemoryHTTP([target])
                with self.assertRaises(exception):
                    self.client(transport).report("https://mirror.example.invalid/start")
                self.assertEqual(len(transport.requests), 1)
                self.assertTrue(transport.responses[0].closed)

    def test_cancellation_during_redirect_prevents_another_request(self) -> None:
        transport = MemoryHTTP(["/second"])
        client = self.client(transport)
        transport.before_response = client.cancel
        with self.assertRaises(CancelledError):
            client.report("https://mirror.example.invalid/start")
        self.assertEqual(len(transport.requests), 1)
        self.assertTrue(transport.responses[0].closed)

    def test_custom_opener_final_url_is_checked_before_reading_its_body(self) -> None:
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.geturl.return_value = "https://other.example.invalid/final"
        opener = mock.Mock()
        opener.open.return_value = response
        client = SyzbotClient(opener=opener, retry=RetryPolicy(attempts=1))
        with self.assertRaises(PayloadError):
            client.report("https://syzkaller.appspot.com/start")
        response.read.assert_not_called()
        response.__exit__.assert_called_once()


if __name__ == "__main__":
    unittest.main()
