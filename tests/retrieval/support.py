from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

from syz_sage.project.config import DataPaths
from syz_sage.project.storage import temporary_directory
from syz_sage.retrieval.client import FetchError
from tests.support import ALPHA_HASH, FIXTURES, GAMMA_HASH


class FakeClient:
    dashboard = "https://syzkaller.appspot.com"

    def __init__(
        self,
        fail_bug: str | None = None,
        on_listing: Callable[[], None] | None = None,
    ) -> None:
        self.fail_bug = fail_bug
        self.on_listing = on_listing
        self.bug_calls: list[str] = []
        self.report_calls: list[str] = []
        self.patch_calls: list[str] = []
        self.patch_repos: list[str | None] = []

    def listing_json(self, namespace: str, status: str) -> bytes:
        self._assert_scope(namespace, status)
        if self.on_listing is not None:
            self.on_listing()
        return (FIXTURES / "raw" / "upstream_fixed.json").read_bytes()

    def listing_html(self, namespace: str, status: str) -> bytes:
        self._assert_scope(namespace, status)
        return (FIXTURES / "raw" / "upstream_fixed.html").read_bytes()

    def bug(self, json_url: str) -> bytes:
        key = "extid-alpha123" if "extid=alpha123" in json_url else "id-beta456"
        self.bug_calls.append(key)
        if key == self.fail_bug:
            raise FetchError(f"planned detail failure for {key}")
        return (FIXTURES / "raw" / "bugs" / f"{key}.json").read_bytes()

    def report(self, url: str) -> bytes:
        self.report_calls.append(url)
        return (FIXTURES / "artifacts" / "reports" / "extid-alpha123.txt").read_bytes()

    def patch(self, commit_hash: str, repo: str | None = None) -> tuple[bytes, str]:
        self.patch_calls.append(commit_hash)
        self.patch_repos.append(repo)
        payload = (FIXTURES / "artifacts" / "patches" / f"{commit_hash}.diff").read_bytes()
        return payload, f"https://example.invalid/{commit_hash}.diff"

    @staticmethod
    def _assert_scope(namespace: str, status: str) -> None:
        if (namespace, status) != ("upstream", "fixed"):
            raise AssertionError(f"unexpected update scope: {namespace}/{status}")


class EmptyListingClient(FakeClient):
    def listing_json(self, namespace: str, status: str) -> bytes:
        self._assert_scope(namespace, status)
        return b'{"version": 1, "Bugs": []}'


class RewrittenHashClient(FakeClient):
    def __init__(self, commit_hash: str) -> None:
        super().__init__()
        self.commit_hash = commit_hash

    def listing_json(self, namespace: str, status: str) -> bytes:
        payload = json.loads(super().listing_json(namespace, status))
        payload["Bugs"][0]["fix-commits"][0]["hash"] = self.commit_hash
        return json.dumps(payload).encode("utf-8")

    def bug(self, json_url: str) -> bytes:
        payload = json.loads(super().bug(json_url))
        if "extid=alpha123" in json_url:
            payload["fix-commits"][0]["hash"] = self.commit_hash
        return json.dumps(payload).encode("utf-8")

    def patch(self, commit_hash: str, repo: str | None = None) -> tuple[bytes, str]:
        self.patch_calls.append(commit_hash)
        payload = (FIXTURES / "artifacts" / "patches" / f"{ALPHA_HASH}.diff").read_bytes()
        return payload, f"https://example.invalid/{commit_hash}.diff"


class ChangedListingTitleClient(FakeClient):
    title = "KASAN: updated live title for alpha"
    report_url = "https://syzkaller.appspot.com/text?tag=CrashReport&x=alpha-updated"
    report_bytes = b"BUG: KASAN: updated alpha crash\nupdated stack trace\n"

    def listing_json(self, namespace: str, status: str) -> bytes:
        payload = json.loads(super().listing_json(namespace, status))
        payload["Bugs"][0]["title"] = self.title
        return json.dumps(payload).encode("utf-8")

    def bug(self, json_url: str) -> bytes:
        payload = json.loads(super().bug(json_url))
        if "extid=alpha123" in json_url:
            payload["title"] = self.title
            payload["crashes"][0]["crash-report-link"] = self.report_url
        return json.dumps(payload).encode("utf-8")

    def report(self, url: str) -> bytes:
        self.report_calls.append(url)
        return self.report_bytes


class CustomDashboardClient(FakeClient):
    dashboard = "https://mirror.example.invalid/syzbot"


class InvalidHtmlClient(FakeClient):
    def listing_html(self, namespace: str, status: str) -> bytes:
        self._assert_scope(namespace, status)
        return b"<html><body>truncated upstream response"


class ChangedReportClient(FakeClient):
    def __init__(
        self,
        *,
        fail_report: bool = False,
        report_payload: bytes | None = None,
        on_report: Callable[[], None] | None = None,
    ) -> None:
        super().__init__()
        self.fail_report = fail_report
        self.report_payload = report_payload
        self.on_report = on_report

    def bug(self, json_url: str) -> bytes:
        payload = json.loads(super().bug(json_url))
        if "extid=alpha123" in json_url:
            payload["crashes"][0]["crash-report-link"] = "/text?tag=CrashReport&x=alpha-new"
        return json.dumps(payload).encode("utf-8")

    def report(self, url: str) -> bytes:
        self.report_calls.append(url)
        if self.on_report is not None:
            self.on_report()
        if self.fail_report:
            raise FetchError("planned changed report failure")
        if self.report_payload is not None:
            return self.report_payload
        return (FIXTURES / "artifacts" / "reports" / "extid-alpha123.txt").read_bytes()


class ResolutionPatchClient(FakeClient):
    def patch(self, commit_hash: str, repo: str | None = None) -> tuple[bytes, str]:
        self.patch_calls.append(commit_hash)
        self.patch_repos.append(repo)
        payload = (FIXTURES / "artifacts" / "patches" / f"{ALPHA_HASH}.diff").read_bytes()
        return payload, f"https://example.invalid/{commit_hash}.diff"


class ExpandedListingClient(FakeClient):
    def __init__(self, *, fail_new_bug: bool = False) -> None:
        super().__init__()
        self.fail_new_bug = fail_new_bug

    def listing_html(self, namespace: str, status: str) -> bytes:
        return (
            super()
            .listing_html(namespace, status)
            .replace(b"</body>", b'<a href="/bug?id=gamma789">gamma</a></body>')
        )

    def listing_json(self, namespace: str, status: str) -> bytes:
        payload = json.loads(super().listing_json(namespace, status))
        payload["Bugs"].append(
            {
                "title": "KMSAN: uninitialized value in gamma",
                "link": "/bug?id=gamma789",
                "fix-commits": [
                    {
                        "title": "net: initialize gamma state",
                        "hash": GAMMA_HASH,
                        "repo": (
                            "git://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git"
                        ),
                        "branch": "master",
                    }
                ],
            }
        )
        return json.dumps(payload).encode("utf-8")

    def bug(self, json_url: str) -> bytes:
        if "id=gamma789" not in json_url:
            return super().bug(json_url)
        self.bug_calls.append("id-gamma789")
        if self.fail_new_bug:
            raise FetchError("planned detail failure for id-gamma789")
        return json.dumps(
            {
                "version": 1,
                "id": "gamma789",
                "title": "KMSAN: uninitialized value in gamma",
                "status": "fixed on 2026/09/01 12:00",
                "fix-commits": [
                    {
                        "title": "net: initialize gamma state",
                        "hash": GAMMA_HASH,
                        "repo": (
                            "git://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git"
                        ),
                        "branch": "master",
                    }
                ],
                "crashes": [
                    {
                        "title": "KMSAN: uninitialized value in gamma",
                        "crash-report-link": "/text?tag=CrashReport&x=gamma",
                    }
                ],
                "discussions": [],
            }
        ).encode("utf-8")

    def patch(self, commit_hash: str, repo: str | None = None) -> tuple[bytes, str]:
        if commit_hash != GAMMA_HASH:
            return super().patch(commit_hash, repo)
        self.patch_calls.append(commit_hash)
        self.patch_repos.append(repo)
        payload = (FIXTURES / "artifacts" / "patches" / f"{ALPHA_HASH}.diff").read_bytes()
        return payload, f"https://example.invalid/{commit_hash}.diff"


class OffOriginReportClient(FakeClient):
    def bug(self, json_url: str) -> bytes:
        payload = json.loads(super().bug(json_url))
        if "extid=alpha123" in json_url:
            payload["crashes"][0]["crash-report-link"] = "https://attacker.example.invalid/report"
        return json.dumps(payload).encode("utf-8")


class InvalidArtifactsClient(FakeClient):
    def report(self, url: str) -> bytes:
        self.report_calls.append(url)
        return b"\xef\xbb\xbf<?xml version='1.0'?><error>temporary failure</error>"

    def patch(self, commit_hash: str, repo: str | None = None) -> tuple[bytes, str]:
        self.patch_calls.append(commit_hash)
        return (
            b"\xef\xbb\xbf<?xml version='1.0'?><error>temporary failure diff --git a/a b/a</error>",
            f"https://example.invalid/{commit_hash}.diff",
        )


class UpdaterFixture:
    """Reusable fixture setup only; concrete tests live in concern modules."""

    def setUp(self) -> None:
        self.temporary = temporary_directory()
        self.paths = DataPaths.from_root(Path(self.temporary.name) / "data")
        self.database_path = self.paths.database

    def tearDown(self) -> None:
        self.temporary.cleanup()
