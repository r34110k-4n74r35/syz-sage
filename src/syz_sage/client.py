"""Small, dependency-free HTTP client for the Syzbot dashboard."""

from __future__ import annotations

import http.client
import random
import threading
import time
import urllib.error
import urllib.request
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import SplitResult, urlsplit, urlunsplit

from . import __version__
from .parsing import DEFAULT_DASHBOARD, HASH_RE, valid_patch, validate_http_url

USER_AGENT = f"syz-sage/{__version__} (Python CLI; syzbot data client)"
TRUSTED_PATCH_HOSTS = frozenset({"git.kernel.org", "github.com"})


class FetchError(RuntimeError):
    """A resource could not be retrieved after bounded retries."""


@dataclass(frozen=True, slots=True)
class RetryPolicy:
    attempts: int = 6
    timeout: float = 90.0
    base_delay: float = 1.0
    rate_limit_delay: float = 45.0


class WindowRateLimiter:
    """Thread-safe sliding-window limiter shared by dashboard workers."""

    def __init__(self, requests: int = 6, window: float = 15.0) -> None:
        if requests < 1 or window <= 0:
            raise ValueError("rate-limit values must be positive")
        self.requests = requests
        self.window = window
        self._times: deque[float] = deque()
        self._lock = threading.Lock()
        self._cooldown_until = 0.0

    def penalize(self, seconds: float) -> None:
        with self._lock:
            self._cooldown_until = max(self._cooldown_until, time.monotonic() + seconds)

    def acquire(self) -> None:
        while True:
            with self._lock:
                now = time.monotonic()
                while self._times and now - self._times[0] >= self.window:
                    self._times.popleft()
                if now >= self._cooldown_until and len(self._times) < self.requests:
                    self._times.append(now)
                    return
                waits = [0.05]
                if now < self._cooldown_until:
                    waits.append(self._cooldown_until - now)
                if len(self._times) >= self.requests:
                    waits.append(self.window - (now - self._times[0]) + 0.05)
                wait = max(waits)
            time.sleep(wait)


def _trusted_patch_url(url: str) -> SplitResult:
    validate_http_url(url)
    parsed = urlsplit(url)
    if parsed.scheme.lower() != "https":
        raise ValueError("patch URLs must use https")
    if parsed.hostname is None or parsed.hostname.lower() not in TRUSTED_PATCH_HOSTS:
        raise ValueError("patch URL host is not trusted")
    if parsed.port is not None:
        raise ValueError("patch URLs must not specify a port")
    if parsed.fragment:
        raise ValueError("patch URLs must not contain a fragment")
    return parsed


def normalize_patch_repository(repo: str | None) -> tuple[str, str]:
    """Return a trusted repository's HTTPS host and URL for patches or research."""
    repository = repo or "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git"
    if not isinstance(repository, str) or not repository or repository != repository.strip():
        raise ValueError("patch repository must be a non-empty URL")
    if any(ord(character) < 0x20 or 0x7F <= ord(character) <= 0x9F for character in repository):
        raise ValueError("patch repository URL contains control characters")
    try:
        parsed = urlsplit(repository)
        explicit_port = parsed.port
    except ValueError as exc:
        raise ValueError(f"invalid patch repository URL: {exc}") from exc
    if parsed.scheme.lower() not in {"git", "http", "https"} or not parsed.netloc:
        raise ValueError("patch repository must use git, http, or https")
    normalized = urlunsplit(("https", parsed.netloc, parsed.path, parsed.query, parsed.fragment))
    validate_http_url(normalized)
    normalized_parts = urlsplit(normalized)
    hostname = normalized_parts.hostname
    if hostname is None or hostname.lower() not in TRUSTED_PATCH_HOSTS:
        raise ValueError("patch repository host is not trusted")
    if explicit_port is not None:
        raise ValueError("patch repository must not specify a port")
    if normalized_parts.query or normalized_parts.fragment:
        raise ValueError("patch repository must not contain a query or fragment")
    path = normalized_parts.path.rstrip("/")
    return hostname.lower(), urlunsplit(("https", hostname.lower(), path, "", ""))


_normalize_patch_repository = normalize_patch_repository


class SyzbotClient:
    """Retrieve listings, bug metadata, reports, and kernel patches."""

    def __init__(
        self,
        dashboard: str = DEFAULT_DASHBOARD,
        retry: RetryPolicy | None = None,
        opener: urllib.request.OpenerDirector | None = None,
        limiter: WindowRateLimiter | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        normalized_dashboard = dashboard.rstrip("/")
        validate_http_url(normalized_dashboard)
        dashboard_parts = urlsplit(normalized_dashboard)
        if dashboard_parts.query or dashboard_parts.fragment:
            raise ValueError("dashboard URL must not contain a query or fragment")
        self.dashboard = normalized_dashboard
        self.retry = retry or RetryPolicy()
        self.opener = opener or urllib.request.build_opener()
        self.limiter = limiter or WindowRateLimiter()
        self.sleep = sleep

    def get(
        self, url: str, *, dashboard_request: bool = False, timeout: float | None = None
    ) -> bytes:
        validate_http_url(url, same_origin_as=self.dashboard if dashboard_request else None)
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        last_error: BaseException | None = None
        for attempt in range(self.retry.attempts):
            if dashboard_request:
                self.limiter.acquire()
            try:
                with self.opener.open(request, timeout=timeout or self.retry.timeout) as response:
                    payload: object = response.read()
                    if not isinstance(payload, bytes):
                        raise FetchError(f"GET {url} returned a non-bytes response")
                    return payload
            except urllib.error.HTTPError as exc:
                last_error = exc
                # HTTPError owns the response body/file descriptor even when
                # the caller never consumes it. Release it before retrying.
                exc.close()
                if exc.code == 429:
                    delay = self.retry.rate_limit_delay * (attempt + 1)
                    if dashboard_request:
                        self.limiter.penalize(delay)
                    elif attempt + 1 < self.retry.attempts:
                        # Patch requests do not acquire the dashboard limiter,
                        # so penalizing it alone would not delay this retry.
                        self.sleep(delay)
                elif exc.code not in {403, 500, 502, 503, 504}:
                    break
            except (
                urllib.error.URLError,
                TimeoutError,
                OSError,
                http.client.IncompleteRead,
            ) as exc:
                last_error = exc
            if attempt + 1 < self.retry.attempts:
                self.sleep(self.retry.base_delay * (1.5**attempt) + random.random() / 4)
        raise FetchError(f"GET {url} failed: {last_error}") from last_error

    def listing_json(self, namespace: str = "upstream", status: str = "fixed") -> bytes:
        return self.get(
            f"{self.dashboard}/{namespace}/{status}?json=1", dashboard_request=True, timeout=180
        )

    def listing_html(self, namespace: str = "upstream", status: str = "fixed") -> bytes:
        return self.get(
            f"{self.dashboard}/{namespace}/{status}", dashboard_request=True, timeout=180
        )

    def bug(self, json_url: str) -> bytes:
        return self.get(json_url, dashboard_request=True)

    def report(self, url: str) -> bytes:
        return self.get(url, dashboard_request=True)

    @staticmethod
    def patch_urls(commit_hash: str, repo: str | None) -> list[str]:
        if not HASH_RE.fullmatch(commit_hash):
            raise ValueError("commit hash must contain exactly 40 hexadecimal characters")
        commit_hash = commit_hash.lower()
        hostname, repository = normalize_patch_repository(repo)
        urls: list[str] = []
        if hostname == "github.com":
            repository_path = repository[:-4] if repository.lower().endswith(".git") else repository
            urls.append(f"{repository_path}/commit/{commit_hash}.diff")
        else:
            urls.append(f"{repository}/patch/?id={commit_hash}")
        fallback = f"https://github.com/torvalds/linux/commit/{commit_hash}.diff"
        if fallback not in urls:
            urls.append(fallback)
        return urls

    def patch(self, commit_hash: str, repo: str | None = None) -> tuple[bytes, str]:
        errors: list[str] = []
        for url in self.patch_urls(commit_hash, repo):
            _trusted_patch_url(url)
            try:
                payload = self.get(url, timeout=60)
            except FetchError as exc:
                errors.append(str(exc))
                continue
            if valid_patch(payload):
                return payload, url
            errors.append(f"invalid patch response from {url}")
        raise FetchError("; ".join(errors))
