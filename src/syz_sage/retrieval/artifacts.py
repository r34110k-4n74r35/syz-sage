"""Shared download contracts, validation, and bounded artifact processing.

These objects live only in memory. Saved JSON, crash reports, and diff bytes
retain their original formats.
"""

from __future__ import annotations

import contextlib
import hashlib
import os
import tempfile
from collections.abc import Callable, Generator, Iterable
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, TypeVar

from syz_sage.parsing.listing import PayloadError, parse_bug_json, valid_patch, valid_report
from syz_sage.project.storage import writable_path

from .client import SyzbotClient

ArtifactKind = Literal["bug-json", "report", "patch"]
DownloadReason = Literal["missing", "invalid", "retry", "refresh"]


@dataclass(frozen=True, slots=True)
class DownloadJob:
    kind: ArtifactKind
    key: str
    path: Path
    source_url: str | None = None
    repo: str | None = None
    reason: DownloadReason = "missing"


@dataclass(frozen=True, slots=True)
class ArtifactResult:
    """One validated resource, including the endpoint that supplied its bytes."""

    job: DownloadJob
    payload: bytes
    source_url: str | None
    digest: str
    detail: dict[str, Any] | None = None


def validate_artifact(
    job: DownloadJob,
    payload: bytes,
    *,
    source_url: str | None = None,
    digest: str | None = None,
) -> ArtifactResult:
    """Validate bytes, optionally reusing their hash from this run's inventory."""
    detail = None
    if job.kind == "bug-json":
        detail = parse_bug_json(payload)
    elif job.kind == "report":
        if not valid_report(payload):
            raise PayloadError("empty or HTML crash report")
    elif not valid_patch(payload):
        raise PayloadError("response is not a valid patch")
    return ArtifactResult(
        job, payload, source_url, digest or hashlib.sha256(payload).hexdigest(), detail
    )


def fetch_artifact(client: SyzbotClient, job: DownloadJob) -> ArtifactResult:
    source_url = job.source_url
    if job.kind == "patch":
        payload, source_url = client.patch(job.key, job.repo)
    else:
        if source_url is None:
            raise ValueError(f"{job.kind} download has no source URL")
        payload = client.bug(source_url) if job.kind == "bug-json" else client.report(source_url)
    return validate_artifact(job, payload, source_url=source_url)


def atomic_write(path: Path, payload: bytes) -> None:
    """Durably replace a project file only when its complete bytes differ."""
    path = writable_path(path)
    try:
        if path.read_bytes() == payload:
            return
    except OSError:
        pass
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            prefix=f".{path.name}.", suffix=".tmp", dir=path.parent, delete=False
        ) as temporary:
            temporary_name = temporary.name
            temporary.write(payload)
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temporary_name, path)
        temporary_name = None
    finally:
        if temporary_name is not None:
            with contextlib.suppress(FileNotFoundError):
                Path(temporary_name).unlink()


Job = TypeVar("Job")
Result = TypeVar("Result")


def bounded_results(
    jobs: Iterable[Job],
    fetch: Callable[[Job], Result],
    *,
    workers: int,
    cancel: Callable[[], None] | None = None,
) -> Generator[tuple[Job, Future[Result]], None, None]:
    """Yield completions with at most twice the worker count scheduled.

    The consumer saves each result before asking for another. Finished payloads
    and queued jobs therefore cannot grow with the size of the entire mirror.
    """
    if workers < 1:
        raise ValueError("workers must be at least one")
    iterator = iter(jobs)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        pending: dict[Future[Result], Job] = {}

        def fill() -> None:
            while len(pending) < workers * 2:
                try:
                    job = next(iterator)
                except StopIteration:
                    break
                pending[pool.submit(fetch, job)] = job

        try:
            fill()
            while pending:
                done, _ = wait(pending, return_when=FIRST_COMPLETED)
                for future in done:
                    job = pending.pop(future)
                    yield job, future
                # Release completed payloads before scheduling another batch.
                done.clear()
                fill()
        except BaseException:
            # Generator close/interrupt must signal running requests before the
            # executor waits for them. Cancelling futures alone stops only work
            # that has not started yet.
            for future in pending:
                future.cancel()
            if cancel is not None:
                cancel()
            raise
        finally:
            for future in pending:
                future.cancel()
