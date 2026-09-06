"""Observational progress shared by database work and command-line renderers."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator
from contextlib import suppress
from dataclasses import dataclass
from typing import TypeVar


@dataclass(frozen=True)
class ProgressEvent:
    phase: str
    message: str
    completed: int | None = None
    total: int | None = None


ProgressCallback = Callable[[ProgressEvent], None]
_T = TypeVar("_T")


def emit_progress(callback: ProgressCallback | None, event: ProgressEvent) -> None:
    """Keep display errors observational; cancellation still interrupts the work."""
    if callback is not None:
        # A broken display must not change persistence or query results.
        with suppress(Exception):
            callback(event)


def report_progress(
    callback: ProgressCallback | None,
    phase: str,
    message: str,
    completed: int | None = None,
    total: int | None = None,
) -> None:
    """Construct an event only when a listener exists."""
    if callback is not None:
        emit_progress(callback, ProgressEvent(phase, message, completed, total))


def progress_items(
    items: Iterable[_T],
    callback: ProgressCallback | None,
    phase: str,
    message: str,
    *,
    total: int | None = None,
) -> Iterator[_T]:
    """Count items after their consumer finishes, including handled failures.

    Finishing a phase means its items were processed, not that a surrounding
    transaction committed or that every item passed validation.
    """
    if callback is None:
        yield from items
        return
    report_progress(callback, phase, message, 0, total)
    for completed, item in enumerate(items, 1):
        yield item
        report_progress(callback, phase, message, completed, total)
