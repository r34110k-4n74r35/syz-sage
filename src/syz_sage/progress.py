"""Small terminal progress display; counters describe work, not its success."""

from __future__ import annotations

import os
import sys
import threading
import time
import unicodedata
from types import TracebackType
from typing import TextIO

from .progress_events import ProgressEvent
from .terminal import safe_text, style, terminal_width

_INTERVAL = 0.1
_SPINNER = "|/-\\"


def _columns(text: str) -> int:
    return sum(
        0 if unicodedata.combining(char) else 2 if unicodedata.east_asian_width(char) in "WF" else 1
        for char in text
    )


def _fit(text: str, width: int) -> str:
    """Clip before adding color, accounting for wide and combining characters."""
    if width <= 0:
        return ""
    if _columns(text) <= width:
        return text
    suffix = "." * min(3, width)
    available = width - len(suffix)
    result = ""
    for char in text:
        if _columns(result + char) > available:
            break
        result += char
    return result + suffix


def _elapsed(seconds: float) -> str:
    seconds = max(0.0, seconds)
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes, remainder = divmod(int(seconds), 60)
    return f"{minutes}:{remainder:02d}"


class ProgressDisplay:
    """Render observational events on stderr, without owning signal handlers.

    Use as a context manager and pass the instance as a progress callback.
    Call ``finish(success=False)`` for handled partial results. Reaching a total
    only means attempts were processed; phase completion is always neutral.
    Without an explicit ``finish``, normal context exit is also neutral.
    """

    def __init__(self, title: str, *, enabled: bool = True, stream: TextIO | None = None) -> None:
        self.title = safe_text(title)
        self.enabled = enabled
        self.stream = stream if stream is not None else sys.stderr
        self._animated = enabled and self.stream.isatty() and os.environ.get("TERM") != "dumb"
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._entered = False
        self._closed = False
        self._event: ProgressEvent | None = None
        self._phase_finished = False
        self._started = 0.0
        self._phase_started = 0.0
        self._last_draw = float("-inf")
        self._frame = 0
        self._line_visible = False
        self._io_failed = False

    def __enter__(self) -> ProgressDisplay:
        with self._lock:
            if self._entered:
                raise RuntimeError("A progress display cannot be entered twice")
            self._entered = True
            self._started = time.monotonic()
            if self.enabled:
                self._write_line(self.title, tone="heading")
                if self._animated and not self._io_failed:
                    self._thread = threading.Thread(
                        target=self._animate, name="syz-sage-progress", daemon=True
                    )
                    self._thread.start()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        if exc_type is None:
            self._close()
        else:
            interrupted = issubclass(exc_type, KeyboardInterrupt)
            self._close("Interrupted" if interrupted else "Failed", tone="error", failed=True)

    def __call__(self, event: ProgressEvent) -> None:
        if not self.enabled:
            return
        with self._lock:
            if not self._entered or self._closed:
                return
            now = time.monotonic()
            new_phase = self._event is None or event.phase != self._event.phase
            # A reused phase identifier may start another bounded batch.
            if (
                not new_phase
                and self._phase_finished
                and (
                    event.completed is None or event.total is None or event.completed < event.total
                )
            ):
                new_phase = True
            if new_phase:
                self._complete_phase(now)
                self._phase_started = now
                self._phase_finished = False
            self._event = event
            if new_phase and not self._animated:
                self._write_line(self._phase_line(now, ending=False), tone="accent")
            if self._at_total(event):
                self._complete_phase(now)
            elif self._animated:
                self._draw(now, force=new_phase)

    def log(self, message: str) -> None:
        """Print a diagnostic above the active line, then resume progress."""
        if not self.enabled:
            return
        with self._lock:
            if not self._entered or self._closed:
                return
            self._clear_line()
            self._write_line(safe_text(message))
            self._draw(time.monotonic(), force=True)

    def finish(self, message: str | None = None, *, success: bool = True) -> None:
        """Stop rendering and report the caller's final outcome once."""
        result = (
            safe_text(message)
            if message is not None
            else "Complete"
            if success
            else "Partial result"
        )
        self._close(
            result,
            tone="success" if success else "warning",
        )

    @staticmethod
    def _at_total(event: ProgressEvent) -> bool:
        return (
            event.completed is not None
            and event.total is not None
            and event.total >= 0
            and event.completed >= event.total
        )

    @staticmethod
    def _counts(event: ProgressEvent) -> str:
        if event.completed is None:
            return ""
        if event.total is None or event.total < 0:
            return f"{max(0, event.completed):,} processed"
        if event.total == 0:
            return "0/0 (no work)" if event.completed == 0 else f"{event.completed:,}/0"
        percent = min(100, max(0, event.completed * 100 // event.total))
        return f"{percent:3d}% {max(0, event.completed):,}/{event.total:,}"

    def _label(self) -> str:
        assert self._event is not None
        return safe_text(self._event.message)

    def _phase_line(self, now: float, *, ending: bool) -> str:
        assert self._event is not None
        counts = self._counts(self._event)
        if counts and ending and self._event.total is not None and self._event.total > 0:
            counts += " processed"
        suffix = f"{counts}; " if counts else ""
        suffix = f"({suffix}{_elapsed(now - self._phase_started)})"
        label = self._label()
        if self._animated:
            width = max(1, terminal_width(self.stream) - 1)
            if _columns(suffix) + 6 > width:
                # Keep actual counts and duration ahead of explanatory prose.
                counts = self._counts(self._event)
                suffix = f"({counts}; {_elapsed(now - self._phase_started)})"
            room = width - _columns(suffix) - 3
            if room <= 0:
                return _fit(suffix, width)
            label = _fit(label, room)
        return f"  {label} {suffix}"

    def _complete_phase(self, now: float) -> None:
        if self._event is None or self._phase_finished:
            return
        self._clear_line()
        self._write_line(self._phase_line(now, ending=True), tone="muted")
        self._phase_finished = True

    def _draw(self, now: float, *, force: bool = False) -> None:
        if not self._animated or self._event is None or self._phase_finished or self._io_failed:
            return
        if not force and now - self._last_draw < _INTERVAL:
            return
        self._last_draw = now
        width = max(1, terminal_width(self.stream) - 1)
        counts = self._counts(self._event)
        elapsed = _elapsed(now - self._phase_started)
        known_total = self._event.total is not None and self._event.total >= 0
        bar = ""
        colored_bar = ""
        if counts and known_total:
            if width >= 48 and self._event.total and self._event.completed is not None:
                size = min(16, max(8, width // 6))
                filled = min(size, max(0, self._event.completed * size // self._event.total))
                bar = f"[{'#' * filled}{'-' * (size - filled)}] "
                colored_bar = (
                    style("[", tone="muted", stream=self.stream)
                    + style("#" * filled, tone="accent", stream=self.stream)
                    + style("-" * (size - filled), tone="muted", stream=self.stream)
                    + style("] ", tone="muted", stream=self.stream)
                )
            left = self._label()
        else:
            left = f"{_SPINNER[self._frame % len(_SPINNER)]} {self._label()}"
        right = f"{bar}{counts} {elapsed}" if counts else elapsed
        colored_right = (
            colored_bar
            + style(counts + " ", tone="number", stream=self.stream)
            + style(elapsed, tone="muted", stream=self.stream)
            if counts
            else style(elapsed, tone="muted", stream=self.stream)
        )
        self._frame += 1
        room = width - _columns(right) - 2
        text = (
            style(_fit(left, room), tone="strong", stream=self.stream) + "  " + colored_right
            if room > 0
            else style(_fit(right, width), tone="number", stream=self.stream)
        )
        self._line_visible = self._write("\r\x1b[2K" + text)

    def _clear_line(self) -> None:
        if self._line_visible:
            self._write("\r\x1b[2K")
            self._line_visible = False

    def _write_line(self, message: str, *, tone: str = "muted") -> None:
        if self._animated:
            message = _fit(message, max(1, terminal_width(self.stream) - 1))
        self._write(style(message, tone=tone, stream=self.stream) + "\n")

    def _write(self, text: str) -> bool:
        if self._io_failed:
            return False
        try:
            self.stream.write(text)
            self.stream.flush()
        except Exception:
            self._io_failed = True
            self._stop.set()
            return False
        return True

    def _animate(self) -> None:
        try:
            while not self._stop.wait(_INTERVAL):
                with self._lock:
                    if self._closed:
                        return
                    self._draw(time.monotonic())
        except Exception:
            # Display errors are observational and must not kill background work.
            self._stop.set()

    def _close(
        self, message: str | None = None, *, tone: str = "muted", failed: bool = False
    ) -> None:
        self._stop.set()
        try:
            with self._lock:
                if self._closed:
                    return
                self._closed = True
                if not self.enabled or not self._entered:
                    return
                now = time.monotonic()
                if failed:
                    self._clear_line()
                    if self._event is not None and not self._phase_finished:
                        self._write_line(self._phase_line(now, ending=False), tone="warning")
                else:
                    self._complete_phase(now)
                if message is not None:
                    self._write_line(f"{message} ({_elapsed(now - self._started)})", tone=tone)
        finally:
            # Never join while holding the lock needed by the animation thread.
            if self._thread is not None and self._thread is not threading.current_thread():
                self._thread.join()
