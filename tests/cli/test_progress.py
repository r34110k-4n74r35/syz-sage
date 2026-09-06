from __future__ import annotations

import io
import os
import re
import threading
import unittest
from unittest import mock

from syz_sage.cli.progress import ProgressDisplay, _columns
from syz_sage.project.progress_events import ProgressEvent

_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")


class TerminalStream(io.StringIO):
    def isatty(self) -> bool:
        return True


class ProgressTests(unittest.TestCase):
    def test_pipe_is_plain_and_sparse_but_keeps_phase_counts(self) -> None:
        stream = io.StringIO()
        with ProgressDisplay("Updating fixed bugs", stream=stream) as display:
            for completed in range(101):
                display(ProgressEvent("reports", "Fetching reports", completed, 100))
            display(ProgressEvent("database", "Importing saved files"))
            display.finish(success=False)
        output = stream.getvalue()
        self.assertNotIn("\r", output)
        self.assertNotIn("\x1b", output)
        self.assertEqual(len(output.splitlines()), 6)
        self.assertIn("Fetching reports (  0% 0/100", output)
        self.assertIn("100% 100/100 processed", output)
        self.assertIn("Importing saved files", output)
        self.assertEqual(output.count("Partial result"), 1)
        self.assertNotIn("Complete", output)

    def test_disabled_display_writes_nothing_and_starts_no_thread(self) -> None:
        stream = TerminalStream()
        with (
            mock.patch("syz_sage.cli.progress.threading.Thread") as thread,
            ProgressDisplay("Silent", enabled=False, stream=stream) as display,
        ):
            display(ProgressEvent("reports", "Fetching", 1, 2))
            display.log("Also silent")
            display.finish()
        thread.assert_not_called()
        self.assertEqual(stream.getvalue(), "")

    def test_dumb_terminal_has_no_animation_or_escape_sequences(self) -> None:
        stream = TerminalStream()
        with (
            mock.patch.dict(os.environ, {"TERM": "dumb"}),
            mock.patch("syz_sage.cli.progress.threading.Thread") as thread,
            ProgressDisplay("Updating", stream=stream) as display,
        ):
            display(ProgressEvent("listing", "Checking remote listing"))
        thread.assert_not_called()
        self.assertNotIn("\r", stream.getvalue())
        self.assertNotIn("\x1b", stream.getvalue())

    def test_no_color_keeps_animation_without_color_codes(self) -> None:
        stream = TerminalStream()
        with (
            mock.patch.dict(os.environ, {"TERM": "xterm", "NO_COLOR": ""}),
            mock.patch("syz_sage.cli.progress.threading.Thread"),
            ProgressDisplay("Updating", stream=stream) as display,
        ):
            display(ProgressEvent("listing", "Checking remote listing"))
        self.assertIn("\r\x1b[2K", stream.getvalue())
        self.assertNotRegex(stream.getvalue(), r"\x1b\[[0-9;]*m")

    def test_unknown_work_spins_without_fabricating_percentages(self) -> None:
        stream = TerminalStream()
        with (
            mock.patch.dict(os.environ, {"TERM": "xterm"}),
            mock.patch("syz_sage.cli.progress.threading.Thread"),
            ProgressDisplay("Updating", stream=stream) as display,
        ):
            display(ProgressEvent("listing", "Checking remote listing"))
            display._draw(display._last_draw + 5)
        output = _ANSI.sub("", stream.getvalue())
        self.assertIn("| Checking remote listing", output)
        self.assertIn("/ Checking remote listing", output)
        self.assertNotIn("%", output)
        self.assertIn("5.0s", output)

    def test_known_total_uses_counts_and_does_not_advance_with_time(self) -> None:
        stream = TerminalStream()
        with (
            mock.patch.dict(os.environ, {"TERM": "xterm"}),
            mock.patch("syz_sage.cli.progress.threading.Thread"),
            mock.patch("syz_sage.cli.progress.terminal_width", return_value=96),
            ProgressDisplay("Updating", stream=stream) as display,
        ):
            display(ProgressEvent("reports", "Fetching reports", 3, 12))
            display._draw(display._last_draw + 9)
        output = _ANSI.sub("", stream.getvalue())
        self.assertGreaterEqual(output.count("25% 3/12"), 2)
        self.assertIn("[###", output)
        self.assertNotIn("100%", output)

    def test_fast_counter_updates_are_throttled_but_completion_is_immediate(self) -> None:
        stream = TerminalStream()
        with (
            mock.patch.dict(os.environ, {"TERM": "xterm"}),
            mock.patch("syz_sage.cli.progress.threading.Thread"),
            mock.patch("syz_sage.cli.progress.time.monotonic", return_value=10.0),
            ProgressDisplay("Updating", stream=stream) as display,
        ):
            for completed in range(101):
                display(ProgressEvent("reports", "Fetching reports", completed, 100))
            self.assertIn("100% 100/100 processed", stream.getvalue())
        # The initial frame and its final erasure, not one redraw per item.
        self.assertEqual(stream.getvalue().count("\r"), 2)

    def test_zero_jobs_finishes_without_percentage_or_success_claim(self) -> None:
        stream = io.StringIO()
        with ProgressDisplay("Updating", stream=stream) as display:
            display(ProgressEvent("reports", "Checking reports", 0, 0))
        output = stream.getvalue()
        self.assertIn("0/0 (no work)", output)
        self.assertNotIn("%", output)
        self.assertNotIn("Complete", output)
        self.assertNotIn("success", output.lower())

    def test_width_is_rechecked_and_wide_source_text_cannot_overrun(self) -> None:
        stream = TerminalStream()
        with (
            mock.patch.dict(os.environ, {"TERM": "xterm", "NO_COLOR": "1"}),
            mock.patch("syz_sage.cli.progress.threading.Thread"),
            mock.patch("syz_sage.cli.progress.terminal_width", return_value=80) as width,
            ProgressDisplay("Updating", stream=stream) as display,
        ):
            display(ProgressEvent("reports", "\u754c" * 40, 3, 12))
            before = len(stream.getvalue())
            width.return_value = 24
            display._draw(display._last_draw + 1)
            narrowed = _ANSI.sub("", stream.getvalue()[before:]).strip("\r")
            self.assertLessEqual(_columns(narrowed), 23)
            self.assertIn("25% 3/12", narrowed)
            before = len(stream.getvalue())
            width.return_value = 8
            display._draw(display._last_draw + 1)
            tiny = _ANSI.sub("", stream.getvalue()[before:]).strip("\r")
            self.assertLessEqual(_columns(tiny), 7)

    def test_log_clears_active_line_and_then_resumes_animation(self) -> None:
        stream = TerminalStream()
        with (
            mock.patch.dict(os.environ, {"TERM": "xterm"}),
            mock.patch("syz_sage.cli.progress.threading.Thread"),
            ProgressDisplay("Updating", stream=stream) as display,
        ):
            display(ProgressEvent("reports", "Fetching reports", 1, 5))
            before = len(stream.getvalue())
            display.log("Retrying one report")
            output = stream.getvalue()[before:]
            self.assertTrue(output.startswith("\r\x1b[2K"))
            self.assertIn("Retrying one report", output)
            self.assertIn("\n\r\x1b[2K", output)
            self.assertIn("20% 1/5", output)

    def test_source_controls_are_escaped(self) -> None:
        stream = io.StringIO()
        with ProgressDisplay("Title\x1b[2J", stream=stream) as display:
            display(ProgressEvent("reports\r", "Bad\x1b[31m\nmessage"))
            display.log("Log\nsecond line")
        output = stream.getvalue()
        self.assertNotIn("\x1b", output)
        self.assertNotIn("\r", output)
        self.assertIn(r"\x1b[31m\x0amessage", output)
        self.assertIn(r"Log\x0asecond line", output)

    def test_completion_is_neutral_and_partial_outcome_is_not_green(self) -> None:
        stream = TerminalStream()
        with (
            mock.patch.dict(os.environ, {"TERM": "xterm"}, clear=True),
            mock.patch("syz_sage.cli.progress.threading.Thread"),
            ProgressDisplay("Updating", stream=stream) as display,
        ):
            display(ProgressEvent("reports", "Fetching reports", 5, 5))
            display(ProgressEvent("database", "Importing files"))
            display.finish("One report failed", success=False)
        output = stream.getvalue()
        self.assertIn("100% 5/5 processed", output)
        self.assertIn("\x1b[33mOne report failed", output)
        self.assertNotIn("\x1b[32m", output)
        self.assertEqual(output.count("One report failed"), 1)

    def test_error_and_interrupt_propagate_and_leave_no_animation_thread(self) -> None:
        for error, label in [
            (ValueError("bad data"), "Failed"),
            (KeyboardInterrupt(), "Interrupted"),
        ]:
            with self.subTest(label=label):
                stream = TerminalStream()
                with mock.patch.dict(os.environ, {"TERM": "xterm"}, clear=True):
                    display = ProgressDisplay("Updating", stream=stream)
                    with self.assertRaises(type(error)), display:
                        display(ProgressEvent("reports", "Fetching reports", 1, 5))
                        raise error
                self.assertIsNotNone(display._thread)
                assert display._thread is not None
                self.assertFalse(display._thread.is_alive())
                self.assertTrue(stream.getvalue().endswith("\n"))
                self.assertIn(label, stream.getvalue())
                self.assertNotIn("Complete", stream.getvalue())
                self.assertNotIn("processed", stream.getvalue())
                self.assertNotIn("\x1b[32m", stream.getvalue())

    def test_spinner_advances_while_caller_is_blocked_and_stops_after_exit(self) -> None:
        advanced = threading.Event()

        class RecordingStream(TerminalStream):
            frames = 0

            def write(self, value: str) -> int:
                result = super().write(value)
                if value.startswith("\r") and "Checking remote listing" in value:
                    self.frames += 1
                    if self.frames >= 2:
                        advanced.set()
                return result

        stream = RecordingStream()
        with (
            mock.patch.dict(os.environ, {"TERM": "xterm"}),
            mock.patch("syz_sage.cli.progress._INTERVAL", 0.01),
            ProgressDisplay("Updating", stream=stream) as display,
        ):
            display(ProgressEvent("listing", "Checking remote listing"))
            self.assertTrue(advanced.wait(1), "Spinner did not advance without another event")
        assert display._thread is not None
        self.assertFalse(display._thread.is_alive())
        self.assertTrue(display._stop.is_set())

    def test_explicit_success_is_rendered_once(self) -> None:
        stream = io.StringIO()
        with ProgressDisplay("Updating", stream=stream) as display:
            display(ProgressEvent("reports", "Fetching reports", 1, 1))
            display.finish()
            display.finish()
        self.assertEqual(stream.getvalue().count("Complete"), 1)

    def test_unknown_total_keeps_processed_count_and_spinner(self) -> None:
        stream = TerminalStream()
        with (
            mock.patch.dict(os.environ, {"TERM": "xterm", "NO_COLOR": "1"}),
            mock.patch("syz_sage.cli.progress.threading.Thread"),
            ProgressDisplay("Checking", stream=stream) as display,
        ):
            display(ProgressEvent("check-internal-blobs", "Checking stored files", 17))
            display._draw(display._last_draw + 1)
        output = _ANSI.sub("", stream.getvalue())
        self.assertIn("17 processed", output)
        self.assertIn("| Checking stored files", output)
        self.assertIn("/ Checking stored files", output)
        self.assertNotIn("%", output)
        self.assertNotIn("check-internal-blobs", output)
        self.assertNotIn("processed processed", output)

    def test_finished_long_message_retains_count_and_elapsed(self) -> None:
        stream = TerminalStream()
        with (
            mock.patch.dict(os.environ, {"TERM": "xterm", "NO_COLOR": "1"}),
            mock.patch("syz_sage.cli.progress.threading.Thread"),
            mock.patch("syz_sage.cli.progress.terminal_width", return_value=48),
            ProgressDisplay("Updating", stream=stream) as display,
        ):
            display(ProgressEvent("reports", "A very long description " * 10, 10, 10))
        final_line = stream.getvalue().splitlines()[-1]
        self.assertLessEqual(_columns(final_line), 47)
        self.assertIn("100% 10/10 processed; 0.0s", final_line)

    def test_narrow_completion_prefers_counts_and_time_to_extra_prose(self) -> None:
        stream = TerminalStream()
        with (
            mock.patch.dict(os.environ, {"TERM": "xterm", "NO_COLOR": "1"}),
            mock.patch("syz_sage.cli.progress.threading.Thread"),
            mock.patch("syz_sage.cli.progress.terminal_width", return_value=24),
            ProgressDisplay("Updating", stream=stream) as display,
        ):
            display(ProgressEvent("reports", "Fetching reports", 10, 10))
        final_line = stream.getvalue().splitlines()[-1]
        self.assertLessEqual(_columns(final_line), 23)
        self.assertIn("100% 10/10", final_line)
        self.assertIn("0.0s", final_line)

    def test_active_line_uses_distinct_label_counts_and_bar_tones(self) -> None:
        stream = TerminalStream()
        with (
            mock.patch.dict(os.environ, {"TERM": "xterm"}, clear=True),
            mock.patch("syz_sage.cli.progress.threading.Thread"),
            mock.patch("syz_sage.cli.progress.terminal_width", return_value=96),
            ProgressDisplay("Updating", stream=stream) as display,
        ):
            display(ProgressEvent("reports", "Fetching reports", 1, 2))
        output = stream.getvalue()
        self.assertIn("\x1b[1mFetching reports", output)
        self.assertIn("\x1b[1;36m 50% 1/2", output)
        self.assertIn("\x1b[36m###", output)
        self.assertIn("\x1b[2m---", output)

    def test_broken_display_stream_does_not_mask_operation_error(self) -> None:
        class BrokenStream(TerminalStream):
            def write(self, value: str) -> int:
                raise OSError("closed display destination")

        with (
            mock.patch.dict(os.environ, {"TERM": "xterm"}),
            mock.patch("syz_sage.cli.progress.threading.Thread") as thread,
            self.assertRaisesRegex(ValueError, "original failure"),
            ProgressDisplay("Updating", stream=BrokenStream()) as display,
        ):
            display(ProgressEvent("reports", "Fetching reports", 1, 5))
            raise ValueError("original failure")
        thread.assert_not_called()


if __name__ == "__main__":
    unittest.main()
