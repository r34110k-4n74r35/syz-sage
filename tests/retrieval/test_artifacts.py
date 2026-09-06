from __future__ import annotations

import contextlib
import hashlib
import threading
import unittest
from pathlib import Path
from unittest import mock

from syz_sage.parsing.listing import PayloadError
from syz_sage.project.storage import temporary_directory
from syz_sage.retrieval.artifacts import (
    DownloadJob,
    atomic_write,
    bounded_results,
    fetch_artifact,
    validate_artifact,
)


class ArtifactTests(unittest.TestCase):
    def test_detail_is_validated_and_decoded_once(self) -> None:
        payload = b'{"title":"example", "crashes":[]}'
        job = DownloadJob("bug-json", "id-example", Path("unused.json"))
        from syz_sage.parsing import listing as parsing

        with mock.patch.object(
            parsing, "decode_json_object", wraps=parsing.decode_json_object
        ) as decode:
            result = validate_artifact(job, payload)
        self.assertEqual(decode.call_count, 1)
        self.assertEqual(result.detail, {"title": "example", "crashes": []})
        self.assertEqual(result.digest, hashlib.sha256(payload).hexdigest())
        self.assertIs(result.payload, payload)

    def test_patch_result_preserves_successful_fallback_url_and_bytes(self) -> None:
        payload = b"diff --git a/file.c b/file.c\n--- a/file.c\n+++ b/file.c\n"
        commit_hash = "a" * 40
        url = f"https://github.com/torvalds/linux/commit/{commit_hash}.diff"
        client = mock.Mock()
        client.patch.return_value = payload, url
        job = DownloadJob(
            "patch", commit_hash, Path("unused.diff"), repo="git://git.kernel.org/repo"
        )

        result = fetch_artifact(client, job)

        client.patch.assert_called_once_with(commit_hash, job.repo)
        self.assertIs(result.payload, payload)
        self.assertEqual(result.source_url, url)

    def test_invalid_responses_never_reach_atomic_save(self) -> None:
        with temporary_directory() as directory:
            path = Path(directory) / "report.txt"
            path.write_bytes(b"original crash report")
            job = DownloadJob("report", "id-example", path)
            with self.assertRaises(PayloadError):
                result = validate_artifact(job, b"<html>upstream error</html>")
                atomic_write(path, result.payload)
            self.assertEqual(path.read_bytes(), b"original crash report")

    def test_bounded_queue_is_lazy_even_with_instant_downloads(self) -> None:
        scheduled: list[int] = []

        def jobs():
            for value in range(1000):
                scheduled.append(value)
                yield value

        consumed = 0
        with contextlib.closing(
            bounded_results(jobs(), lambda value: value * 2, workers=2)
        ) as results:
            for job, future in results:
                self.assertLessEqual(len(scheduled) - consumed, 4)
                self.assertEqual(future.result(), job * 2)
                consumed += 1
                if consumed == 10:
                    break
        self.assertLess(len(scheduled), 1000)

    def test_failure_does_not_hide_other_completed_results(self) -> None:
        def fetch(value: int) -> int:
            if value == 2:
                raise OSError("planned failure")
            return value

        successes = []
        errors = []
        for job, future in bounded_results(range(5), fetch, workers=2):
            try:
                successes.append(future.result())
            except OSError:
                errors.append(job)
        self.assertEqual(sorted(successes), [0, 1, 3, 4])
        self.assertEqual(errors, [2])

    def test_generator_close_signals_running_workers_before_joining_them(self) -> None:
        running = threading.Event()
        cancelled = threading.Event()

        def fetch(value: int) -> int:
            if value == 0:
                if not running.wait(timeout=2):
                    raise RuntimeError("test worker never started")
                return value
            running.set()
            if not cancelled.wait(timeout=2):
                raise RuntimeError("running worker did not receive cancellation")
            return value

        results = bounded_results([0, 1], fetch, workers=2, cancel=cancelled.set)
        with contextlib.closing(results):
            job, future = next(results)
            self.assertEqual((job, future.result()), (0, 0))
        self.assertTrue(cancelled.is_set())

    def test_completed_iteration_does_not_cancel_client_for_the_next_phase(self) -> None:
        cancel = mock.Mock()
        results = list(bounded_results([1, 2], lambda value: value, workers=1, cancel=cancel))
        self.assertEqual(sorted(future.result() for _, future in results), [1, 2])
        cancel.assert_not_called()

    def test_interrupt_while_waiting_cancels_workers_before_executor_shutdown(self) -> None:
        cancelled = threading.Event()

        def fetch(value: int) -> int:
            if not cancelled.wait(timeout=2):
                raise RuntimeError("worker was not cancelled during interrupted wait")
            return value

        with (
            mock.patch("syz_sage.retrieval.artifacts.wait", side_effect=KeyboardInterrupt),
            self.assertRaises(KeyboardInterrupt),
        ):
            list(bounded_results([1, 2], fetch, workers=2, cancel=cancelled.set))
        self.assertTrue(cancelled.is_set())


if __name__ == "__main__":
    unittest.main()
