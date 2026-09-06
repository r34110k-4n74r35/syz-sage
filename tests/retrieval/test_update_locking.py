from __future__ import annotations

import os
import subprocess
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from syz_sage.retrieval.sync import (
    _exclusive_update_lock,
)
from tests.retrieval.support import UpdaterFixture
from tests.support import (
    PROJECT_ROOT,
)


class UpdateLockingTests(UpdaterFixture, unittest.TestCase):
    def test_existing_input_lock_preserves_read_only_file_and_directory(self) -> None:
        self.paths.root.mkdir()
        lock = self.paths.root / ".syz_sage.update.lock"
        lock.write_bytes(b"saved lock metadata\n")
        lock.chmod(0o444)
        self.paths.root.chmod(0o555)
        before = lock.read_bytes(), lock.stat().st_mtime_ns, lock.stat().st_mode
        try:
            with (
                mock.patch.object(Path, "mkdir", side_effect=AssertionError("created directory")),
                _exclusive_update_lock(self.paths.root, create=False),
            ):
                self.assertEqual(set(self.paths.root.iterdir()), {lock})
            self.assertEqual(
                (lock.read_bytes(), lock.stat().st_mtime_ns, lock.stat().st_mode), before
            )
        finally:
            self.paths.root.chmod(0o755)
            lock.chmod(0o644)

    def test_existing_input_lock_does_not_create_missing_paths(self) -> None:
        with (
            self.assertRaises(FileNotFoundError),
            _exclusive_update_lock(self.paths.root, create=False),
        ):
            self.fail("missing lock was acquired")
        self.assertFalse(self.paths.root.exists())
        self.paths.root.mkdir()
        with (
            self.assertRaises(FileNotFoundError),
            _exclusive_update_lock(self.paths.root, create=False),
        ):
            self.fail("missing lock was acquired")
        self.assertEqual(list(self.paths.root.iterdir()), [])

    def test_windows_existing_empty_lock_does_not_initialize_a_byte(self) -> None:
        self.paths.root.mkdir()
        lock = self.paths.root / ".syz_sage.update.lock"
        lock.write_bytes(b"")
        before = lock.stat().st_mtime_ns
        locking = SimpleNamespace(LK_NBLCK=2, LK_UNLCK=0, locking=mock.Mock())
        with (
            mock.patch(
                "syz_sage.project.storage.os", SimpleNamespace(name="nt", SEEK_END=os.SEEK_END)
            ),
            mock.patch("syz_sage.project.storage.importlib.import_module", return_value=locking),
            _exclusive_update_lock(self.paths.root, create=False),
        ):
            self.assertEqual(lock.read_bytes(), b"")
        self.assertEqual(lock.read_bytes(), b"")
        self.assertEqual(lock.stat().st_mtime_ns, before)
        self.assertEqual(
            [call.args[1:] for call in locking.locking.call_args_list], [(2, 1), (0, 1)]
        )

    def test_update_lock_is_exclusive_between_processes(self) -> None:
        source = PROJECT_ROOT / "src"
        environment = os.environ.copy()
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        environment["PYTHONPATH"] = os.pathsep.join(
            [str(source), environment.get("PYTHONPATH", "")]
        ).rstrip(os.pathsep)
        program = """
import sys
from pathlib import Path
from syz_sage.retrieval.sync import _exclusive_update_lock

try:
    with _exclusive_update_lock(Path(sys.argv[1]), create=sys.argv[2] == "create"):
        pass
except RuntimeError:
    raise SystemExit(23)
"""

        for mode in ("create", "read-only"):
            with self.subTest(mode=mode):
                command = [sys.executable, "-c", program, str(self.paths.root), mode]
                with _exclusive_update_lock(self.paths.root):
                    blocked = subprocess.run(
                        command, check=False, capture_output=True, env=environment
                    )
                available = subprocess.run(
                    command, check=False, capture_output=True, env=environment
                )
                self.assertEqual(blocked.returncode, 23, blocked.stderr.decode())
                self.assertEqual(available.returncode, 0, available.stderr.decode())


if __name__ == "__main__":
    unittest.main()
