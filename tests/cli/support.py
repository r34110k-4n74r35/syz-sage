from __future__ import annotations

import contextlib
import io
import os
import re
import shutil
from pathlib import Path
from unittest import mock

from syz_sage.cli import main
from syz_sage.project.storage import temporary_directory
from tests.support import FIXTURES

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def compact(text: str) -> str:
    """Compare content without depending on presentation alignment or wrapping."""
    return " ".join(ANSI_RE.sub("", text).split())


def invoke(arguments: list[str]) -> tuple[int, str, str]:
    stdout = io.StringIO()
    stderr = io.StringIO()
    with (
        contextlib.redirect_stdout(stdout),
        contextlib.redirect_stderr(stderr),
        mock.patch(
            "syz_sage.cli.terminal.shutil.get_terminal_size",
            return_value=os.terminal_size((96, 24)),
        ),
    ):
        code = main(arguments)
    return code, stdout.getvalue(), stderr.getvalue()


class CliFixture:
    """Reusable fixture setup only; concrete tests live in concern modules."""

    def setUp(self) -> None:
        self.temporary = temporary_directory()
        self.root = Path(self.temporary.name)
        self.legacy = self.root / "legacy"
        shutil.copytree(FIXTURES, self.legacy)
        self.database = self.root / "database" / "syz-sage.sqlite3"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def import_fixture(self) -> None:
        code, stdout, stderr = invoke(
            ["--database", str(self.database), "import-legacy", str(self.legacy)]
        )
        self.assertEqual(code, 0, stderr or stdout)
