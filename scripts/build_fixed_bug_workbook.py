"""Run the project's Node workbook builder at the requested output paths."""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

from syz_sage.project.storage import writable_path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("analysis", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("previews", type=Path)
    args = parser.parse_args()
    try:
        output = writable_path(args.output)
        previews = writable_path(args.previews)
    except ValueError as exc:
        parser.error(str(exc))
    node = shutil.which("node")
    if node is None:
        parser.error("Node.js is required for workbook generation")
    return subprocess.run(
        [
            node,
            str(Path(__file__).with_suffix(".mjs")),
            str(args.analysis.expanduser().resolve()),
            str(output),
            str(previews),
        ],
        check=False,
    ).returncode


if __name__ == "__main__":
    sys.exit(main())
