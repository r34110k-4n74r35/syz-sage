"""Run Syz Sage with ``python -m syz_sage``."""

from __future__ import annotations

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
