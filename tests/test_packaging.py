from __future__ import annotations

import unittest
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - exercised on Python 3.10
    import tomli as tomllib

ROOT = Path(__file__).resolve().parents[1]


class PackagingTests(unittest.TestCase):
    def test_distribution_and_both_console_entry_points_are_declared(self) -> None:
        metadata = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        project = metadata["project"]

        self.assertEqual(project["name"], "syz-sage")
        self.assertEqual(project["scripts"]["syz-sage"], "syz_sage.cli:main")
        self.assertEqual(project["scripts"]["ss"], "syz_sage.cli:main")

    def test_build_configuration_uses_the_src_layout(self) -> None:
        self.assertTrue((ROOT / "src" / "syz_sage" / "__init__.py").is_file())
        self.assertTrue((ROOT / "src" / "syz_sage" / "__main__.py").is_file())


if __name__ == "__main__":
    unittest.main()
