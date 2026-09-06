"""Shared paths and URL helpers for the Syzbot data fetchers."""

from __future__ import annotations

from pathlib import Path

from syz_sage.artifacts import atomic_write
from syz_sage.client import SyzbotClient, normalize_patch_repository
from syz_sage.parsing import DEFAULT_DASHBOARD
from syz_sage.storage import (
    make_directory,
    project_root,
)
from syz_sage.storage import (
    writable_path as writable_path,
)

ROOT = project_root()
DATA = ROOT / "data"
RAW = DATA / "raw"
PROCESSED = DATA / "processed"
ARTIFACTS = DATA / "artifacts"
BUG_JSON = RAW / "bugs"
REPORTS = ARTIFACTS / "reports"
PATCHES = ARTIFACTS / "patches"
REPROS = ARTIFACTS / "repros"
CONFIGS = ARTIFACTS / "configs"
DASHBOARD = DEFAULT_DASHBOARD
CLIENT = SyzbotClient(dashboard=DASHBOARD)


def write_bytes(path: Path, payload: bytes) -> None:
    """Use the same validated atomic file replacement as the main updater."""
    atomic_write(path, payload)


def write_text(path: Path, payload: str) -> None:
    write_bytes(path, payload.encode("utf-8"))


def ensure_dirs() -> None:
    # Optional artifact writers create their own parent directories when needed.
    paths = [writable_path(p) for p in (RAW, PROCESSED, BUG_JSON, REPORTS, PATCHES)]
    for path in paths:
        make_directory(path)


def normalize_repo_url(repo: str) -> str:
    return normalize_patch_repository(repo)[1]


def git_patch_url(repo: str, commit_hash: str) -> str:
    return SyzbotClient.patch_urls(commit_hash, repo)[0]


def github_diff_url(commit_hash: str) -> str:
    return SyzbotClient.patch_urls(commit_hash, None)[-1]
