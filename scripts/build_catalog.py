#!/usr/bin/env python3
"""Convert Syzbot's fixed-bug listing into the fetcher's flat catalog."""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone

from .common import DASHBOARD, PROCESSED, RAW, ensure_dirs, write_text


def key_from_link(link: str) -> str:
    match = re.search(r"[?&](extid|id)=([^&]+)", link)
    if not match:
        return ""
    return f"{match.group(1)}-{match.group(2)}"


def main() -> None:
    argparse.ArgumentParser(description=__doc__).parse_args()
    ensure_dirs()
    source = RAW / "upstream_fixed.json"
    payload = json.loads(source.read_text())
    listing = payload.get("Bugs") or payload.get("bugs") or []
    bugs = []
    for bug in listing:
        link = bug.get("link") or ""
        key = key_from_link(link)
        if not key:
            continue
        absolute = link if link.startswith("http") else DASHBOARD + link
        separator = "&" if "?" in absolute else "?"
        fixes = bug.get("fix-commits") or []
        hashes = [fix.get("hash") for fix in fixes if fix.get("hash")]
        bugs.append(
            {
                "key": key,
                "title": bug.get("title", ""),
                "bug_url": absolute,
                "json_url": f"{absolute}{separator}json=1",
                "fix_commits": fixes,
                "primary_fix_hash": hashes[0] if hashes else "",
            }
        )
    out = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": f"{DASHBOARD}/upstream/fixed?json=1",
        "source_version": payload.get("version"),
        "bugs": bugs,
    }
    dest = PROCESSED / "catalog.json"
    write_text(dest, json.dumps(out, indent=2, ensure_ascii=False) + "\n")
    print(
        json.dumps(
            {
                "output": str(dest),
                "fixed_listing": len(listing),
                "catalog": len(bugs),
                "with_hash": sum(bool(b["primary_fix_hash"]) for b in bugs),
                "without_hash": sum(not b["primary_fix_hash"] for b in bugs),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
