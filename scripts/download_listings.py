#!/usr/bin/env python3
"""Refresh the syzbot upstream/fixed JSON and HTML listings."""

from __future__ import annotations

import argparse

from syz_sage.parsing import PayloadError, parse_listing, validate_listing_membership
from syz_sage.sync import _exclusive_update_lock

from .common import CLIENT, DASHBOARD, RAW, ensure_dirs, write_bytes


def main() -> None:
    argparse.ArgumentParser(description=__doc__).parse_args()
    with _exclusive_update_lock(RAW.parent):
        ensure_dirs()
        print(f"GET {DASHBOARD}/upstream/fixed?json=1")
        listing = CLIENT.listing_json()
        records = parse_listing(listing, dashboard=DASHBOARD)
        if not records:
            raise PayloadError("live listing contains no bug records")
        print(f"GET {DASHBOARD}/upstream/fixed")
        html = CLIENT.listing_html()
        if not validate_listing_membership(html, [record["key"] for record in records]):
            raise PayloadError("HTML listing bug keys do not match the JSON listing")
        # Validate both representations before replacing either retained source.
        for name, payload in (("upstream_fixed.json", listing), ("upstream_fixed.html", html)):
            dest = RAW / name
            write_bytes(dest, payload)
            print(f"  wrote {dest} ({dest.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
