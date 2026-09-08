"""Human output for comparisons, descriptive statistics, and selective retrieval."""

from __future__ import annotations

from typing import Any

from ..terminal import paragraph, safe_text, section
from .common import bug_type_label, c_reproducer_label, fields, title_colors


def _case(value: dict[str, Any]) -> None:
    paragraph(value.get("title") or value["key"], highlight=title_colors)
    fields(
        [
            ("Key", value["key"]),
            ("URL", value.get("bug_url") or "unknown"),
            ("Bug type", bug_type_label(value.get("bug_type"))),
            ("Failure pattern", value.get("family") or "unknown"),
            ("Access", value.get("access_mode") or "unknown"),
            ("Subsystems", ", ".join(value.get("subsystems") or []) or "unknown"),
            ("C reproducer", c_reproducer_label(value.get("c_reproducer_status"))),
        ]
    )


def _reasons(reasons: list[dict[str, Any]]) -> None:
    if not reasons:
        paragraph("No shared commit or source location recorded.", indent=2, tone="muted")
    for reason in reasons:
        fields([(reason["kind"].replace("-", " ").capitalize(), ", ".join(reason["values"]))])


def human_related(value: dict[str, Any]) -> None:
    paragraph(f"Related bugs · {value['bug']['key']}", tone="heading")
    fields([("Matches", value["total"]), ("Showing", len(value["matches"]))])
    for index, match in enumerate(value["matches"], 1):
        section(f"{index}. {match['bug']['key']}")
        _case(match["bug"])
        _reasons(match["reasons"])
    print()
    paragraph(value["method"], tone="muted")
    paragraph(value["interpretation"], tone="muted")


def human_compare(value: dict[str, Any]) -> None:
    paragraph("Compare fixed bugs", tone="heading")
    for label in ("left", "right"):
        section("A" if label == "left" else "B")
        bug = value[label]
        _case(bug)
        locations = bug.get("crash_locations") or []
        fields(
            [
                (
                    "Crash sites",
                    "; ".join(
                        f"{loc.get('function_name') or '?'} at "
                        f"{loc.get('file_path') or '?'}:{loc.get('line_number') or '?'}"
                        for loc in locations
                    )
                    or "unknown",
                )
            ]
        )
        paths = sorted(
            {
                str(loc[field])
                for loc in bug.get("fix_locations") or []
                for field in ("old_file_path", "new_file_path")
                if loc.get(field)
            }
        )
        fields([("Changed files", ", ".join(paths) or "unknown")])
        for fix in bug.get("fixes", []):
            fields(
                [
                    ("Commit", fix.get("commit_hash") or fix.get("hash") or "unresolved"),
                    ("Fix", fix.get("title") or "unknown"),
                ]
            )
    section("Shared evidence")
    _reasons(value["shared_evidence"])
    section("Differences")
    if not value["differences"]:
        paragraph("Selected diagnostic and metadata fields match.", indent=2, tone="muted")
    for difference in value["differences"]:
        paragraph(difference["field"].replace("_", " ").capitalize(), indent=2, tone="strong")
        fields([("A", difference["left"]), ("B", difference["right"])], indent=4)
    print()
    paragraph(value["interpretation"], tone="muted")


def human_statistics(value: dict[str, Any], *, top: int = 10) -> None:
    paragraph("Fixed-bug statistics", tone="heading")
    total = value["total_bugs"]
    fields(
        [
            ("Selected bugs", f"{total:,}"),
            ("Distinct fix commits", f"{value['distinct_fix_commits']:,}"),
            ("Bug–commit links", f"{value['bug_commit_links']:,}"),
            ("Bugs without a fix hash", f"{value['bugs_without_known_fix_hash']:,}"),
        ]
    )
    section("Evidence availability · bug counts")
    available = value["availability"]
    fields(
        [
            (name.replace("_", " ").capitalize(), f"{count:,} / {total:,}")
            for name, count in available.items()
            if isinstance(count, int)
        ]
    )
    for entry in available["c_reproducer"]:
        fields([("C repro " + entry["value"], f"{entry['count']:,} / {total:,}")])
    for name, entries in value["counts"].items():
        section(name.replace("_", " ").capitalize() + " · bugs per value")
        if not entries:
            paragraph("None recorded.", indent=2, tone="muted")
        fields(
            [
                (safe_text(entry["value"]), f"{entry['count']:,} / {total:,}")
                for entry in entries[:top]
            ]
        )
        if len(entries) > top:
            paragraph(
                f"{len(entries) - top:,} more values; increase --top or use --json.",
                indent=2,
                tone="muted",
            )
    section("Fix sizes · complete known evidence only")
    for metric, summary in value["fix_size"].items():
        paragraph(metric.replace("_", " ").capitalize(), indent=2, tone="strong")
        fields(
            [
                (name.replace("_", " ").capitalize(), number if number is not None else "unknown")
                for name, number in summary.items()
            ],
            indent=4,
        )
    section("Counting rules")
    for rule in value["counting_rules"]:
        paragraph(rule, indent=2, tone="muted")


def human_fetch(value: dict[str, Any]) -> None:
    paragraph("Selected crash evidence", tone="heading")
    crash = value["crash"]
    fields(
        [
            ("Key", value["key"]),
            ("Crash ordinal", crash["ordinal"]),
            ("Kernel commit", crash.get("kernel_source_commit") or "unknown"),
            ("Downloaded", value["downloaded"]),
            ("Reused", value["reused"]),
            ("Unavailable", value["unavailable"]),
        ]
    )
    for item in value["artifacts"]:
        section(item["kind"].replace("_", " ").replace("-", " ").capitalize())
        fields(
            [
                ("Result", item["status"]),
                ("URL", item.get("url") or "not recorded"),
                ("File", item.get("path") or "not saved"),
            ]
        )
        if item.get("error"):
            paragraph(item["error"], indent=2, tone="error")
    print()
    paragraph(
        "Downloaded source has not been compiled or executed; reproduction is untested.",
        tone="muted",
    )
