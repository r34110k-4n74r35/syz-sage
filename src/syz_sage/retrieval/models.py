"""Update options, listing scope, and structured retrieval results."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class UpdateOptions:
    namespace: str = "upstream"
    status: str = "fixed"
    workers: int = 8
    refresh_details: bool = False
    refresh_artifacts: bool = False
    reports: bool = True
    patches: bool = True
    limit: int | None = None
    recheck_fixes: bool = False


@dataclass(slots=True)
class UpdateSummary:
    namespace: str
    status: str
    listing_bugs: int = 0
    known_fixed_bugs: int = 0
    new_fixed_bugs: int = 0
    new_fixed_bug_keys: list[str] = field(default_factory=list)
    changed_bugs: int = 0
    changed_bug_keys: list[str] = field(default_factory=list)
    no_longer_listed_bugs: int = 0
    no_longer_listed_bug_keys: list[str] = field(default_factory=list)
    details_downloaded: int = 0
    details_reused: int = 0
    reports_downloaded: int = 0
    reports_reused: int = 0
    reports_unavailable: int = 0
    patches_downloaded: int = 0
    patches_reused: int = 0
    failures: list[dict[str, str]] = field(default_factory=list)
    database: dict[str, Any] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        if self.failures or not self.database:
            return False
        return (
            self.database.get("status") in {"completed", "unchanged"}
            and not self.database.get("failure_count")
            and not self.database.get("failures")
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "namespace": self.namespace,
            "status": self.status,
            "listing_bugs": self.listing_bugs,
            "known_fixed_bugs": self.known_fixed_bugs,
            "new_fixed_bugs": self.new_fixed_bugs,
            "new_fixed_bug_keys": self.new_fixed_bug_keys,
            "changed_bugs": self.changed_bugs,
            "changed_bug_keys": self.changed_bug_keys,
            "no_longer_listed_bugs": self.no_longer_listed_bugs,
            "no_longer_listed_bug_keys": self.no_longer_listed_bug_keys,
            "details_downloaded": self.details_downloaded,
            "details_reused": self.details_reused,
            "reports_downloaded": self.reports_downloaded,
            "reports_reused": self.reports_reused,
            "reports_unavailable": self.reports_unavailable,
            "patches_downloaded": self.patches_downloaded,
            "patches_reused": self.patches_reused,
            "failures": self.failures,
            "database": self.database,
        }


@dataclass(frozen=True, slots=True)
class UpdatePlan:
    """Validated listing membership and the scope selected for this attempt."""

    records: list[dict[str, Any]]
    selected: list[dict[str, Any]]

    @property
    def live_keys(self) -> set[str]:
        return {str(record["key"]) for record in self.records}
