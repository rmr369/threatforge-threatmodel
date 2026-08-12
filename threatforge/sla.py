# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""
Remediation SLA policy.

The clock starts when a finding is **first seen**, not when someone notices it.
That distinction is the whole point: a critical finding that has been sitting in
the repository for eight months is eight months overdue, not new today. Stable
finding ids make the first-seen date meaningful across scans.

Default windows, in days from first sighting:

    critical   7
    high      30
    medium    90
    low      180
    info       -- no SLA

Override in `.threatforge.yml`:

    sla:
      windows: {critical: 3, high: 14, medium: 60, low: 180}
      business_days: false
      grace_days: 0
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional

DEFAULT_WINDOWS: Dict[str, Optional[int]] = {
    "critical": 7,
    "high": 30,
    "medium": 90,
    "low": 180,
    "info": None,          # tracked, never overdue
}

# Statuses that stop the clock.
CLOSED_STATUSES = {"resolved", "accepted", "false_positive", "suppressed"}
OPEN_STATUSES = {"open", "in_progress", "awaiting_verification"}

ALL_STATUSES = sorted(OPEN_STATUSES | CLOSED_STATUSES)


def today() -> date:
    return datetime.now(timezone.utc).date()


def parse_date(value: Any) -> Optional[date]:
    if not value:
        return None
    if isinstance(value, date) and not isinstance(value, datetime):
        return value
    if isinstance(value, datetime):
        return value.date()
    text = str(value)
    for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            return datetime.strptime(text[:len(fmt) + 6], fmt).date()
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).date()
    except ValueError:
        return None


@dataclass
class Policy:
    windows: Dict[str, Optional[int]]
    business_days: bool = False
    grace_days: int = 0

    @staticmethod
    def from_config(cfg: Optional[Dict[str, Any]] = None) -> "Policy":
        section = (cfg or {}).get("sla", {}) or {}
        windows = dict(DEFAULT_WINDOWS)
        for level, days in (section.get("windows") or {}).items():
            key = str(level).lower()
            windows[key] = None if days in (None, "", "none") else int(days)
        return Policy(
            windows=windows,
            business_days=bool(section.get("business_days", False)),
            grace_days=int(section.get("grace_days", 0) or 0),
        )

    def window_for(self, risk_level: str) -> Optional[int]:
        days = self.windows.get(str(risk_level).lower(), None)
        if days is None:
            return None
        return days + self.grace_days

    def due_date(self, risk_level: str, first_seen: Any) -> Optional[date]:
        start = parse_date(first_seen)
        days = self.window_for(risk_level)
        if start is None or days is None:
            return None
        if not self.business_days:
            return start + timedelta(days=days)
        # Skip weekends. Deliberately ignores public holidays -- guessing a
        # jurisdiction's calendar would be worse than being slightly generous.
        current, remaining = start, days
        while remaining > 0:
            current += timedelta(days=1)
            if current.weekday() < 5:
                remaining -= 1
        return current


@dataclass
class SlaState:
    """Where one finding stands against the policy."""
    due_date: Optional[date]
    days_remaining: Optional[int]
    breached: bool
    state: str            # on_track | due_soon | breached | closed | no_sla
    age_days: Optional[int]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "due_date": self.due_date.isoformat() if self.due_date else None,
            "days_remaining": self.days_remaining,
            "breached": self.breached,
            "state": self.state,
            "age_days": self.age_days,
        }


DUE_SOON_DAYS = 7


def evaluate(policy: Policy, risk_level: str, first_seen: Any,
             status: str = "open", resolved_at: Any = None,
             as_of: Optional[date] = None) -> SlaState:
    """Position of a single finding against its SLA."""
    now = as_of or today()
    start = parse_date(first_seen)
    age = (now - start).days if start else None

    if str(status).lower() in CLOSED_STATUSES:
        closed_on = parse_date(resolved_at)
        return SlaState(
            due_date=policy.due_date(risk_level, first_seen),
            days_remaining=None,
            breached=False,
            state="closed",
            age_days=((closed_on - start).days if closed_on and start else age),
        )

    due = policy.due_date(risk_level, first_seen)
    if due is None:
        return SlaState(None, None, False, "no_sla", age)

    remaining = (due - now).days
    if remaining < 0:
        state = "breached"
    elif remaining <= DUE_SOON_DAYS:
        state = "due_soon"
    else:
        state = "on_track"
    return SlaState(due, remaining, remaining < 0, state, age)


def summarise(policy: Policy, rows: Iterable[Dict[str, Any]],
              as_of: Optional[date] = None) -> Dict[str, Any]:
    """Portfolio view: counts, worst offenders, per-owner breakdown.

    `rows` are dicts with risk_level, first_seen, status, resolved_at, owner.
    """
    now = as_of or today()
    buckets = {"on_track": 0, "due_soon": 0, "breached": 0,
               "closed": 0, "no_sla": 0}
    by_level: Dict[str, Dict[str, int]] = {}
    by_owner: Dict[str, Dict[str, int]] = {}
    overdue: List[Dict[str, Any]] = []
    total_open = 0
    resolution_days: List[int] = []

    for row in rows:
        level = str(row.get("risk_level", "medium")).lower()
        status = str(row.get("status", "open")).lower()
        state = evaluate(policy, level, row.get("first_seen"), status,
                         row.get("resolved_at"), now)
        buckets[state.state] = buckets.get(state.state, 0) + 1

        lvl = by_level.setdefault(level, {"open": 0, "breached": 0, "closed": 0})
        owner = row.get("owner") or "unassigned"
        own = by_owner.setdefault(owner, {"open": 0, "breached": 0, "closed": 0})

        if state.state == "closed":
            lvl["closed"] += 1
            own["closed"] += 1
            if state.age_days is not None:
                resolution_days.append(state.age_days)
            continue

        total_open += 1
        lvl["open"] += 1
        own["open"] += 1
        if state.breached:
            lvl["breached"] += 1
            own["breached"] += 1
            overdue.append({
                "id": row.get("id"),
                "rule_id": row.get("rule_id"),
                "title": row.get("title"),
                "component": row.get("component"),
                "risk_level": level,
                "owner": owner,
                "due_date": state.due_date.isoformat() if state.due_date else None,
                "days_overdue": -(state.days_remaining or 0),
                "age_days": state.age_days,
            })

    overdue.sort(key=lambda x: -x["days_overdue"])
    compliant = total_open - buckets["breached"]
    return {
        "as_of": now.isoformat(),
        "policy": {k: v for k, v in policy.windows.items()},
        "buckets": buckets,
        "open": total_open,
        "breached": buckets["breached"],
        "compliance_pct": round(100 * compliant / total_open) if total_open else 100,
        "median_resolution_days": (sorted(resolution_days)[len(resolution_days) // 2]
                                   if resolution_days else None),
        "by_level": by_level,
        "by_owner": dict(sorted(by_owner.items(),
                                key=lambda kv: -kv[1]["breached"])),
        "overdue": overdue[:100],
    }
