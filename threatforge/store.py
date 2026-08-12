# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""
Persistence.

Up to this point ThreatForge has been stateless: every scan recomputes
everything and remembers nothing. That is the right default for a CI gate and
useless for anything involving people. An owner, a status, an SLA clock and a
review decision are all facts about *time*, and time needs a store.

The design rests on one property established earlier: **finding ids are stable
across runs**, derived from `rule_id + component`. That is what lets a scan say
"this is the same finding I saw in March" rather than creating a new row.

Schema
------
    scans     one row per `threatforge scan`, for trend lines
    findings  current state of every finding ever seen, keyed by stable id
    events    append-only audit trail; nothing is edited without a record

Rules of the store
------------------
* A finding is **never deleted**. If it stops appearing in scans it is closed
  as `resolved`, with the date. Deleting would lose the remediation record,
  which is the main thing an auditor asks for.
* `first_seen` is written once and never updated. The SLA clock depends on it.
* Human decisions (owner, status, notes) survive re-scans. The scanner owns
  the technical fields; the human owns the workflow fields.
* SQLite only, single file, no server. `sqlite3` is in the standard library.
"""

from __future__ import annotations

import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

from .model import ThreatModel
from .sla import CLOSED_STATUSES, OPEN_STATUSES, Policy, evaluate

SCHEMA_VERSION = 1

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);

CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    project     TEXT NOT NULL,
    root        TEXT,
    started_at  TEXT NOT NULL,
    duration_s  REAL,
    assets      INTEGER,
    flows       INTEGER,
    findings    INTEGER,
    critical    INTEGER,
    high        INTEGER,
    medium      INTEGER,
    low         INTEGER,
    attack_paths INTEGER
);

CREATE TABLE IF NOT EXISTS findings (
    id           TEXT PRIMARY KEY,
    project      TEXT NOT NULL,
    rule_id      TEXT NOT NULL,
    title        TEXT NOT NULL,
    component    TEXT NOT NULL,
    component_type TEXT,
    severity     TEXT,
    risk_level   TEXT,
    risk_score   INTEGER,
    stride       TEXT,
    confidence   TEXT,
    description  TEXT,
    remediation  TEXT,
    evidence_file TEXT,
    evidence_line INTEGER,
    references_json TEXT,

    -- lifecycle: written by the scanner
    first_seen   TEXT NOT NULL,
    last_seen    TEXT NOT NULL,
    last_scan_id INTEGER,

    -- workflow: written by humans, preserved across scans
    status       TEXT NOT NULL DEFAULT 'open',
    owner        TEXT,
    notes        TEXT,
    resolved_at  TEXT,
    due_override TEXT
);

CREATE INDEX IF NOT EXISTS ix_findings_project ON findings(project);
CREATE INDEX IF NOT EXISTS ix_findings_status  ON findings(status);
CREATE INDEX IF NOT EXISTS ix_findings_level   ON findings(risk_level);

CREATE TABLE IF NOT EXISTS events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id TEXT NOT NULL,
    at         TEXT NOT NULL,
    actor      TEXT,
    kind       TEXT NOT NULL,
    detail     TEXT
);
CREATE INDEX IF NOT EXISTS ix_events_finding ON events(finding_id);
"""

# Fields the scanner owns. Everything else is the human's and must survive.
SCANNER_FIELDS = (
    "project", "rule_id", "title", "component", "component_type", "severity",
    "risk_level", "risk_score", "stride", "confidence", "description",
    "remediation", "evidence_file", "evidence_line", "references_json",
)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def default_db_path(root: str) -> str:
    return os.path.join(os.path.abspath(root), ".threatforge", "threatforge.db")


class Store:
    """SQLite-backed history of findings and their workflow state."""

    def __init__(self, path: str) -> None:
        self.path = os.path.abspath(path)
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        with self._tx() as c:
            c.executescript(SCHEMA)
            c.execute("INSERT OR IGNORE INTO meta(key, value) VALUES('schema', ?)",
                      (str(SCHEMA_VERSION),))

    # -- plumbing ---------------------------------------------------------
    @contextmanager
    def _tx(self):
        cur = self._conn.cursor()
        try:
            yield cur
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise
        finally:
            cur.close()

    def clear(self) -> Dict[str, int]:
        """Throw away every finding, scan and event.

        Deliberately destructive and deliberately total: half a history is
        worse than none, because the SLA clock reads `first_seen` and a
        partially cleared store would date findings from the wrong moment.
        The diagram, overlay and document are untouched -- this clears what
        the analysis produced, not what you drew.
        """
        counts = {
            "findings": self._conn.execute(
                "SELECT COUNT(*) FROM findings").fetchone()[0],
            "scans": self._conn.execute(
                "SELECT COUNT(*) FROM scans").fetchone()[0],
            "events": self._conn.execute(
                "SELECT COUNT(*) FROM events").fetchone()[0],
        }
        with self._conn:
            self._conn.execute("DELETE FROM events")
            self._conn.execute("DELETE FROM findings")
            self._conn.execute("DELETE FROM scans")
        return counts

    def close(self) -> None:
        self._conn.close()

    # -- ingest a scan -----------------------------------------------------
    def record_scan(self, model: ThreatModel, root: str = "") -> Dict[str, Any]:
        """Merge a scan into history.

        Returns a summary of what changed, which is what makes a scan
        interesting to a human: what is new, what came back, what got fixed.
        """
        stamp = now_iso()
        counts = model.counts()

        with self._tx() as c:
            c.execute(
                "INSERT INTO scans(project, root, started_at, duration_s, assets,"
                " flows, findings, critical, high, medium, low, attack_paths)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (model.project, root or model.metadata.get("root", ""), stamp,
                 model.metadata.get("total_seconds"), len(model.assets),
                 len(model.flows), len(model.active_findings),
                 counts["critical"], counts["high"], counts["medium"],
                 counts["low"], len(model.attack_paths)))
            scan_id = c.lastrowid

            seen_ids: List[str] = []
            new_ids: List[str] = []
            reopened_ids: List[str] = []

            for f in model.active_findings:
                seen_ids.append(f.id)
                src = f.primary_source
                row = {
                    "project": model.project,
                    "rule_id": f.rule_id,
                    "title": f.title,
                    "component": f.component,
                    "component_type": f.component_type,
                    "severity": f.severity.value,
                    "risk_level": f.risk_level.value,
                    "risk_score": f.risk_score,
                    "stride": ",".join(f.stride),
                    "confidence": f.confidence.value,
                    "description": " ".join((f.description or "").split()),
                    "remediation": (f.remediation.summary if f.remediation else None),
                    "evidence_file": src.file,
                    "evidence_line": src.line,
                    "references_json": json.dumps(f.references or {}),
                }

                existing = c.execute(
                    "SELECT status, risk_level FROM findings WHERE id = ?",
                    (f.id,)).fetchone()

                if existing is None:
                    cols = ", ".join(SCANNER_FIELDS)
                    marks = ", ".join("?" for _ in SCANNER_FIELDS)
                    c.execute(
                        f"INSERT INTO findings(id, {cols}, first_seen, last_seen,"
                        f" last_scan_id, status) VALUES(?, {marks}, ?, ?, ?, 'open')",
                        (f.id, *[row[k] for k in SCANNER_FIELDS],
                         stamp, stamp, scan_id))
                    new_ids.append(f.id)
                    self._event(c, f.id, "discovered",
                                f"{f.rule_id} on {f.component} "
                                f"({f.risk_level.value}, risk {f.risk_score})")
                    continue

                # Scanner fields refresh; workflow fields are left alone.
                sets = ", ".join(f"{k} = ?" for k in SCANNER_FIELDS)
                c.execute(
                    f"UPDATE findings SET {sets}, last_seen = ?, last_scan_id = ?"
                    f" WHERE id = ?",
                    (*[row[k] for k in SCANNER_FIELDS], stamp, scan_id, f.id))

                if existing["status"] in CLOSED_STATUSES and \
                        existing["status"] != "accepted":
                    c.execute(
                        "UPDATE findings SET status='open', resolved_at=NULL"
                        " WHERE id = ?", (f.id,))
                    reopened_ids.append(f.id)
                    self._event(c, f.id, "reopened",
                                "seen again in a later scan after being closed")

                if existing["risk_level"] != f.risk_level.value:
                    self._event(c, f.id, "risk_changed",
                                f"{existing['risk_level']} -> {f.risk_level.value}")

            # Anything not in this scan, and still open, is fixed.
            placeholders = ",".join("?" for _ in seen_ids) or "''"
            resolved = c.execute(
                f"SELECT id, rule_id, component FROM findings"
                f" WHERE project = ? AND status IN ({','.join('?' for _ in OPEN_STATUSES)})"
                f" AND id NOT IN ({placeholders})",
                (model.project, *sorted(OPEN_STATUSES), *seen_ids)).fetchall()
            for r in resolved:
                c.execute(
                    "UPDATE findings SET status='resolved', resolved_at=?"
                    " WHERE id = ?", (stamp, r["id"]))
                self._event(c, r["id"], "resolved",
                            "no longer present in the scan")

        return {
            "scan_id": scan_id,
            "at": stamp,
            "new": new_ids,
            "reopened": reopened_ids,
            "resolved": [r["id"] for r in resolved],
            "total_seen": len(seen_ids),
        }

    def _event(self, cur, finding_id: str, kind: str, detail: str,
               actor: str = "scanner") -> None:
        cur.execute(
            "INSERT INTO events(finding_id, at, actor, kind, detail)"
            " VALUES(?,?,?,?,?)", (finding_id, now_iso(), actor, kind, detail))

    # -- workflow ----------------------------------------------------------
    def update_finding(self, finding_id: str, *, status: Optional[str] = None,
                       owner: Optional[str] = None, notes: Optional[str] = None,
                       due_override: Optional[str] = None,
                       actor: str = "user") -> Dict[str, Any]:
        """Change workflow state, recording an event for every change."""
        with self._tx() as c:
            before = c.execute("SELECT * FROM findings WHERE id = ?",
                               (finding_id,)).fetchone()
            if before is None:
                raise KeyError(f"unknown finding: {finding_id}")

            if status is not None:
                status = status.lower()
                if status not in (OPEN_STATUSES | CLOSED_STATUSES):
                    raise ValueError(f"invalid status: {status}")
                if status != before["status"]:
                    resolved_at = (now_iso() if status in CLOSED_STATUSES else None)
                    c.execute("UPDATE findings SET status=?, resolved_at=?"
                              " WHERE id=?", (status, resolved_at, finding_id))
                    self._event(c, finding_id, "status_changed",
                                f"{before['status']} -> {status}", actor)

            if owner is not None and owner != (before["owner"] or ""):
                c.execute("UPDATE findings SET owner=? WHERE id=?",
                          (owner or None, finding_id))
                self._event(c, finding_id, "assigned",
                            f"{before['owner'] or 'unassigned'} -> "
                            f"{owner or 'unassigned'}", actor)

            if notes is not None:
                c.execute("UPDATE findings SET notes=? WHERE id=?",
                          (notes, finding_id))
                self._event(c, finding_id, "note", notes[:500], actor)

            if due_override is not None:
                c.execute("UPDATE findings SET due_override=? WHERE id=?",
                          (due_override or None, finding_id))
                self._event(c, finding_id, "due_override",
                            f"due date set to {due_override}", actor)

            row = c.execute("SELECT * FROM findings WHERE id = ?",
                            (finding_id,)).fetchone()
        return dict(row)

    # -- queries -----------------------------------------------------------
    def findings(self, project: Optional[str] = None,
                 status: Optional[Iterable[str]] = None,
                 policy: Optional[Policy] = None) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM findings"
        clauses, params = [], []
        if project:
            clauses.append("project = ?")
            params.append(project)
        if status:
            status = list(status)
            clauses.append(f"status IN ({','.join('?' for _ in status)})")
            params += status
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY risk_score DESC, rule_id"

        rows = [dict(r) for r in self._conn.execute(sql, params).fetchall()]
        pol = policy or Policy.from_config()
        for r in rows:
            state = evaluate(pol, r["risk_level"],
                             r["due_override"] or r["first_seen"],
                             r["status"], r["resolved_at"])
            # An explicit due_override replaces the computed date entirely.
            if r["due_override"]:
                from .sla import parse_date, today
                due = parse_date(r["due_override"])
                remaining = (due - today()).days if due else None
                state.due_date = due
                state.days_remaining = remaining
                state.breached = bool(remaining is not None and remaining < 0
                                      and r["status"] in OPEN_STATUSES)
                state.state = ("closed" if r["status"] in CLOSED_STATUSES
                               else "breached" if state.breached
                               else "due_soon" if (remaining or 99) <= 7
                               else "on_track")
            r["sla"] = state.to_dict()
            r["references"] = json.loads(r.get("references_json") or "{}")
        return rows

    def events(self, finding_id: str) -> List[Dict[str, Any]]:
        return [dict(r) for r in self._conn.execute(
            "SELECT * FROM events WHERE finding_id = ? ORDER BY id DESC",
            (finding_id,)).fetchall()]

    def scans(self, limit: int = 60) -> List[Dict[str, Any]]:
        return [dict(r) for r in self._conn.execute(
            "SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)).fetchall()]

    def projects(self) -> List[str]:
        return [r[0] for r in self._conn.execute(
            "SELECT DISTINCT project FROM findings ORDER BY project").fetchall()]

    def owners(self) -> List[str]:
        return [r[0] for r in self._conn.execute(
            "SELECT DISTINCT owner FROM findings WHERE owner IS NOT NULL"
            " ORDER BY owner").fetchall()]

    def stats(self, project: Optional[str] = None) -> Dict[str, Any]:
        rows = self.findings(project)
        open_rows = [r for r in rows if r["status"] in OPEN_STATUSES]
        by_level: Dict[str, int] = {}
        for r in open_rows:
            by_level[r["risk_level"]] = by_level.get(r["risk_level"], 0) + 1
        return {
            "total": len(rows),
            "open": len(open_rows),
            "closed": len(rows) - len(open_rows),
            "by_level": by_level,
            "breached": sum(1 for r in open_rows if r["sla"]["breached"]),
            "unassigned": sum(1 for r in open_rows if not r["owner"]),
        }
