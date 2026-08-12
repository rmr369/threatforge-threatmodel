# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""
Attack path analysis.

Findings tell you what is wrong. Attack paths tell you what an attacker would
actually do -- which is what makes a threat model persuasive to people who do
not read scanner output.

A path is a chain from an untrusted entry point to a crown-jewel asset where
every hop is a real edge in the graph, scored by the findings sitting on the
assets along the way.
"""

from __future__ import annotations

from collections import deque
from typing import Dict, List, Optional, Set, Tuple

from ..model import (AttackPath, Element, Finding, Severity, ThreatModel)
from .reachability import BIDIRECTIONAL_EDGES, FORWARD_EDGES, NON_PATH_EDGES

MAX_PATHS = 40
MAX_DEPTH = 8


def find_paths(model: ThreatModel, max_paths: int = MAX_PATHS) -> List[AttackPath]:
    adj = _adjacency(model)
    entries = [a.id for a in model.assets.values()
               if a.element == Element.EXTERNAL_ENTITY and "untrusted" in a.tags]
    if not entries:
        entries = [a.id for a in model.assets.values()
                   if a.element == Element.EXTERNAL_ENTITY]
    targets = _crown_jewels(model)
    findings_by_asset = _findings_by_asset(model)

    paths: List[AttackPath] = []
    seen_sigs: Set[Tuple[str, str]] = set()

    for entry in entries:
        for target in targets:
            if (entry, target) in seen_sigs:
                continue
            hops = _shortest(adj, entry, target)
            if not hops or len(hops) > MAX_DEPTH:
                continue
            seen_sigs.add((entry, target))
            ap = _build(model, entry, target, hops, findings_by_asset)
            if ap:
                paths.append(ap)

    paths.sort(key=lambda p: -p.score)
    model.attack_paths = paths[:max_paths]
    model.metadata["attack_paths"] = {
        "entry_points": entries,
        "crown_jewels": len(targets),
        "paths_found": len(paths),
        "reported": len(model.attack_paths),
    }
    return model.attack_paths


# ---------------------------------------------------------------------------

def _adjacency(model: ThreatModel) -> Dict[str, List[str]]:
    adj: Dict[str, List[str]] = {}
    for f in model.flows:
        if f.kind in NON_PATH_EDGES:
            continue
        if f.kind in FORWARD_EDGES or f.kind == "flow":
            adj.setdefault(f.source, []).append(f.target)
        if f.kind in BIDIRECTIONAL_EDGES:
            adj.setdefault(f.target, []).append(f.source)
    return adj


def _crown_jewels(model: ThreatModel) -> List[str]:
    """What an attacker is actually after."""
    out: Set[str] = set()
    for a in model.assets.values():
        if a.element == Element.DATA_STORE and a.sensitivity >= 4:
            out.add(a.id)
        if "privileged_role" in a.tags:
            out.add(a.id)
        if a.kind in ("Secret", "SealedSecret"):
            out.add(a.id)
        if "cloud_data_store" in a.tags:
            out.add(a.id)
        if "node_filesystem" in a.tags:
            out.add(a.id)
    return sorted(out)


def _findings_by_asset(model: ThreatModel) -> Dict[str, List[Finding]]:
    out: Dict[str, List[Finding]] = {}
    for f in model.active_findings:
        out.setdefault(f.component, []).append(f)
    return out


def _shortest(adj: Dict[str, List[str]], src: str, dst: str) -> Optional[List[str]]:
    if src == dst:
        return [src]
    prev: Dict[str, str] = {}
    q = deque([src])
    seen = {src}
    while q:
        cur = q.popleft()
        for nxt in adj.get(cur, []):
            if nxt in seen:
                continue
            seen.add(nxt)
            prev[nxt] = cur
            if nxt == dst:
                path = [dst]
                while path[-1] != src:
                    path.append(prev[path[-1]])
                return list(reversed(path))
            q.append(nxt)
    return None


def _build(model: ThreatModel, entry: str, target: str, hops: List[str],
           fba: Dict[str, List[Finding]]) -> Optional[AttackPath]:
    finding_ids: List[str] = []
    narrative: List[str] = []
    score = 0

    tgt_asset = model.assets.get(target)
    entry_asset = model.assets.get(entry)
    narrative.append(
        f"Attacker starts at {entry_asset.display if entry_asset else entry}.")

    for i, hop in enumerate(hops[1:], start=1):
        a = model.assets.get(hop)
        if not a:
            continue
        hop_findings = sorted(fba.get(hop, []), key=lambda f: -f.risk_score)
        flow = _flow_between(model, hops[i - 1], hop)
        verb = _verb(flow.kind if flow else "flow")

        if hop_findings:
            top = hop_findings[0]
            finding_ids += [f.id for f in hop_findings[:3]]
            score += sum(f.risk_score for f in hop_findings[:3])
            narrative.append(
                f"{verb} {a.display}, where {top.title.lower()} "
                f"({top.rule_id}, risk {top.risk_score}) provides the next step.")
        else:
            narrative.append(f"{verb} {a.display}.")

    if tgt_asset:
        what = (", ".join(sorted(dc.value for dc in tgt_asset.data_classes))
                or "privileged access")
        narrative.append(f"Objective reached: {tgt_asset.display} ({what}).")

    # Shorter paths with more findings are more dangerous.
    score = int(score * (1.0 + (MAX_DEPTH - len(hops)) * 0.12))
    if not finding_ids:
        score = max(1, score // 3)      # a clean path is still a path, just less urgent

    level = (Severity.CRITICAL if score >= 60 else
             Severity.HIGH if score >= 30 else
             Severity.MEDIUM if score >= 12 else Severity.LOW)

    return AttackPath(
        id=f"AP-{abs(hash((entry, target))) % 10**8:08d}",
        entry=entry, target=target, hops=hops,
        findings=sorted(set(finding_ids)), narrative=narrative,
        score=score, level=level,
    )


def _flow_between(model: ThreatModel, a: str, b: str):
    for f in model.flows:
        if (f.source == a and f.target == b) or (f.source == b and f.target == a):
            return f
    return None


_VERBS = {
    "external-access": "Sends a request to",
    "routes-to": "Is routed to",
    "runs": "Pivots into",
    "mounts": "Reads the mounted",
    "reads": "Reads",
    "writes": "Writes to",
    "calls": "Calls",
    "assumes": "Assumes the identity of",
    "granted": "Uses permissions from",
    "bound-to": "Follows the binding to",
    "built-from": "Traces back to",
}


def _verb(kind: str) -> str:
    return _VERBS.get(kind, "Moves to")
