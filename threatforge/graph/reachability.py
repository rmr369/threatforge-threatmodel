"""
Reachability and blast radius.

Two numbers drive most of the risk model:

  exposure_hops  -- shortest distance from an untrusted external entity.
                    0 = is the external entity, 1 = directly exposed, None = unreachable.
  blast_radius   -- how many assets an attacker can touch after landing here.

Both are computed on the *directed* flow graph, with a couple of deliberate
adjustments: `runs` and `mounts` edges are traversable in both directions
during blast-radius calculation, because owning a container means owning the
pod's mounted secrets and vice versa.
"""

from __future__ import annotations

from collections import deque
from typing import Dict, List, Optional, Set

from ..model import Element, ThreatModel

# Edges that an attacker can traverse forwards (data/control flow direction).
FORWARD_EDGES = {
    "external-access", "routes-to", "runs", "mounts", "reads", "writes",
    "calls", "assumes", "granted", "bound-to", "provisioned-by", "built-from",
}

# Edges where compromise propagates backwards too (shared trust).
BIDIRECTIONAL_EDGES = {"runs", "mounts", "assumes"}

# Edges that describe a control, not a path.
NON_PATH_EDGES = {"protects"}


def compute(model: ThreatModel) -> None:
    fwd, back = _adjacency(model)
    hops = _exposure(model, fwd)
    for aid, a in model.assets.items():
        a.facts["exposure_hops"] = hops.get(aid)
        a.facts["internet_reachable"] = hops.get(aid) is not None
        if hops.get(aid) is not None and hops[aid] <= 2 and a.element != Element.EXTERNAL_ENTITY:
            a.tag("internet_reachable")
    blast = _blast_radius(model, fwd, back)
    for aid, a in model.assets.items():
        a.facts["blast_radius"] = blast.get(aid, 0)
        a.facts["reaches_sensitive"] = _reaches_sensitive(model, aid, fwd, back)
    model.metadata["reachability"] = {
        "internet_reachable_assets": sum(1 for a in model.assets.values()
                                         if a.facts.get("internet_reachable")),
        "max_blast_radius": max(blast.values()) if blast else 0,
    }


# ---------------------------------------------------------------------------

def _adjacency(model: ThreatModel):
    fwd: Dict[str, List[str]] = {}
    back: Dict[str, List[str]] = {}
    for f in model.flows:
        if f.kind in NON_PATH_EDGES:
            continue
        if f.kind in FORWARD_EDGES or f.kind == "flow":
            fwd.setdefault(f.source, []).append(f.target)
            back.setdefault(f.target, []).append(f.source)
        if f.kind in BIDIRECTIONAL_EDGES:
            fwd.setdefault(f.target, []).append(f.source)
    return fwd, back


def _entry_points(model: ThreatModel) -> List[str]:
    return [a.id for a in model.assets.values()
            if a.element == Element.EXTERNAL_ENTITY and "untrusted" in a.tags] or \
           [a.id for a in model.assets.values() if a.element == Element.EXTERNAL_ENTITY]


def _exposure(model: ThreatModel, fwd: Dict[str, List[str]]) -> Dict[str, Optional[int]]:
    hops: Dict[str, int] = {}
    q = deque()
    for e in _entry_points(model):
        hops[e] = 0
        q.append(e)
    while q:
        cur = q.popleft()
        for nxt in fwd.get(cur, []):
            if nxt not in hops:
                hops[nxt] = hops[cur] + 1
                q.append(nxt)
    return hops


def _blast_radius(model: ThreatModel, fwd, back) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for aid in model.assets:
        seen: Set[str] = set()
        q = deque([aid])
        while q:
            cur = q.popleft()
            for nxt in fwd.get(cur, []):
                if nxt not in seen and nxt != aid:
                    seen.add(nxt)
                    q.append(nxt)
        out[aid] = len(seen)
    return out


def _reaches_sensitive(model: ThreatModel, aid: str, fwd, back) -> bool:
    seen: Set[str] = set()
    q = deque([aid])
    while q:
        cur = q.popleft()
        for nxt in fwd.get(cur, []):
            if nxt in seen:
                continue
            seen.add(nxt)
            tgt = model.assets.get(nxt)
            if tgt and tgt.element == Element.DATA_STORE and tgt.sensitivity >= 4:
                return True
            q.append(nxt)
    return False


def shortest_path(model: ThreatModel, src: str, dst: str) -> Optional[List[str]]:
    fwd, _ = _adjacency(model)
    prev: Dict[str, str] = {}
    q = deque([src])
    seen = {src}
    while q:
        cur = q.popleft()
        if cur == dst:
            path = [dst]
            while path[-1] != src:
                path.append(prev[path[-1]])
            return list(reversed(path))
        for nxt in fwd.get(cur, []):
            if nxt not in seen:
                seen.add(nxt)
                prev[nxt] = cur
                q.append(nxt)
    return None
