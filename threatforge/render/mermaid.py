"""
Mermaid renderers.

Two diagrams, because one diagram cannot serve both purposes:

  * `dfd`         -- the classic data flow diagram, grouped by trust boundary,
                     with DFD-correct shapes and risk-coloured nodes.
  * `attack_path` -- a single ranked attack chain, for the report.

Large estates are unreadable as one graph, so `dfd` supports scoping to a
namespace or to the internet-reachable subgraph only.
"""

from __future__ import annotations

import re
from typing import Dict, Iterable, List, Optional, Set

from ..model import Element, Severity, ThreatModel

SHAPE = {
    Element.EXTERNAL_ENTITY: ('[["', '"]]'),      # subroutine box
    Element.PROCESS: ('(["', '"])'),              # stadium
    Element.DATA_STORE: ('[("', '")]'),           # cylinder
}

LEVEL_CLASS = {
    Severity.CRITICAL: "crit",
    Severity.HIGH: "high",
    Severity.MEDIUM: "med",
    Severity.LOW: "low",
    Severity.INFO: "ok",
}

CLASS_DEFS = """
    classDef crit fill:#7f1d1d,stroke:#ef4444,stroke-width:2px,color:#fff;
    classDef high fill:#7c2d12,stroke:#f97316,stroke-width:2px,color:#fff;
    classDef med  fill:#713f12,stroke:#eab308,stroke-width:1px,color:#fff;
    classDef low  fill:#1e3a5f,stroke:#3b82f6,stroke-width:1px,color:#fff;
    classDef ok   fill:#14532d,stroke:#22c55e,stroke-width:1px,color:#fff;
    classDef ext  fill:#3f3f46,stroke:#a1a1aa,stroke-width:2px,color:#fff;
"""


def _safe(node_id: str, table: Dict[str, str]) -> str:
    if node_id in table:
        return table[node_id]
    alias = f"n{len(table)}"
    table[node_id] = alias
    return alias


def _label(text: str, limit: int = 42) -> str:
    text = re.sub(r'["`]', "'", str(text)).replace("\n", " ")
    return text if len(text) <= limit else text[: limit - 1] + "…"


def render_dfd(model: ThreatModel, *, namespace: Optional[str] = None,
               reachable_only: bool = False, max_nodes: int = 120,
               direction: str = "LR") -> str:
    """Trust-boundary-grouped DFD."""
    worst: Dict[str, Severity] = {}
    for f in model.active_findings:
        cur = worst.get(f.component)
        if cur is None or f.risk_level.rank > cur.rank:
            worst[f.component] = f.risk_level

    assets = list(model.assets.values())
    if namespace:
        assets = [a for a in assets
                  if a.namespace == namespace or a.element == Element.EXTERNAL_ENTITY]
    if reachable_only:
        assets = [a for a in assets if a.facts.get("internet_reachable")]

    # Containers explode the diagram; fold them unless they carry findings.
    assets = [a for a in assets
              if a.kind != "Container" or a.id in worst]

    if len(assets) > max_nodes:
        assets.sort(key=lambda a: (
            -(worst.get(a.id, Severity.INFO).rank),
            -(a.facts.get("blast_radius") or 0),
        ))
        assets = assets[:max_nodes]

    keep: Set[str] = {a.id for a in assets}
    alias: Dict[str, str] = {}
    lines: List[str] = [f"flowchart {direction}", CLASS_DEFS.rstrip()]

    # group by innermost boundary
    grouped: Dict[str, List] = {}
    for a in assets:
        bid = _innermost_id(model, a) or "boundary:ungrouped"
        grouped.setdefault(bid, []).append(a)

    for bid, members in sorted(grouped.items()):
        b = model.boundaries.get(bid)
        title = _label(b.name if b else "Ungrouped", 40)
        trust = f" (trust {b.trust_level})" if b else ""
        lines.append(f'    subgraph {_safe(bid, alias)}["{title}{trust}"]')
        lines.append("    direction TB")
        for a in members:
            open_s, close_s = SHAPE.get(a.element, ('["', '"]'))
            lines.append(f'        {_safe(a.id, alias)}{open_s}{_label(a.display)}{close_s}')
        lines.append("    end")

    for f in model.flows:
        if f.source not in keep or f.target not in keep:
            continue
        s, t = alias.get(f.source), alias.get(f.target)
        if not s or not t:
            continue
        lbl = f.kind
        if f.protocol:
            lbl += f" / {f.protocol}"
        if f.crosses_boundary:
            lbl = "⚠ " + lbl
        arrow = "-.->" if f.details.get("confidence") == "possible" else "-->"
        lines.append(f'    {s} {arrow}|{_label(lbl, 28)}| {t}')

    for a in assets:
        cls = ("ext" if a.element == Element.EXTERNAL_ENTITY
               else LEVEL_CLASS.get(worst.get(a.id, Severity.INFO), "ok"))
        lines.append(f"    class {alias[a.id]} {cls};")

    return "\n".join(lines)


def render_attack_path(model: ThreatModel, path_index: int = 0) -> str:
    if not model.attack_paths:
        return "flowchart LR\n    none[\"No attack path found\"]"
    p = model.attack_paths[min(path_index, len(model.attack_paths) - 1)]
    alias: Dict[str, str] = {}
    lines = ["flowchart LR", CLASS_DEFS.rstrip()]
    for i, hop in enumerate(p.hops):
        a = model.assets.get(hop)
        label = _label(a.display if a else hop)
        shape = SHAPE.get(a.element if a else Element.PROCESS, ('["', '"]'))
        lines.append(f'    {_safe(hop, alias)}{shape[0]}{i}. {label}{shape[1]}')
    for i in range(len(p.hops) - 1):
        flow = next((f for f in model.flows
                     if f.source == p.hops[i] and f.target == p.hops[i + 1]), None)
        lbl = flow.kind if flow else "pivot"
        lines.append(f'    {alias[p.hops[i]]} ==>|{lbl}| {alias[p.hops[i+1]]}')
    lines.append(f"    class {alias[p.hops[0]]} ext;")
    lines.append(f"    class {alias[p.hops[-1]]} crit;")
    return "\n".join(lines)


def render_boundary_map(model: ThreatModel) -> str:
    """Nesting of trust boundaries with asset counts -- the 10,000ft view."""
    lines = ["flowchart TD", CLASS_DEFS.rstrip()]
    alias: Dict[str, str] = {}
    for b in sorted(model.boundaries.values(), key=lambda x: x.trust_level):
        lines.append(
            f'    {_safe(b.id, alias)}["{_label(b.name, 36)}<br/>'
            f'trust {b.trust_level} · {len(b.members)} assets"]')
    for b in model.boundaries.values():
        if b.parent and b.parent in alias:
            lines.append(f"    {alias[b.parent]} --> {alias[b.id]}")
    return "\n".join(lines)


def _innermost_id(model: ThreatModel, asset) -> Optional[str]:
    if not asset.boundaries:
        return None
    bs = [model.boundaries[b] for b in asset.boundaries if b in model.boundaries]
    if not bs:
        return None
    return max(bs, key=lambda b: b.trust_level).id
