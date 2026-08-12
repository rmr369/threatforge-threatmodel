# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""
draw.io / diagrams.net export.

Produces an editable `.drawio` of the generated model. Open it at
diagrams.net, in the VS Code extension, or in Confluence, move things around,
add the component the scanner could not see, save, and re-scan -- the importer
reads it back.

Design choices that matter for the result being *usable* rather than merely
valid:

* **Risk colouring.** Node fill follows the highest risk level found on that
  component, so the diagram is a heat map rather than a box drawing.
* **Explicit typing on the way out.** Every shape carries `tfType`, so a
  re-import is exact rather than guessed from the shape style.
* **Boundaries as background containers**, emitted first so they sit behind
  their members, with members parented to them — dragging the boundary moves
  the group, which is what anyone editing it expects.
* **Plain, uncompressed XML.** draw.io reads it happily and it diffs in git,
  which the compressed form does not.
"""

from __future__ import annotations

import re
from datetime import date
from typing import Dict, List, Optional, Tuple
from xml.sax.saxutils import escape, quoteattr

from ..model import Element, Severity, ThreatModel

# Fill / stroke per risk level. Muted enough to read text over.
RISK_STYLE = {
    Severity.CRITICAL: ("#f8cecc", "#b85450"),
    Severity.HIGH: ("#ffe6cc", "#d79b00"),
    Severity.MEDIUM: ("#fff2cc", "#d6b656"),
    Severity.LOW: ("#dae8fc", "#6c8ebf"),
    Severity.INFO: ("#d5e8d4", "#82b366"),
}
CLEAN_STYLE = ("#d5e8d4", "#82b366")

SHAPE = {
    Element.PROCESS: "ellipse;whiteSpace=wrap;html=1;",
    Element.DATA_STORE: "shape=datastore;whiteSpace=wrap;html=1;",
    Element.EXTERNAL_ENTITY: "rounded=0;whiteSpace=wrap;html=1;",
}
TF_TYPE = {
    Element.PROCESS: "process",
    Element.DATA_STORE: "data_store",
    Element.EXTERNAL_ENTITY: "external_entity",
}

COL_W, ROW_H = 260, 150
NODE_W, NODE_H = 160, 70
ORIGIN_X, ORIGIN_Y = 80, 80
MAX_ROWS = 9
PAD = 34


def _esc(text) -> str:
    return escape(str(text if text is not None else ""))


def _safe_id(raw: str) -> str:
    """mxGraph ids must not contain characters that break attribute quoting."""
    return re.sub(r"[^A-Za-z0-9_.:-]", "_", str(raw))


def render(model: ThreatModel, *, include_findings: bool = True) -> str:
    assets = [a for a in model.assets.values()
              if a.element in SHAPE and a.kind != "Container"]
    flagged = {f.component for f in model.active_findings}
    assets += [a for a in model.assets.values()
               if a.kind == "Container" and a.id in flagged and a.element in SHAPE]

    worst: Dict[str, Severity] = {}
    counts: Dict[str, int] = {}
    for f in model.active_findings:
        counts[f.component] = counts.get(f.component, 0) + 1
        cur = worst.get(f.component)
        if cur is None or f.risk_level.rank > cur.rank:
            worst[f.component] = f.risk_level

    positions = _layout(assets)
    keep = {a.id for a in assets}
    parent_of = _boundary_membership(model, keep)

    cells: List[str] = []

    # Boundaries first so they render behind their members.
    for b, rect in _boundary_rects(model, assets, positions):
        x, y, w, h = rect
        style = ("rounded=1;arcSize=6;dashed=1;dashPattern=8 8;html=1;"
                 "fillColor=none;strokeColor=#9673a6;strokeWidth=2;"
                 "verticalAlign=top;align=left;spacingLeft=10;spacingTop=4;"
                 "fontStyle=2;fontColor=#6c3483;container=1;collapsible=0;")
        cells.append(_vertex(_safe_id(b.id),
                             f"{b.name}  (trust {b.trust_level})",
                             style, x, y, w, h, parent="1",
                             extra={"tfType": "boundary",
                                    "tfTrustLevel": str(b.trust_level)}))

    for a in assets:
        x, y = positions[a.id]
        fill, stroke = RISK_STYLE.get(worst.get(a.id), CLEAN_STYLE) \
            if include_findings else CLEAN_STYLE
        n = counts.get(a.id, 0)
        label = a.name if not n else f"{a.name}\n({n} finding{'s' if n > 1 else ''})"
        style = (SHAPE[a.element]
                 + f"fillColor={fill};strokeColor={stroke};"
                 + "verticalAlign=middle;fontSize=11;")
        parent = parent_of.get(a.id, "1")
        px, py = (x, y)
        if parent != "1":
            # children are positioned relative to their container
            bx, by = _container_origin(parent, model, assets, positions)
            px, py = x - bx, y - by
        cells.append(_vertex(
            _safe_id(a.id), label, style, px, py, NODE_W, NODE_H, parent=parent,
            extra={"tfType": TF_TYPE[a.element], "tfId": a.id,
                   "tfExposure": str(a.facts.get("exposure_hops")),
                   "tfBlastRadius": str(a.facts.get("blast_radius") or 0),
                   "tfFindings": str(n)}))

    # Edges.
    for i, f in enumerate(model.flows):
        if f.source not in keep or f.target not in keep:
            continue
        if f.kind in ("protects", "runs"):
            continue
        label = f.details.get("name") or f.kind.replace("-", " ")
        if f.protocol:
            label = f"{label} ({f.protocol})"
        stroke = "#b85450" if f.encrypted is False else "#666666"
        dashed = "1" if f.details.get("confidence") == "possible" else "0"
        style = (f"edgeStyle=orthogonalEdgeStyle;rounded=1;html=1;"
                 f"strokeColor={stroke};dashed={dashed};"
                 f"endArrow=blockThin;endFill=1;fontSize=10;")
        cells.append(_edge(f"e{i}", label, style,
                           _safe_id(f.source), _safe_id(f.target)))

    body = "\n".join(cells)
    title = _esc(f"{model.project} — generated DFD")
    c = model.counts()
    legend = _esc(
        f"Generated by ThreatForge on {date.today().isoformat()} · "
        f"{len(assets)} elements · {c['critical']} critical, {c['high']} high · "
        f"colour = highest risk on the component · red edge = unencrypted · "
        f"dashed edge = inferred")

    return (
        f'<mxfile host="ThreatForge" type="device">\n'
        f'  <diagram id="threatforge" name={quoteattr(title)}>\n'
        f'    <mxGraphModel dx="1440" dy="900" grid="1" gridSize="10" guides="1" '
        f'tooltips="1" connect="1" arrows="1" fold="1" page="1" pageScale="1" '
        f'pageWidth="1654" pageHeight="1169" math="0" shadow="0">\n'
        f'      <root>\n'
        f'        <mxCell id="0" />\n'
        f'        <mxCell id="1" parent="0" />\n'
        f'{body}\n'
        f'        <object id="legend" label={quoteattr(legend)} tfType="annotation">\n'
        f'          <mxCell style="text;html=1;align=left;verticalAlign=top;'
        f'fontSize=10;fontColor=#666666;" vertex="1" parent="1">\n'
        f'            <mxGeometry x="80" y="20" width="1200" height="30" '
        f'as="geometry" />\n'
        f'          </mxCell>\n'
        f'        </object>\n'
        f'      </root>\n'
        f'    </mxGraphModel>\n'
        f'  </diagram>\n'
        f'</mxfile>\n'
    )


# ---------------------------------------------------------------------------

def _vertex(cid: str, label: str, style: str, x: float, y: float,
            w: float, h: float, parent: str = "1",
            extra: Optional[Dict[str, str]] = None) -> str:
    """A shape. Wrapped in <object> when it carries custom properties, which is
    how draw.io round-trips metadata through its Edit Data dialog."""
    geo = (f'          <mxGeometry x="{int(x)}" y="{int(y)}" '
           f'width="{int(w)}" height="{int(h)}" as="geometry" />')
    if extra:
        attrs = " ".join(f'{k}={quoteattr(v)}' for k, v in extra.items()
                         if v not in (None, "None"))
        return (
            f'        <object id={quoteattr(cid)} label={quoteattr(label)} {attrs}>\n'
            f'          <mxCell style={quoteattr(style)} vertex="1" '
            f'parent={quoteattr(parent)}>\n'
            f'  {geo}\n'
            f'          </mxCell>\n'
            f'        </object>'
        )
    return (
        f'        <mxCell id={quoteattr(cid)} value={quoteattr(label)} '
        f'style={quoteattr(style)} vertex="1" parent={quoteattr(parent)}>\n'
        f'{geo}\n'
        f'        </mxCell>'
    )


def _edge(cid: str, label: str, style: str, source: str, target: str) -> str:
    return (
        f'        <mxCell id={quoteattr(cid)} value={quoteattr(label)} '
        f'style={quoteattr(style)} edge="1" parent="1" '
        f'source={quoteattr(source)} target={quoteattr(target)}>\n'
        f'          <mxGeometry relative="1" as="geometry" />\n'
        f'        </mxCell>'
    )


def _layout(assets: List) -> Dict[str, Tuple[int, int]]:
    columns: Dict[int, List] = {}
    for a in assets:
        hops = a.facts.get("exposure_hops")
        col = 9 if hops is None else min(int(hops), 8)
        columns.setdefault(col, []).append(a)
    out: Dict[str, Tuple[int, int]] = {}
    for col in sorted(columns):
        for i, a in enumerate(columns[col]):
            out[a.id] = (ORIGIN_X + col * COL_W,
                         ORIGIN_Y + (i % MAX_ROWS) * ROW_H + (i // MAX_ROWS) * 40)
    return out


def _boundary_rects(model: ThreatModel, assets: List,
                    positions: Dict[str, Tuple[int, int]]):
    keep = {a.id for a in assets}
    for b in sorted(model.boundaries.values(), key=lambda x: -x.trust_level):
        members = [m for m in b.members if m in keep and m in positions]
        if len(members) < 2:
            continue
        xs = [positions[m][0] for m in members]
        ys = [positions[m][1] for m in members]
        left, top = min(xs) - PAD, min(ys) - PAD - 12
        width = (max(xs) + NODE_W + PAD) - left
        height = (max(ys) + NODE_H + PAD) - top
        yield b, (left, top, width, height)


def _boundary_membership(model: ThreatModel, keep) -> Dict[str, str]:
    """Parent each asset to its innermost boundary that has a drawn rectangle."""
    out: Dict[str, str] = {}
    for b in sorted(model.boundaries.values(), key=lambda x: x.trust_level):
        members = [m for m in b.members if m in keep]
        if len(members) < 2:
            continue
        for m in members:
            out[m] = _safe_id(b.id)
    return out


def _container_origin(parent_id: str, model: ThreatModel, assets: List,
                      positions: Dict[str, Tuple[int, int]]) -> Tuple[int, int]:
    for b, rect in _boundary_rects(model, assets, positions):
        if _safe_id(b.id) == parent_id:
            return rect[0], rect[1]
    return 0, 0
