# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""
draw.io / diagrams.net importer.

Architects draw in draw.io. Not in TMT, not in YAML -- in draw.io, because it is
free, runs in a browser, and the diagram ends up in Confluence. Those diagrams
are usually the only written record of how a system actually fits together, and
they are invisible to a scanner.

This reads them, so a diagram someone drew in a design review becomes a first
class part of the model: reachability, blast radius and attack paths all run
across it.

Format notes
------------
`.drawio` files hold mxGraph XML. Two encodings exist and both appear in the
wild:

* **plain** -- `<diagram><mxGraphModel>...` directly.
* **compressed** -- the `<diagram>` body is base64 of a raw DEFLATE stream of
  the URL-encoded XML. draw.io writes this by default for large diagrams, so an
  importer that only handles plain text fails on exactly the files that matter.

Typing an element
-----------------
Shape semantics are guessed from the draw.io style, which is a heuristic and
sometimes wrong. To be explicit, either

* name the shape `Process: checkout-api`, or
* add a `tfType=data_store` key to the shape's style, or
* set a custom property `tfType` in draw.io's *Edit Data* dialog.

Explicit typing always wins over the heuristic, and the report says which was
used so a wrong guess is visible rather than silent.
"""

from __future__ import annotations

import base64
import html
import os
import re
import urllib.parse
import xml.etree.ElementTree as ET
import zlib
from typing import Any, Dict, List, Optional, Tuple

from ..model import Asset, Boundary, DataClass, Element, Flow, SourceRef, ThreatModel
from .base import Ingestor, register, walk_files

DRAWIO_PREFIX = "drawio:"

# Explicit type names accepted in labels, styles and custom properties.
EXPLICIT_TYPES = {
    "process": Element.PROCESS,
    "service": Element.PROCESS,
    "app": Element.PROCESS,
    "data_store": Element.DATA_STORE,
    "datastore": Element.DATA_STORE,
    "store": Element.DATA_STORE,
    "database": Element.DATA_STORE,
    "db": Element.DATA_STORE,
    "external_entity": Element.EXTERNAL_ENTITY,
    "external": Element.EXTERNAL_ENTITY,
    "actor": Element.EXTERNAL_ENTITY,
    "user": Element.EXTERNAL_ENTITY,
    "boundary": Element.TRUST_BOUNDARY,
    "trust_boundary": Element.TRUST_BOUNDARY,
}

# Style fragment -> element, checked in order. First match wins, so the more
# specific shapes must come before the generic ones.
STYLE_HINTS: List[Tuple[str, Element]] = [
    ("shape=datastore", Element.DATA_STORE),
    ("shape=cylinder", Element.DATA_STORE),
    ("shape=cylinder3", Element.DATA_STORE),
    ("mxgraph.flowchart.database", Element.DATA_STORE),
    ("shape=umlactor", Element.EXTERNAL_ENTITY),
    ("shape=actor", Element.EXTERNAL_ENTITY),
    ("mxgraph.basic.user", Element.EXTERNAL_ENTITY),
    ("ellipse", Element.PROCESS),
    ("rhombus", Element.PROCESS),
]

# Names that read like a boundary even when the shape is a plain rectangle.
BOUNDARY_NAME = re.compile(
    r"(trust\s*boundary|boundary|dmz|vpc\b|subnet|zone|perimeter|"
    r"internet|cluster|network\s*segment)", re.I)

SENSITIVE_NAME = re.compile(
    r"(secret|credential|password|token|key|vault|customer|user|patient|"
    r"account|billing|payment|card|pii|profile)", re.I)

PROTOCOL_IN_LABEL = re.compile(
    r"\b(https?|tls|mtls|ssh|grpc|amqp|sql|jdbc|tcp|udp|ftp|smtp|ws{1,2})\b", re.I)

ENCRYPTED_PROTOCOLS = {"https", "tls", "mtls", "ssh", "wss"}
PLAINTEXT_PROTOCOLS = {"http", "ftp", "smtp", "telnet", "ws"}
# Everything else -- sql, jdbc, grpc, amqp, tcp -- may or may not be wrapped in
# TLS. Unknown is the correct answer, not False.


def drawio_id(raw: str) -> str:
    return f"{DRAWIO_PREFIX}{raw}"


# ---------------------------------------------------------------------------
# Decoding
# ---------------------------------------------------------------------------

def decode_diagram(node: ET.Element) -> Optional[ET.Element]:
    """Return the <mxGraphModel> for a <diagram>, decompressing if needed."""
    inner = node.find("mxGraphModel")
    if inner is not None:
        return inner

    payload = (node.text or "").strip()
    if not payload:
        return None
    try:
        raw = base64.b64decode(payload)
        # raw DEFLATE, no zlib header -- hence the negative window size
        xml_text = zlib.decompress(raw, -zlib.MAX_WBITS).decode("utf-8")
        xml_text = urllib.parse.unquote(xml_text)
        return ET.fromstring(xml_text)
    except Exception:
        return None


def _style_map(style: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for part in (style or "").split(";"):
        if "=" in part:
            k, _, v = part.partition("=")
            out[k.strip().lower()] = v.strip()
        elif part.strip():
            out[part.strip().lower()] = "1"
    return out


def _clean_label(value: str) -> str:
    """draw.io labels are HTML: <b>API</b><br>gateway."""
    text = re.sub(r"<br\s*/?>", " ", value or "")
    text = re.sub(r"<[^>]+>", "", text)
    return html.unescape(text).strip()


def is_decorative(style: str, custom: Dict[str, str]) -> bool:
    """Text labels, notes, legends and images carry no security meaning.

    Real diagrams are full of them. Importing them would inflate the asset count
    and, worse, put fictional nodes into reachability and attack path analysis.
    """
    declared = (custom.get("tftype") or "").strip().lower()
    if declared in ("annotation", "note", "text", "legend", "ignore"):
        return True
    smap = _style_map(style)
    if declared:
        return False
    if "shape" in smap or "ellipse" in smap or "rhombus" in smap:
        return False
    return ("text" in smap or "label" in smap
            or smap.get("shape", "") in ("note", "image")
            or "image=" in (style or "").lower())


def classify(label: str, style: str, custom: Dict[str, str]) -> Tuple[Element, str]:
    """Return (element, how) where `how` is 'explicit' or 'heuristic'."""
    smap = _style_map(style)

    for key in ("tftype", "threatforge", "type"):
        declared = (custom.get(key) or smap.get(key) or "").strip().lower()
        if declared in EXPLICIT_TYPES:
            return EXPLICIT_TYPES[declared], "explicit"

    m = re.match(r"\s*([A-Za-z_ ]{3,20}?)\s*:\s*\S", label or "")
    if m:
        declared = m.group(1).strip().lower().replace(" ", "_")
        if declared in EXPLICIT_TYPES:
            return EXPLICIT_TYPES[declared], "explicit"

    low = (style or "").lower()
    for fragment, element in STYLE_HINTS:
        if fragment in low:
            return element, "heuristic"

    if BOUNDARY_NAME.search(label or ""):
        return Element.TRUST_BOUNDARY, "heuristic"
    if smap.get("dashed") == "1" and smap.get("fillcolor", "").lower() in ("none", ""):
        return Element.TRUST_BOUNDARY, "heuristic"

    return Element.PROCESS, "heuristic"


def strip_type_prefix(label: str) -> str:
    return re.sub(r"^\s*[A-Za-z_ ]{3,20}\s*:\s*", "", label or "").strip() or label


# ---------------------------------------------------------------------------

@register
class DrawioIngestor(Ingestor):
    """Reads `.drawio` / `.dio` / diagram-bearing `.xml` files."""

    name = "drawio"
    provider = "drawio"


    def _files(self, root: str, exts) -> list:
        """Files under the scan root, plus any named explicitly in config.

        The app writes an imported diagram into its own workspace rather than
        into the repository being scanned -- putting it in the repo would mean
        a UI action silently edits the user's checkout. So the ingestor has to
        be told where else to look, the same way the manual overlay reader is.
        """
        import os as _os
        found = list(walk_files(root, exts))
        seen = {_os.path.abspath(p) for p in found}
        for extra in self.config.get("paths") or []:
            if _os.path.isdir(extra):
                candidates = walk_files(extra, exts)
            elif _os.path.isfile(extra) and extra.lower().endswith(tuple(exts)):
                candidates = [extra]
            else:
                continue
            for p in candidates:
                if _os.path.abspath(p) not in seen:
                    seen.add(_os.path.abspath(p))
                    found.append(p)
        return found

    def detect(self, root: str) -> bool:
        return bool(self._files(root, (".drawio", ".dio", ".drawio.xml")))

    def ingest(self, root: str, model: ThreatModel) -> None:
        for path in self._files(root, (".drawio", ".dio", ".drawio.xml")):
            try:
                rel = os.path.relpath(path, root)
            except ValueError:
                rel = os.path.basename(path)
            try:
                tree = ET.parse(path)
            except ET.ParseError as exc:
                model.error("ingest.drawio", f"not valid XML: {exc}", file=rel)
                self.stats["skipped"] += 1
                continue
            except Exception as exc:
                model.error("ingest.drawio", f"read failed: {exc}", file=rel)
                self.stats["skipped"] += 1
                continue

            self.stats["files"] += 1
            root_el = tree.getroot()
            diagrams = (root_el.findall(".//diagram")
                        if root_el.tag == "mxfile" else [root_el])
            if not diagrams:
                diagrams = [root_el]

            for page, node in enumerate(diagrams):
                graph = (decode_diagram(node) if node.tag == "diagram"
                         else node.find(".//mxGraphModel") or node)
                if graph is None:
                    model.error("ingest.drawio",
                                "diagram page could not be decoded (compressed "
                                "with an unexpected encoding?)",
                                file=rel, page=page)
                    continue
                name = node.get("name") or f"page-{page + 1}"
                self._page(graph, rel, name, model)

    # -- one page ---------------------------------------------------------
    def _page(self, graph: ET.Element, rel: str, page: str,
              model: ThreatModel) -> None:
        cells = list(graph.iter("mxCell"))
        objects = list(graph.iter("object"))

        # <object> wraps an mxCell when the shape carries custom properties.
        custom_by_id: Dict[str, Dict[str, str]] = {}
        label_by_id: Dict[str, str] = {}
        for obj in objects:
            oid = obj.get("id")
            if not oid:
                continue
            custom_by_id[oid] = {k.lower(): v for k, v in obj.attrib.items()
                                 if k not in ("id", "label")}
            label_by_id[oid] = obj.get("label", "")
            for c in obj.iter("mxCell"):
                c.set("id", oid)

        geometry: Dict[str, Tuple[float, float, float, float]] = {}
        boundaries: List[Tuple[Boundary, Tuple[float, float, float, float]]] = []
        vertices: Dict[str, Asset] = {}
        edges: List[ET.Element] = []
        heuristic_count = 0

        for cell in cells:
            cid = cell.get("id")
            if not cid or cid in ("0", "1"):
                continue
            if cell.get("edge") == "1":
                edges.append(cell)
                continue
            if cell.get("vertex") != "1":
                continue

            label = _clean_label(label_by_id.get(cid) or cell.get("value") or "")
            style = cell.get("style") or ""
            custom = custom_by_id.get(cid, {})
            if is_decorative(style, custom):
                continue
            if not label:
                label = cid

            element, how = classify(label, style, custom)
            if how == "heuristic":
                heuristic_count += 1
            display = strip_type_prefix(label)

            geo = cell.find("mxGeometry")
            if geo is not None:
                try:
                    geometry[cid] = (float(geo.get("x", 0)), float(geo.get("y", 0)),
                                     float(geo.get("width", 0)),
                                     float(geo.get("height", 0)))
                except ValueError:
                    pass

            if element == Element.TRUST_BOUNDARY:
                b = Boundary(
                    id=f"boundary:drawio:{cid}",
                    name=display,
                    kind="drawio",
                    trust_level=_trust_for(display),
                    description=f"Trust boundary from {rel} ({page}).",
                )
                boundaries.append((b, geometry.get(cid, (0, 0, 0, 0))))
                continue

            asset = Asset(
                id=drawio_id(cid),
                kind={Element.EXTERNAL_ENTITY: "ExternalEntity",
                      Element.DATA_STORE: "DataStore"}.get(element, "Process"),
                name=display,
                provider="drawio",
                element=element,
                spec={"drawio": {"cell_id": cid, "style": style, "page": page,
                                 "custom": custom, "typed": how}},
                source=SourceRef(file=rel, pointer=f"{page}/{cid}"),
            )
            asset.tag("hand_authored", "imported_from_drawio", f"typed:{how}")
            if element == Element.EXTERNAL_ENTITY:
                asset.tag("untrusted")
            if element == Element.DATA_STORE:
                asset.classify(DataClass.PII if SENSITIVE_NAME.search(display)
                               else DataClass.CONFIG)
            elif SENSITIVE_NAME.search(display):
                asset.classify(DataClass.PII)

            vertices[cid] = self.emit(model, asset)

        # -- edges ---------------------------------------------------------
        for cell in edges:
            src, tgt = cell.get("source"), cell.get("target")
            if not src or not tgt or src not in vertices or tgt not in vertices:
                continue
            label = _clean_label(label_by_id.get(cell.get("id", "")) or
                                 cell.get("value") or "")
            protocol = None
            encrypted = None
            m = PROTOCOL_IN_LABEL.search(label)
            if m:
                protocol = m.group(1).lower()
                # Three states, and the third one matters. Claiming a flow is
                # unencrypted when the label merely said "sql" invents evidence
                # for TF-FLOW-001; leaving it unknown is honest.
                if protocol in ENCRYPTED_PROTOCOLS:
                    encrypted = True
                elif protocol in PLAINTEXT_PROTOCOLS:
                    encrypted = False

            model.add_flow(Flow(
                source=drawio_id(src), target=drawio_id(tgt), kind="calls",
                protocol=protocol, encrypted=encrypted,
                details={"confidence": "confirmed", "hand_authored": True,
                         "name": label or None, "source_diagram": rel},
                source_ref=SourceRef(file=rel, pointer=f"{page}/{cell.get('id')}"),
            ))

        # -- boundaries are geometric, as in any diagram tool ---------------
        for boundary, (bx, by, bw, bh) in boundaries:
            if bw <= 0 or bh <= 0:
                continue
            for cid, (x, y, w, h) in geometry.items():
                if cid not in vertices:
                    continue
                cx, cy = x + w / 2, y + h / 2
                if bx <= cx <= bx + bw and by <= cy <= by + bh:
                    boundary.members.add(drawio_id(cid))
                    vertices[cid].boundaries.add(boundary.id)
            model.add_boundary(boundary)

        model.metadata.setdefault("drawio_imports", []).append({
            "file": rel, "page": page,
            "elements": len(vertices), "boundaries": len(boundaries),
            "heuristically_typed": heuristic_count,
        })
        if heuristic_count:
            model.error(
                "ingest.drawio",
                f"{heuristic_count} shape(s) on '{page}' were typed by shape style "
                f"rather than declared. Add `tfType=process|data_store|"
                f"external_entity` to the shape, or prefix the label, to be explicit.",
                file=rel)


def _trust_for(name: str) -> int:
    low = (name or "").lower()
    if any(k in low for k in ("internet", "public", "untrusted")):
        return 10
    if any(k in low for k in ("dmz", "perimeter", "edge")):
        return 30
    if any(k in low for k in ("host", "machine", "kernel", "node")):
        return 85
    return 60
