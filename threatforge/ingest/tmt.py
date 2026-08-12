# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""
Microsoft Threat Modeling Tool (.tm7) importer.

Most organisations that have done threat modelling at all have done it in
Microsoft TMT. Those models represent real analyst effort -- often years of it --
and they are stranded: TMT is Windows-only, its last release was 2016-era, and
the files are a .NET DataContract XML dialect nothing else reads.

Importing them turns that archive into a live baseline. A model drawn by hand in
2019 can be merged with today's scan, so the elements an analyst knew about but
the manifests never mentioned keep participating in reachability, blast radius
and attack paths.

Format notes (schema Version 4.3)
---------------------------------
* Shapes live in ``DrawingSurfaceList/.../Borders`` as guid -> object pairs.
  ``GenericTypeId`` gives the DFD role; ``TypeId`` gives the stencil, which is
  the only place protocol and technology hints appear.
* Flows live in ``Lines``, joined by ``SourceGuid`` / ``TargetGuid``.
* Trust boundaries are *geometric*: a boundary is a rectangle, and an element
  belongs to it if its centre falls inside. There is no membership list.
* Analyst-authored threats live in ``ThreatInstances`` with their state and
  mitigation text.

Interoperability note
---------------------
This is an independent implementation written against the Microsoft schema and a
sample document. `.tm7` is Microsoft's format. No source code from any other
implementation of this importer is incorporated or derived from.
See ``docs/INTEROP.md``.
"""

from __future__ import annotations

import os
import re
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional, Tuple

from ..model import Asset, Boundary, DataClass, Element, Flow, SourceRef, ThreatModel
from .base import Ingestor, register, walk_files

TMT_PREFIX = "tmt:"

# GenericTypeId -> DFD role.
GENERIC_TYPES = {
    "GE.EI": Element.EXTERNAL_ENTITY,     # external interactor
    "GE.P": Element.PROCESS,              # process
    "GE.DS": Element.DATA_STORE,          # data store
    "GE.XX.UNKNOWN": Element.PROCESS,     # unrecognised stencil
}

BOUNDARY_TYPES = {"GE.TB.B", "GE.TB.L"}   # box boundary, line boundary
FLOW_TYPE = "GE.DF"
SURFACE_TYPE = "DRAWINGSURFACE"

# TypeId stencil -> protocol. This is the only protocol signal TMT records, and
# it is what lets an imported flow be assessed for transport encryption.
STENCIL_PROTOCOL = {
    "SE.DF.HTTPS": ("https", True), "SE.DF.HTTP": ("http", False),
    "SE.DF.SQL": ("sql", None), "SE.DF.SSL": ("tls", True),
    "SE.DF.TLS": ("tls", True), "SE.DF.RPC": ("rpc", None),
    "SE.DF.NamedPipe": ("named-pipe", None), "SE.DF.IOCTL": ("ioctl", None),
    "SE.DF.Binary": ("binary", None), "SE.DF.ALPC": ("alpc", None),
}

# TypeId stencil -> a technology label worth keeping for the report.
STENCIL_TECH = {
    "SE.P.TW": "web application", "SE.P.TWS": "web service",
    "SE.P.WinService": "windows service", "SE.P.Thread": "thread",
    "SE.EI.BU": "browser user", "SE.EI.Ext": "external application",
    "SE.DS.SQL": "sql database", "SE.DS.FileSystem": "file system",
    "SE.DS.Registry": "windows registry", "SE.DS.Cache": "cache",
    "SE.DS.Cloud": "cloud storage", "SE.DS.WebApp": "web application storage",
}

SENSITIVE_NAME = re.compile(
    r"(secret|credential|password|token|key|cert|customer|user|patient|"
    r"account|billing|payment|card|order|profile|identity)", re.I)

STRIDE_FROM_CATEGORY = {
    "spoofing": "S", "tampering": "T", "repudiation": "R",
    "information disclosure": "I", "denial of service": "D",
    "elevation of privilege": "E",
}


def _tag(el: ET.Element) -> str:
    return el.tag.split("}")[-1]


def _text(el: Optional[ET.Element]) -> str:
    if el is None or el.text is None:
        return ""
    return el.text.strip()


def _child(el: ET.Element, name: str) -> Optional[ET.Element]:
    for c in el:
        if _tag(c) == name:
            return c
    return None


def _num(el: ET.Element, name: str) -> Optional[float]:
    try:
        return float(_text(_child(el, name)))
    except (TypeError, ValueError):
        return None


def _properties(value: ET.Element) -> Dict[str, str]:
    """TMT stores element attributes as a list of DisplayName/Value pairs."""
    out: Dict[str, str] = {}
    props = _child(value, "Properties")
    if props is None:
        return out
    for any_type in props:
        name = _text(_child(any_type, "DisplayName"))
        val = _text(_child(any_type, "Value"))
        if name:
            out[name] = val
    return out


def _kv_properties(value: ET.Element) -> Dict[str, str]:
    """Threat instances use Key/Value string pairs instead."""
    out: Dict[str, str] = {}
    props = _child(value, "Properties")
    if props is None:
        return out
    for kv in props:
        k = _text(_child(kv, "Key"))
        v = _text(_child(kv, "Value"))
        if k:
            out[k] = v
    return out


def tmt_id(guid: str) -> str:
    return f"{TMT_PREFIX}{guid}"


# ---------------------------------------------------------------------------

@register
class TmtIngestor(Ingestor):
    """Reads Microsoft Threat Modeling Tool `.tm7` documents."""

    name = "tmt"
    provider = "tmt"


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
        return bool(self._files(root, (".tm7",)))

    def ingest(self, root: str, model: ThreatModel) -> None:
        for path in self._files(root, (".tm7",)):
            try:
                rel = os.path.relpath(path, root)
            except ValueError:
                rel = os.path.basename(path)
            try:
                tree = ET.parse(path)
            except ET.ParseError as exc:
                model.error("ingest.tmt", f"not valid XML: {exc}", file=rel)
                self.stats["skipped"] += 1
                continue
            except Exception as exc:
                model.error("ingest.tmt", f"read failed: {exc}", file=rel)
                self.stats["skipped"] += 1
                continue
            self.stats["files"] += 1
            try:
                self._document(tree.getroot(), rel, model)
            except Exception as exc:
                model.error("ingest.tmt", f"import failed: {exc}", file=rel)

    # -- one document -----------------------------------------------------
    def _document(self, root_el: ET.Element, rel: str, model: ThreatModel) -> None:
        version = _text(root_el.find(".//{*}Version")) or "unknown"
        model.metadata.setdefault("tmt_imports", []).append(
            {"file": rel, "schema_version": version})

        shapes = self._collect(root_el, "Borders")
        lines = self._collect(root_el, "Lines")

        geometry: Dict[str, Tuple[float, float]] = {}   # element centres
        boundaries: List[Tuple[Boundary, Tuple[float, float, float, float]]] = []
        excluded: set = set()

        # -- shapes --------------------------------------------------------
        for guid, value in shapes:
            generic = _text(_child(value, "GenericTypeId"))
            if generic == SURFACE_TYPE:
                continue
            props = _properties(value)
            name = props.get("Name") or ""
            type_id = _text(_child(value, "TypeId"))

            if generic in BOUNDARY_TYPES:
                b, rect = self._boundary(guid, name or type_id or "Trust boundary",
                                         value, generic)
                boundaries.append((b, rect))
                continue

            if str(props.get("Out Of Scope", "")).lower() == "true":
                excluded.add(guid)
                continue

            element = GENERIC_TYPES.get(generic, Element.PROCESS)
            display = name or STENCIL_TECH.get(type_id) or type_id or "Unnamed element"

            asset = Asset(
                id=tmt_id(guid),
                kind={Element.EXTERNAL_ENTITY: "ExternalEntity",
                      Element.DATA_STORE: "DataStore"}.get(element, "Process"),
                name=display,
                provider="tmt",
                element=element,
                spec={"tmt": {"guid": guid, "generic_type": generic,
                              "type_id": type_id, "properties": props}},
                source=SourceRef(file=rel, pointer=f"Borders/{guid}"),
            )
            asset.tag("hand_authored", "imported_from_tmt")
            tech = STENCIL_TECH.get(type_id)
            if tech:
                asset.tag(f"tmt_stencil:{tech.replace(' ', '_')}")
            if element == Element.EXTERNAL_ENTITY:
                asset.tag("untrusted")
            if element == Element.DATA_STORE:
                asset.classify(DataClass.PII if SENSITIVE_NAME.search(display)
                               else DataClass.CONFIG)
            elif SENSITIVE_NAME.search(display):
                asset.classify(DataClass.PII)

            self.emit(model, asset)

            left, top = _num(value, "Left"), _num(value, "Top")
            width, height = _num(value, "Width"), _num(value, "Height")
            if None not in (left, top, width, height):
                geometry[guid] = (left + width / 2, top + height / 2)

        # -- flows ---------------------------------------------------------
        for guid, value in lines:
            if _text(_child(value, "GenericTypeId")) != FLOW_TYPE:
                continue
            src = _text(_child(value, "SourceGuid"))
            tgt = _text(_child(value, "TargetGuid"))
            if not src or not tgt:
                continue
            # A connector to an out-of-scope shape is not a flow in our model.
            if src in excluded or tgt in excluded:
                continue
            if tmt_id(src) not in model.assets or tmt_id(tgt) not in model.assets:
                continue

            props = _properties(value)
            type_id = _text(_child(value, "TypeId"))
            protocol, encrypted = STENCIL_PROTOCOL.get(type_id, (None, None))
            name = props.get("Name") or ""

            model.add_flow(Flow(
                source=tmt_id(src), target=tmt_id(tgt), kind="calls",
                protocol=protocol, encrypted=encrypted,
                details={"confidence": "confirmed", "hand_authored": True,
                         "name": name or None, "tmt_stencil": type_id or None},
                source_ref=SourceRef(file=rel, pointer=f"Lines/{guid}"),
            ))

        # -- boundaries are geometric --------------------------------------
        for boundary, (bx, by, bw, bh) in boundaries:
            for guid, (cx, cy) in geometry.items():
                if bx <= cx <= bx + bw and by <= cy <= by + bh:
                    aid = tmt_id(guid)
                    boundary.members.add(aid)
                    asset = model.assets.get(aid)
                    if asset:
                        asset.boundaries.add(boundary.id)
            model.add_boundary(boundary)

        # -- analyst threats -----------------------------------------------
        self._threats(root_el, rel, model, excluded)

    # -- helpers -----------------------------------------------------------
    def _collect(self, root_el: ET.Element, section: str) -> List[Tuple[str, ET.Element]]:
        out: List[Tuple[str, ET.Element]] = []
        for holder in root_el.iter():
            if _tag(holder) != section:
                continue
            for entry in holder:
                key = _text(_child(entry, "Key"))
                value = _child(entry, "Value")
                if key and value is not None:
                    out.append((key, value))
        return out

    def _boundary(self, guid: str, name: str, value: ET.Element,
                  generic: str) -> Tuple[Boundary, Tuple[float, float, float, float]]:
        left = _num(value, "Left") or 0.0
        top = _num(value, "Top") or 0.0
        width = _num(value, "Width") or 0.0
        height = _num(value, "Height") or 0.0
        lowered = name.lower()
        # TMT records no trust level, so infer one from the conventional names
        # analysts give boundaries. Wrong guesses are visible in the report.
        if any(k in lowered for k in ("internet", "public", "untrusted")):
            trust = 10
        elif any(k in lowered for k in ("dmz", "perimeter", "edge")):
            trust = 30
        elif any(k in lowered for k in ("machine", "process", "kernel", "host")):
            trust = 85
        else:
            trust = 60
        b = Boundary(
            id=f"boundary:tmt:{guid}",
            name=name,
            kind="tmt-line" if generic == "GE.TB.L" else "tmt-box",
            trust_level=trust,
            description=f"Trust boundary imported from a Microsoft TMT model ({name}).",
        )
        return b, (left, top, width, height)

    def _threats(self, root_el: ET.Element, rel: str, model: ThreatModel,
                 excluded: set) -> None:
        holder = root_el.find(".//{*}ThreatInstances")
        if holder is None:
            return
        for entry in holder:
            value = _child(entry, "Value")
            if value is None:
                continue
            props = _kv_properties(value)
            title = (props.get("Title") or _text(_child(value, "Title"))
                     or props.get("UserThreatCategory") or "Untitled TMT threat")
            category = (props.get("UserThreatCategory")
                        or props.get("ThreatCategory") or "")
            state = _text(_child(value, "State")) or "Unknown"
            src = _text(_child(value, "SourceGuid"))
            tgt = _text(_child(value, "TargetGuid"))
            component = tmt_id(src) if src and src not in excluded else None
            if component and component not in model.assets:
                component = None

            model.metadata.setdefault("manual_threats", []).append({
                "id": _text(_child(value, "Id")) or _text(_child(entry, "Key")),
                "title": title,
                "category": category,
                "stride": STRIDE_FROM_CATEGORY.get(category.lower()),
                "severity": (props.get("Priority")
                             or _text(_child(value, "Priority")) or "").lower() or None,
                "component": component,
                "target": tmt_id(tgt) if tgt else None,
                "description": props.get("UserThreatDescription") or "",
                "mitigation": state,
                "mitigation_detail": _text(_child(value, "StateInformation")),
                "source_file": rel,
                "origin": "microsoft-tmt",
            })
