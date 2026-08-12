# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""
Hand-authored threat model ingestion.

Static analysis can only see what is declared in the repository. It cannot see
the payment provider you call over the internet, the mainframe behind the
corporate firewall, the human operator with console access, or the SaaS tool
holding a copy of your customer data. Those are frequently the most interesting
nodes in the graph, and their absence silently understates every reachability
and blast-radius number downstream.

This ingestor closes that gap by reading models a human drew, and merging them
into the same graph the scanner produces.

Two dialects are supported:

  *.tfm.yml / threatforge-overlay.yml
      Native overlay. Terse, designed to be hand-edited next to your manifests,
      and able to attach directly to scanner-discovered assets by id.

  *.thf
      An interchange dialect used by graphical threat-modelling editors. Reading
      and writing it lets a diagram drawn in an editor participate in automated
      analysis, and lets an automatically generated model be opened and edited
      by hand.

Interoperability note
---------------------
The `.thf` support here is an independent implementation written against the
observed structure of the data format. File formats are not themselves
copyrightable, and no source code from any editor implementing this format is
incorporated, referenced, or derived from. See `docs/INTEROP.md`.
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

from .. import library
from ..model import (Asset, Boundary, DataClass, Element, Flow,
                     SourceRef, ThreatModel)
from .base import Ingestor, load_yaml_with_lines, ref, register, walk_files

# ---------------------------------------------------------------------------
# Vocabulary mapping
# ---------------------------------------------------------------------------

ELEMENT_TYPES = {
    "process": Element.PROCESS,
    "data_store": Element.DATA_STORE,
    "datastore": Element.DATA_STORE,
    "external_entity": Element.EXTERNAL_ENTITY,
    "external": Element.EXTERNAL_ENTITY,
    "actor": Element.EXTERNAL_ENTITY,
    "generic": Element.PROCESS,
}

# Purely presentational node kinds in graphical editors. They carry no security
# meaning, so importing them would inflate the asset count for nothing.
DECORATIVE_TYPES = {"text", "note", "comment", "label", "sticky", "image"}

# trust_zone -> boundary trust level, on the same 0..100 scale the rest of the
# pipeline uses (0 = internet, 95 = node/host).
TRUST_ZONES = {
    "external": 0,
    "public": 0,
    "internet": 0,
    "untrusted": 10,
    "dmz": 30,
    "perimeter": 30,
    "partner": 40,
    "internal": 70,
    "private": 70,
    "restricted": 85,
    "trusted": 85,
    "management": 90,
}

DATA_CLASS_HINTS = {
    "secret": DataClass.SECRET, "credential": DataClass.CREDENTIAL,
    "password": DataClass.CREDENTIAL, "token": DataClass.CREDENTIAL,
    "key": DataClass.CREDENTIAL, "pii": DataClass.PII, "personal": DataClass.PII,
    "customer": DataClass.PII, "phi": DataClass.PHI, "health": DataClass.PHI,
    "medical": DataClass.PHI, "pci": DataClass.PCI, "card": DataClass.PCI,
    "payment": DataClass.PCI, "config": DataClass.CONFIG, "public": DataClass.PUBLIC,
}

MANUAL_PREFIX = "manual:"


def manual_id(raw: str) -> str:
    """Namespace hand-authored ids so they cannot collide with scanned assets."""
    raw = str(raw)
    if ":" in raw and not raw.startswith(MANUAL_PREFIX):
        return raw                      # already a canonical urn -- an attach-to reference
    return raw if raw.startswith(MANUAL_PREFIX) else f"{MANUAL_PREFIX}{raw}"


def _data_classes(values: Any) -> set:
    out = set()
    for v in (values if isinstance(values, (list, tuple)) else [values]):
        text = str(v or "").lower()
        for hint, dc in DATA_CLASS_HINTS.items():
            if hint in text:
                out.add(dc)
    return out


# ---------------------------------------------------------------------------

@register
class ManualModelIngestor(Ingestor):
    """Reads hand-authored models and merges them into the scanned graph."""

    name = "manual"
    provider = "manual"

    OVERLAY_NAMES = ["threatforge-overlay.yml", "threatforge-overlay.yaml",
                     "threat-model.tfm.yml"]

    def detect(self, root: str) -> bool:
        return bool(self._files(root))

    def _files(self, root: str) -> List[str]:
        files = walk_files(root, (".thf", ".tfm.yml", ".tfm.yaml"),
                           filenames=self.OVERLAY_NAMES)
        explicit = self.config.get("paths") or []
        for p in explicit:
            full = p if os.path.isabs(p) else os.path.join(root, p)
            if os.path.exists(full) and full not in files:
                files.append(full)
        return files

    def ingest(self, root: str, model: ThreatModel) -> None:
        for path in self._files(root):
            rel = os.path.relpath(path, root)
            try:
                docs = load_yaml_with_lines(path)
            except Exception as exc:
                model.error("ingest.manual", f"parse failed: {exc}", file=rel)
                self.stats["skipped"] += 1
                continue
            self.stats["files"] += 1
            for doc, lines in docs:
                if isinstance(doc, dict):
                    self._load(doc, lines, rel, model)

    # -- one document -----------------------------------------------------
    def _load(self, doc: Dict[str, Any], lines: Dict[str, int],
              rel: str, model: ThreatModel) -> None:
        meta = doc.get("metadata") or {}
        if meta.get("title"):
            model.metadata.setdefault("manual_models", []).append(
                {"file": rel, "title": meta.get("title"),
                 "description": meta.get("description")})

        # `elements` is the interchange spelling, `components` the overlay one.
        elements = (doc.get("elements") or []) + (doc.get("components") or [])
        for i, el in enumerate(elements):
            if isinstance(el, dict):
                self._element(el, ref(rel, lines, f"elements[{i}]"), model)

        flows = (doc.get("data_flows") or []) + (doc.get("flows") or [])
        for i, fl in enumerate(flows):
            if isinstance(fl, dict):
                self._flow(fl, ref(rel, lines, f"data_flows[{i}]"), model)

        # `relationships` are non-data edges (deploys_to, depends_on...). They
        # matter for blast radius even though nothing flows along them.
        for i, r in enumerate(doc.get("relationships") or []):
            if isinstance(r, dict):
                self._flow(r, ref(rel, lines, f"relationships[{i}]"), model,
                           default_kind=str(r.get("type") or "relates-to"))

        for i, b in enumerate(doc.get("trust_boundaries") or []):
            if isinstance(b, dict):
                self._boundary(b, model)

        # Pre-existing manual threats are recorded so the report can show what a
        # human already identified alongside what the scanner found.
        for t in doc.get("threats") or []:
            if isinstance(t, dict):
                model.metadata.setdefault("manual_threats", []).append({
                    "id": t.get("id"), "title": t.get("title"),
                    "category": t.get("category"), "severity": t.get("severity"),
                    "component": manual_id(t.get("element") or t.get("flow") or ""),
                    "description": t.get("description"),
                    "mitigation": (t.get("mitigation") or {}).get("status")
                    if isinstance(t.get("mitigation"), dict) else t.get("mitigation"),
                    "source_file": rel,
                })

    # -- element ----------------------------------------------------------
    def _element(self, el: Dict[str, Any], src: SourceRef, model: ThreatModel) -> None:
        etype = str(el.get("type") or "generic").lower()
        if etype in DECORATIVE_TYPES:
            return

        # `attach_to` lets an overlay annotate an asset the scanner already found
        # rather than creating a duplicate node beside it. This is checked before
        # the id requirement, because an annotation legitimately has no id of its
        # own -- it borrows the target's.
        attach = el.get("attach_to")
        if attach:
            target = model.assets.get(str(attach))
            if target is None:
                model.error("ingest.manual",
                            f"attach_to references an asset that was not found: {attach}",
                            file=src.file, hint="run `threatforge scan . -f json` and "
                                                "check the asset ids in threat-model.json")
                return
            target.tag("annotated_by_hand")
            for dc in _data_classes(el.get("data") or el.get("data_classification")):
                target.classify(dc)
            for t in el.get("tags") or []:
                target.tag(str(t))
            if el.get("trust_zone"):
                target.facts["manual.trust_zone"] = el["trust_zone"]
            if el.get("description"):
                target.facts["manual.description"] = el["description"]
            for k, v in library.coerce(target.element.value,
                                       el.get("attributes") or {}).items():
                target.facts[f"attr.{k}"] = v
            return

        raw_id = el.get("id") or el.get("name")
        if not raw_id:
            return

        asset = Asset(
            id=manual_id(raw_id),
            kind=el.get("kind") or etype.replace("_", " ").title().replace(" ", ""),
            name=str(el.get("name") or raw_id),
            provider="manual",
            element=ELEMENT_TYPES.get(etype, Element.PROCESS),
            spec={"manual": el, "technologies": el.get("technologies") or []},
            source=src,
        )
        asset.tag("hand_authored")
        for t in el.get("tags") or []:
            asset.tag(str(t))

        zone = str(el.get("trust_zone") or "").lower()
        if zone:
            asset.tag(f"trust_zone:{zone}")
            if TRUST_ZONES.get(zone, 100) <= 10:
                asset.tag("untrusted")
                asset.element = Element.EXTERNAL_ENTITY

        # Design attributes become `attr.*` facts so rules can read them. They
        # are validated first: an unknown key would be a fact no rule reads and
        # no reviewer can interpret.
        attrs = library.coerce(asset.element.value, el.get("attributes") or {})
        for k, v in attrs.items():
            asset.facts[f"attr.{k}"] = v
        if attrs:
            asset.facts["attr._answered"] = sorted(attrs)
        asset.facts["attr._unanswered"] = library.unanswered(
            asset.element.value, attrs)
        # Custom attributes are recorded as `custom.*` facts. No built-in rule
        # reads them -- that is the point. They exist so an organisation can
        # write its own rules against its own vocabulary without patching the
        # schema, and they are namespaced so they can never collide with one.
        for k, v in (el.get("custom_attributes") or {}).items():
            key = str(k).strip()[:60]
            if key:
                asset.facts[f"custom.{key}"] = str(v)[:500]
        if el.get("component_type"):
            asset.facts["library.type"] = str(el["component_type"])
        for tech in el.get("technologies") or []:
            asset.tag(f"tech:{str(tech).lower()}")

        asset.data_classes |= _data_classes(
            el.get("data") or el.get("data_classification") or el.get("description"))
        if asset.element == Element.DATA_STORE and not asset.data_classes:
            asset.classify(DataClass.PII)     # a data store with unstated contents
        self.emit(model, asset)

    # -- flow -------------------------------------------------------------
    def _flow(self, fl: Dict[str, Any], src: SourceRef, model: ThreatModel,
              default_kind: str = "calls") -> None:
        a, b = fl.get("from") or fl.get("source"), fl.get("to") or fl.get("target")
        if not a or not b:
            return
        source_id, target_id = manual_id(a), manual_id(b)
        # A hand-drawn edge may point at a scanned asset by its canonical id.
        source_id = source_id if source_id in model.assets or a not in model.assets else a
        target_id = target_id if target_id in model.assets or b not in model.assets else b

        protocol = str(fl.get("protocol") or "") or None
        encrypted = fl.get("encrypted")
        if encrypted is None and protocol:
            p = protocol.lower()
            encrypted = any(k in p for k in ("tls", "https", "ssh", "mtls", "wss"))
            if any(k in p for k in ("http/", "http ", "ftp", "telnet")) and "https" not in p:
                encrypted = False

        model.add_flow(Flow(
            source=source_id,
            target=target_id,
            kind=str(fl.get("kind") or default_kind),
            protocol=protocol,
            encrypted=encrypted,
            authenticated=fl.get("authenticated"),
            data_classes=_data_classes(fl.get("data")),
            details={"confidence": "confirmed", "hand_authored": True,
                     "name": fl.get("name"), "flow_number": fl.get("flow_number"),
                     "attributes": library.coerce("data_flow",
                                                  fl.get("attributes") or {})},
            source_ref=src,
        ))

    # -- boundary ---------------------------------------------------------
    def _boundary(self, b: Dict[str, Any], model: ThreatModel) -> None:
        raw_id = b.get("id") or b.get("name")
        if not raw_id:
            return
        zone = str(b.get("trust_zone") or b.get("zone") or "").lower()
        boundary = Boundary(
            id=f"boundary:manual:{raw_id}",
            name=str(b.get("name") or raw_id),
            kind=str(b.get("kind") or "manual"),
            trust_level=int(b.get("trust_level", TRUST_ZONES.get(zone, 50))),
            parent=b.get("parent"),
            description=str(b.get("description") or "Hand-authored trust boundary."),
        )
        for member in b.get("contains") or []:
            mid = manual_id(member)
            boundary.members.add(mid if mid in model.assets else str(member))
        model.add_boundary(boundary)

        for mid in boundary.members:
            asset = model.assets.get(mid)
            if asset:
                asset.boundaries.add(boundary.id)
