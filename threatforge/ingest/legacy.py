# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""
Legacy importer for the original stage-based pipeline.

Lets you load `architecture.json` (stage 3) or `stage7-dfd.json` (stage 7) into
the new model so historical output can be re-scored and diffed without
re-running discovery.  Note: legacy files carry no raw spec, so control-based
rules will not fire -- only graph/topology rules will.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict

from ..model import Asset, Element, Flow, SourceRef, ThreatModel
from .base import Ingestor, register


def _element(node_type: str) -> Element:
    t = (node_type or "").lower()
    if t in ("data_store", "datastore"):
        return Element.DATA_STORE
    if t in ("external_entity", "external"):
        return Element.EXTERNAL_ENTITY
    return Element.PROCESS


def canonical_id(legacy_id: str) -> str:
    """Translate stage-7 ids (`Kind:ns:name`) into the canonical URN scheme.

    Without this, importing both architecture.json and stage7-dfd.json produces
    two disconnected copies of the same cluster.
    """
    if not legacy_id or legacy_id.startswith(("k8s:", "tf:", "ext:", "docker:",
                                              "compose:", "boundary:", "external:")):
        return legacy_id.replace("external:internet", "ext:internet")
    parts = legacy_id.split(":")
    if len(parts) == 3:
        kind, ns, name = parts
        return f"k8s:{kind}:{ns or 'default'}/{name}"
    if len(parts) == 4 and parts[0] == "Container":
        _, ns, workload, cname = parts
        return f"k8s:Container:{ns or 'default'}/{workload}/{cname}"
    return legacy_id


@register
class LegacyStage7Ingestor(Ingestor):
    name = "legacy"
    provider = "legacy"

    CANDIDATES = ("stage7-dfd.json", "dfd.json", "architecture.json")

    def detect(self, root: str) -> bool:
        return any(os.path.exists(os.path.join(root, c)) for c in self.CANDIDATES)

    def ingest(self, root: str, model: ThreatModel) -> None:
        explicit = self.config.get("path")
        paths = [explicit] if explicit else [
            os.path.join(root, c) for c in self.CANDIDATES
            if os.path.exists(os.path.join(root, c))
        ]
        for path in paths:
            if not path or not os.path.exists(path):
                continue
            try:
                data = json.load(open(path, "r", encoding="utf-8"))
            except Exception as exc:
                model.error("ingest.legacy", f"{path}: {exc}")
                continue
            self.stats["files"] += 1
            rel = os.path.basename(path)
            if "resources" in data:
                self._from_architecture(data, rel, model)
            if "nodes" in data:
                self._from_dfd(data, rel, model)
            model.metadata.setdefault("legacy_imports", []).append(rel)

    # -- stage 3 ----------------------------------------------------------
    def _from_architecture(self, data: Dict[str, Any], rel: str, model: ThreatModel) -> None:
        for res in data.get("resources") or []:
            kind = res.get("type")
            name = res.get("name")
            if not kind or not name:
                continue
            ns = res.get("namespace") or "default"
            asset = Asset(
                id=f"k8s:{kind}:{ns}/{name}",
                kind=kind, name=name, namespace=ns,
                provider="kubernetes",
                element=_element("data_store" if kind in
                                 ("Secret", "ConfigMap", "PersistentVolume",
                                  "PersistentVolumeClaim") else "process"),
                spec={"legacy": res},
                source=SourceRef(file=res.get("source_file") or rel),
            )
            asset.tag("legacy_import")
            self.emit(model, asset)

    # -- stage 7 ----------------------------------------------------------
    def _from_dfd(self, data: Dict[str, Any], rel: str, model: ThreatModel) -> None:
        for node in data.get("nodes") or []:
            nid = node.get("id")
            if not nid:
                continue
            cid = canonical_id(nid)
            asset = Asset(
                id=cid,
                kind=cid.split(":")[1] if cid.startswith("k8s:") else
                     node.get("type", "Unknown"),
                name=node.get("name") or node.get("label") or nid,
                namespace=node.get("namespace"),
                provider="kubernetes",
                element=_element(node.get("type", "")),
                spec={"legacy": node},
                source=SourceRef(file=rel),
            )
            asset.tag("legacy_import")
            self.emit(model, asset)

        for edge in data.get("edges") or []:
            src, tgt = edge.get("source"), edge.get("target")
            if not src or not tgt:
                continue
            model.add_flow(Flow(
                source=canonical_id(src), target=canonical_id(tgt),
                kind=edge.get("relationship", "flow"),
                details={"confidence": "possible", **(edge.get("details") or {})},
                source_ref=SourceRef(file=rel),
            ))
