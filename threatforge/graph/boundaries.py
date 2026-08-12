# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""
Trust boundary derivation and flow annotation.

A trust boundary is any place where the level of trust changes.  We derive a
nested hierarchy:

    internet (trust 0)
      └── cloud account / VPC (trust 40)
            └── cluster (trust 60)
                  └── namespace (trust 70..90 by tier)
                        └── pod (trust 85)
                              └── container (trust 90)

Every flow is then annotated with whether it crosses a boundary and, if so,
which one -- because a flow that stays inside one boundary is rarely the
interesting part of a threat model.
"""

from __future__ import annotations

from typing import Dict, Optional

from ..model import Asset, Boundary, Element, ThreatModel

INTERNET_BOUNDARY = "boundary:internet"
CLUSTER_BOUNDARY = "boundary:cluster:default"

# Namespaces that are effectively part of the control plane -- compromise here
# is materially worse than in an app namespace.
PRIVILEGED_NAMESPACES = {
    "kube-system", "kube-public", "kube-node-lease", "istio-system",
    "cert-manager", "ingress-nginx", "argocd", "flux-system", "linkerd",
    "monitoring", "observability", "vault", "external-secrets",
}

PROD_HINTS = ("prod", "production", "live")
NONPROD_HINTS = ("dev", "test", "staging", "stage", "qa", "sandbox", "uat")


def build_boundaries(model: ThreatModel) -> None:
    _internet(model)
    _cluster_and_namespaces(model)
    _cloud(model)
    _nodes(model)
    _assign_membership(model)
    annotate_flows(model)


# ---------------------------------------------------------------------------

def _internet(model: ThreatModel) -> None:
    model.add_boundary(Boundary(
        id=INTERNET_BOUNDARY, name="Internet", kind="internet", trust_level=0,
        description="Anonymous, unauthenticated, fully untrusted network.",
    ))


def _cluster_and_namespaces(model: ThreatModel) -> None:
    k8s_assets = [a for a in model.assets.values() if a.provider in ("kubernetes", "live")]
    if not k8s_assets:
        return
    model.add_boundary(Boundary(
        id=CLUSTER_BOUNDARY, name="Kubernetes cluster", kind="cluster",
        trust_level=60, parent=INTERNET_BOUNDARY,
        description="Everything inside the cluster network and API server.",
    ))

    namespaces = {a.namespace for a in k8s_assets if a.namespace}
    for ns in sorted(namespaces):
        trust = 70
        desc = "Application namespace."
        if ns in PRIVILEGED_NAMESPACES:
            trust = 90
            desc = "Control-plane / platform namespace. Compromise implies cluster compromise."
        elif any(h in ns.lower() for h in PROD_HINTS):
            trust = 80
            desc = "Production namespace."
        elif any(h in ns.lower() for h in NONPROD_HINTS):
            trust = 65
            desc = "Non-production namespace. Often a soft entry point into shared infrastructure."
        model.add_boundary(Boundary(
            id=f"boundary:namespace:{ns}", name=f"namespace/{ns}", kind="namespace",
            trust_level=trust, parent=CLUSTER_BOUNDARY, description=desc,
        ))


def _cloud(model: ThreatModel) -> None:
    tf = [a for a in model.assets.values() if a.provider == "terraform"]
    if not tf:
        return
    clouds = set()
    for a in tf:
        for t in a.tags:
            if t.startswith("cloud:"):
                clouds.add(t.split(":", 1)[1])
    for c in sorted(clouds or {"cloud"}):
        model.add_boundary(Boundary(
            id=f"boundary:cloud:{c}", name=f"{c.upper()} account", kind="cloud-account",
            trust_level=40, parent=INTERNET_BOUNDARY,
            description=f"Managed {c} resources. Trust is enforced by IAM, not by network position.",
        ))


def _nodes(model: ThreatModel) -> None:
    """A host-path / host-network workload escapes the pod boundary onto the node."""
    escapes = [a for a in model.assets.values()
               if a.tags & {"host_path_mount", "host_network", "privileged"}]
    if not escapes:
        return
    model.add_boundary(Boundary(
        id="boundary:node", name="Worker node (host OS)", kind="node",
        trust_level=95, parent=CLUSTER_BOUNDARY,
        description="Node filesystem, kubelet, and container runtime. "
                    "Reaching here means the container boundary has been bypassed.",
    ))


def _assign_membership(model: ThreatModel) -> None:
    for a in model.assets.values():
        if a.element == Element.EXTERNAL_ENTITY:
            a.boundaries.add(INTERNET_BOUNDARY)
            model.boundaries[INTERNET_BOUNDARY].members.add(a.id)
            continue

        if a.provider == "terraform":
            cloud = next((t.split(":", 1)[1] for t in a.tags if t.startswith("cloud:")), "cloud")
            bid = f"boundary:cloud:{cloud}"
            if bid in model.boundaries:
                a.boundaries.add(bid)
                model.boundaries[bid].members.add(a.id)
            continue

        if a.provider in ("kubernetes", "live"):
            if CLUSTER_BOUNDARY in model.boundaries:
                a.boundaries.add(CLUSTER_BOUNDARY)
                model.boundaries[CLUSTER_BOUNDARY].members.add(a.id)
            if a.namespace:
                bid = f"boundary:namespace:{a.namespace}"
                if bid in model.boundaries:
                    a.boundaries.add(bid)
                    model.boundaries[bid].members.add(a.id)
            if a.tags & {"host_path_mount", "host_network", "privileged"} and \
                    "boundary:node" in model.boundaries:
                a.boundaries.add("boundary:node")
                model.boundaries["boundary:node"].members.add(a.id)


# ---------------------------------------------------------------------------

def innermost(model: ThreatModel, asset_id: str) -> Optional[Boundary]:
    """The most specific (highest trust) boundary an asset belongs to."""
    a = model.assets.get(asset_id)
    if not a or not a.boundaries:
        return None
    bs = [model.boundaries[b] for b in a.boundaries if b in model.boundaries]
    if not bs:
        return None
    return max(bs, key=lambda b: b.trust_level)


def annotate_flows(model: ThreatModel) -> None:
    """Mark boundary-crossing flows and record the trust delta."""
    for f in model.flows:
        src = innermost(model, f.source)
        tgt = innermost(model, f.target)
        if not src or not tgt:
            continue
        if src.id == tgt.id:
            f.crosses_boundary = False
            continue
        f.crosses_boundary = True
        # the boundary being *entered* is what matters for attack modelling
        entered = tgt if tgt.trust_level > src.trust_level else src
        f.boundary_crossed = entered.id
        f.details["trust_delta"] = tgt.trust_level - src.trust_level
        f.details["from_boundary"] = src.id
        f.details["to_boundary"] = tgt.id
