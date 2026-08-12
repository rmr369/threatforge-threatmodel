# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""
Risk scoring.

Score = likelihood x impact, both on 1..5, both derived from observable
properties of the graph rather than from a static table keyed on the STRIDE
letter.  Every adjustment is recorded in `finding.risk.control_offsets` and
`finding.risk.notes` so a reviewer can see exactly why a number came out the
way it did -- and argue with it.

The single most important input is exposure: the same missing control on an
internet-reachable pod and on an isolated batch job are not the same risk, and
a scoring model that cannot express that will drown its users in "High".
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from .model import (Confidence, Element, Finding, RiskFactors, Severity,
                    ThreatModel)

BASE = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFO: 1,
}

CONFIDENCE_ADJ = {
    Confidence.CONFIRMED: 0,
    Confidence.LIKELY: 0,
    Confidence.POSSIBLE: -1,
}

# Namespaces where compromise is materially worse.
CONTROL_PLANE_NS = {
    "kube-system", "kube-public", "istio-system", "cert-manager",
    "argocd", "flux-system", "vault", "external-secrets", "ingress-nginx",
}


def score_all(model: ThreatModel, config: Optional[Dict[str, Any]] = None) -> None:
    cfg = config or {}
    prod_only = cfg.get("production_namespaces")
    for finding in model.findings:
        _score(model, finding, cfg, prod_only)
    model.findings.sort(key=lambda f: (-f.risk_score, f.risk_level.rank * -1, f.rule_id))
    model.metadata["risk"] = {
        "method": "likelihood x impact (1-25), exposure- and control-adjusted",
        "distribution": model.counts(),
        "top_rules": _top_rules(model),
    }


# ---------------------------------------------------------------------------

def _score(model: ThreatModel, f: Finding, cfg: Dict[str, Any],
           prod_only: Optional[List[str]]) -> None:
    asset = model.assets.get(f.component)
    facts: Dict[str, Any] = asset.facts if asset else {}
    rf = RiskFactors()
    offsets: Dict[str, int] = {}
    notes: List[str] = []

    base = BASE[f.severity]
    likelihood = base
    impact = base

    # -- exposure ---------------------------------------------------------
    hops = facts.get("exposure_hops")
    if f.component_type == "data_flow":
        hops = _flow_hops(model, f.component)
    rf.exposure_hops = hops

    if hops is None:
        offsets["not_internet_reachable"] = -2
        likelihood -= 2
        notes.append("No path from an external entity was found, so remote exploitation "
                     "requires an existing foothold.")
    elif hops <= 1:
        offsets["directly_internet_exposed"] = +1
        likelihood += 1
        notes.append("Directly reachable from the internet.")
    elif hops <= 3:
        notes.append(f"Reachable from the internet in {hops} hops.")
    else:
        offsets["deep_in_the_graph"] = -1
        likelihood -= 1
        notes.append(f"{hops} hops from the internet; requires chaining.")

    # -- confidence -------------------------------------------------------
    adj = CONFIDENCE_ADJ.get(f.confidence, 0)
    if adj:
        offsets["confidence"] = adj
        likelihood += adj
        notes.append(f"Confidence is '{f.confidence.value}', so likelihood is discounted.")

    # -- compensating controls -------------------------------------------
    if facts.get("net.has_ingress_policy") and "network" in f.tags:
        offsets["network_policy_present"] = -1
        likelihood -= 1
        notes.append("An ingress NetworkPolicy limits who can reach this workload.")
    if facts.get("pod.has_seccomp") and "container-escape" in f.tags:
        offsets["seccomp_present"] = -1
        likelihood -= 1
        notes.append("A seccomp profile blocks many escape syscalls.")
    if facts.get("ns.pss_is_restricted"):
        offsets["pss_restricted"] = -1
        likelihood -= 1
        notes.append("Namespace enforces the restricted Pod Security Standard.")

    # -- aggravating context ----------------------------------------------
    ns = (asset.namespace if asset else None) or ""
    if ns in CONTROL_PLANE_NS:
        offsets["control_plane_namespace"] = +1
        impact += 1
        notes.append(f"Lives in control-plane namespace '{ns}'; compromise implies "
                     "cluster-wide impact.")
    if prod_only and ns in prod_only:
        offsets["production"] = +1
        impact += 1
        notes.append("Production namespace.")

    sensitivity = facts.get("sensitivity", asset.sensitivity if asset else 1)
    rf.sensitivity = sensitivity
    if sensitivity >= 5:
        offsets["holds_secrets"] = +1
        impact += 1
        notes.append("Holds secret or credential material.")
    elif sensitivity >= 4:
        notes.append("Handles personal or otherwise regulated data.")

    if facts.get("reaches_sensitive") and f.component_type != "data_flow":
        offsets["reaches_sensitive_data"] = +1
        impact += 1
        notes.append("Has a path to a sensitive data store.")

    blast = int(facts.get("blast_radius") or 0)
    rf.blast_radius = blast
    if blast >= 50:
        offsets["large_blast_radius"] = +2
        impact += 2
        notes.append(f"Compromise reaches {blast} downstream assets.")
    elif blast >= 15:
        offsets["moderate_blast_radius"] = +1
        impact += 1
        notes.append(f"Compromise reaches {blast} downstream assets.")

    if "critical-path" in f.tags:
        offsets["critical_path_rule"] = +1
        impact += 1

    # -- clamp and finalise ------------------------------------------------
    likelihood = max(1, min(5, likelihood))
    impact = max(1, min(5, impact))
    rf.likelihood = likelihood
    rf.impact = impact
    rf.control_offsets = offsets
    rf.notes = notes

    f.risk = rf
    f.risk_score = likelihood * impact
    f.risk_level = _level(f.risk_score, f.severity)


def _level(score: int, base_sev: Severity) -> Severity:
    if base_sev == Severity.INFO:
        return Severity.INFO
    if score >= 20:
        return Severity.CRITICAL
    if score >= 12:
        return Severity.HIGH
    if score >= 6:
        return Severity.MEDIUM
    return Severity.LOW


def _flow_hops(model: ThreatModel, flow_id: str) -> Optional[int]:
    for fl in model.flows:
        if fl.id != flow_id:
            continue
        src = model.assets.get(fl.source)
        if src and src.element == Element.EXTERNAL_ENTITY:
            return 0
        return src.facts.get("exposure_hops") if src else None
    return None


def _top_rules(model: ThreatModel) -> List[Dict[str, Any]]:
    counts: Dict[str, Dict[str, Any]] = {}
    for f in model.active_findings:
        e = counts.setdefault(f.rule_id, {"rule_id": f.rule_id, "title": f.title,
                                          "count": 0, "max_score": 0})
        e["count"] += 1
        e["max_score"] = max(e["max_score"], f.risk_score)
    return sorted(counts.values(), key=lambda x: (-x["max_score"], -x["count"]))[:15]


# ---------------------------------------------------------------------------
# Suppression / baseline
# ---------------------------------------------------------------------------

def path_matches(path: str, pattern: str) -> bool:
    """Glob match that behaves the way people expect.

    `fnmatch` requires a literal separator for `**/`, so `**/*.tf` misses a
    top-level `main.tf`. We try the full path, the path with a leading `**/`
    stripped, and the basename.
    """
    import fnmatch
    p = str(path).replace("\\", "/")
    pat = str(pattern).replace("\\", "/")
    candidates = {pat}
    if pat.startswith("**/"):
        candidates.add(pat[3:])
    return any(fnmatch.fnmatch(p, c) or fnmatch.fnmatch(p.split("/")[-1], c)
               for c in candidates)


def apply_suppressions(model: ThreatModel, config: Dict[str, Any],
                       baseline: Optional[Dict[str, Any]] = None) -> None:
    """Config-driven ignores plus an accepted-risk baseline file."""
    import fnmatch

    rules_off = set(config.get("suppress", {}).get("rules", []) or [])
    components = config.get("suppress", {}).get("components", []) or []
    paths = config.get("suppress", {}).get("paths", []) or []
    below = config.get("suppress", {}).get("below_severity")

    baseline_ids = set((baseline or {}).get("accepted", {}).keys()) if baseline else set()
    baseline_meta = (baseline or {}).get("accepted", {}) if baseline else {}

    order = [s.value for s in (Severity.INFO, Severity.LOW, Severity.MEDIUM,
                               Severity.HIGH, Severity.CRITICAL)]

    # Out of scope, declared on the component itself in the DFD editor. Handled
    # here rather than in each rule so a rule cannot forget it, and suppressed
    # rather than deleted so the decision -- and its stated reason -- stays
    # visible in the report instead of the component quietly going quiet.
    out_of_scope: Dict[str, str] = {}
    for asset in model.assets.values():
        if asset.facts.get("attr.out_of_scope") is True:
            out_of_scope[asset.id] = str(
                asset.facts.get("attr.out_of_scope_reason") or "no reason recorded")

    for f in model.findings:
        if f.component in out_of_scope:
            f.suppressed = True
            f.suppression_reason = f"out of scope: {out_of_scope[f.component]}"
            continue
        if f.rule_id in rules_off or any(fnmatch.fnmatch(f.rule_id, r) for r in rules_off):
            f.suppressed, f.suppression_reason = True, "rule disabled in configuration"
            continue
        if any(fnmatch.fnmatch(f.component, c) for c in components):
            f.suppressed, f.suppression_reason = True, "component excluded in configuration"
            continue
        src = f.primary_source
        if src.file and any(path_matches(src.file, p) for p in paths):
            f.suppressed, f.suppression_reason = True, f"path excluded: {src.file}"
            continue
        if below and order.index(f.risk_level.value) < order.index(below):
            f.suppressed, f.suppression_reason = True, f"below reporting threshold ({below})"
            continue
        if f.id in baseline_ids:
            meta = baseline_meta.get(f.id, {})
            f.suppressed = True
            f.baseline_accepted = True
            f.suppression_reason = (f"accepted risk: {meta.get('reason', 'no reason recorded')}"
                                    f" (owner: {meta.get('owner', 'unassigned')},"
                                    f" expires: {meta.get('expires', 'never')})")
