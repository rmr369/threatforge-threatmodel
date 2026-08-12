# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""
Markdown threat model document.

Written to be read by a human in a review meeting, not scrolled past: executive
summary first, attack narratives second, the finding register last.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, List

from ..model import Element, Severity, ThreatModel
from .mermaid import render_attack_path, render_dfd

STRIDE_FULL = {
    "S": "Spoofing", "T": "Tampering", "R": "Repudiation",
    "I": "Information Disclosure", "D": "Denial of Service",
    "E": "Elevation of Privilege",
}


def render(model: ThreatModel, *, max_findings: int = 60,
           include_diagrams: bool = True) -> str:
    out: List[str] = []
    w = out.append
    counts = model.counts()
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    w(f"# Threat model — {model.project}\n")
    w(f"*Generated {now} by ThreatForge. Evidence-based STRIDE analysis of "
      f"infrastructure-as-code.*\n")

    # -- executive summary -------------------------------------------------
    w("## Executive summary\n")
    w(_summary_prose(model, counts))
    w("")
    w("| Risk level | Findings |")
    w("|---|---|")
    for lvl in ("critical", "high", "medium", "low", "info"):
        if counts.get(lvl):
            w(f"| {lvl.title()} | {counts[lvl]} |")
    w("")

    cov = model.metadata.get("control_coverage") or {}
    if cov.get("workloads"):
        w("### Control coverage\n")
        w(f"Across {cov['workloads']} workloads:\n")
        w("| Control | Coverage |")
        w("|---|---|")
        for k, v in sorted(cov.items(), key=lambda kv: kv[1] if kv[0] != "workloads" else 999):
            if k == "workloads":
                continue
            w(f"| {k.replace('_', ' ').title()} | {v}% |")
        w("")

    # -- scope -------------------------------------------------------------
    w("## Scope\n")
    w(f"- **Assets modelled:** {len(model.assets)}")
    w(f"- **Data flows:** {len(model.flows)}")
    w(f"- **Trust boundaries:** {len(model.boundaries)}")
    ing = model.metadata.get("ingestors", {})
    if ing:
        srcs = ", ".join(f"{k} ({v.get('files', 0)} files)" for k, v in ing.items()
                         if v.get("assets"))
        w(f"- **Sources parsed:** {srcs}")
    w("")
    w("**Out of scope for this analysis:** application source code, image contents and "
      "CVEs, runtime behaviour, admission or mesh policy applied outside the scanned "
      "sources, and any resource created out-of-band. Absence of a finding here is not "
      "evidence that a risk does not exist.\n")

    # -- trust boundaries --------------------------------------------------
    w("## Trust boundaries\n")
    w("| Boundary | Kind | Trust | Assets | Notes |")
    w("|---|---|---|---|---|")
    for b in sorted(model.boundaries.values(), key=lambda x: x.trust_level):
        w(f"| {b.name} | {b.kind} | {b.trust_level} | {len(b.members)} | {b.description} |")
    w("")

    # -- DFD ---------------------------------------------------------------
    if include_diagrams:
        w("## Data flow diagram\n")
        w("```mermaid")
        w(render_dfd(model, max_nodes=70))
        w("```\n")

    # -- attack paths ------------------------------------------------------
    w("## Attack paths\n")
    if not model.attack_paths:
        w("No complete path was found from an untrusted entry point to a crown-jewel "
          "asset in the modelled graph.\n")
    else:
        w("Ranked chains from an untrusted entry point to an asset worth stealing. "
          "Each step is a real edge in the graph; the findings named are what make "
          "the step possible.\n")
        for i, p in enumerate(model.attack_paths[:6], start=1):
            entry = model.assets.get(p.entry)
            target = model.assets.get(p.target)
            w(f"### AP-{i}: {entry.display if entry else p.entry} → "
              f"{target.display if target else p.target}\n")
            w(f"**Score {p.score}** ({p.level.value}) · {len(p.hops)} hops · "
              f"{len(p.findings)} enabling findings\n")
            for step in p.narrative:
                w(f"1. {step}")
            w("")
            if include_diagrams:
                w("```mermaid")
                w(render_attack_path(model, i - 1))
                w("```\n")

    # -- STRIDE ------------------------------------------------------------
    w("## STRIDE coverage\n")
    w("| Category | Findings | Highest risk |")
    w("|---|---|---|")
    for letter, name in STRIDE_FULL.items():
        fs = [f for f in model.active_findings if letter in f.stride]
        top = max((f.risk_score for f in fs), default=0)
        w(f"| **{letter}** {name} | {len(fs)} | {top} |")
    w("")

    # -- findings ----------------------------------------------------------
    w("## Findings\n")
    shown = model.active_findings[:max_findings]
    if len(model.active_findings) > max_findings:
        w(f"*Showing the {max_findings} highest-risk of "
          f"{len(model.active_findings)} findings. Full set in `threat-model.json`.*\n")

    for f in shown:
        w(f"### {f.risk_score}/25 · {f.title}\n")
        w(f"`{f.rule_id}` · **{f.risk_level.value}** · component `{f.component}` · "
          f"confidence *{f.confidence.value}* · STRIDE "
          f"{', '.join(f'{s} ({STRIDE_FULL.get(s, s)})' for s in f.stride) or '—'}\n")
        if f.description:
            w(f"{' '.join(f.description.split())}\n")

        w("**Evidence**\n")
        for e in f.evidence:
            loc = ""
            if e.source and e.source.file:
                loc = f" — `{e.source.file}"
                if e.source.line:
                    loc += f":{e.source.line}"
                loc += "`"
                if e.source.pointer:
                    loc += f" at `{e.source.pointer}`"
            obs = f" (observed: `{e.observed}`)" if e.observed not in (None, "") else ""
            w(f"- {e.description}{obs}{loc}")
        w("")

        r = f.risk
        w(f"**Risk** — likelihood {r.likelihood} × impact {r.impact} = {f.risk_score}. "
          f"Exposure: {'unreachable from an external entity' if r.exposure_hops is None else str(r.exposure_hops) + ' hop(s) from the internet'}; "
          f"blast radius {r.blast_radius}; data sensitivity {r.sensitivity}.\n")
        for n in r.notes:
            w(f"- {n}")
        w("")

        if f.remediation:
            w(f"**Remediation** — {f.remediation.summary} "
              f"*(effort: {f.remediation.effort}, breaking risk: {f.remediation.breaking_risk})*\n")
            if f.remediation.guidance:
                w(f"{' '.join(f.remediation.guidance.split())}\n")
            if f.remediation.patch:
                w("```yaml")
                w(f.remediation.patch.rstrip())
                w("```\n")

        if f.references:
            refs = " · ".join(f"**{k.upper()}** {', '.join(v)}"
                              for k, v in f.references.items() if v)
            if refs:
                w(f"{refs}\n")
        w("---\n")

    # -- suppressed --------------------------------------------------------
    supp = [f for f in model.findings if f.suppressed]
    if supp:
        w("## Accepted / suppressed\n")
        w("| Finding | Component | Reason |")
        w("|---|---|---|")
        for f in supp[:60]:
            w(f"| {f.rule_id} | `{f.component}` | {f.suppression_reason} |")
        w("")

    if model.errors:
        w("## Parse warnings\n")
        for e in model.errors[:40]:
            w(f"- `[{e.get('stage')}]` {e.get('message')}"
              f"{' — ' + e['file'] if e.get('file') else ''}")
        w("")

    return "\n".join(out)


def _summary_prose(model: ThreatModel, counts: Dict[str, int]) -> str:
    total = len(model.active_findings)
    crit, high = counts.get("critical", 0), counts.get("high", 0)
    exposed = sum(1 for a in model.assets.values() if a.facts.get("internet_reachable"))
    stores = len([a for a in model.assets.values()
                  if a.element == Element.DATA_STORE and a.sensitivity >= 4])
    paths = len(model.attack_paths)

    bits = [
        f"This analysis modelled {len(model.assets)} assets and {len(model.flows)} data "
        f"flows across {len(model.boundaries)} trust boundaries, and produced {total} "
        f"evidence-backed findings."
    ]
    if crit or high:
        bits.append(
            f"{crit} are critical and {high} are high risk after adjusting for exposure "
            f"and compensating controls.")
    else:
        bits.append("Nothing reached critical or high risk after adjustment.")
    bits.append(
        f"{exposed} assets are reachable from an untrusted network and {stores} hold "
        f"sensitive data.")
    if paths:
        top = model.attack_paths[0]
        tgt = model.assets.get(top.target)
        bits.append(
            f"{paths} complete attack paths were found; the highest-scoring one reaches "
            f"{tgt.display if tgt else top.target} in {len(top.hops) - 1} hops.")
    else:
        bits.append("No complete attack path from an untrusted entry point to a "
                    "crown-jewel asset was found in the modelled graph.")
    return " ".join(bits)
