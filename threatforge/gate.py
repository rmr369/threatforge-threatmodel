# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""
CI security gate.

Two failure modes, and the distinction matters for adoption:

  * **threshold gate** -- fail if anything at or above `fail_on` exists.
    Correct for a new repo. Brutal for an existing one.
  * **ratchet gate**   -- fail only on findings that are not in the baseline.
    Correct for adoption: today's debt is accepted, tomorrow's is blocked.

Exit codes: 0 pass, 1 gate failed, 2 execution error.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from .model import Severity, ThreatModel

ORDER = ["info", "low", "medium", "high", "critical"]


def evaluate(model: ThreatModel, gate_cfg: Dict[str, Any],
             baseline: Optional[Dict[str, Any]] = None) -> Tuple[bool, Dict[str, Any]]:
    fail_on = str(gate_cfg.get("fail_on", "high")).lower()
    max_new = int(gate_cfg.get("max_new", 0))
    gate_disabled = fail_on in ("none", "off", "")

    # `fail_on: none` turns the gate off entirely. Failing on an attack path
    # after the user explicitly asked for no gate is the kind of surprise that
    # gets a tool removed from a pipeline.
    fail_paths = bool(gate_cfg.get("fail_on_attack_path", True)) and not gate_disabled

    # Baseline-accepted findings stay visible to the gate so the ratchet can tell
    # "known and accepted" apart from "fixed".
    findings = model.gateable_findings
    reasons: List[str] = []

    # -- threshold ---------------------------------------------------------
    breaching: List = []
    if not gate_disabled:
        threshold = ORDER.index(fail_on)
        breaching = [f for f in findings if ORDER.index(f.risk_level.value) >= threshold]

    # -- ratchet -----------------------------------------------------------
    known = set((baseline or {}).get("accepted", {}).keys())
    new = [f for f in breaching if f.id not in known] if known else breaching
    fixed = sorted(known - {f.id for f in findings}) if known else []

    if known:
        if len(new) > max_new:
            reasons.append(
                f"{len(new)} new finding(s) at or above '{fail_on}' "
                f"(allowed: {max_new})")
    elif breaching:
        reasons.append(f"{len(breaching)} finding(s) at or above '{fail_on}'")

    # -- attack paths ------------------------------------------------------
    crit_paths = [p for p in model.attack_paths if p.level == Severity.CRITICAL]
    if fail_paths and crit_paths:
        reasons.append(f"{len(crit_paths)} critical attack path(s) from an untrusted "
                       f"entry point to a crown-jewel asset")

    counts = {lvl: 0 for lvl in ORDER}
    for f in findings:
        counts[f.risk_level.value] += 1

    passed = not reasons
    report = {
        "passed": passed,
        "fail_on": fail_on,
        "mode": "ratchet (baseline present)" if known else "threshold",
        "reasons": reasons,
        "counts": counts,
        "accepted": len([f for f in findings if f.baseline_accepted]),
        "breaching": len(breaching),
        "new": [
            {"id": f.id, "rule_id": f.rule_id, "title": f.title,
             "component": f.component, "risk_score": f.risk_score,
             "level": f.risk_level.value,
             "file": f.primary_source.file, "line": f.primary_source.line}
            for f in sorted(new, key=lambda x: -x.risk_score)[:50]
        ],
        "fixed_since_baseline": fixed[:50],
        "critical_attack_paths": [
            {"id": p.id, "entry": p.entry, "target": p.target, "score": p.score}
            for p in crit_paths[:10]
        ],
    }
    return passed, report


def format_report(report: Dict[str, Any], model: ThreatModel) -> str:
    c = report["counts"]
    lines = [
        "",
        "=" * 68,
        f"  ThreatForge security gate — {'PASS' if report['passed'] else 'FAIL'}",
        "=" * 68,
        f"  mode        : {report['mode']}",
        f"  fail_on     : {report['fail_on']}",
        f"  findings    : {c['critical']} critical · {c['high']} high · "
        f"{c['medium']} medium · {c['low']} low",
        f"  attack paths: {len(model.attack_paths)} "
        f"({len(report['critical_attack_paths'])} critical)",
    ]
    if report.get("accepted"):
        lines.append(f"  accepted    : {report['accepted']} in baseline")
    if report["fixed_since_baseline"]:
        lines.append(f"  fixed       : {len(report['fixed_since_baseline'])} "
                     f"since baseline — nice")
    if report["reasons"]:
        lines.append("")
        for r in report["reasons"]:
            lines.append(f"  ✗ {r}")
    if report["new"]:
        lines.append("")
        lines.append("  Blocking findings:")
        for f in report["new"][:15]:
            loc = f" {f['file']}:{f['line']}" if f.get("file") else ""
            lines.append(f"    [{f['risk_score']:>2}] {f['rule_id']:<14} "
                         f"{f['title'][:52]}")
            lines.append(f"         {f['component']}{loc}")
        if len(report["new"]) > 15:
            lines.append(f"    … and {len(report['new']) - 15} more")
    if report["passed"]:
        lines.append("")
        lines.append("  No blocking findings.")
    lines.append("=" * 68)
    lines.append("")
    return "\n".join(lines)


def github_step_summary(report: Dict[str, Any], model: ThreatModel) -> str:
    """Markdown for $GITHUB_STEP_SUMMARY."""
    c = report["counts"]
    icon = "✅" if report["passed"] else "❌"
    out = [
        f"## {icon} ThreatForge — {'passed' if report['passed'] else 'failed'}",
        "",
        f"| Critical | High | Medium | Low | Attack paths |",
        f"|---|---|---|---|---|",
        f"| {c['critical']} | {c['high']} | {c['medium']} | {c['low']} | "
        f"{len(model.attack_paths)} |",
        "",
    ]
    if report["reasons"]:
        out.append("**Why this failed**")
        out += [f"- {r}" for r in report["reasons"]]
        out.append("")
    if report["new"]:
        out.append("<details><summary>Blocking findings</summary>")
        out.append("")
        out.append("| Risk | Rule | Finding | Component | Location |")
        out.append("|---|---|---|---|---|")
        for f in report["new"][:30]:
            loc = f"`{f['file']}:{f['line']}`" if f.get("file") else "—"
            out.append(f"| {f['risk_score']} | `{f['rule_id']}` | {f['title']} | "
                       f"`{f['component']}` | {loc} |")
        out.append("")
        out.append("</details>")
    if model.attack_paths:
        top = model.attack_paths[0]
        out.append("")
        out.append(f"**Top attack path** (score {top.score}): "
                   + " → ".join(
                       (model.assets[h].display if h in model.assets else h)
                       for h in top.hops))
    return "\n".join(out)
