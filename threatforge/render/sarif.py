# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""
SARIF 2.1.0 output for GitHub Code Scanning (and any other SARIF consumer).

Notes on the mapping:
  * `level` follows GitHub's error/warning/note, driven by *risk* level rather
    than the rule's base severity, so the annotations reflect this environment.
  * `security-severity` is a 0-10 float; GitHub uses it to bucket findings, so
    we map the 1-25 risk score onto that range rather than hardcoding by rule.
  * `partialFingerprints` uses the stable finding id, so GitHub can track a
    finding across commits even when line numbers move.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

from ..model import Severity, ThreatModel

SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def _security_severity(risk_score: int) -> str:
    # 1..25  ->  0.4..10.0
    return f"{min(10.0, round(risk_score * 0.4, 1)):.1f}"


def render(model: ThreatModel, tool_version: str = "1.0.0") -> str:
    findings = model.active_findings
    rules: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []

    for f in findings:
        if f.rule_id not in rules:
            refs = f.references or {}
            help_lines = [f.description.strip()]
            if f.remediation:
                help_lines.append(f"\n**Remediation:** {f.remediation.summary}")
                if f.remediation.guidance:
                    help_lines.append(f"\n{f.remediation.guidance}")
                if f.remediation.patch:
                    help_lines.append(f"\n```yaml\n{f.remediation.patch.strip()}\n```")
            ref_bits = []
            for key in ("cwe", "mitre", "cis", "nist", "owasp"):
                if refs.get(key):
                    ref_bits.append(f"{key.upper()}: {', '.join(refs[key])}")
            if ref_bits:
                help_lines.append("\n" + " · ".join(ref_bits))

            rules[f.rule_id] = {
                "id": f.rule_id,
                "name": _pascal(f.title),
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": _one_line(f.description) or f.title},
                "help": {"text": _one_line(" ".join(help_lines)),
                         "markdown": "\n".join(help_lines)},
                "defaultConfiguration": {"level": SARIF_LEVEL[f.severity]},
                "properties": {
                    "tags": sorted(set(
                        f.tags
                        + [f"stride/{s}" for s in f.stride]
                        + [f"cwe/{c}" for c in refs.get("cwe", [])]
                        + [f"mitre/{m}" for m in refs.get("mitre", [])]
                        + ["security"]
                    )),
                    "security-severity": _security_severity(f.risk_score),
                    "precision": {"confirmed": "very-high", "likely": "high",
                                  "possible": "medium"}[f.confidence.value],
                },
            }

        src = f.primary_source
        location = {
            "physicalLocation": {
                "artifactLocation": {"uri": _uri(src.file or "unknown"),
                                     "uriBaseId": "%SRCROOT%"},
                "region": {"startLine": max(1, src.line or 1)},
            },
            "logicalLocations": [{"name": f.component, "kind": f.component_type}],
        }
        if src.pointer:
            location["physicalLocation"]["region"]["snippet"] = {"text": src.pointer}

        results.append({
            "ruleId": f.rule_id,
            "level": SARIF_LEVEL[f.risk_level],
            "message": {"text": _message(f)},
            "locations": [location],
            "partialFingerprints": {"threatforge/v1": f.fingerprint},
            "properties": {
                "riskScore": f.risk_score,
                "riskLevel": f.risk_level.value,
                "likelihood": f.risk.likelihood,
                "impact": f.risk.impact,
                "exposureHops": f.risk.exposure_hops,
                "blastRadius": f.risk.blast_radius,
                "stride": f.stride,
                "component": f.component,
                "confidence": f.confidence.value,
            },
        })

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "ThreatForge",
                "version": tool_version,
                "informationUri": "https://github.com/rmr369/threatforge-threatmodel",
                "rules": list(rules.values()),
            }},
            "results": results,
            "properties": {
                "project": model.project,
                "assets": len(model.assets),
                "flows": len(model.flows),
                "attackPaths": len(model.attack_paths),
                "summary": model.counts(),
            },
        }],
    }
    return json.dumps(sarif, indent=2)


def _message(f) -> str:
    bits = [f"{f.title} on {f.component}."]
    if f.evidence:
        e = f.evidence[0]
        obs = e.observed
        if obs is not None and obs != "":
            bits.append(f"Evidence: {e.description} (observed: {obs}).")
        else:
            bits.append(f"Evidence: {e.description}.")
    bits.append(f"Risk {f.risk_score}/25 ({f.risk_level.value}); "
                f"likelihood {f.risk.likelihood}, impact {f.risk.impact}.")
    if f.remediation:
        bits.append(f"Fix: {f.remediation.summary}")
    return " ".join(bits)


def _one_line(text: str) -> str:
    return " ".join((text or "").split())


def _pascal(title: str) -> str:
    return "".join(w.capitalize() for w in
                   "".join(c if c.isalnum() else " " for c in title).split())[:80]


def _uri(path: str) -> str:
    return str(path).replace("\\", "/").lstrip("./")
