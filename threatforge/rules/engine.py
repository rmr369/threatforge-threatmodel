"""
Evidence-based rule engine.

A rule fires only when a *fact* extracted from a real manifest satisfies a
predicate.  There is no "every process has a spoofing threat" path through this
code, by design.

Rule schema (YAML)
------------------
    id: K8S-PRIV-001
    title: Container runs in privileged mode
    severity: critical            # critical|high|medium|low|info (base, before risk scoring)
    stride: [E, T]
    confidence: confirmed         # confirmed|likely|possible
    applies_to:
      provider: [kubernetes]      # optional filters, all ANDed
      kind: [Container]
      element: [process]
      tag: [workload]
      not_tag: [legacy_import]
    when:                         # predicate tree: all / any / not / leaf
      all:
        - {fact: container.privileged, op: is_true}
    evidence:
      - {fact: container.privileged, text: "securityContext.privileged is true"}
    description: >
      Free text explaining the threat in terms of what an attacker gains.
    remediation:
      summary: ...
      guidance: ...
      patch: |
        ...
      effort: low
      breaking_risk: medium
    references:
      cwe: [CWE-250]
      mitre: [T1611]
      cis: ["5.2.1"]
      nist: [AC-6]
    tags: [runtime, container-escape]

Leaf operators
--------------
    is_true is_false exists absent eq ne gt gte lt lte
    in not_in contains not_contains regex not_regex
    non_empty empty len_gt len_lt any_in
"""

from __future__ import annotations

import fnmatch
import os
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional

import yaml

from ..model import (Asset, Confidence, Element, Evidence, Finding, Flow,
                     Severity, SourceRef, ThreatModel)

PACK_DIR = os.path.join(os.path.dirname(__file__), "packs")


# ---------------------------------------------------------------------------
# Operators
# ---------------------------------------------------------------------------

def _as_list(v: Any) -> List[Any]:
    if v is None:
        return []
    if isinstance(v, (list, tuple, set)):
        return list(v)
    return [v]


OPS: Dict[str, Callable[[Any, Any], bool]] = {
    "is_true":      lambda a, b: a is True or a == "true",
    "is_false":     lambda a, b: a is False or a == "false",
    "exists":       lambda a, b: a is not None,
    "absent":       lambda a, b: a is None,
    "eq":           lambda a, b: a == b,
    "ne":           lambda a, b: a != b,
    "gt":           lambda a, b: _num(a) is not None and _num(a) > _num(b),
    "gte":          lambda a, b: _num(a) is not None and _num(a) >= _num(b),
    "lt":           lambda a, b: _num(a) is not None and _num(a) < _num(b),
    "lte":          lambda a, b: _num(a) is not None and _num(a) <= _num(b),
    "in":           lambda a, b: a in _as_list(b),
    "not_in":       lambda a, b: a not in _as_list(b),
    "contains":     lambda a, b: b in _as_list(a),
    "not_contains": lambda a, b: b not in _as_list(a),
    "any_in":       lambda a, b: bool(set(map(str, _as_list(a))) & set(map(str, _as_list(b)))),
    "none_in":      lambda a, b: not (set(map(str, _as_list(a))) & set(map(str, _as_list(b)))),
    "non_empty":    lambda a, b: bool(a),
    "empty":        lambda a, b: not bool(a),
    "len_gt":       lambda a, b: len(_as_list(a)) > int(b),
    "len_lt":       lambda a, b: len(_as_list(a)) < int(b),
    "regex":        lambda a, b: bool(re.search(str(b), str(a or ""), re.I)),
    "not_regex":    lambda a, b: not re.search(str(b), str(a or ""), re.I),
    "glob":         lambda a, b: fnmatch.fnmatch(str(a or ""), str(b)),
}


def _num(v: Any) -> Optional[float]:
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------------------
# Rule
# ---------------------------------------------------------------------------

@dataclass
class Rule:
    id: str
    title: str
    severity: Severity = Severity.MEDIUM
    stride: List[str] = field(default_factory=list)
    confidence: Confidence = Confidence.CONFIRMED
    applies_to: Dict[str, Any] = field(default_factory=dict)
    when: Dict[str, Any] = field(default_factory=dict)
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    description: str = ""
    remediation: Dict[str, Any] = field(default_factory=dict)
    references: Dict[str, List[str]] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    risk: Dict[str, Any] = field(default_factory=dict)   # optional likelihood/impact overrides
    pack: str = ""
    enabled: bool = True

    @staticmethod
    def from_dict(d: Dict[str, Any], pack: str) -> "Rule":
        return Rule(
            id=d["id"],
            title=d["title"],
            severity=Severity(str(d.get("severity", "medium")).lower()),
            stride=[s.upper() for s in d.get("stride", [])],
            confidence=Confidence(str(d.get("confidence", "confirmed")).lower()),
            applies_to=d.get("applies_to", {}) or {},
            when=d.get("when", {}) or {},
            evidence=d.get("evidence", []) or [],
            description=(d.get("description") or "").strip(),
            remediation=d.get("remediation", {}) or {},
            references=d.get("references", {}) or {},
            tags=d.get("tags", []) or [],
            risk=d.get("risk", {}) or {},
            pack=pack,
            enabled=d.get("enabled", True),
        )

    # -- matching ---------------------------------------------------------
    def targets(self, subject: "Subject") -> bool:
        at = self.applies_to
        if not at:
            return True
        if "provider" in at and subject.provider not in _as_list(at["provider"]):
            return False
        if "kind" in at and subject.kind not in _as_list(at["kind"]):
            return False
        if "element" in at and subject.element not in _as_list(at["element"]):
            return False
        if "tag" in at and not (set(_as_list(at["tag"])) & subject.tags):
            return False
        if "all_tags" in at and not set(_as_list(at["all_tags"])) <= subject.tags:
            return False
        if "not_tag" in at and (set(_as_list(at["not_tag"])) & subject.tags):
            return False
        if "kind_regex" in at and not re.search(at["kind_regex"], subject.kind, re.I):
            return False
        return True

    def evaluate(self, facts: Dict[str, Any]) -> bool:
        return _eval_node(self.when, facts)


def _eval_node(node: Any, facts: Dict[str, Any]) -> bool:
    if node is None or node == {}:
        return True
    if isinstance(node, list):
        return all(_eval_node(n, facts) for n in node)
    if not isinstance(node, dict):
        return bool(node)

    if "all" in node:
        return all(_eval_node(n, facts) for n in node["all"])
    if "any" in node:
        return any(_eval_node(n, facts) for n in node["any"])
    if "none" in node:
        return not any(_eval_node(n, facts) for n in node["none"])
    if "not" in node:
        return not _eval_node(node["not"], facts)

    fact = node.get("fact")
    op = node.get("op", "is_true")
    value = node.get("value")
    if fact is None:
        return True
    actual = facts.get(fact)
    fn = OPS.get(op)
    if fn is None:
        raise ValueError(f"unknown operator: {op}")
    try:
        return bool(fn(actual, value))
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Subject: an asset or a flow, presented uniformly to rules
# ---------------------------------------------------------------------------

@dataclass
class Subject:
    id: str
    kind: str
    provider: str
    element: str
    tags: set
    facts: Dict[str, Any]
    source: SourceRef
    display: str
    evidence_map: Dict[str, SourceRef] = field(default_factory=dict)

    @staticmethod
    def from_asset(a: Asset) -> "Subject":
        return Subject(
            id=a.id, kind=a.kind, provider=a.provider, element=a.element.value,
            tags=set(a.tags), facts=a.facts, source=a.source, display=a.display,
            evidence_map=a.facts.get("_ev", {}) or {},
        )

    @staticmethod
    def from_flow(f: Flow, model: ThreatModel) -> "Subject":
        src = model.assets.get(f.source)
        tgt = model.assets.get(f.target)
        facts: Dict[str, Any] = {
            "flow.kind": f.kind,
            "flow.protocol": f.protocol,
            "flow.encrypted": f.encrypted,
            "flow.authenticated": f.authenticated,
            "flow.crosses_boundary": f.crosses_boundary,
            "flow.boundary_crossed": f.boundary_crossed,
            "flow.trust_delta": f.details.get("trust_delta"),
            "flow.sensitive": f.details.get("sensitive"),
            "flow.confidence": f.details.get("confidence"),
            "flow.data_classes": sorted(dc.value for dc in f.data_classes),
            "flow.source_kind": src.kind if src else None,
            "flow.target_kind": tgt.kind if tgt else None,
            "flow.source_element": src.element.value if src else None,
            "flow.target_element": tgt.element.value if tgt else None,
            "flow.source_tags": sorted(src.tags) if src else [],
            "flow.target_tags": sorted(tgt.tags) if tgt else [],
            "flow.target_sensitivity": tgt.sensitivity if tgt else 1,
            "flow.from_internet": f.source == "ext:internet",
        }
        return Subject(
            id=f.id, kind="DataFlow", provider="graph", element="data_flow",
            tags=set(), facts=facts, source=f.source_ref,
            display=f"{src.display if src else f.source} -> {tgt.display if tgt else f.target}",
        )


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class RuleEngine:
    def __init__(self, rules: Optional[List[Rule]] = None) -> None:
        self.rules: List[Rule] = rules or []
        self.load_errors: List[str] = []

    # -- loading ----------------------------------------------------------
    @classmethod
    def load(cls, paths: Optional[Iterable[str]] = None,
             disabled: Optional[Iterable[str]] = None,
             only: Optional[Iterable[str]] = None) -> "RuleEngine":
        engine = cls()
        search = list(paths) if paths else [PACK_DIR]
        seen: set = set()
        for base in search:
            if os.path.isfile(base):
                engine._load_file(base, seen)
                continue
            for dirpath, _dirs, files in os.walk(base):
                for fn in sorted(files):
                    if fn.endswith((".yml", ".yaml")):
                        engine._load_file(os.path.join(dirpath, fn), seen)

        dis = set(disabled or ())
        keep_only = set(only or ())
        engine.rules = [
            r for r in engine.rules
            if r.enabled
            and not any(fnmatch.fnmatch(r.id, d) or r.pack == d for d in dis)
            and (not keep_only or any(fnmatch.fnmatch(r.id, k) or r.pack == k
                                      for k in keep_only))
        ]
        return engine

    def _load_file(self, path: str, seen: set) -> None:
        try:
            with open(path, "r", encoding="utf-8") as fh:
                doc = yaml.safe_load(fh) or {}
        except Exception as exc:
            self.load_errors.append(f"{path}: {exc}")
            return
        pack = doc.get("pack") or os.path.splitext(os.path.basename(path))[0]
        for rd in doc.get("rules", []):
            try:
                if rd["id"] in seen:
                    self.load_errors.append(f"{path}: duplicate rule id {rd['id']}")
                    continue
                seen.add(rd["id"])
                self.rules.append(Rule.from_dict(rd, pack))
            except Exception as exc:
                self.load_errors.append(f"{path}: bad rule {rd.get('id')}: {exc}")

    # -- running ----------------------------------------------------------
    def run(self, model: ThreatModel) -> List[Finding]:
        findings: List[Finding] = []
        subjects: List[Subject] = [Subject.from_asset(a) for a in model.assets.values()]
        subjects += [Subject.from_flow(f, model) for f in model.flows]

        for subj in subjects:
            for rule in self.rules:
                if not rule.targets(subj):
                    continue
                try:
                    if not rule.evaluate(subj.facts):
                        continue
                except Exception as exc:
                    model.error("rules", f"{rule.id} failed on {subj.id}: {exc}")
                    continue
                findings.append(self._finding(rule, subj))

        model.metadata["rules"] = {
            "loaded": len(self.rules),
            "packs": sorted({r.pack for r in self.rules}),
            "load_errors": self.load_errors,
            "subjects_evaluated": len(subjects),
        }
        return findings

    # -- construction -----------------------------------------------------
    def _finding(self, rule: Rule, subj: Subject) -> Finding:
        evidence: List[Evidence] = []
        for spec in rule.evidence:
            fact = spec.get("fact")
            observed = subj.facts.get(fact) if fact else None
            src = subj.evidence_map.get(fact) if fact else None
            evidence.append(Evidence(
                description=_interp(spec.get("text", fact or rule.title), subj),
                observed=observed,
                expected=spec.get("expected"),
                source=src or subj.source or SourceRef(),
            ))
        if not evidence:
            evidence.append(Evidence(
                description=rule.title, observed=None,
                source=subj.source or SourceRef()))

        rem = None
        if rule.remediation:
            from ..model import Remediation
            rem = Remediation(
                summary=_interp(rule.remediation.get("summary", ""), subj),
                guidance=_interp(rule.remediation.get("guidance", ""), subj),
                patch=rule.remediation.get("patch"),
                effort=rule.remediation.get("effort", "medium"),
                breaking_risk=rule.remediation.get("breaking_risk", "low"),
            )

        return Finding(
            rule_id=rule.id,
            title=rule.title,
            component=subj.id,
            component_type=subj.element,
            severity=rule.severity,
            stride=rule.stride,
            description=_interp(rule.description, subj),
            confidence=rule.confidence,
            evidence=evidence,
            remediation=rem,
            references={k: [str(x) for x in _as_list(v)] for k, v in rule.references.items()},
            tags=list(rule.tags) + [f"pack:{rule.pack}"],
        )


_TOKEN = re.compile(r"\{\{\s*([a-zA-Z0-9_.]+)\s*\}\}")


def _interp(text: str, subj: Subject) -> str:
    """Allow {{ fact.name }} and {{ component }} inside rule text."""
    if not text:
        return ""

    def sub(m):
        key = m.group(1)
        if key == "component":
            return subj.display
        if key == "id":
            return subj.id
        val = subj.facts.get(key)
        if isinstance(val, (list, tuple)):
            return ", ".join(str(v) for v in val)
        return str(val) if val is not None else ""

    return _TOKEN.sub(sub, text)
