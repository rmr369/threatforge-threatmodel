"""
ThreatForge canonical object model.

Everything that any ingestor produces is normalised into these types.  The rest
of the pipeline (relationships, controls, rules, risk, reporting) only ever
speaks this language, which is what makes the framework provider-agnostic.

URN scheme
----------
    k8s:<Kind>:<namespace>/<name>
    k8s:Container:<namespace>/<workload>/<container>
    tf:<resource_type>.<resource_name>
    docker:image:<image-ref>
    compose:service:<name>
    ext:<name>                      (external entity, e.g. ext:internet)
    boundary:<kind>:<name>
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List, Optional, Set


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class Element(str, Enum):
    """DFD element classification (Shostack's four-element model + boundary)."""
    PROCESS = "process"
    DATA_STORE = "data_store"
    EXTERNAL_ENTITY = "external_entity"
    DATA_FLOW = "data_flow"
    TRUST_BOUNDARY = "trust_boundary"


STRIDE_NAMES = {
    "S": "Spoofing",
    "T": "Tampering",
    "R": "Repudiation",
    "I": "Information Disclosure",
    "D": "Denial of Service",
    "E": "Elevation of Privilege",
}


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}[self.value]


SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


class Confidence(str, Enum):
    """How certain we are the finding is real (static analysis has blind spots)."""
    CONFIRMED = "confirmed"   # evidence is unambiguous in the manifest
    LIKELY = "likely"         # strong inference, small chance of runtime override
    POSSIBLE = "possible"     # heuristic / naming-based


class DataClass(str, Enum):
    SECRET = "secret"
    CREDENTIAL = "credential"
    PII = "pii"
    PHI = "phi"
    PCI = "pci"
    CONFIG = "config"
    PUBLIC = "public"


DATA_CLASS_WEIGHT = {
    DataClass.SECRET: 5,
    DataClass.CREDENTIAL: 5,
    DataClass.PHI: 5,
    DataClass.PCI: 5,
    DataClass.PII: 4,
    DataClass.CONFIG: 2,
    DataClass.PUBLIC: 1,
}


# ---------------------------------------------------------------------------
# Provenance
# ---------------------------------------------------------------------------

@dataclass
class SourceRef:
    """Where a fact came from. Required for every finding -- no evidence, no finding."""
    file: Optional[str] = None
    line: Optional[int] = None
    end_line: Optional[int] = None
    pointer: Optional[str] = None     # e.g. spec.template.spec.containers[0].securityContext
    snippet: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass
class Evidence:
    """A single observed fact that justifies a finding."""
    description: str
    observed: Any = None
    expected: Any = None
    source: SourceRef = field(default_factory=SourceRef)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "description": self.description,
            "observed": self.observed,
            "expected": self.expected,
            "source": self.source.to_dict(),
        }


# ---------------------------------------------------------------------------
# Core graph objects
# ---------------------------------------------------------------------------

@dataclass
class Asset:
    """A node in the architecture graph."""
    id: str
    kind: str                                   # Deployment, Service, aws_s3_bucket, ...
    name: str
    provider: str = "kubernetes"                # kubernetes | terraform | docker | compose | live | external
    namespace: Optional[str] = None
    element: Element = Element.PROCESS
    labels: Dict[str, str] = field(default_factory=dict)
    annotations: Dict[str, str] = field(default_factory=dict)
    spec: Dict[str, Any] = field(default_factory=dict)      # raw provider object
    source: SourceRef = field(default_factory=SourceRef)
    tags: Set[str] = field(default_factory=set)             # derived: internet_facing, privileged...
    data_classes: Set[DataClass] = field(default_factory=set)
    boundaries: Set[str] = field(default_factory=set)
    facts: Dict[str, Any] = field(default_factory=dict)     # populated by controls.py

    @property
    def display(self) -> str:
        ns = f"{self.namespace}/" if self.namespace else ""
        return f"{self.kind} {ns}{self.name}"

    def tag(self, *names: str) -> None:
        self.tags.update(names)

    def classify(self, *classes: DataClass) -> None:
        self.data_classes.update(classes)

    @property
    def sensitivity(self) -> int:
        if not self.data_classes:
            return 1
        return max(DATA_CLASS_WEIGHT.get(dc, 1) for dc in self.data_classes)

    def to_dict(self, include_spec: bool = False) -> Dict[str, Any]:
        d = {
            "id": self.id,
            "kind": self.kind,
            "name": self.name,
            "provider": self.provider,
            "namespace": self.namespace,
            "element": self.element.value,
            "labels": self.labels,
            "tags": sorted(self.tags),
            "data_classes": sorted(dc.value for dc in self.data_classes),
            "boundaries": sorted(self.boundaries),
            "source": self.source.to_dict(),
        }
        if include_spec:
            d["spec"] = self.spec
            d["facts"] = self.facts
        return d


@dataclass
class Flow:
    """A directed edge: data or control moving between two assets."""
    source: str
    target: str
    kind: str = "flow"                # routes-to | runs | mounts | reads | writes | binds | calls | egress
    id: str = ""
    protocol: Optional[str] = None
    encrypted: Optional[bool] = None  # None = unknown
    authenticated: Optional[bool] = None
    data_classes: Set[DataClass] = field(default_factory=set)
    crosses_boundary: bool = False
    boundary_crossed: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)
    source_ref: SourceRef = field(default_factory=SourceRef)

    def __post_init__(self) -> None:
        if not self.id:
            self.id = f"{self.source}--{self.kind}-->{self.target}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "source": self.source,
            "target": self.target,
            "kind": self.kind,
            "protocol": self.protocol,
            "encrypted": self.encrypted,
            "authenticated": self.authenticated,
            "data_classes": sorted(dc.value for dc in self.data_classes),
            "crosses_boundary": self.crosses_boundary,
            "boundary_crossed": self.boundary_crossed,
            "details": self.details,
        }


@dataclass
class Boundary:
    """A trust boundary. Crossing one is what makes a flow interesting."""
    id: str
    name: str
    kind: str = "namespace"     # internet | cluster | namespace | node | cloud-account | vpc | container
    trust_level: int = 50       # 0 = fully untrusted, 100 = fully trusted
    parent: Optional[str] = None
    members: Set[str] = field(default_factory=set)
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "kind": self.kind,
            "trust_level": self.trust_level,
            "parent": self.parent,
            "members": sorted(self.members),
            "description": self.description,
        }


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

@dataclass
class Remediation:
    summary: str
    guidance: str = ""
    patch: Optional[str] = None       # YAML/HCL snippet the user can paste
    effort: str = "medium"            # low | medium | high
    breaking_risk: str = "low"        # low | medium | high

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class RiskFactors:
    """Every number is explainable. This is what gets shown in the report."""
    likelihood: int = 3
    impact: int = 3
    exposure_hops: Optional[int] = None      # hops from an external entity; None = unreachable
    blast_radius: int = 0
    sensitivity: int = 1
    control_offsets: Dict[str, int] = field(default_factory=dict)
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Finding:
    rule_id: str
    title: str
    component: str                      # asset or flow id
    component_type: str = "process"
    severity: Severity = Severity.MEDIUM
    stride: List[str] = field(default_factory=list)
    description: str = ""
    confidence: Confidence = Confidence.CONFIRMED
    evidence: List[Evidence] = field(default_factory=list)
    remediation: Optional[Remediation] = None
    references: Dict[str, List[str]] = field(default_factory=dict)
    risk: RiskFactors = field(default_factory=RiskFactors)
    risk_score: int = 0
    risk_level: Severity = Severity.MEDIUM
    tags: List[str] = field(default_factory=list)
    id: str = ""
    suppressed: bool = False
    suppression_reason: Optional[str] = None
    # Accepted-risk suppressions are hidden from reports but still visible to the
    # CI gate, so a ratchet can tell "known debt" from "genuinely absent".
    baseline_accepted: bool = False

    def __post_init__(self) -> None:
        if not self.id:
            raw = f"{self.rule_id}|{self.component}"
            self.id = f"TF-{hashlib.sha1(raw.encode()).hexdigest()[:10].upper()}"

    @property
    def fingerprint(self) -> str:
        """Stable across runs -- used for baselines and diffing."""
        return self.id

    @property
    def primary_source(self) -> SourceRef:
        for e in self.evidence:
            if e.source and e.source.file:
                return e.source
        return SourceRef()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "title": self.title,
            "component": self.component,
            "component_type": self.component_type,
            "severity": self.severity.value,
            "stride": self.stride,
            "stride_names": [STRIDE_NAMES.get(s, s) for s in self.stride],
            "description": self.description,
            "confidence": self.confidence.value,
            "evidence": [e.to_dict() for e in self.evidence],
            "remediation": self.remediation.to_dict() if self.remediation else None,
            "references": self.references,
            "risk": self.risk.to_dict(),
            "risk_score": self.risk_score,
            "risk_level": self.risk_level.value,
            "tags": self.tags,
            "suppressed": self.suppressed,
            "suppression_reason": self.suppression_reason,
            "baseline_accepted": self.baseline_accepted,
        }


@dataclass
class AttackPath:
    """An ordered chain from an untrusted entry point to a valuable asset."""
    id: str
    entry: str
    target: str
    hops: List[str]
    findings: List[str] = field(default_factory=list)
    narrative: List[str] = field(default_factory=list)
    score: int = 0
    level: Severity = Severity.MEDIUM

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "entry": self.entry,
            "target": self.target,
            "hops": self.hops,
            "length": len(self.hops),
            "findings": self.findings,
            "narrative": self.narrative,
            "score": self.score,
            "level": self.level.value,
        }


# ---------------------------------------------------------------------------
# The model container
# ---------------------------------------------------------------------------

@dataclass
class ThreatModel:
    """Everything the pipeline knows, in one object."""
    project: str = "unnamed"
    assets: Dict[str, Asset] = field(default_factory=dict)
    flows: List[Flow] = field(default_factory=list)
    boundaries: Dict[str, Boundary] = field(default_factory=dict)
    findings: List[Finding] = field(default_factory=list)
    attack_paths: List[AttackPath] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    errors: List[Dict[str, Any]] = field(default_factory=list)

    # -- mutation ---------------------------------------------------------
    def add_asset(self, asset: Asset) -> Asset:
        existing = self.assets.get(asset.id)
        if existing:
            existing.labels.update(asset.labels)
            existing.annotations.update(asset.annotations)
            existing.tags |= asset.tags
            existing.data_classes |= asset.data_classes
            if not existing.spec:
                existing.spec = asset.spec
            return existing
        self.assets[asset.id] = asset
        return asset

    def add_flow(self, flow: Flow) -> Flow:
        for f in self.flows:
            if f.id == flow.id:
                return f
        self.flows.append(flow)
        return flow

    def add_boundary(self, boundary: Boundary) -> Boundary:
        existing = self.boundaries.get(boundary.id)
        if existing:
            existing.members |= boundary.members
            return existing
        self.boundaries[boundary.id] = boundary
        return boundary

    def error(self, stage: str, message: str, **extra: Any) -> None:
        self.errors.append({"stage": stage, "message": message, **extra})

    # -- queries ----------------------------------------------------------
    def by_kind(self, *kinds: str) -> List[Asset]:
        wanted = {k.lower() for k in kinds}
        return [a for a in self.assets.values() if a.kind.lower() in wanted]

    def by_element(self, element: Element) -> List[Asset]:
        return [a for a in self.assets.values() if a.element == element]

    def by_provider(self, provider: str) -> List[Asset]:
        return [a for a in self.assets.values() if a.provider == provider]

    def outgoing(self, asset_id: str) -> List[Flow]:
        return [f for f in self.flows if f.source == asset_id]

    def incoming(self, asset_id: str) -> List[Flow]:
        return [f for f in self.flows if f.target == asset_id]

    @property
    def active_findings(self) -> List[Finding]:
        """What the reports show: everything not suppressed."""
        return [f for f in self.findings if not f.suppressed]

    @property
    def gateable_findings(self) -> List[Finding]:
        """What CI evaluates: active findings plus accepted-risk baseline items,
        so the ratchet can distinguish known debt from new debt."""
        return [f for f in self.findings if not f.suppressed or f.baseline_accepted]

    def counts(self) -> Dict[str, int]:
        out = {s.value: 0 for s in Severity}
        for f in self.active_findings:
            out[f.risk_level.value] += 1
        return out

    # -- serialisation ----------------------------------------------------
    def to_dict(self, include_spec: bool = False) -> Dict[str, Any]:
        return {
            "project": self.project,
            "metadata": self.metadata,
            "summary": {
                "assets": len(self.assets),
                "flows": len(self.flows),
                "boundaries": len(self.boundaries),
                "findings": len(self.active_findings),
                "suppressed": len(self.findings) - len(self.active_findings),
                "attack_paths": len(self.attack_paths),
                "by_level": self.counts(),
                "by_element": {
                    e.value: len(self.by_element(e))
                    for e in (Element.PROCESS, Element.DATA_STORE, Element.EXTERNAL_ENTITY)
                },
            },
            "boundaries": [b.to_dict() for b in self.boundaries.values()],
            "assets": [a.to_dict(include_spec) for a in self.assets.values()],
            "flows": [f.to_dict() for f in self.flows],
            "findings": [f.to_dict() for f in self.findings],
            "attack_paths": [p.to_dict() for p in self.attack_paths],
            "errors": self.errors,
        }

    def to_json(self, include_spec: bool = False, indent: int = 2) -> str:
        return json.dumps(self.to_dict(include_spec), indent=indent, default=str)
