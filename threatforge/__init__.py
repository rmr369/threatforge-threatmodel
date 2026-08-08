"""
ThreatForge — automated, evidence-based threat modelling for infrastructure-as-code.

    from threatforge import scan
    model = scan("./infra")
    print(model.counts())
    for f in model.active_findings[:10]:
        print(f.risk_score, f.rule_id, f.component)
"""

from .model import (Asset, AttackPath, Boundary, Confidence, DataClass, Element,
                    Evidence, Finding, Flow, Remediation, RiskFactors, Severity,
                    SourceRef, ThreatModel)

__version__ = "1.0.0"

__all__ = [
    "scan", "ThreatModel", "Asset", "Flow", "Boundary", "Finding", "Evidence",
    "Remediation", "RiskFactors", "AttackPath", "Severity", "Confidence",
    "DataClass", "Element", "SourceRef", "__version__",
]


def scan(path: str = ".", config=None, baseline=None, verbose: bool = False):
    """Run the full pipeline and return a ThreatModel."""
    from . import config as cfgmod
    from . import pipeline
    cfg = config or cfgmod.load(path)
    return pipeline.run(path, cfg, baseline, verbose=verbose)
