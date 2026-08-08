"""
Configuration loading (.threatforge.yml) and baseline handling.

Design note: everything has a working default. A repository with no config file
should produce a useful report on the first run; config exists to tune, not to
enable.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional

import yaml

CONFIG_NAMES = (".threatforge.yml", ".threatforge.yaml", "threatforge.yml")
BASELINE_NAME = ".threatforge-baseline.json"

DEFAULTS: Dict[str, Any] = {
    "project": None,                       # defaults to the directory name
    "ingestors": ["kubernetes", "terraform", "dockerfile", "compose"],
    "rules": {
        "packs": [],                       # empty = all built-in packs
        "extra_paths": [],                 # additional rule directories
        "disabled": [],                    # rule ids or glob patterns
        "only": [],                        # if set, run only these
    },
    "controls": {
        "allowed_registries": [],          # empty = registry rule never fires
    },
    "risk": {
        "production_namespaces": [],
    },
    "suppress": {
        "rules": [],
        "components": [],
        "paths": ["**/test/**", "**/tests/**", "**/examples/**", "**/*.test.yaml"],
        "below_severity": None,            # info | low | medium | high
    },
    "gate": {
        "fail_on": "high",                 # critical | high | medium | low | none
        "max_new": 0,                      # allowed new findings vs baseline
        "fail_on_attack_path": True,       # fail if a critical attack path exists
    },
    "output": {
        "dir": "threatforge-out",
        "formats": ["json", "html", "sarif", "markdown", "mermaid"],
        "max_findings_in_doc": 60,
    },
    "helm": {"render": True},
    "kustomize": {"render": True},
    "live": {"enabled": False, "namespace": None},
}


def load(root: str, explicit: Optional[str] = None) -> Dict[str, Any]:
    cfg = _deep_copy(DEFAULTS)
    path = explicit
    if not path:
        for name in CONFIG_NAMES:
            candidate = os.path.join(root, name)
            if os.path.exists(candidate):
                path = candidate
                break
    if path and os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                user = yaml.safe_load(fh) or {}
            cfg = _merge(cfg, user)
            cfg["_config_file"] = path
        except Exception as exc:
            cfg["_config_error"] = f"{path}: {exc}"
    if not cfg.get("project"):
        cfg["project"] = os.path.basename(os.path.abspath(root)) or "threat-model"
    return cfg


def ingestor_config(cfg: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Per-ingestor options, keyed by ingestor name."""
    return {
        "kubernetes": {
            "render_helm": cfg.get("helm", {}).get("render", True),
            "render_kustomize": cfg.get("kustomize", {}).get("render", True),
        },
        "terraform": {},
        "dockerfile": {},
        "compose": {},
        "live": cfg.get("live", {}),
        "legacy": cfg.get("legacy", {}),
    }


# ---------------------------------------------------------------------------
# Baseline
# ---------------------------------------------------------------------------

def load_baseline(root: str, path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    p = path or os.path.join(root, BASELINE_NAME)
    if not os.path.exists(p):
        return None
    try:
        with open(p, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return None


def write_baseline(model, path: str, reason: str = "baselined at adoption",
                   owner: str = "unassigned") -> str:
    """Freeze the current findings as accepted risk so CI can gate on new ones only."""
    payload = {
        "version": 1,
        "generated": _now(),
        "project": model.project,
        "accepted": {
            f.id: {
                "rule_id": f.rule_id,
                "component": f.component,
                "title": f.title,
                "risk_score": f.risk_score,
                "reason": reason,
                "owner": owner,
                "expires": None,
            }
            for f in model.active_findings
        },
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
    return path


def _now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ---------------------------------------------------------------------------

def _merge(base: Dict[str, Any], over: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(base)
    for k, v in (over or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge(out[k], v)
        else:
            out[k] = v
    return out


def _deep_copy(d: Dict[str, Any]) -> Dict[str, Any]:
    return json.loads(json.dumps(d))


SAMPLE = """\
# .threatforge.yml -- every key is optional; defaults are shown commented out.
project: my-platform

# Which sources to parse.
ingestors: [kubernetes, terraform, dockerfile, compose]

rules:
  # packs: []                 # empty = all built-in packs
  # extra_paths: [./security/rules]
  disabled:
    - TF-K8S-019              # probes: tracked in the reliability backlog instead
  # only: []

controls:
  allowed_registries:
    - ghcr.io
    - 123456789012.dkr.ecr.eu-west-1.amazonaws.com

risk:
  production_namespaces: [prod, payments-prod]

suppress:
  paths:
    - "**/examples/**"
    - "**/test/**"
  components: []
  # below_severity: low       # hide anything scored below this

gate:
  fail_on: high               # critical | high | medium | low | none
  max_new: 0                  # new findings allowed vs the baseline
  fail_on_attack_path: true

output:
  dir: threatforge-out
  formats: [json, html, sarif, markdown, mermaid]   # add 'docx' if python-docx is installed

helm: {render: true}
kustomize: {render: true}
live: {enabled: false}
"""
