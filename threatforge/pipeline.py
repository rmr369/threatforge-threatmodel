# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""
Pipeline orchestration.

    discover -> ingest -> relate -> bound -> reach -> facts
             -> rules -> risk -> suppress -> paths -> render

Each stage is independently callable and each one only reads what the previous
stage produced, so a stage can be replaced without touching the others. This is
the successor to the original stage1..stage12 scripts: same shape, but the
intermediate JSON files are now optional artefacts rather than the interface.
"""

from __future__ import annotations

import os
import time
from typing import Any, Dict, List, Optional

from . import config as cfgmod
from . import controls, risk
from .graph import (build_boundaries, build_relationships, compute_reachability,
                    find_paths)
from .ingest import build as build_ingestors, set_output_exclusions
from .model import ThreatModel
from .rules.engine import PACK_DIR, RuleEngine

STAGES = ["ingest", "relate", "boundaries", "reachability", "facts",
          "rules", "risk", "suppress", "attack_paths"]


def run(root: str, config: Optional[Dict[str, Any]] = None,
        baseline: Optional[Dict[str, Any]] = None,
        verbose: bool = False, out_dir: Optional[str] = None) -> ThreatModel:
    cfg = config or cfgmod.load(root)

    # Never read our own output. Several output formats (.thf, .json) are also
    # valid input formats, so a report left inside the scanned tree would be
    # re-ingested on the next run and quietly change the results.
    configured = out_dir or (cfg.get("output", {}) or {}).get("dir") or "threatforge-out"
    set_output_exclusions([
        configured if os.path.isabs(configured) else os.path.join(root, configured),
        os.path.join(root, "threatforge-out"),
    ])
    model = ThreatModel(project=cfg.get("project") or os.path.basename(os.path.abspath(root)))
    model.metadata["root"] = os.path.abspath(root)
    model.metadata["config_file"] = cfg.get("_config_file")
    if cfg.get("_config_error"):
        model.error("config", cfg["_config_error"])
    timings: Dict[str, float] = {}

    def stage(name: str, fn) -> None:
        t0 = time.time()
        try:
            fn()
        except Exception as exc:                       # never lose the whole run
            model.error(name, f"stage failed: {type(exc).__name__}: {exc}")
            if verbose:
                import traceback
                traceback.print_exc()
        timings[name] = round(time.time() - t0, 3)
        if verbose:
            print(f"  {name:<14} {timings[name]:>7.3f}s   "
                  f"assets={len(model.assets)} flows={len(model.flows)} "
                  f"findings={len(model.findings)}")

    # 1. ingest ------------------------------------------------------------
    ing_cfg = cfgmod.ingestor_config(cfg)
    names = list(cfg.get("ingestors") or [])
    if cfg.get("live", {}).get("enabled") and "live" not in names:
        names.append("live")
    ingestors = build_ingestors(names, ing_cfg)

    def _ingest() -> None:
        stats: Dict[str, Any] = {}
        for ing in ingestors:
            try:
                if not ing.detect(root):
                    stats[ing.name] = {"files": 0, "assets": 0, "detected": False}
                    continue
                ing.ingest(root, model)
                stats[ing.name] = {**ing.stats, "detected": True}
            except Exception as exc:
                model.error(f"ingest.{ing.name}", str(exc))
                stats[ing.name] = {"error": str(exc)}
        model.metadata["ingestors"] = stats

    stage("ingest", _ingest)
    stage("relate", lambda: build_relationships(model))
    stage("boundaries", lambda: build_boundaries(model))
    stage("reachability", lambda: compute_reachability(model))
    stage("facts", lambda: controls.extract_facts(model, cfg.get("controls", {})))

    # 6. rules -------------------------------------------------------------
    rcfg = cfg.get("rules", {})
    paths: List[str] = list(rcfg.get("extra_paths") or [])
    packs = rcfg.get("packs") or []
    if packs:
        paths += [os.path.join(PACK_DIR, f"{p}.yaml") for p in packs]
    else:
        paths.append(PACK_DIR)
    engine = RuleEngine.load(paths, disabled=rcfg.get("disabled"), only=rcfg.get("only"))

    def _rules() -> None:
        model.findings = engine.run(model)

    stage("rules", _rules)
    stage("risk", lambda: risk.score_all(model, cfg.get("risk", {})))
    stage("suppress", lambda: risk.apply_suppressions(model, cfg, baseline))
    stage("attack_paths", lambda: find_paths(model))

    model.metadata["timings"] = timings
    model.metadata["total_seconds"] = round(sum(timings.values()), 3)
    return model


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def write_outputs(model: ThreatModel, out_dir: str,
                  formats: Optional[List[str]] = None,
                  max_findings_in_doc: int = 60) -> Dict[str, str]:
    from .render import docx_report, drawio, html, markdown, mermaid, sarif, thf, tmt

    formats = formats or ["json", "html", "sarif", "markdown", "mermaid", "thf"]
    os.makedirs(out_dir, exist_ok=True)
    written: Dict[str, str] = {}

    def put(name: str, content: str) -> None:
        path = os.path.join(out_dir, name)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
        written[name] = path

    if "json" in formats:
        put("threat-model.json", model.to_json())
        put("findings.json", model.to_json())            # alias for tooling
    if "html" in formats:
        put("security-report.html", html.render(model))
    if "sarif" in formats:
        put("threatforge.sarif", sarif.render(model))
    if "markdown" in formats:
        put("threat-model.md", markdown.render(model, max_findings=max_findings_in_doc))
    if "mermaid" in formats:
        put("dfd.mmd", mermaid.render_dfd(model))
        put("dfd-exposed.mmd", mermaid.render_dfd(model, reachable_only=True))
        put("trust-boundaries.mmd", mermaid.render_boundary_map(model))
        if model.attack_paths:
            put("attack-path-1.mmd", mermaid.render_attack_path(model, 0))
    if "thf" in formats:
        put("threat-model.thf", thf.render(model))
    if "drawio" in formats:
        put("threat-model.drawio", drawio.render(model))
    if "tmt" in formats:
        put("threat-model.tm7", tmt.render(model))
    if "docx" in formats:
        if docx_report.available():
            path = os.path.join(out_dir, "threat-model.docx")
            docx_report.render(model, path, max_findings=max_findings_in_doc)
            written["threat-model.docx"] = path
        else:
            model.error("render", "docx requested but python-docx is not installed "
                                  "(pip install python-docx); wrote Markdown instead")
            put("threat-model.md", markdown.render(model, max_findings=max_findings_in_doc))

    return written
