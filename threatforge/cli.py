"""
ThreatForge command line interface.

    threatforge scan .                      full pipeline + all reports
    threatforge scan . --fail-on high       scan and gate in one step (CI)
    threatforge gate .                      gate only, minimal output
    threatforge diff . --against base.json  what changed vs a previous run
    threatforge baseline .                  freeze current findings as accepted
    threatforge dfd . --namespace prod      just the diagram
    threatforge rules                       list loaded rules
    threatforge init                        write a starter .threatforge.yml
    threatforge migrate ./legacy            import stage7-dfd.json / architecture.json
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict, List, Optional

from . import config as cfgmod
from . import gate as gatemod
from . import pipeline
from .model import Severity, ThreatModel
from .rules.engine import PACK_DIR, RuleEngine

VERSION = "1.0.0"

C = {
    "critical": "\033[91m", "high": "\033[93m", "medium": "\033[33m",
    "low": "\033[94m", "info": "\033[90m", "ok": "\033[92m",
    "b": "\033[1m", "d": "\033[2m", "x": "\033[0m",
}


def _no_color() -> None:
    for k in C:
        C[k] = ""


# ---------------------------------------------------------------------------

def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(
        prog="threatforge",
        description="Automated, evidence-based threat modelling for "
                    "infrastructure-as-code.")
    p.add_argument("--version", action="version", version=f"threatforge {VERSION}")
    p.add_argument("--no-color", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp):
        sp.add_argument("path", nargs="?", default=".", help="repository root")
        sp.add_argument("-c", "--config", help="path to .threatforge.yml")
        sp.add_argument("-b", "--baseline", help="path to baseline json")
        sp.add_argument("-v", "--verbose", action="store_true")
        return sp

    s = common(sub.add_parser("scan", help="run the full pipeline and write reports"))
    s.add_argument("-o", "--out", help="output directory")
    s.add_argument("-f", "--format", action="append", dest="formats",
                   choices=["json", "html", "sarif", "markdown", "mermaid", "docx"],
                   help="repeatable; default from config")
    s.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "none"],
                   help="also run the gate and exit non-zero if breached")
    s.add_argument("--ingestor", action="append", dest="ingestors",
                   help="restrict ingestors, repeatable")
    s.add_argument("--live", action="store_true", help="also collect from the live cluster")
    s.add_argument("--quiet", action="store_true")

    g = common(sub.add_parser("gate", help="evaluate the CI gate only"))
    g.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "none"])
    g.add_argument("--max-new", type=int)
    g.add_argument("--json", action="store_true", help="emit the gate report as JSON")
    g.add_argument("--github-summary", action="store_true",
                   help="append markdown to $GITHUB_STEP_SUMMARY")

    d = common(sub.add_parser("diff", help="compare against a previous threat-model.json"))
    d.add_argument("--against", required=True)

    bl = common(sub.add_parser("baseline", help="freeze current findings as accepted risk"))
    bl.add_argument("-o", "--out", default=None)
    bl.add_argument("--reason", default="baselined at adoption")
    bl.add_argument("--owner", default="unassigned")

    df = common(sub.add_parser("dfd", help="render the data flow diagram only"))
    df.add_argument("-n", "--namespace")
    df.add_argument("--reachable-only", action="store_true")
    df.add_argument("-o", "--out")

    r = sub.add_parser("rules", help="list rules")
    r.add_argument("--pack")
    r.add_argument("--json", action="store_true")

    i = sub.add_parser("init", help="write a starter .threatforge.yml")
    i.add_argument("path", nargs="?", default=".")

    m = common(sub.add_parser("migrate", help="import legacy stage7/architecture JSON"))
    m.add_argument("-o", "--out", default="threatforge-out")

    args = p.parse_args(argv)
    if getattr(args, "no_color", False) or not sys.stdout.isatty():
        _no_color()

    try:
        return {
            "scan": cmd_scan, "gate": cmd_gate, "diff": cmd_diff,
            "baseline": cmd_baseline, "dfd": cmd_dfd, "rules": cmd_rules,
            "init": cmd_init, "migrate": cmd_migrate,
        }[args.cmd](args)
    except UsageError as exc:
        print(f"{C['critical']}error:{C['x']} {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        print(f"{C['critical']}error:{C['x']} {type(exc).__name__}: {exc}", file=sys.stderr)
        if getattr(args, "verbose", False):
            import traceback
            traceback.print_exc()
        return 2


# ---------------------------------------------------------------------------

class UsageError(Exception):
    """A problem with what the user asked for, not with the code."""


def _resolve_root(raw: str) -> str:
    """Validate the scan target before anything is written.

    Silently scanning a directory that does not exist -- and creating it on the
    way out -- is worse than failing, because an empty report looks like a clean
    one.
    """
    expanded = os.path.expanduser(raw)
    root = os.path.abspath(expanded)

    if os.path.isdir(root):
        return root

    hint = ""
    # PowerShell and cmd do not expand '~', so it arrives as a literal path
    # segment and os.path.expanduser only handles a leading '~'.
    if "~" in raw:
        home = os.path.expanduser("~")
        guess = os.path.abspath(os.path.join(home, raw.lstrip("~/\\")))
        hint = ("\n  '~' is not expanded by PowerShell or cmd. Use the full path"
                f"\n  or '$HOME'. You may have meant:\n    {guess}")
    elif not os.path.exists(root):
        parent = os.path.dirname(root)
        if os.path.isdir(parent):
            siblings = sorted(d for d in os.listdir(parent)
                              if os.path.isdir(os.path.join(parent, d)))[:8]
            if siblings:
                hint = ("\n  Directories in "
                        f"{parent}:\n    " + "\n    ".join(siblings))
    elif os.path.isfile(root):
        hint = "\n  That is a file. Pass the directory that contains it."

    raise UsageError(f"scan target does not exist: {root}{hint}")


def _load(args) -> tuple:
    root = _resolve_root(args.path)
    cfg = cfgmod.load(root, getattr(args, "config", None))
    if getattr(args, "ingestors", None):
        cfg["ingestors"] = args.ingestors
    if getattr(args, "live", False):
        cfg.setdefault("live", {})["enabled"] = True
    if getattr(args, "fail_on", None):
        cfg.setdefault("gate", {})["fail_on"] = args.fail_on
    if getattr(args, "max_new", None) is not None:
        cfg.setdefault("gate", {})["max_new"] = args.max_new
    baseline = cfgmod.load_baseline(root, getattr(args, "baseline", None))
    return root, cfg, baseline


def cmd_scan(args) -> int:
    root, cfg, baseline = _load(args)
    quiet = getattr(args, "quiet", False)
    if not quiet:
        print(f"{C['b']}ThreatForge{C['x']} {VERSION} — scanning {root}")
    model = pipeline.run(root, cfg, baseline, verbose=args.verbose)

    out_dir = args.out or cfg["output"]["dir"]
    if not os.path.isabs(out_dir):
        out_dir = os.path.join(root, out_dir)
    formats = args.formats or cfg["output"]["formats"]
    written = pipeline.write_outputs(
        model, out_dir, formats, cfg["output"].get("max_findings_in_doc", 60))

    if not quiet:
        _print_summary(model)
        print(f"\n{C['b']}Reports{C['x']}")
        for name, path in written.items():
            print(f"  {C['d']}{path}{C['x']}")

    if args.fail_on:
        passed, report = gatemod.evaluate(model, cfg["gate"], baseline)
        print(gatemod.format_report(report, model))
        return 0 if passed else 1
    return 0


def cmd_gate(args) -> int:
    root, cfg, baseline = _load(args)
    model = pipeline.run(root, cfg, baseline, verbose=args.verbose)
    passed, report = gatemod.evaluate(model, cfg["gate"], baseline)

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(gatemod.format_report(report, model))

    if args.github_summary:
        path = os.environ.get("GITHUB_STEP_SUMMARY")
        if path:
            with open(path, "a", encoding="utf-8") as fh:
                fh.write(gatemod.github_step_summary(report, model) + "\n")
    return 0 if passed else 1


def cmd_diff(args) -> int:
    root, cfg, baseline = _load(args)
    model = pipeline.run(root, cfg, baseline, verbose=args.verbose)
    with open(args.against, "r", encoding="utf-8") as fh:
        prev = json.load(fh)

    old = {f["id"]: f for f in prev.get("findings", []) if not f.get("suppressed")}
    new = {f.id: f for f in model.active_findings}

    added = [new[i] for i in new.keys() - old.keys()]
    removed = [old[i] for i in old.keys() - new.keys()]
    worse = [(new[i], old[i]) for i in new.keys() & old.keys()
             if new[i].risk_score > old[i].get("risk_score", 0)]

    print(f"\n{C['b']}Diff vs {args.against}{C['x']}")
    print(f"  {C['critical']}+{len(added)} new{C['x']}   "
          f"{C['ok']}-{len(removed)} resolved{C['x']}   "
          f"{C['high']}↑{len(worse)} worsened{C['x']}\n")

    for f in sorted(added, key=lambda x: -x.risk_score)[:25]:
        print(f"  {C['critical']}+{C['x']} [{f.risk_score:>2}] {f.rule_id:<14} "
              f"{f.title[:52]}\n      {C['d']}{f.component}{C['x']}")
    for f in sorted(removed, key=lambda x: -x.get("risk_score", 0))[:15]:
        print(f"  {C['ok']}-{C['x']} [{f.get('risk_score', 0):>2}] "
              f"{f.get('rule_id', ''):<14} {f.get('title', '')[:52]}")
    for n, o in worse[:15]:
        print(f"  {C['high']}↑{C['x']} {n.rule_id:<14} {n.title[:44]} "
              f"{o.get('risk_score')} → {n.risk_score}")
    print()
    return 1 if added else 0


def cmd_baseline(args) -> int:
    root, cfg, _ = _load(args)
    model = pipeline.run(root, cfg, None, verbose=args.verbose)
    out = args.out or os.path.join(root, cfgmod.BASELINE_NAME)
    cfgmod.write_baseline(model, out, args.reason, args.owner)
    print(f"Baselined {len(model.active_findings)} findings → {out}")
    print(f"{C['d']}Future scans will only fail on findings not in this file. "
          f"Commit it.{C['x']}")
    return 0


def cmd_dfd(args) -> int:
    from .render import mermaid
    root, cfg, baseline = _load(args)
    model = pipeline.run(root, cfg, baseline, verbose=args.verbose)
    out = mermaid.render_dfd(model, namespace=args.namespace,
                             reachable_only=args.reachable_only)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(out)
        print(f"Wrote {args.out}")
    else:
        print(out)
    return 0


def cmd_rules(args) -> int:
    engine = RuleEngine.load([PACK_DIR])
    rules = engine.rules
    if args.pack:
        rules = [r for r in rules if r.pack == args.pack]
    if args.json:
        print(json.dumps([{
            "id": r.id, "title": r.title, "pack": r.pack,
            "severity": r.severity.value, "stride": r.stride,
            "confidence": r.confidence.value,
            "applies_to": r.applies_to, "references": r.references, "tags": r.tags,
        } for r in rules], indent=2))
        return 0

    print(f"\n{C['b']}{len(rules)} rules{C['x']} "
          f"across {len({r.pack for r in rules})} packs\n")
    for pack in sorted({r.pack for r in rules}):
        print(f"{C['b']}{pack}{C['x']}")
        for r in [x for x in rules if x.pack == pack]:
            col = C.get(r.severity.value, "")
            print(f"  {col}{r.severity.value:<8}{C['x']} {r.id:<15} "
                  f"{r.title[:60]}  {C['d']}[{''.join(r.stride)}]{C['x']}")
        print()
    if engine.load_errors:
        print(f"{C['high']}Load errors:{C['x']}")
        for e in engine.load_errors:
            print(f"  {e}")
    return 0


def cmd_init(args) -> int:
    path = os.path.join(os.path.abspath(args.path), ".threatforge.yml")
    if os.path.exists(path):
        print(f"{path} already exists; not overwriting.")
        return 1
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(cfgmod.SAMPLE)
    print(f"Wrote {path}")
    return 0


def cmd_migrate(args) -> int:
    root, cfg, baseline = _load(args)
    cfg["ingestors"] = ["legacy"]
    model = pipeline.run(root, cfg, baseline, verbose=args.verbose)
    out_dir = args.out if os.path.isabs(args.out) else os.path.join(root, args.out)
    written = pipeline.write_outputs(model, out_dir, ["json", "html", "markdown", "mermaid"])
    _print_summary(model)
    print(f"\n{C['d']}Legacy sources carry no raw spec, so control-based rules cannot "
          f"fire —\nonly topology and exposure rules ran. Re-scan the original "
          f"manifests for the full picture.{C['x']}")
    for name, path in written.items():
        print(f"  {C['d']}{path}{C['x']}")
    return 0


# ---------------------------------------------------------------------------

def _print_summary(model: ThreatModel) -> None:
    c = model.counts()

    # Two assets means only the synthetic external entities were created: nothing
    # in the target directory was recognised. An empty report must not be mistaken
    # for a clean one.
    real = [a for a in model.assets.values() if a.provider != "external"]
    if not real:
        ing = model.metadata.get("ingestors", {})
        detected = [n for n, s in ing.items() if s.get("detected")]
        print(f"\n{C['high']}warning:{C['x']} no infrastructure was found in "
              f"{model.metadata.get('root')}")
        print(f"  ingestors that found candidate files: "
              f"{', '.join(detected) if detected else 'none'}")
        print(f"  {C['d']}Check you are pointing at the right directory, that the "
              f"manifests are .yaml/.yml/.tf/Dockerfile,\n  and that they are not "
              f"excluded by suppress.paths in .threatforge.yml.{C['x']}")
        return

    print(f"\n{C['b']}Model{C['x']}  "
          f"{len(model.assets)} assets · {len(model.flows)} flows · "
          f"{len(model.boundaries)} boundaries · "
          f"{model.metadata.get('total_seconds', 0)}s")
    print(f"{C['b']}Risk {C['x']}  "
          f"{C['critical']}{c['critical']} critical{C['x']} · "
          f"{C['high']}{c['high']} high{C['x']} · "
          f"{C['medium']}{c['medium']} medium{C['x']} · "
          f"{C['low']}{c['low']} low{C['x']}"
          + (f" · {C['d']}{len(model.findings) - len(model.active_findings)} "
             f"suppressed{C['x']}"
             if len(model.findings) != len(model.active_findings) else ""))

    if model.attack_paths:
        top = model.attack_paths[0]
        chain = " → ".join(
            (model.assets[h].display if h in model.assets else h) for h in top.hops)
        print(f"{C['b']}Paths{C['x']}  {len(model.attack_paths)} "
              f"(top score {top.score})")
        print(f"       {C['d']}{chain[:150]}{C['x']}")

    top_findings = model.active_findings[:8]
    if top_findings:
        print(f"\n{C['b']}Highest risk{C['x']}")
        for f in top_findings:
            col = C.get(f.risk_level.value, "")
            src = f.primary_source
            loc = f" {C['d']}{src.file}:{src.line}{C['x']}" if src.file else ""
            print(f"  {col}[{f.risk_score:>2}]{C['x']} {f.rule_id:<14} "
                  f"{f.title[:54]}")
            print(f"       {C['d']}{f.component}{C['x']}{loc}")

    errs = [e for e in model.errors if "stage failed" in str(e.get("message", ""))]
    if errs:
        print(f"\n{C['high']}Stage errors:{C['x']}")
        for e in errs:
            print(f"  [{e['stage']}] {e['message']}")


if __name__ == "__main__":
    sys.exit(main())
