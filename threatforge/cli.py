# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

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
    threatforge serve .                     local web app with SLA + workflow
    threatforge sla .                       SLA status from stored history
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
                   choices=["json", "html", "sarif", "markdown", "mermaid", "thf", "tmt",
                            "drawio", "docx"],
                   help="repeatable; default from config")
    s.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "none"],
                   help="also run the gate and exit non-zero if breached")
    s.add_argument("--ingestor", action="append", dest="ingestors",
                   help="restrict ingestors, repeatable")
    s.add_argument("--live", action="store_true", help="also collect from the live cluster")
    s.add_argument("--quiet", action="store_true")
    s.add_argument("--track", action="store_true",
                   help="record this scan in the history database "
                        "(first-seen dates, SLA clocks, workflow state)")
    s.add_argument("--db", help="path to the history database")

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

    sv = common(sub.add_parser("serve", help="run the local web app"))
    sv.add_argument("-p", "--port", type=int, help="default 8787")
    sv.add_argument("--db", help="path to the SQLite database")
    sv.add_argument("--no-browser", action="store_true")
    sv.add_argument("--no-scan", action="store_true",
                    help="skip the scan on startup and serve stored findings")
    sv.add_argument("--fresh", action="store_true",
                    help="delete stored findings, scans and history, then start "
                         "empty; implies --no-scan")

    sl = common(sub.add_parser("sla", help="SLA status from the stored history"))
    sl.add_argument("--db", help="path to the SQLite database")
    sl.add_argument("--json", action="store_true")
    sl.add_argument("--breached-only", action="store_true")
    sl.add_argument("--fail-on-breach", action="store_true",
                    help="exit 1 if anything is past its SLA")

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
            "serve": cmd_serve, "sla": cmd_sla,
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


def _resolve_out(explicit: Optional[str], configured: str, root: str) -> str:
    """Where reports go.

    -o is relative to the working directory; output.dir in config is relative to
    the scan root. Getting this backwards produces paths like `target/target/out`
    when someone types `-o target/out` from the parent directory.
    """
    if explicit:
        return os.path.abspath(explicit)
    return (configured if os.path.isabs(configured)
            else os.path.join(root, configured))


def cmd_scan(args) -> int:
    root, cfg, baseline = _load(args)
    quiet = getattr(args, "quiet", False)
    if not quiet:
        print(f"{C['b']}ThreatForge{C['x']} {VERSION} — scanning {root}")

    # An explicit -o is resolved against the working directory, like every other
    # CLI tool. output.dir from config is resolved against the scan root, because
    # it is a per-project setting that has to make sense from anywhere.
    out_dir = _resolve_out(args.out, cfg["output"]["dir"], root)

    model = pipeline.run(root, cfg, baseline, verbose=args.verbose, out_dir=out_dir)
    formats = args.formats or cfg["output"]["formats"]
    written = pipeline.write_outputs(
        model, out_dir, formats, cfg["output"].get("max_findings_in_doc", 60))

    if not quiet:
        _print_summary(model)
        print(f"\n{C['b']}Reports{C['x']}")
        for name, path in written.items():
            print(f"  {C['d']}{path}{C['x']}")

    if getattr(args, "track", False):
        from .store import Store, default_db_path
        store = Store(args.db or (cfg.get("serve", {}) or {}).get("database")
                      or default_db_path(root))
        delta = store.record_scan(model, root)
        store.close()
        if not quiet:
            print(f"\n{C['b']}History{C['x']}  {len(delta['new'])} new · "
                  f"{len(delta['resolved'])} resolved · "
                  f"{len(delta['reopened'])} reopened   "
                  f"{C['d']}{args.db or default_db_path(root)}{C['x']}")

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


def cmd_serve(args) -> int:
    from . import server
    root, cfg, _ = _load(args)
    serve_cfg = cfg.get("serve", {}) or {}
    server.serve(
        root,
        port=args.port or serve_cfg.get("port", 8787),
        db=args.db or serve_cfg.get("database"),
        config=cfg,
        open_browser=not args.no_browser and serve_cfg.get("open_browser", True),
        # --fresh implies --no-scan: clearing the history and then immediately
        # repopulating it would defeat the point of asking for a clean start.
        scan_on_start=not (args.no_scan or args.fresh),
        fresh=args.fresh,
    )
    return 0


def cmd_sla(args) -> int:
    from .sla import Policy, summarise
    from .store import Store, default_db_path
    root, cfg, _ = _load(args)
    db = args.db or (cfg.get("serve", {}) or {}).get("database") or default_db_path(root)
    if not os.path.exists(db):
        raise UsageError(
            f"no history database at {db}\n"
            "  SLA tracking needs at least one recorded scan. Run:\n"
            "    threatforge serve .      (records automatically)\n"
            "  or scan once with the store enabled.")

    store = Store(db)
    policy = Policy.from_config(cfg)
    rows = store.findings(policy=policy)
    report = summarise(policy, rows)
    store.close()

    if args.json:
        print(json.dumps(report, indent=2))
        return 1 if (args.fail_on_breach and report["breached"]) else 0

    b = report["buckets"]
    print(f"\n{C['b']}SLA{C['x']}  as of {report['as_of']}  ·  "
          f"database {C['d']}{db}{C['x']}")
    print(f"  compliance : {report['compliance_pct']}% "
          f"({report['open'] - report['breached']}/{report['open']} open within SLA)")
    print(f"  breached   : {C['critical'] if report['breached'] else C['ok']}"
          f"{report['breached']}{C['x']}")
    print(f"  due soon   : {C['medium']}{b['due_soon']}{C['x']}   "
          f"on track: {C['ok']}{b['on_track']}{C['x']}   closed: {b['closed']}")
    if report["median_resolution_days"] is not None:
        print(f"  median fix : {report['median_resolution_days']} days")

    print(f"\n{C['b']}Policy{C['x']}  " + "  ".join(
        f"{k}={'none' if v is None else str(v) + 'd'}"
        for k, v in report["policy"].items()))

    if report["overdue"]:
        print(f"\n{C['b']}Overdue{C['x']}")
        for o in report["overdue"][:20]:
            print(f"  {C['critical']}{o['days_overdue']:>4}d over{C['x']} "
                  f"{o['risk_level']:<8} {o['rule_id']:<14} {o['title'][:44]}")
            print(f"       {C['d']}{o['component']} · owner {o['owner']}"
                  f" · due {o['due_date']}{C['x']}")
        if len(report["overdue"]) > 20:
            print(f"  … and {len(report['overdue']) - 20} more")
    elif not args.breached_only:
        print(f"\n  {C['ok']}Nothing overdue.{C['x']}")
    print()
    return 1 if (args.fail_on_breach and report["breached"]) else 0


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
