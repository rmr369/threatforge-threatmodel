# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""
The executive report.

Written for the person who has to decide something, not the person who has to
fix it. That difference drives every choice here:

* **Numbers appear once, near the top, and are never repeated.** A reader who
  needs the detail opens the workbook.
* **Nothing is described as a "risk" without saying what it lets an attacker
  do.** "Seventeen critical findings" is not information; "an anonymous caller
  can reach the credential store in three hops" is.
* **What the assessment does not cover is stated as plainly as what it does.**
  A report that only lists what was found invites the reader to assume the rest
  was checked and passed.
* **Unanswered design questions are reported as unanswered**, not folded into
  the finding count. Silence is a different state from safety, and an executive
  summary that blurs the two is worse than none.

Self-contained HTML: no CDN, no fonts to fetch, prints to PDF from the browser.
"""

from __future__ import annotations

import datetime as _dt
from typing import Any, Dict, List, Optional

from ..model import ThreatModel

STRIDE_FULL = {
    "S": "Spoofing", "T": "Tampering", "R": "Repudiation",
    "I": "Information disclosure", "D": "Denial of service",
    "E": "Elevation of privilege",
}

_WORDS = ["no", "one", "two", "three", "four", "five", "six", "seven", "eight",
          "nine", "ten", "eleven", "twelve"]


def _num(n: int) -> str:
    return _WORDS[n] if n < len(_WORDS) else f"{n:,}"


def _esc(v: Any) -> str:
    return (str("" if v is None else v).replace("&", "&amp;")
            .replace("<", "&lt;").replace(">", "&gt;"))


CSS = """
*{box-sizing:border-box}
body{margin:0;background:#fff;color:#16161a;font:16px/1.65 -apple-system,
 "Segoe UI",Roboto,Helvetica,Arial,sans-serif;-webkit-print-color-adjust:exact;
 print-color-adjust:exact}
.wrap{max-width:860px;margin:0 auto;padding:56px 32px 96px}
h1{font-size:30px;line-height:1.25;margin:0 0 6px;font-weight:650;letter-spacing:-.02em}
.sub{color:#5d5d68;font-size:15px;margin-bottom:38px}
h2{font-size:19px;margin:44px 0 12px;font-weight:600;letter-spacing:-.01em;
 display:flex;align-items:baseline;gap:11px}
h2 .n{font-size:12px;color:#9a9aa6;font-weight:700;letter-spacing:.09em}
h3{font-size:15px;margin:24px 0 7px;font-weight:600}
p{margin:0 0 13px}
.lead{font-size:17px;line-height:1.6}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(126px,1fr));
 gap:11px;margin:18px 0 8px}
.kpi{border:1px solid #e4e4ea;border-radius:11px;padding:13px 15px}
.kpi .v{font-size:27px;font-weight:650;line-height:1.15}
.kpi .l{font-size:11px;text-transform:uppercase;letter-spacing:.07em;color:#6c6c78;
 margin-top:2px}
.crit{color:#b91c1c}.high{color:#c2410c}.med{color:#a16207}.low{color:#1d4ed8}
.ok{color:#15803d}.muted{color:#6c6c78}
table{width:100%;border-collapse:collapse;font-size:14px;margin:12px 0 4px}
th{text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:.06em;
 color:#6c6c78;border-bottom:2px solid #e4e4ea;padding:8px 10px 7px}
td{border-bottom:1px solid #eeeef2;padding:9px 10px;vertical-align:top}
tr:last-child td{border-bottom:none}
.pill{display:inline-block;padding:2px 8px;border-radius:999px;font-size:11px;
 font-weight:650;text-transform:uppercase;letter-spacing:.03em}
.p-critical{background:#fee2e2;color:#991b1b}.p-high{background:#ffedd5;color:#9a3412}
.p-medium{background:#fef3c7;color:#854d0e}.p-low{background:#dbeafe;color:#1e40af}
.p-info{background:#eef0f3;color:#4b5563}
.callout{border-left:3px solid #16161a;padding:2px 0 2px 15px;margin:16px 0;
 color:#3a3a44}
.callout.warn{border-color:#b91c1c}
.mono{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:12.5px;
 color:#4b4b56}
ol,ul{margin:0 0 14px;padding-left:22px}li{margin-bottom:6px}
.path{border:1px solid #e4e4ea;border-radius:10px;padding:13px 15px;margin-bottom:11px}
.chain{font-size:13.5px;color:#3a3a44;margin-top:6px}
.chain b{color:#16161a}
footer{margin-top:56px;padding-top:18px;border-top:1px solid #e4e4ea;
 color:#8a8a96;font-size:12.5px}
@media print{.wrap{padding:0 0 24px}h2{page-break-after:avoid}
 table,.path,.kpi{page-break-inside:avoid}}
"""


def render(model: ThreatModel, document: Optional[Dict[str, Any]] = None,
           findings=None) -> str:
    doc = (document or {}).get("fields", {}) or {}
    answers = (document or {}).get("answers", {}) or {}
    rows = list(findings if findings is not None else model.active_findings)
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    rows.sort(key=lambda f: (order.get(f.risk_level.value, 9), -f.risk_score))

    counts = model.counts()
    crit, high = counts.get("critical", 0), counts.get("high", 0)
    actionable = [f for f in rows if f.risk_level.value != "info"]
    coverage = [f for f in rows if f.rule_id == "TF-DSN-000"]
    paths = list(model.attack_paths)
    title = doc.get("title") or model.project or "Threat model"
    today = _dt.date.today().strftime("%d %B %Y")

    o: List[str] = []
    w = o.append
    w(f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{_esc(title)} — threat model</title><style>{CSS}</style></head><body>
<div class="wrap">
<h1>{_esc(title)}</h1>
<div class="sub">Threat model · {today}
{(' · ' + _esc(doc['owner'])) if doc.get('owner') else ''}
{(' · reviewed by ' + _esc(doc['reviewer'])) if doc.get('reviewer') else ''}</div>""")

    # -- 01 at a glance ---------------------------------------------------
    w('<h2><span class="n">01</span>At a glance</h2>')
    if not actionable:
        verdict = ("Nothing actionable was found. That is a real result only if "
                   "the design questions below were answered; where they were not, "
                   "the correct reading is that the analysis is incomplete.")
    elif crit:
        verdict = (f"{_num(crit).capitalize()} critical "
                   f"{'issue' if crit == 1 else 'issues'} "
                   f"{'is' if crit == 1 else 'are'} open. "
                   "Each is exploitable as the system stands today, without an "
                   "attacker needing a condition they cannot arrange.")
    elif high:
        verdict = (f"No critical issues. {_num(high).capitalize()} high "
                   f"{'issue' if high == 1 else 'issues'} "
                   f"{'is' if high == 1 else 'are'} open — each needs one further "
                   "condition before it becomes exploitable.")
    else:
        verdict = ("Nothing critical or high is open. What remains is worth "
                   "scheduling, not escalating.")
    w(f'<p class="lead">{verdict}</p>')
    w('<div class="grid">')
    for label, value, klass in (("Critical", crit, "crit"), ("High", high, "high"),
                                ("Medium", counts.get("medium", 0), "med"),
                                ("Low", counts.get("low", 0), "low"),
                                ("Attack paths", len(paths),
                                 "crit" if paths else "ok"),
                                ("Open questions", len(coverage), "muted")):
        w(f'<div class="kpi"><div class="v {klass}">{value}</div>'
          f'<div class="l">{label}</div></div>')
    w('</div>')
    w('<p class="muted" style="font-size:13.5px">Counts are of open items only. '
      'Anything accepted, resolved or ruled out of scope is excluded, and the '
      'reason is recorded against it in the workbook.</p>')

    # -- 02 what was assessed --------------------------------------------
    w('<h2><span class="n">02</span>What was assessed</h2>')
    w(f'<p>{len(model.assets)} components, {len(model.flows)} data flows and '
      f'{len(model.boundaries)} trust boundaries, derived from the '
      'infrastructure definitions themselves rather than from a diagram drawn '
      'separately. Every finding in this report cites the file and line that '
      'produced it.</p>')
    if doc.get("scope"):
        w(f'<h3>In scope</h3><p>{_esc(doc["scope"])}</p>')
    if doc.get("out_of_scope"):
        w(f'<h3>Explicitly out of scope</h3><p>{_esc(doc["out_of_scope"])}</p>')
    if doc.get("assumptions"):
        w('<h3>Assumptions this rests on</h3><ul>'
          + "".join(f"<li>{_esc(line)}</li>"
                    for line in str(doc["assumptions"]).splitlines() if line.strip())
          + '</ul>')
    if doc.get("dependencies"):
        w('<h3>Depends on systems we do not control</h3>'
          f'<p>{_esc(doc["dependencies"])}</p>')

    # -- 03 what an attacker can do --------------------------------------
    w('<h2><span class="n">03</span>What an attacker could do today</h2>')
    if paths:
        w(f'<p>{_num(len(paths)).capitalize()} complete '
          f'{"route" if len(paths) == 1 else "routes"} '
          'from an external entity to something worth reaching. A route is only '
          'listed when every step of it is backed by a finding, so each one is '
          'walkable rather than theoretical.</p>')
        for p in paths[:5]:
            labels = [model.assets[h].display if h in model.assets else h
                      for h in p.hops]
            w(f'<div class="path"><span class="pill p-{p.level.value}">'
              f'{p.level.value}</span> <b>{_esc(labels[0] if labels else "")}</b> '
              f'&rarr; <b>{_esc(labels[-1] if labels else "")}</b>'
              f'<div class="chain">{" &rarr; ".join(_esc(x) for x in labels)}</div>'
              f'<div class="chain muted">Breaking any single step closes it: '
              f'{_esc(", ".join(p.findings[:4]))}</div></div>')
        if len(paths) > 5:
            w(f'<p class="muted">{len(paths) - 5} further routes are listed in '
              'the workbook.</p>')
    else:
        w('<p>No complete route was found from an external entity to a sensitive '
          'component. That is a meaningful result: it means the issues below, '
          'while real, do not currently chain into a walkable path.</p>')

    # -- 04 the issues ----------------------------------------------------
    w('<h2><span class="n">04</span>The issues that matter most</h2>')
    top = [f for f in actionable if f.risk_level.value in ("critical", "high")][:12]
    if top:
        w('<table><thead><tr><th>Severity</th><th>Issue</th><th>Component</th>'
          '<th>Weakness</th><th>Fix</th></tr></thead><tbody>')
        for f in top:
            cwe = ", ".join((f.references or {}).get("cwe", []) or []) or "—"
            fix = f.remediation.summary if f.remediation else ""
            w(f'<tr><td><span class="pill p-{f.risk_level.value}">'
              f'{f.risk_level.value}</span></td>'
              f'<td>{_esc(f.title)}<div class="mono">{_esc(f.rule_id)}</div></td>'
              f'<td class="mono">{_esc(f.component)}</td>'
              f'<td>{_esc(cwe)}</td><td>{_esc(fix)}</td></tr>')
        w('</tbody></table>')
        if len(actionable) > len(top):
            w(f'<p class="muted">{len(actionable) - len(top)} further issues of '
              'medium severity and below are in the workbook.</p>')
    else:
        w('<p>Nothing critical or high is open.</p>')

    # -- 05 coverage ------------------------------------------------------
    w('<h2><span class="n">05</span>What this does not tell you</h2>')
    per = {k: 0 for k in STRIDE_FULL}
    for f in rows:
        for letter in (f.stride or []):
            key = getattr(letter, "value", letter)
            if key in per:
                per[key] += 1
    silent = [f"{k} ({STRIDE_FULL[k].lower()})" for k, v in per.items() if not v]
    w('<div class="callout">Static analysis can only report what the '
      'configuration states. It cannot see application logic, business rules, '
      'or a control that exists but is not declared anywhere it can read.</div>')
    if coverage:
        w(f'<p><b>{len(coverage)} component'
          f'{"" if len(coverage) == 1 else "s"} have unanswered design '
          'questions.</b> These are not findings and are not counted as risk. '
          'They are questions — does this sanitise input, does it authenticate, '
          'what does it store — that nobody has answered, so no rule could '
          'decide either way. Until they are answered, a clean result for those '
          'components means nothing was asked, not that nothing is wrong.</p>')
    if silent:
        w('<p>No threats were raised in these STRIDE categories: '
          + ", ".join(silent)
          + '. That may be correct, or it may mean the model does not yet '
          'describe the parts of the system where those threats live.</p>')
    unanswered = _security_gaps(answers)
    if unanswered:
        w('<p>Security questions still open:</p><ul>'
          + "".join(f"<li>{_esc(q)}</li>" for q in unanswered[:8]) + '</ul>')

    # -- 06 what is needed ------------------------------------------------
    w('<h2><span class="n">06</span>What we are asking for</h2>')
    w('<ol>')
    if crit:
        w(f'<li><b>Fix the {_num(crit)} critical '
          f'{"issue" if crit == 1 else "issues"} before the next release.</b> '
          'Each is exploitable as things stand.</li>')
    if paths:
        w('<li><b>Break at least one step in each attack route.</b> '
          'The cheapest step is usually not the first one — the table above names '
          'the candidates for each route.</li>')
    if coverage:
        w('<li><b>Answer the open design questions.</b> They take minutes each '
          'and they are what turns an incomplete analysis into a conclusion.</li>')
    w('<li><b>Name an owner for each issue.</b> Unassigned work does not get '
      'done, and the SLA clock starts when the issue first appeared, not when '
      'someone noticed it.</li>')
    w('</ol>')
    if doc.get("stakeholders"):
        w(f'<p class="muted">Stakeholders: {_esc(doc["stakeholders"])}</p>')

    w(f'<footer>Generated by ThreatForge on {today}. Every finding cites the '
      'file and line it came from; the accompanying workbook carries the full '
      'list with evidence, owners and remediation.</footer></div></body></html>')
    return "\n".join(o)


def _security_gaps(answers: Dict[str, Any]) -> List[str]:
    from ..library import SECURITY_QUESTIONS
    return [q["q"] for q in SECURITY_QUESTIONS
            if not str(answers.get(q["id"], "") or "").strip()]
