"""
Self-contained interactive HTML report.

One file, no build step, no server. Data is embedded as JSON and the UI is
vanilla JS; Chart.js and Mermaid load from CDN with graceful degradation if the
machine is offline (charts disappear, everything else still works).
"""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from typing import Any, Dict, List

from ..model import Severity, ThreatModel
from .mermaid import render_attack_path, render_boundary_map, render_dfd

LEVEL_COLOR = {
    "critical": "#ef4444", "high": "#f97316", "medium": "#eab308",
    "low": "#3b82f6", "info": "#64748b",
}

STRIDE_FULL = {
    "S": "Spoofing", "T": "Tampering", "R": "Repudiation",
    "I": "Information Disclosure", "D": "Denial of Service",
    "E": "Elevation of Privilege",
}


def render(model: ThreatModel, *, title: str = "") -> str:
    payload = _payload(model)
    data_json = json.dumps(payload, default=str)
    heading = html.escape(title or f"Threat model: {model.project}")
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    return _TEMPLATE.format(
        title=heading,
        generated=generated,
        data=data_json,
        dfd=html.escape(payload["diagrams"]["dfd"]),
        boundary=html.escape(payload["diagrams"]["boundaries"]),
    )


# ---------------------------------------------------------------------------

def _payload(model: ThreatModel) -> Dict[str, Any]:
    findings = [f.to_dict() for f in model.active_findings]
    suppressed = [f.to_dict() for f in model.findings if f.suppressed]

    stride: Dict[str, int] = {k: 0 for k in STRIDE_FULL}
    for f in model.active_findings:
        for s in f.stride:
            if s in stride:
                stride[s] += 1

    by_ns: Dict[str, Dict[str, int]] = {}
    for f in model.active_findings:
        a = model.assets.get(f.component)
        ns = (a.namespace if a else None) or "cluster-scoped"
        e = by_ns.setdefault(ns, {"critical": 0, "high": 0, "medium": 0,
                                  "low": 0, "info": 0, "total": 0})
        e[f.risk_level.value] += 1
        e["total"] += 1

    matrix = [[0] * 5 for _ in range(5)]
    for f in model.active_findings:
        matrix[f.risk.likelihood - 1][f.risk.impact - 1] += 1

    paths = []
    for i, p in enumerate(model.attack_paths[:12]):
        d = p.to_dict()
        d["mermaid"] = render_attack_path(model, i)
        d["hop_labels"] = [
            (model.assets[h].display if h in model.assets else h) for h in p.hops]
        paths.append(d)

    return {
        "project": model.project,
        "summary": model.to_dict()["summary"],
        "coverage": model.metadata.get("control_coverage", {}),
        "metadata": model.metadata,
        "findings": findings,
        "suppressed": suppressed,
        "stride": stride,
        "by_namespace": by_ns,
        "matrix": matrix,
        "attack_paths": paths,
        "assets": [a.to_dict() for a in model.assets.values()],
        "boundaries": [b.to_dict() for b in model.boundaries.values()],
        "errors": model.errors,
        "diagrams": {
            "dfd": render_dfd(model, reachable_only=False, max_nodes=90),
            "boundaries": render_boundary_map(model),
        },
    }


# ---------------------------------------------------------------------------

_TEMPLATE = """<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
:root {{
  --bg:#0b0f19; --panel:#131a2a; --panel2:#1a2338; --line:#25304a;
  --text:#e6edf7; --muted:#93a2bd; --accent:#60a5fa;
  --crit:#ef4444; --high:#f97316; --med:#eab308; --low:#3b82f6; --info:#64748b;
}}
* {{ box-sizing:border-box; }}
body {{ margin:0; background:var(--bg); color:var(--text);
  font:14px/1.55 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif; }}
header {{ padding:22px 28px; border-bottom:1px solid var(--line);
  background:linear-gradient(180deg,#141d31,#0b0f19); }}
h1 {{ margin:0 0 4px; font-size:21px; letter-spacing:-.01em; }}
.sub {{ color:var(--muted); font-size:12.5px; }}
main {{ padding:22px 28px 70px; max-width:1500px; margin:0 auto; }}
.cards {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:12px; }}
.card {{ background:var(--panel); border:1px solid var(--line); border-radius:11px; padding:14px 16px; }}
.card .n {{ font-size:27px; font-weight:650; line-height:1.15; }}
.card .l {{ color:var(--muted); font-size:11.5px; text-transform:uppercase; letter-spacing:.06em; }}
.grid {{ display:grid; gap:16px; margin-top:20px; }}
.g2 {{ grid-template-columns:1.35fr 1fr; }}
.g3 {{ grid-template-columns:repeat(3,1fr); }}
@media (max-width:1080px) {{ .g2,.g3 {{ grid-template-columns:1fr; }} }}
.panel {{ background:var(--panel); border:1px solid var(--line); border-radius:11px; padding:16px 18px; }}
.panel h2 {{ margin:0 0 12px; font-size:14px; text-transform:uppercase;
  letter-spacing:.07em; color:var(--muted); font-weight:600; }}
.tabs {{ display:flex; gap:6px; margin:24px 0 14px; flex-wrap:wrap; }}
.tab {{ padding:7px 15px; border-radius:8px; background:var(--panel2); cursor:pointer;
  border:1px solid var(--line); font-size:13px; }}
.tab.on {{ background:var(--accent); color:#06101f; border-color:var(--accent); font-weight:600; }}
.view {{ display:none; }} .view.on {{ display:block; }}
.filters {{ display:flex; gap:8px; flex-wrap:wrap; margin-bottom:12px; align-items:center; }}
input,select {{ background:var(--panel2); color:var(--text); border:1px solid var(--line);
  border-radius:7px; padding:7px 10px; font-size:13px; font-family:inherit; }}
input[type=search] {{ min-width:270px; }}
table {{ width:100%; border-collapse:collapse; font-size:13px; }}
th {{ text-align:left; color:var(--muted); font-weight:600; font-size:11.5px;
  text-transform:uppercase; letter-spacing:.05em; padding:8px 9px;
  border-bottom:1px solid var(--line); position:sticky; top:0; background:var(--panel);
  cursor:pointer; user-select:none; }}
td {{ padding:9px; border-bottom:1px solid #1c2438; vertical-align:top; }}
tr.f-row {{ cursor:pointer; }} tr.f-row:hover {{ background:#182135; }}
.pill {{ display:inline-block; padding:2px 8px; border-radius:999px; font-size:11px;
  font-weight:650; text-transform:uppercase; letter-spacing:.04em; }}
.crit {{ background:#7f1d1d; color:#fecaca; }} .high {{ background:#7c2d12; color:#fed7aa; }}
.med {{ background:#713f12; color:#fde68a; }} .low {{ background:#1e3a5f; color:#bfdbfe; }}
.info {{ background:#334155; color:#cbd5e1; }}
.tag {{ display:inline-block; padding:1px 7px; border-radius:5px; background:#1f2a42;
  color:var(--muted); font-size:11px; margin:1px 3px 1px 0; }}
.mono {{ font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:12px; }}
.detail {{ display:none; background:#0f1626; }}
.detail.on {{ display:table-row; }}
.detail td {{ padding:16px 18px 20px; }}
.dgrid {{ display:grid; grid-template-columns:1fr 1fr; gap:18px; }}
@media (max-width:900px) {{ .dgrid {{ grid-template-columns:1fr; }} }}
pre {{ background:#080d16; border:1px solid var(--line); border-radius:8px; padding:11px 13px;
  overflow:auto; font-size:12px; margin:7px 0 0; }}
.kv {{ color:var(--muted); font-size:12px; margin:3px 0; }}
.kv b {{ color:var(--text); font-weight:600; }}
.bar {{ height:7px; border-radius:4px; background:#1f2a42; overflow:hidden; margin-top:4px; }}
.bar>i {{ display:block; height:100%; background:var(--accent); }}
.mx {{ border-collapse:collapse; }}
.mx td {{ width:52px; height:42px; text-align:center; border:1px solid var(--line);
  font-weight:650; font-size:13px; }}
.mx th {{ position:static; background:none; border:none; font-size:11px; padding:4px; }}
.path {{ border:1px solid var(--line); border-radius:10px; padding:14px 16px;
  margin-bottom:12px; background:var(--panel2); }}
.path ol {{ margin:8px 0 0 18px; padding:0; color:var(--muted); font-size:13px; }}
.path li {{ margin:3px 0; }}
.mermaid {{ background:#0f1626; border-radius:9px; padding:10px; overflow:auto; }}
.note {{ color:var(--muted); font-size:12.5px; }}
.right {{ text-align:right; }}
a {{ color:var(--accent); }}
</style></head><body>

<header>
  <h1>{title}</h1>
  <div class="sub">Generated {generated} · ThreatForge · evidence-based STRIDE with
    exposure-adjusted risk scoring</div>
</header>

<main>
  <div class="cards" id="cards"></div>

  <div class="tabs">
    <div class="tab on" data-v="findings">Findings</div>
    <div class="tab" data-v="paths">Attack paths</div>
    <div class="tab" data-v="dfd">Data flow diagram</div>
    <div class="tab" data-v="posture">Posture</div>
    <div class="tab" data-v="assets">Assets</div>
    <div class="tab" data-v="about">Method &amp; coverage</div>
  </div>

  <section class="view on" id="v-findings">
    <div class="panel">
      <div class="filters">
        <input type="search" id="q" placeholder="Search title, component, rule, file…">
        <select id="fLevel"><option value="">All risk levels</option>
          <option>critical</option><option>high</option><option>medium</option>
          <option>low</option><option>info</option></select>
        <select id="fStride"><option value="">All STRIDE</option></select>
        <select id="fNs"><option value="">All namespaces</option></select>
        <select id="fConf"><option value="">Any confidence</option>
          <option>confirmed</option><option>likely</option><option>possible</option></select>
        <label class="note"><input type="checkbox" id="fGroup"> group by rule</label>
        <span class="note" id="count"></span>
      </div>
      <div style="max-height:66vh;overflow:auto">
        <table id="tbl"><thead><tr>
          <th data-s="risk_score">Risk</th><th data-s="title">Finding</th>
          <th data-s="component">Component</th><th data-s="stride">STRIDE</th>
          <th data-s="confidence">Conf.</th><th data-s="file">Location</th>
        </tr></thead><tbody id="rows"></tbody></table>
      </div>
    </div>
  </section>

  <section class="view" id="v-paths"><div id="paths"></div></section>

  <section class="view" id="v-dfd">
    <div class="panel">
      <h2>Data flow diagram — grouped by trust boundary</h2>
      <div class="note" style="margin-bottom:10px">Node colour is the highest risk level
        found on that component. Dashed edges are heuristic inferences. ⚠ marks a flow
        that crosses a trust boundary.</div>
      <div class="mermaid" id="m-dfd">{dfd}</div>
    </div>
    <div class="panel" style="margin-top:16px">
      <h2>Trust boundary hierarchy</h2>
      <div class="mermaid" id="m-bnd">{boundary}</div>
    </div>
  </section>

  <section class="view" id="v-posture">
    <div class="grid g2">
      <div class="panel"><h2>Risk matrix — likelihood × impact</h2>
        <div id="matrix"></div>
        <div class="note" style="margin-top:9px">Cells are counts. Everything in the
          bottom-right quadrant is both easy to reach and expensive to lose.</div></div>
      <div class="panel"><h2>STRIDE distribution</h2><canvas id="cStride" height="210"></canvas></div>
    </div>
    <div class="grid g2" style="margin-top:16px">
      <div class="panel"><h2>Risk by namespace</h2><canvas id="cNs" height="230"></canvas></div>
      <div class="panel"><h2>Control coverage</h2><div id="coverage"></div></div>
    </div>
  </section>

  <section class="view" id="v-assets">
    <div class="panel">
      <div class="filters"><input type="search" id="qa" placeholder="Filter assets…"></div>
      <div style="max-height:70vh;overflow:auto">
        <table><thead><tr><th>Kind</th><th>Name</th><th>Namespace</th><th>Element</th>
          <th>Hops</th><th>Blast</th><th>Tags</th></tr></thead>
          <tbody id="arows"></tbody></table>
      </div>
    </div>
  </section>

  <section class="view" id="v-about"><div class="panel" id="about"></div></section>
</main>

<script id="tf-data" type="application/json">{data}</script>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
<script type="module">
  try {{
    const m = await import('https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.esm.min.mjs');
    m.default.initialize({{startOnLoad:false, theme:'dark',
      themeVariables:{{fontSize:'12px'}}, maxTextSize:200000, securityLevel:'loose'}});
    window.__mermaid = m.default;
  }} catch (e) {{ console.warn('mermaid unavailable', e); }}
</script>
<script>
const D = JSON.parse(document.getElementById('tf-data').textContent);
const esc = s => String(s==null?'':s).replace(/[&<>"]/g, c =>
  ({{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}}[c]));
const cls = l => ({{critical:'crit',high:'high',medium:'med',low:'low',info:'info'}}[l]||'info');
const STRIDE = {{S:'Spoofing',T:'Tampering',R:'Repudiation',
  I:'Information Disclosure',D:'Denial of Service',E:'Elevation of Privilege'}};

/* ---- cards ---- */
(function () {{
  const s = D.summary, b = s.by_level || {{}};
  const items = [
    ['Critical', b.critical||0, 'var(--crit)'], ['High', b.high||0, 'var(--high)'],
    ['Medium', b.medium||0, 'var(--med)'], ['Low', b.low||0, 'var(--low)'],
    ['Attack paths', s.attack_paths||0, 'var(--text)'],
    ['Assets', s.assets||0, 'var(--text)'], ['Data flows', s.flows||0, 'var(--text)'],
    ['Suppressed', s.suppressed||0, 'var(--muted)'],
  ];
  document.getElementById('cards').innerHTML = items.map(([l,n,c]) =>
    `<div class="card"><div class="n" style="color:${{c}}">${{n}}</div>
     <div class="l">${{l}}</div></div>`).join('');
}})();

/* ---- tabs ---- */
document.querySelectorAll('.tab').forEach(t => t.onclick = () => {{
  document.querySelectorAll('.tab').forEach(x => x.classList.remove('on'));
  document.querySelectorAll('.view').forEach(x => x.classList.remove('on'));
  t.classList.add('on');
  document.getElementById('v-' + t.dataset.v).classList.add('on');
  if (t.dataset.v === 'dfd') drawMermaid();
  if (t.dataset.v === 'posture') drawCharts();
}});

/* ---- findings table ---- */
let sortKey = 'risk_score', sortDir = -1;
const fileOf = f => (f.evidence && f.evidence[0] && f.evidence[0].source) || {{}};
const nsOf = f => {{ const a = D.assets.find(a => a.id === f.component);
  return (a && a.namespace) || 'cluster-scoped'; }};

function filtered() {{
  const q = document.getElementById('q').value.toLowerCase();
  const lv = document.getElementById('fLevel').value;
  const st = document.getElementById('fStride').value;
  const ns = document.getElementById('fNs').value;
  const cf = document.getElementById('fConf').value;
  return D.findings.filter(f => {{
    if (lv && f.risk_level !== lv) return false;
    if (st && !(f.stride||[]).includes(st)) return false;
    if (cf && f.confidence !== cf) return false;
    if (ns && nsOf(f) !== ns) return false;
    if (q) {{
      const hay = (f.title+' '+f.component+' '+f.rule_id+' '+
        (fileOf(f).file||'')+' '+(f.tags||[]).join(' ')).toLowerCase();
      if (!hay.includes(q)) return false;
    }}
    return true;
  }});
}}

function renderRows() {{
  let list = filtered();
  const grouped = document.getElementById('fGroup').checked;
  list.sort((a,b) => {{
    let x = a[sortKey], y = b[sortKey];
    if (sortKey==='file') {{ x = fileOf(a).file||''; y = fileOf(b).file||''; }}
    if (sortKey==='stride') {{ x=(a.stride||[]).join(''); y=(b.stride||[]).join(''); }}
    return (x>y?1:x<y?-1:0) * sortDir;
  }});
  document.getElementById('count').textContent =
    `${{list.length}} of ${{D.findings.length}} findings`;

  if (grouped) {{
    const by = {{}};
    list.forEach(f => (by[f.rule_id] = by[f.rule_id] || []).push(f));
    document.getElementById('rows').innerHTML = Object.entries(by)
      .sort((a,b) => Math.max(...b[1].map(f=>f.risk_score)) -
                     Math.max(...a[1].map(f=>f.risk_score)))
      .map(([rid, fs]) => {{
        const top = fs[0];
        return `<tr class="f-row"><td><span class="pill ${{cls(top.risk_level)}}">
          ${{Math.max(...fs.map(f=>f.risk_score))}}</span></td>
          <td><b>${{esc(top.title)}}</b><div class="note mono">${{rid}}</div></td>
          <td colspan="4">${{fs.length}} affected component${{fs.length>1?'s':''}}:
            ${{fs.slice(0,6).map(f=>`<span class="tag mono">${{esc(f.component)}}</span>`).join('')}}
            ${{fs.length>6?`<span class="tag">+${{fs.length-6}} more</span>`:''}}</td></tr>`;
      }}).join('') || '<tr><td colspan="6" class="note">No findings match.</td></tr>';
    return;
  }}

  document.getElementById('rows').innerHTML = list.map((f,i) => {{
    const src = fileOf(f);
    const loc = src.file ? `${{esc(src.file)}}${{src.line?':'+src.line:''}}` : '—';
    return `<tr class="f-row" data-i="${{i}}">
      <td><span class="pill ${{cls(f.risk_level)}}">${{f.risk_score}}</span></td>
      <td><b>${{esc(f.title)}}</b><div class="note mono">${{f.rule_id}}</div></td>
      <td class="mono">${{esc(f.component)}}</td>
      <td>${{(f.stride||[]).map(s=>`<span class="tag" title="${{STRIDE[s]||s}}">${{s}}</span>`).join('')}}</td>
      <td class="note">${{f.confidence}}</td>
      <td class="mono note">${{loc}}</td></tr>
      <tr class="detail" id="d${{i}}"><td colspan="6">${{detail(f)}}</td></tr>`;
  }}).join('') || '<tr><td colspan="6" class="note">No findings match.</td></tr>';

  document.querySelectorAll('#rows tr.f-row').forEach(tr => tr.onclick = () => {{
    const d = document.getElementById('d' + tr.dataset.i);
    if (d) d.classList.toggle('on');
  }});
}}

function detail(f) {{
  const r = f.risk || {{}};
  const off = Object.entries(r.control_offsets||{{}})
    .map(([k,v]) => `<span class="tag">${{esc(k)}} ${{v>0?'+':''}}${{v}}</span>`).join('');
  const ev = (f.evidence||[]).map(e => `<div class="kv">• ${{esc(e.description)}}
      ${{e.observed!==null&&e.observed!==undefined&&e.observed!==''
        ? `<br><span class="mono">observed: ${{esc(JSON.stringify(e.observed))}}</span>`:''}}
      ${{e.expected!=null?`<br><span class="mono">expected: ${{esc(JSON.stringify(e.expected))}}</span>`:''}}
      ${{e.source&&e.source.file?`<br><span class="mono note">${{esc(e.source.file)}}${{
        e.source.line?':'+e.source.line:''}} ${{e.source.pointer?'· '+esc(e.source.pointer):''}}</span>`:''}}
    </div>`).join('');
  const refs = Object.entries(f.references||{{}})
    .map(([k,v]) => `<div class="kv"><b>${{k.toUpperCase()}}</b> ${{esc((v||[]).join(', '))}}</div>`).join('');
  const rem = f.remediation || {{}};
  return `<div class="dgrid">
    <div>
      <div class="kv"><b>Threat</b></div>
      <div class="note" style="margin-bottom:10px">${{esc(f.description)}}</div>
      <div class="kv"><b>Evidence</b></div>${{ev}}
      <div class="kv" style="margin-top:10px"><b>STRIDE</b>
        ${{(f.stride||[]).map(s=>`<span class="tag">${{s}} — ${{STRIDE[s]||''}}</span>`).join('')}}</div>
      ${{refs}}
      <div class="kv"><b>Tags</b> ${{(f.tags||[]).map(t=>`<span class="tag">${{esc(t)}}</span>`).join('')}}</div>
    </div>
    <div>
      <div class="kv"><b>Risk ${{f.risk_score}}/25</b> — likelihood ${{r.likelihood}} ×
        impact ${{r.impact}} · ${{f.risk_level}}</div>
      <div class="kv">Exposure: ${{r.exposure_hops==null?'not reachable from an external entity'
        : r.exposure_hops + ' hop(s) from the internet'}} ·
        blast radius ${{r.blast_radius}} · sensitivity ${{r.sensitivity}}</div>
      <div class="kv">${{off||'<span class="note">no adjustments</span>'}}</div>
      ${{(r.notes||[]).map(n=>`<div class="kv note">— ${{esc(n)}}</div>`).join('')}}
      <div class="kv" style="margin-top:12px"><b>Remediation</b> — ${{esc(rem.summary||'—')}}
        <span class="tag">effort ${{esc(rem.effort||'?')}}</span>
        <span class="tag">breaking risk ${{esc(rem.breaking_risk||'?')}}</span></div>
      ${{rem.guidance?`<div class="note">${{esc(rem.guidance)}}</div>`:''}}
      ${{rem.patch?`<pre>${{esc(rem.patch)}}</pre>`:''}}
      <div class="kv note mono" style="margin-top:10px">id ${{f.id}} · suppress with
        rules: ["${{f.rule_id}}"]</div>
    </div></div>`;
}}

['q','fLevel','fStride','fNs','fConf','fGroup'].forEach(id =>
  document.getElementById(id).addEventListener('input', renderRows));
document.querySelectorAll('#tbl th').forEach(th => th.onclick = () => {{
  const k = th.dataset.s; if (!k) return;
  sortDir = (k === sortKey) ? -sortDir : -1; sortKey = k; renderRows();
}});
(function initFilters() {{
  const st = document.getElementById('fStride');
  Object.entries(STRIDE).forEach(([k,v]) =>
    st.innerHTML += `<option value="${{k}}">${{k}} — ${{v}}</option>`);
  const nss = [...new Set(D.findings.map(nsOf))].sort();
  const ns = document.getElementById('fNs');
  nss.forEach(n => ns.innerHTML += `<option>${{esc(n)}}</option>`);
}})();
renderRows();

/* ---- attack paths ---- */
document.getElementById('paths').innerHTML = D.attack_paths.length
  ? D.attack_paths.map((p,i) => `<div class="path">
      <div><span class="pill ${{cls(p.level)}}">score ${{p.score}}</span>
        <b style="margin-left:8px">${{esc(p.hop_labels[0])}} →
        ${{esc(p.hop_labels[p.hop_labels.length-1])}}</b>
        <span class="note"> · ${{p.length}} hops · ${{p.findings.length}} enabling findings</span></div>
      <ol>${{p.narrative.map(n=>`<li>${{esc(n)}}</li>`).join('')}}</ol>
      <div class="mermaid" id="ap${{i}}" style="margin-top:10px">${{esc(p.mermaid)}}</div>
    </div>`).join('')
  : `<div class="panel note">No complete path was found from an untrusted entry point to a
     crown-jewel asset. That is a good sign, but check the coverage notes — a missing
     relationship also produces this result.</div>`;

/* ---- posture ---- */
let charted = false;
function drawCharts() {{
  if (charted || typeof Chart === 'undefined') return; charted = true;
  new Chart(document.getElementById('cStride'), {{
    type:'bar',
    data:{{labels:Object.keys(D.stride).map(k=>k+' · '+STRIDE[k]),
      datasets:[{{data:Object.values(D.stride), backgroundColor:'#60a5fa'}}]}},
    options:{{indexAxis:'y', plugins:{{legend:{{display:false}}}},
      scales:{{x:{{ticks:{{color:'#93a2bd'}},grid:{{color:'#25304a'}}}},
              y:{{ticks:{{color:'#93a2bd'}},grid:{{display:false}}}}}}}}
  }});
  const ns = Object.entries(D.by_namespace).sort((a,b)=>b[1].total-a[1].total).slice(0,14);
  new Chart(document.getElementById('cNs'), {{
    type:'bar',
    data:{{labels:ns.map(x=>x[0]), datasets:[
      {{label:'critical', data:ns.map(x=>x[1].critical), backgroundColor:'#ef4444'}},
      {{label:'high', data:ns.map(x=>x[1].high), backgroundColor:'#f97316'}},
      {{label:'medium', data:ns.map(x=>x[1].medium), backgroundColor:'#eab308'}},
      {{label:'low', data:ns.map(x=>x[1].low), backgroundColor:'#3b82f6'}}]}},
    options:{{plugins:{{legend:{{labels:{{color:'#93a2bd'}}}}}},
      scales:{{x:{{stacked:true,ticks:{{color:'#93a2bd'}},grid:{{display:false}}}},
              y:{{stacked:true,ticks:{{color:'#93a2bd'}},grid:{{color:'#25304a'}}}}}}}}
  }});
}}
(function matrix() {{
  const m = D.matrix; let h = '<table class="mx"><tr><th></th>';
  for (let i=1;i<=5;i++) h += `<th>impact ${{i}}</th>`; h += '</tr>';
  for (let l=5;l>=1;l--) {{
    h += `<tr><th>likelihood ${{l}}</th>`;
    for (let im=1;im<=5;im++) {{
      const n = m[l-1][im-1], s = l*im;
      const c = s>=20?'#7f1d1d':s>=12?'#7c2d12':s>=6?'#713f12':'#1e3a5f';
      h += `<td style="background:${{n?c:'#131a2a'}};color:${{n?'#fff':'#3c4966'}}">${{n||''}}</td>`;
    }}
    h += '</tr>';
  }}
  document.getElementById('matrix').innerHTML = h + '</table>';
}})();
(function coverage() {{
  const c = D.coverage || {{}}; const n = c.workloads || 0;
  const rows = Object.entries(c).filter(([k]) => k !== 'workloads')
    .sort((a,b) => a[1]-b[1]);
  document.getElementById('coverage').innerHTML = n
    ? `<div class="note" style="margin-bottom:10px">Across ${{n}} workloads.</div>` +
      rows.map(([k,v]) => `<div class="kv"><b>${{esc(k.replace(/_/g,' '))}}</b>
        <span class="right" style="float:right">${{v}}%</span>
        <div class="bar"><i style="width:${{v}}%;background:${{
          v<34?'#ef4444':v<67?'#eab308':'#22c55e'}}"></i></div></div>`).join('')
    : '<div class="note">No Kubernetes workloads were found.</div>';
}})();

/* ---- assets ---- */
function renderAssets() {{
  const q = document.getElementById('qa').value.toLowerCase();
  const list = D.assets.filter(a => !q ||
    (a.id+' '+a.kind+' '+(a.tags||[]).join(' ')).toLowerCase().includes(q)).slice(0,600);
  document.getElementById('arows').innerHTML = list.map(a => `<tr>
    <td class="mono">${{esc(a.kind)}}</td><td>${{esc(a.name)}}</td>
    <td class="note">${{esc(a.namespace||'—')}}</td><td class="note">${{esc(a.element)}}</td>
    <td class="note">—</td><td class="note">—</td>
    <td>${{(a.tags||[]).slice(0,6).map(t=>`<span class="tag">${{esc(t)}}</span>`).join('')}}</td>
  </tr>`).join('');
}}
document.getElementById('qa').addEventListener('input', renderAssets);
renderAssets();

/* ---- about ---- */
(function about() {{
  const md = D.metadata || {{}};
  const rules = md.rules || {{}};
  document.getElementById('about').innerHTML = `
    <h2>How these numbers were produced</h2>
    <div class="note" style="line-height:1.7">
      <p><b>Findings are evidence-based.</b> A rule fires only when a fact extracted from a
      real manifest satisfies its predicate. Every finding cites the file, line, and
      config path that triggered it. There is no code path that assigns a threat to a
      component simply because of its type.</p>
      <p><b>Risk = likelihood × impact</b>, both 1–5. The starting point is the rule's base
      severity; it is then adjusted by how far the component sits from an untrusted entry
      point, what compensating controls are present, how much data the component can reach,
      and how large the blast radius is. Every adjustment is listed on the finding.</p>
      <p><b>Confidence</b> is separate from severity. <i>confirmed</i> means the manifest is
      unambiguous; <i>likely</i> means a runtime override is conceivable; <i>possible</i>
      means the relationship or value was inferred heuristically and should be verified.</p>
      <p><b>What this cannot see:</b> application code, running container contents, CVEs in
      images, admission controllers or mesh policy applied out-of-band, and anything
      configured outside the scanned sources. Absence of a finding is not evidence of
      absence of risk.</p>
    </div>
    <h2 style="margin-top:20px">Scan coverage</h2>
    <div class="kv">Rules loaded: <b>${{rules.loaded||0}}</b> from packs
      ${{(rules.packs||[]).map(p=>`<span class="tag">${{esc(p)}}</span>`).join('')}}</div>
    <div class="kv">Subjects evaluated: <b>${{rules.subjects_evaluated||0}}</b>
      (assets + data flows)</div>
    <div class="kv">Relationship edges by type:
      ${{Object.entries(md.relationship_strategies||{{}})
        .map(([k,v])=>`<span class="tag">${{esc(k)}} ${{v}}</span>`).join('')}}</div>
    <div class="kv">Ingestors: ${{Object.entries(md.ingestors||{{}})
      .map(([k,v])=>`<span class="tag">${{esc(k)}} ${{v.files||0}} files / ${{v.assets||0}} assets</span>`)
      .join('')}}</div>
    ${{(D.errors||[]).length ? `<h2 style="margin-top:20px">Parse warnings (${{D.errors.length}})</h2>
      <pre>${{esc(D.errors.slice(0,60).map(e=>`[${{e.stage}}] ${{e.message}}${{
        e.file?' — '+e.file:''}}`).join('\\n'))}}</pre>` : ''}}
    ${{(D.suppressed||[]).length ? `<h2 style="margin-top:20px">Suppressed (${{D.suppressed.length}})</h2>
      <pre>${{esc(D.suppressed.slice(0,80).map(f=>
        `${{f.rule_id}} ${{f.component}} — ${{f.suppression_reason}}`).join('\\n'))}}</pre>` : ''}}`;
}})();

/* ---- mermaid ---- */
let drawn = false;
async function drawMermaid() {{
  if (drawn || !window.__mermaid) return; drawn = true;
  for (const el of document.querySelectorAll('.mermaid')) {{
    const src = el.textContent;
    try {{
      const {{svg}} = await window.__mermaid.render('mm' + Math.random().toString(36).slice(2), src);
      el.innerHTML = svg;
    }} catch (e) {{ el.innerHTML = '<pre>' + esc(src) + '</pre>'; }}
  }}
}}
setTimeout(drawMermaid, 900);
</script>
</body></html>
"""
