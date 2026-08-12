# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""
The served single-page app.

Kept as one Python string rather than a template directory so the package stays
a pure-Python install with no data files to lose and no framework to configure.
The page talks to the JSON API in `server.py` and carries the session token that
mutating routes require.

The diagram and the editor share one canvas implementation. That is deliberate:
two renderers would drift, and the thing you edit should look exactly like the
thing you read.
"""

from .canvas import (CANVAS_CSS, CANVAS_JS, DOCK_HTML, LIBRARY_JS,
                     PROPS_JS, RAIL_HTML)

_PAGE_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>ThreatForge — __PROJECT__</title>
<style>
:root{--bg:#000000;--panel:#0a0a0d;--panel2:#121216;--line:#26262f;--text:#e9e9ef;
 --muted:#8b8b9a;--accent:#4f9cf9;--crit:#ef4444;--high:#f97316;--med:#eab308;
 --low:#3b82f6;--info:#64748b;--ok:#22c55e;
 --hover:#1b1b22;--sunken:#050506;--chip:#17171d}
*{box-sizing:border-box}
/* Chrome's default gutter is ~15px, which on a dense panel is a visible
   column of chrome. 9px is roughly 60% of that and still a comfortable
   drag target. Firefox gets the same via scrollbar-width. */
*{scrollbar-width:thin;scrollbar-color:#33333d transparent}
::-webkit-scrollbar{width:9px;height:9px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:#33333d;border-radius:5px}
::-webkit-scrollbar-thumb:hover{background:#454552}
::-webkit-scrollbar-corner{background:transparent}
/* App shell: a fixed header, a navigation rail, and a main area that owns the
   rest of the viewport. The canvas views need height, and height is only
   available if every ancestor agrees to give it up. */
html,body{height:100%}
body{margin:0;background:var(--bg);color:var(--text);overflow:hidden;
 font:14px/1.55 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
 display:grid;grid-template-columns:214px 1fr;grid-template-rows:52px 1fr}
header{grid-column:1/3;padding:0 18px;border-bottom:1px solid var(--line);
 background:var(--sunken);display:flex;
 align-items:center;gap:14px}
h1{margin:0;font-size:15px;letter-spacing:-.01em;display:flex;align-items:center;gap:8px}
h1 .dot{width:9px;height:9px;border-radius:3px;background:var(--accent)}
nav.side{border-right:1px solid var(--line);background:var(--sunken);overflow:auto;
 padding:10px 9px;display:flex;flex-direction:column;gap:2px}
nav.side .grp{font-size:9.5px;text-transform:uppercase;letter-spacing:.09em;
 color:#6c6c7d;font-weight:700;margin:13px 0 4px 9px}
nav.side .grp:first-child{margin-top:2px}
.nav{display:flex;align-items:center;gap:9px;padding:7px 10px;border-radius:7px;
 cursor:pointer;font-size:13px;color:#c2c2d0;user-select:none}
.nav:hover{background:var(--hover)}
.nav.on{background:var(--accent);color:#06101f;font-weight:600}
.nav svg{flex:none;stroke:currentColor;fill:none;stroke-width:1.5}
.nav .ct{margin-left:auto;font-size:10.5px;padding:1px 6px;border-radius:20px;
 background:var(--chip);color:#c9c9d8;font-weight:600}
.nav.on .ct{background:#04223f;color:#dbe7fb}
main{overflow:auto;padding:16px 20px 24px;min-width:0}
main.full{overflow:hidden;padding:12px 14px}
/* Collapsing a pane is a grid-template change, so the canvas simply gets the
   space back -- no reflow of the diagram, no scrollbars appearing halfway. */
/* Collapsed is a 46px icon rail, not a disappearance. Hiding the navigation
   outright leaves no way back except a control the user has to remember, and
   an empty gutter reads as a broken layout rather than a deliberate one. */
body.no-left{grid-template-columns:46px 1fr}
body.no-left nav.side{padding:10px 6px;overflow:visible}
body.no-left nav.side .grp,
body.no-left .nav span:not(.ct),
body.no-left .nav{justify-content:center;padding:9px 0;position:relative}
body.no-left .nav .ct{position:absolute;top:2px;right:1px;margin:0;padding:0 4px;
 font-size:9px;line-height:13px}
.hbar{display:flex;align-items:center;gap:5px}
.vsep{width:1px;height:20px;background:var(--line);margin:0 4px}
button.ico{display:inline-flex;align-items:center;gap:6px;padding:5px 9px;
 background:transparent;border:1px solid transparent;color:var(--muted);font-size:12.5px}
button.ico:hover{background:var(--hover);color:var(--text);border-color:var(--line)}
button.ico svg{stroke:currentColor;fill:none;stroke-width:1.5}
button.ico.sq{padding:5px 7px}
button.ico.on{background:var(--hover);color:var(--accent);border-color:var(--line)}
.menu{position:relative}
.drop{display:none;position:absolute;right:0;top:32px;background:var(--panel);
 border:1px solid var(--line);border-radius:9px;padding:5px;min-width:220px;z-index:60;
 box-shadow:0 12px 30px #000c}
.drop.on{display:block}
.drop button{display:block;width:100%;text-align:left;background:transparent;
 border:none;padding:7px 10px;border-radius:6px;font-size:12.5px;color:var(--text)}
.drop button:hover{background:var(--hover)}
.drop .sec{font-size:9.5px;text-transform:uppercase;letter-spacing:.09em;
 color:#6c6c7d;font-weight:700;padding:8px 10px 4px}
.sub{color:var(--muted);font-size:12px}
.grow{flex:1}
button{background:var(--panel2);color:var(--text);border:1px solid var(--line);
 border-radius:7px;padding:6px 12px;font-size:13px;cursor:pointer;font-family:inherit}
button:hover{background:var(--hover)}
button.primary{background:var(--accent);color:#06101f;border-color:var(--accent);font-weight:600}
button.danger{border-color:#7f1d1d;color:#fecaca}
button:disabled{opacity:.45;cursor:default}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px;
 margin-bottom:14px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:11px;padding:12px 14px}
.card .n{font-size:24px;font-weight:650;line-height:1.15}
.card .l{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.06em}
.view{display:none}
.view.on{display:block}
/* Canvas views take the full height of main instead of scrolling inside it. */
.view.canvasview.on{display:flex;flex-direction:column;height:100%}
.view.canvasview .panel{flex:1;display:flex;flex-direction:column;min-height:0}
.view.canvasview .stage{flex:1;height:auto;min-height:0}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:11px;padding:14px 16px}
.panel h2{margin:0 0 11px;font-size:13px;text-transform:uppercase;letter-spacing:.07em;
 color:var(--muted);font-weight:600}
.filters{display:flex;gap:7px;flex-wrap:wrap;align-items:center;margin-bottom:11px}
input,select,textarea{background:var(--panel2);color:var(--text);border:1px solid var(--line);
 border-radius:7px;padding:6px 9px;font-size:13px;font-family:inherit}
input[type=search]{min-width:240px}
label.fld{display:block;color:var(--muted);font-size:11px;text-transform:uppercase;
 letter-spacing:.05em;margin:9px 0 3px}
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;color:var(--muted);font-weight:600;font-size:11px;text-transform:uppercase;
 letter-spacing:.05em;padding:8px;border-bottom:1px solid var(--line);position:sticky;
 top:0;background:var(--panel);z-index:2}
td{padding:8px;border-bottom:1px solid #1c1c23;vertical-align:top}
tr.row:hover{background:var(--hover)}
.pill{display:inline-block;padding:2px 8px;border-radius:999px;font-size:11px;
 font-weight:650;text-transform:uppercase;letter-spacing:.04em}

.crit{background:#7f1d1d;color:#fecaca}.high{background:#7c2d12;color:#fed7aa}
.med{background:#713f12;color:#fde68a}.low{background:#1e3a5f;color:#bfdbfe}
.info{background:#334155;color:#cbd5e1}
.sla-breached{background:#7f1d1d;color:#fecaca}.sla-due_soon{background:#713f12;color:#fde68a}
.sla-on_track{background:#14532d;color:#bbf7d0}.sla-closed{background:#334155;color:#cbd5e1}
.sla-no_sla{background:#1f2937;color:#9ca3af}
.tag{display:inline-block;padding:1px 7px;border-radius:5px;background:var(--chip);
 color:var(--muted);font-size:11px;margin:1px 3px 1px 0}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px}
.detail{display:none;background:var(--sunken)}.detail.on{display:table-row}
.detail td{padding:14px 17px 17px}
.dgrid{display:grid;grid-template-columns:1.3fr 1fr;gap:17px}
/* Fixed layout: without it one long threat title collapses every other column,
   which is what made this table unreadable. */
table.fixed{table-layout:fixed}
table.fixed td,table.fixed th{overflow-wrap:anywhere}
.th-stride{width:64px}.th-sev{width:96px}.th-comp{width:23%}
.th-weak{width:15%}.th-tech{width:15%}
.sevcell{white-space:nowrap}
.strides{display:flex;gap:3px;flex-wrap:wrap}
.strides .tag{margin:0}
.acc{cursor:pointer;user-select:none;display:flex;align-items:center;gap:9px}
.acc .caret{transition:transform .15s;color:var(--muted)}
.acc.open .caret{transform:rotate(90deg)}
.accbody{display:none;padding-top:10px}
.accbody.on{display:block}
@media(max-width:1000px){.dgrid{grid-template-columns:1fr}}
pre{background:var(--sunken);border:1px solid var(--line);border-radius:8px;padding:10px 12px;
 overflow:auto;font-size:12px;margin:6px 0 0}
.kv{color:var(--muted);font-size:12px;margin:3px 0}.kv b{color:var(--text)}
.bar{height:7px;border-radius:4px;background:var(--chip);overflow:hidden;margin-top:4px}
.bar>i{display:block;height:100%}
.note{color:var(--muted);font-size:12.5px}
.toast{position:fixed;right:18px;bottom:18px;background:var(--panel2);
 border:1px solid var(--line);border-radius:9px;padding:11px 15px;font-size:13px;
 opacity:0;transition:opacity .2s;pointer-events:none;z-index:50}
.toast.on{opacity:1}
.path{border:1px solid var(--line);border-radius:10px;padding:12px 14px;
 margin-bottom:10px;background:var(--panel2)}
.path ol{margin:7px 0 0 18px;padding:0;color:var(--muted);font-size:13px}
.right{float:right}
.srcpick{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-bottom:13px}
.src{border:1px solid var(--line);border-radius:9px;padding:11px 13px;cursor:pointer;
 background:var(--panel2)}
.src.on{border-color:var(--accent);background:#0d1c30}
.srcform{display:none}.srcform.on{display:block}
.spin{display:inline-block;width:12px;height:12px;border:2px solid var(--muted);
 border-top-color:transparent;border-radius:50%;animation:s .7s linear infinite}
@keyframes s{to{transform:rotate(360deg)}}

__CANVAS_CSS__
</style></head><body>

<header>
  <h1 id="brand" title="ThreatForge · __PROJECT__"><span class="dot"></span>ThreatForge</h1>
  <div class="grow"></div>
  <div class="hbar">
    <button class="ico" id="h-open" title="Open a .tfm model"><svg width="15" height="15" viewBox="0 0 20 20"><path d="M2 5h6l2 2h8v9H2z"/><path d="M2 16l2.5-6h14l-2.5 6z"/></svg><span>Open</span></button>
    <button class="ico" id="h-save" title="Save everything to one .tfm file"><svg width="15" height="15" viewBox="0 0 20 20"><path d="M3 3h11l3 3v11H3z"/><path d="M6 3v5h7V3M6 17v-5h8v5"/></svg><span>Save</span></button>
    <div class="menu">
      <button class="ico" id="h-export" title="Export in another format"><svg width="15" height="15" viewBox="0 0 20 20"><path d="M10 13V3M10 3L6.5 6.5M10 3l3.5 3.5"/><path d="M3 12v5h14v-5"/></svg><span>Export</span><svg width="9" height="9" viewBox="0 0 10 10"><path d="M1 3.5L5 7l4-3.5"/></svg></button>
      <div class="drop" id="exportmenu"></div>
    </div>
    <input type="file" id="h-file" accept=".tfm,.json" style="display:none">
    <span class="vsep"></span>
    <button class="ico sq" id="t-left" title="Hide or show the navigation (Ctrl+B)"><svg width="15" height="15" viewBox="0 0 20 20"><rect x="2.5" y="3.5" width="15" height="13" rx="2"/><path d="M7.5 3.5v13"/><path d="M4 6h2M4 8.5h2M4 11h2" stroke-linecap="round"/></svg></button>
    <button class="ico sq" id="t-right" title="Hide or show the inspector (Ctrl+J)"><svg width="15" height="15" viewBox="0 0 20 20"><rect x="2.5" y="3.5" width="15" height="13" rx="2"/><path d="M12.5 3.5v13"/><path d="M14 6h2M14 8.5h2M14 11h2" stroke-linecap="round"/></svg></button>
  </div>
  <span class="note" id="scanstate" style="margin-left:10px"></span>
</header>

<nav class="side">
  <div class="grp">Analyse</div>
  <div class="nav on" data-v="scan"><svg width="15" height="15" viewBox="0 0 20 20"><path d="M3 3h5M3 3v5M17 3h-5M17 3v5M3 17h5M3 17v-5M17 17h-5M17 17v-5M6 10h8"/></svg><span>Scan</span></div>
  <div class="nav" data-v="findings"><svg width="15" height="15" viewBox="0 0 20 20"><path d="M9 3a6 6 0 104.2 10.2L17 17"/><circle cx="9" cy="9" r="6"/></svg><span>Findings</span>
    <span class="ct" id="n-find">0</span></div>
  <div class="nav" data-v="threats"><svg width="15" height="15" viewBox="0 0 20 20"><path d="M10 2l7 3v5c0 4-3 7-7 8-4-1-7-4-7-8V5z"/><path d="M10 7v4M10 13.5v.5"/></svg><span>Threats</span>
    <span class="ct" id="n-threats">0</span></div>
  <div class="nav" data-v="sla"><svg width="15" height="15" viewBox="0 0 20 20"><circle cx="10" cy="10" r="7.5"/><path d="M10 5.5V10l3 2"/></svg><span>SLA</span>
    <span class="ct" id="n-sla">0</span></div>

  <div class="grp">Model</div>
  <div class="nav" data-v="diagram"><svg width="15" height="15" viewBox="0 0 20 20"><rect x="2" y="3" width="6" height="5" rx="1"/><rect x="12" y="12" width="6" height="5" rx="1"/><path d="M8 5.5h4v9h0"/></svg><span>Diagram</span></div>
  <div class="nav" data-v="editor"><svg width="15" height="15" viewBox="0 0 20 20"><path d="M3 14.5V17h2.5L14 8.5 11.5 6 3 14.5z"/><path d="M11.5 6L14 3.5 16.5 6 14 8.5"/></svg><span>DFD editor</span></div>
  <div class="nav" data-v="paths"><svg width="15" height="15" viewBox="0 0 20 20"><circle cx="4" cy="10" r="2"/><circle cx="16" cy="5" r="2"/><circle cx="16" cy="15" r="2"/><path d="M6 9.4L14 5.6M6 10.6L14 14.4"/></svg><span>Attack paths</span>
    <span class="ct" id="n-paths">0</span></div>

  <div class="nav" data-v="document"><svg width="15" height="15" viewBox="0 0 20 20"><path d="M5 2h7l4 4v12H5z"/><path d="M8 9h6M8 12h6M8 15h4"/></svg><span>Document</span></div>

  <div class="grp">Record</div>
  <div class="nav" data-v="history"><svg width="15" height="15" viewBox="0 0 20 20"><path d="M3 10a7 7 0 107-7 7 7 0 00-5 2M3 3v3h3"/><path d="M10 6v4l3 2"/></svg><span>Scan history</span></div>
  <div style="flex:1"></div>
</nav>

<main id="main">
  <div class="cards" id="cards"></div>

  <!-- ============================ SCAN ============================ -->
  <section class="view on" id="v-scan">
    <div class="panel">
      <h2>Scan a source</h2>
      <div class="note mono" id="curpath" style="margin:-4px 0 11px;word-break:break-all"></div>
      <div class="srcpick">
        <div class="src on" data-s="path"><b>Local folder</b>
          <div class="note">A path on this machine. Trusted — Helm and Kustomize are rendered.</div></div>
        <div class="src" data-s="git"><b>Git repository</b>
          <div class="note">Shallow clone. Untrusted — chart rendering is disabled.</div></div>
        <div class="src" data-s="upload"><b>Upload .zip</b>
          <div class="note">Config files only. Untrusted — chart rendering is disabled.</div></div>
      </div>
      <div class="srcform on" id="f-path">
        <input id="in-path" type="text" style="width:100%" placeholder="C:\Users\you\repos\infra">
        <div class="note" style="margin-top:6px">Full path. PowerShell does not expand
          <span class="mono">~</span>.</div>
      </div>
      <div class="srcform" id="f-git">
        <input id="in-git" type="text" style="width:100%"
               placeholder="owner/repo   or   https://github.com/owner/repo">
        <input id="in-ref" type="text" style="width:220px;margin-top:8px"
               placeholder="branch or tag (optional)">
        <div class="note" style="margin-top:6px" id="githosts"></div>
      </div>
      <div class="srcform" id="f-upload">
        <input id="in-zip" type="file" accept=".zip">
        <div class="note" style="margin-top:6px">Only configuration files are extracted.
          Archives that try to escape the extraction directory are rejected.</div>
      </div>
      <div style="margin-top:13px">
        <button class="primary" id="go">Scan</button>
        <span class="note" id="scanmsg" style="margin-left:10px"></span>
      </div>
      <div id="srcinfo" style="margin-top:13px"></div>
    </div>
    <div class="panel" style="margin-top:14px">
      <h2>Export the current model</h2>
      <div class="note" style="margin-bottom:9px">Includes anything added in the DFD editor.</div>
      <div id="exports"></div>
    </div>
  </section>

  <!-- ========================== FINDINGS ========================== -->
  <section class="view" id="v-findings">
    <div class="panel">
      <div class="filters">
        <input type="search" id="q" placeholder="Search title, component, rule, file…">
        <select id="fLevel"><option value="">All risk</option>
          <option>critical</option><option>high</option><option>medium</option><option>low</option></select>
        <select id="fStatus"><option value="open_only">Open only</option>
          <option value="">All statuses</option></select>
        <select id="fSla"><option value="">Any SLA state</option>
          <option value="breached">Breached</option><option value="due_soon">Due soon</option>
          <option value="on_track">On track</option></select>
        <select id="fOwner"><option value="">Any owner</option>
          <option value="__none__">Unassigned</option></select>
        <span class="note" id="count"></span>
      </div>
      <div style="max-height:64vh;overflow:auto">
        <table><thead><tr>
          <th>Risk</th><th>SLA</th><th>Finding</th><th>Component</th>
          <th>Status</th><th>Owner</th><th>Age</th>
        </tr></thead><tbody id="rows"></tbody></table>
      </div>
    </div>
  </section>

  <!-- ============================ SLA ============================= -->
  <section class="view" id="v-sla">
    <div class="cards" id="slacards"></div>
    <div class="panel" style="margin-top:14px"><h2>Overdue</h2><div id="overdue"></div></div>
    <div class="panel" style="margin-top:14px"><h2>By owner</h2><div id="byowner"></div></div>
    <div class="panel" style="margin-top:14px"><h2>Policy</h2><div id="policy"></div></div>
  </section>

  <!-- =========================== DIAGRAM ========================== -->
  <section class="view canvasview" id="v-diagram">
    <div class="stage">
      <div class="canvaswrap">
        <svg class="cv" id="cv-diagram"></svg>
        <div class="empty" id="d-empty">This canvas is empty.<br>
          Tools &rarr; Load from scan, or drag a component from Stencils.</div>
        <div class="zoombar">
          <button id="d-zin">+</button><button id="d-zout">&minus;</button>
        </div>
      </div>
      __DOCK_DIAGRAM__
      __RAIL_DIAGRAM__
    </div>
    <input type="file" id="d-file" accept=".tfm,.json" style="display:none">
    <input type="file" id="d-import" accept=".tm7,.drawio,.xml,.thf,.yml,.yaml"
           style="display:none">
  </section>

  <!-- =========================== EDITOR =========================== -->
  <section class="view canvasview" id="v-editor">
    <div class="stage">
      <div class="canvaswrap">
        <svg class="cv" id="cv-editor"></svg>
        <div class="empty" id="e-empty">This canvas is empty.<br>
          Drag a component from Stencils, or Tools &rarr; Load from scan.</div>
        <div class="zoombar">
          <button id="e-zin">+</button><button id="e-zout">&minus;</button>
        </div>
      </div>
      __DOCK_EDITOR__
      __RAIL_EDITOR__
    </div>
    <input type="file" id="e-file" accept=".tfm,.json" style="display:none">
    <input type="file" id="e-import" accept=".tm7,.drawio,.xml,.thf,.yml,.yaml"
           style="display:none">
  </section>

  <!-- ========================== THREATS ============================ -->
  <section class="view" id="v-threats">
    <div class="panel">
      <div class="tbar">
        <button class="primary" id="th-run">Run STRIDE analysis</button>
        <button id="th-clear" class="danger">Clear findings</button>
        <select id="th-stride"><option value="">All STRIDE</option>
          <option value="S">S · Spoofing</option><option value="T">T · Tampering</option>
          <option value="R">R · Repudiation</option>
          <option value="I">I · Information disclosure</option>
          <option value="D">D · Denial of service</option>
          <option value="E">E · Elevation of privilege</option></select>
        <select id="th-sev"><option value="">All severities</option>
          <option>critical</option><option>high</option><option>medium</option>
          <option>low</option><option>info</option></select>
        <input type="search" id="th-q" placeholder="Search threat, component, CWE…">
        <div class="grow"></div>
        <span class="note" id="th-count"></span>
      </div>
      <div id="th-cover"></div>
      <div class="note" style="margin-top:9px">Counts are open threats. Info-level
        rows are coverage gaps — questions nobody has answered — not risk.</div>
      <div style="max-height:64vh;overflow:auto;margin-top:12px">
        <table class="fixed"><thead><tr>
          <th class="th-stride">STRIDE</th><th class="th-sev">Severity</th>
          <th>Threat</th><th class="th-comp">Component</th>
          <th class="th-weak">Weakness</th><th class="th-tech">Technique</th>
        </tr></thead><tbody id="th-rows"></tbody></table>
      </div>
    </div>
  </section>

  <!-- ========================= DOCUMENT ============================ -->
  <section class="view" id="v-document">
    <div class="panel">
      <div class="tbar"><b style="font-size:13px">Threat model document</b>
        <div class="grow"></div>
        <span class="note" id="doc-msg"></span>
        <button class="primary" id="doc-save">Save</button></div>
      <div class="dgrid">
        <div><div id="doc-fields"></div></div>
        <div>
          <div class="sect" style="border:none;padding:0;margin:0 0 8px">
            Security questions</div>
          <div class="note" style="margin-bottom:9px">Unanswered questions are
            reported as coverage, not as findings. A reviewer six months from now
            needs to see which questions were asked, not only which failed.</div>
          <div id="doc-questions"></div>
        </div>
      </div>
    </div>
  </section>

  <!-- ========================= ATTACK PATHS ======================== -->
  <section class="view" id="v-paths"><div id="paths"></div></section>

  <!-- =========================== HISTORY =========================== -->
  <section class="view" id="v-history"><div class="panel">
    <h2>Scans</h2><div id="history"></div></div></section>
</main>

<div class="toast" id="toast"></div>

<script>
const TOKEN = "__TOKEN__";
const esc = s => String(s==null?'':s).replace(/[&<>"]/g,c=>
  ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const cls = l => ({critical:'crit',high:'high',medium:'med',low:'low',info:'info'}[l]||'info');
const STRIDE = {S:'Spoofing',T:'Tampering',R:'Repudiation',
  I:'Information Disclosure',D:'Denial of Service',E:'Elevation of Privilege'};
let FIND=[], BOOT={}, SLA={}, GRAPH=null;

async function api(path, body){
  const opt = body
    ? {method:'POST',headers:{'Content-Type':'application/json','X-ThreatForge-Token':TOKEN},
       body:JSON.stringify(body)}
    : {};
  const r = await fetch(path, opt);
  const j = await r.json().catch(()=>({error:r.statusText}));
  if(!r.ok) throw new Error(j.error || r.statusText);
  return j;
}
function toast(m){const t=document.getElementById('toast');t.textContent=m;t.classList.add('on');
  clearTimeout(t._h);t._h=setTimeout(()=>t.classList.remove('on'),2400);}

/* Pane visibility. Remembered across restarts: a reviewer who works with the
   navigation collapsed should not have to collapse it again every morning. */
const PANE = {
  left:  localStorage.getItem('tf.left')  !== '0',
  right: localStorage.getItem('tf.right') !== '0',
};
function applyPanes(){
  document.body.classList.toggle('no-left', !PANE.left);
  document.querySelectorAll('.stage').forEach(s =>
    s.classList.toggle('no-right', !PANE.right));
  const l=document.getElementById('t-left'), r=document.getElementById('t-right');
  if(l) l.classList.toggle('on', !PANE.left);
  if(r) r.classList.toggle('on', !PANE.right);
  // The canvas measures itself from the DOM, so it has to redraw after the
  // grid changes -- otherwise it keeps the old width until the next click.
  setTimeout(()=>{ try{ Diagram.resize(); Editor.resize(); }catch(e){} }, 0);
}
function togglePane(which){
  PANE[which] = !PANE[which];
  localStorage.setItem('tf.'+which, PANE[which] ? '1' : '0');
  applyPanes();
}

const CANVAS_VIEWS = ['diagram','editor'];
document.querySelectorAll('.nav').forEach(t=>t.onclick=()=>{
  document.querySelectorAll('.nav').forEach(x=>x.classList.remove('on'));
  document.querySelectorAll('.view').forEach(x=>x.classList.remove('on'));
  t.classList.add('on');
  document.getElementById('v-'+t.dataset.v).classList.add('on');
  // The diagram wants the whole viewport; the KPI strip is a distraction there
  // and, more to the point, it is 90 pixels of canvas.
  const full = CANVAS_VIEWS.includes(t.dataset.v);
  document.getElementById('main').classList.toggle('full', full);
  document.getElementById('cards').style.display = full ? 'none' : '';
  if(t.dataset.v==='diagram') Diagram.open();
  if(t.dataset.v==='editor')  Editor.open();
  if(t.dataset.v==='paths')   loadPaths();
  if(t.dataset.v==='threats') renderThreats();
  if(t.dataset.v==='document')loadDoc();
  if(t.dataset.v==='sla')     loadSla();
  if(t.dataset.v==='history') renderHistory();
});

__CANVAS_JS__
__LIBRARY_JS__
__PROPS_JS__

/* ---------- graph loading, shared ---------- */
async function fetchGraph(force){
  if(GRAPH && !force) return GRAPH;
  GRAPH = await api('/api/graph');
  return GRAPH;
}
function toCanvasModel(g){
  const nodes = g.elements.map(e=>({
    id:e.id, name:e.name, type:e.type, kind:e.kind, namespace:e.namespace,
    hops:e.hops, blast:e.blast, hand:e.hand, risk:e.risk, findings:e.findings||0,
    zone:e.zone||'internal', desc:e.desc||'',
    data:(e.own_data&&e.own_data.length?e.own_data:e.data)||[],
    tech:e.tech||[], libType:e.lib_type||null,
    attrs:e.attrs||{}, custom:e.custom||{},
    tags:e.tags||[], x:0, y:0,
    w:(DEF[e.type]||DEF.process).w, h:(DEF[e.type]||DEF.process).h}));
  const ids = new Set(nodes.map(n=>n.id));
  const edges = g.flows.filter(f=>ids.has(f.source)&&ids.has(f.target)).map(f=>({
    id:f.id, source:f.source, target:f.target, name:f.name, protocol:f.protocol,
    encrypted:f.encrypted, kind:f.kind, crosses:f.crosses, hand:!!f.hand,
    attrs:f.attrs||{}}));
  // Scanned boundaries arrive as a member list; give them a rectangle so they
  // behave like every other boundary on the canvas.
  const bounds = (g.boundaries||[]).map(b=>({
    id:b.id, name:b.name, trust_level:b.trust_level,
    // A boundary that came back from a scan may still be one the user drew:
    // it was written to the overlay last time and re-ingested. Treating it as
    // scanner-owned would drop it from the next save.
    hand: String(b.id||'').startsWith('boundary:manual:'),
    members:(b.members||[]).filter(m=>ids.has(m)),
    x:0, y:0, w:200, h:140}));
  return {nodes, edges, bounds};
}

/* The action rail. One implementation, two canvases: the read-only diagram
   simply gets the editing verbs disabled rather than a second rail that would
   drift out of step with this one. */
function wireRail(railId, C, opt){
  const rail = document.getElementById(railId);
  if(!rail) return;
  const act = a => rail.querySelector(`[data-act="${a}"]`);
  const off = a => { const b=act(a); if(b){ b.disabled=true; b.style.opacity=.3; } };

  if(!opt.editable) ['new','open','import','duplicate','delete','undo','redo']
    .forEach(off);

  const on=(a,fn)=>{ const b=act(a); if(b) b.onclick=fn; };

  on('stencils', ()=>{ const s=C.svg.closest('.stage');
    s.classList.toggle('no-left'); C.resize(); });
  on('inspector', ()=>{ const s=C.svg.closest('.stage');
    s.classList.toggle('no-right'); C.resize(); });
  on('fit',   ()=>C.fit());
  on('arrange', ()=>{ if(opt.editable) C.push(); C.layout(); });
  on('save',  ()=>location='/api/export/tfm');
  on('tmt',   ()=>location='/api/export/tm7');
  on('report', ()=>location='/api/export/xlsx');
  on('stride', ()=>runStride());

  if(!opt.editable) return;
  on('duplicate', ()=>C.duplicate());
  on('delete',    ()=>C.remove());
  on('undo',      ()=>C.undo());
  on('redo',      ()=>C.redo());
  on('new', async ()=>{
    if(opt.dirty() && !confirm('Start a new diagram? Unsaved changes are lost.')) return;
    if(!confirm('This clears every hand-drawn component and flow. Scanned '
                + 'elements come back on the next scan. Continue?')) return;
    try{
      await api('/api/overlay', {overlay:'', layout:{nodes:{},bounds:{}}, rescan:true});
      GRAPH=null; Diagram.reset(); await loadFindings();
      opt.clean(); await opt.reload(); toast('New diagram');
    }catch(e){ toast('Failed: '+e.message); }
  });

  const fileId=opt.fileId||'e-file', importId=opt.importId||'e-import';
  on('open',   ()=>document.getElementById(fileId).click());
  on('import', ()=>document.getElementById(importId).click());
  document.getElementById(fileId).onchange = async ev=>{
    const f=ev.target.files[0]; if(!f) return; ev.target.value='';
    if(opt.dirty() && !confirm('Opening replaces the current model. Continue?')) return;
    try{
      const r=await api('/api/import',{document:JSON.parse(await f.text())});
      GRAPH=null; await loadFindings();
      opt.clean(); Diagram.markStale(); Editor.markStale();
      await opt.reload();
      toast(`Opened ${f.name} — ${r.restored} decision(s) restored`);
    }catch(e){ toast('Could not open: '+e.message); }
  };
  document.getElementById(importId).onchange = async ev=>{
    const f=ev.target.files[0]; if(!f) return; ev.target.value='';
    try{
      const r=await api('/api/ingest',{name:f.name, text:await f.text()});
      GRAPH=null; await loadFindings();
      opt.clean(); Diagram.markStale(); Editor.markStale();
      await opt.reload();
      toast(`Imported ${r.added} element(s) from ${f.name}`);
    }catch(e){ toast('Could not import: '+e.message); }
  };
}

/* The overlay writer and the canvas key bindings, shared by both canvases.
   The diagram and the editor are the same surface with different furniture, so
   a shape deleted in one has to be deleted the same way in the other. */
/* YAML for a flat map of scalars. Booleans stay bare so they parse as
   booleans; everything else is JSON-quoted, which YAML accepts and which
   removes any question about colons, hashes and leading spaces in values. */
function mapBlock(name, obj, indent){
  const keys = Object.keys(obj||{}).filter(k => obj[k] !== null &&
                                                obj[k] !== undefined &&
                                                obj[k] !== '');
  if(!keys.length) return '';
  const pad = ' '.repeat(indent);
  let out = `${pad}${name}:\n`;
  for(const k of keys){
    const v = obj[k];
    const rendered = (v === true || v === false) ? String(v)
                   : JSON.stringify(String(v));
    out += `${pad}  ${JSON.stringify(String(k))}: ${rendered}\n`;
  }
  return out;
}

function overlayYamlFor(C){
  const q=s=>JSON.stringify(String(s==null?'':s));
  const hn=C.nodes.filter(n=>n.hand), he=C.edges.filter(e=>e.hand);
  const hb=C.bounds.filter(b=>b.hand);
  let y='# Written by the ThreatForge DFD editor. Merged into every scan.\n';
  y+='metadata:\n  title: Hand-authored additions\n';
  if(hn.length){
    y+='components:\n';
    for(const n of hn){
      y+=`  - id: ${q(n.id)}\n    type: ${n.type}\n    name: ${q(n.name)}\n`;
      y+=`    trust_zone: ${n.zone||'internal'}\n`;
      if(n.libType) y+=`    component_type: ${q(n.libType)}\n`;
      if(n.desc) y+=`    description: ${q(n.desc)}\n`;
      if((n.data||[]).length) y+=`    data: [${n.data.map(q).join(', ')}]\n`;
      if((n.tech||[]).length) y+=`    technologies: [${n.tech.map(q).join(', ')}]\n`;
      y+=mapBlock('attributes', n.attrs, 4);
      y+=mapBlock('custom_attributes', n.custom, 4);
    }
  }
  if(he.length){
    y+='flows:\n';
    for(const e of he){
      y+=`  - from: ${q(e.source)}\n    to: ${q(e.target)}\n`;
      if(e.name) y+=`    name: ${q(e.name)}\n`;
      if(e.protocol) y+=`    protocol: ${q(e.protocol)}\n`;
      if(e.encrypted!=null) y+=`    encrypted: ${e.encrypted}\n`;
      y+=mapBlock('attributes', e.attrs, 4);
    }
  }
  if(hb.length){
    y+='trust_boundaries:\n';
    for(const b of hb){
      const inside=C.membersOf(b);
      y+=`  - id: ${q(b.id.replace('boundary:manual:',''))}\n    name: ${q(b.name)}\n`;
      y+=`    trust_level: ${b.trust_level==null?50:b.trust_level}\n`;
      if(inside.length) y+=`    contains: [${inside.map(q).join(', ')}]\n`;
    }
  }
  return y;
}


/* Keyboard, bound to whichever canvas view is on screen. */
function bindCanvasKeys(C, viewId, touched){
  document.addEventListener('keydown', ev=>{
    const view=document.getElementById(viewId);
    if(!view || !view.classList.contains('on')) return;
    if(ev.target.matches('input,textarea,select')) return;
    const mod = ev.ctrlKey||ev.metaKey;
    if(ev.key==='Delete'||ev.key==='Backspace'){ev.preventDefault();C.remove();touched();}
    else if(mod&&ev.key.toLowerCase()==='z'){ev.preventDefault();
      ev.shiftKey?C.redo():C.undo(); touched();}
    else if(mod&&ev.key.toLowerCase()==='y'){ev.preventDefault();C.redo();touched();}
    else if(mod&&ev.key.toLowerCase()==='c'){ev.preventDefault();C.copy();}
    else if(mod&&ev.key.toLowerCase()==='v'){ev.preventDefault();C.paste();touched();}
    else if(mod&&ev.key.toLowerCase()==='d'){ev.preventDefault();C.duplicate();touched();}
    else if(mod&&ev.key.toLowerCase()==='a'){ev.preventDefault();
      C.sel=C.nodes.map(n=>({kind:'node',id:n.id})); C.draw(); C.props();}
    else if(ev.key==='Escape'){C.setMode('select');C.sel=[];C.draw();C.props();}
    else if(ev.key.startsWith('Arrow')){
      const ns=C.selNodes().filter(n=>n.hand);
      if(!ns.length) return;
      ev.preventDefault(); C.push();
      const d=ev.shiftKey?10:1;
      ns.forEach(n=>{
        if(ev.key==='ArrowLeft') n.x-=d; if(ev.key==='ArrowRight') n.x+=d;
        if(ev.key==='ArrowUp')   n.y-=d; if(ev.key==='ArrowDown')  n.y+=d;});
      C.draw(); touched();
    }
  });
}

/* One canvas view, built twice. The diagram and the editor differ only in
   which filters the Tools pane offers; making them two implementations is what
   let delete work in one and not the other. */
function CanvasView(opt){
  const V = {C:null, dirty:false, raw:null, autoload:false};
  const dock = document.getElementById(opt.dockId);
  const pane = sel => dock.querySelector(sel);
  const setMsg = m => { const e=pane('[data-msg]'); if(e) e.innerHTML=m; };

  function touched(){
    V.dirty = true;
    const b = pane('[data-tool="save"]');
    if (b) b.textContent = 'Save & re-scan •';
  }
  function clean(){
    V.dirty = false;
    const b = pane('[data-tool="save"]');
    if (b) b.textContent = 'Save & re-scan';
  }
  function refreshEmpty(){
    const e = document.getElementById(opt.emptyId);
    if (e) e.style.display = (V.C && V.C.nodes.length) ? 'none' : '';
  }

  async function open(){
    if (!V.C) build();
    // Blank on boot: the canvas is yours to draw on, and the scanned model is
    // one click away rather than dumped on top of whatever you were doing.
    //
    // Opening a file is the opposite -- an explicit request for that model --
    // so an import marks the view stale and it loads on arrival. Without this
    // an import appears to do nothing, which is how it first shipped.
    if (V.autoload) { V.autoload = false; await loadFromScan(); return; }
    if (!V.C.nodes.length) { V.C.draw(); V.C.props(); }
    refreshEmpty();
  }

  function build(){
    V.C = Canvas(opt.svgId, opt.dockId + '-props', null, {
      editable: true,
      onChange: () => { touched(); refreshEmpty(); },
      onSelect: () => { bindProps(V.C); renderDockThreats(); },
    });

    dock.querySelectorAll('.dtab').forEach(tab => tab.onclick = () => {
      dock.querySelectorAll('.dtab').forEach(x => x.classList.toggle('on', x === tab));
      dock.querySelectorAll('.dpane').forEach(x =>
        x.classList.toggle('on', x.dataset.dpane === tab.dataset.dtab));
      if (tab.dataset.dtab === 'threats') renderDockThreats();
    });

    dock.querySelectorAll('[data-mode]').forEach(b => b.onclick = () => {
      V.C.setMode(b.dataset.mode);
      dock.querySelectorAll('[data-mode]').forEach(x => x.classList.toggle('on', x === b));
    });

    dock.querySelectorAll('[data-show]').forEach(cb => cb.onchange = () => {
      const key = cb.dataset.show;
      if (key === 'grid')   V.C.showGrid   = cb.checked;
      if (key === 'rulers') V.C.showRulers = cb.checked;
      if (key === 'bounds') V.C.showBounds = cb.checked;
      if (key === 'labels') V.C.showLabels = cb.checked;
      V.C.draw();
    });

    pane('[data-tool="load"]').onclick   = loadFromScan;
    pane('[data-tool="clear"]').onclick  = clearCanvas;
    pane('[data-tool="save"]').onclick   = save;
    pane('[data-tool="discard"]').onclick = async () => {
      if (V.dirty && !confirm('Discard unsaved changes?')) return;
      V.C.nodes = []; V.C.edges = []; V.C.bounds = []; V.C.sel = [];
      clean(); V.C.draw(); V.C.props(); refreshEmpty(); setMsg('Discarded.');
    };

    document.getElementById(opt.zoomInId).onclick  = () => V.C.zoom(1.2);
    document.getElementById(opt.zoomOutId).onclick = () => V.C.zoom(1/1.2);

    // Drop a stencil anywhere on the canvas.
    const svg = document.getElementById(opt.svgId);
    svg.addEventListener('dragover', ev => { ev.preventDefault();
      ev.dataTransfer.dropEffect = 'copy'; });
    svg.addEventListener('drop', ev => {
      ev.preventDefault();
      const s = ev.dataTransfer.getData('text/plain');
      if (!s) return;
      if (s.startsWith('comp:')) {
        const c = (CATALOG.components || []).find(x => x.id === s.slice(5));
        if (!c) return;
        V.C.dropNode(c.element, ev.clientX, ev.clientY);
        const n = V.C.nodes.find(x => x.id === V.C.sel[0].id);
        if (n) { n.name = c.label; n.libType = c.id; n.zone = c.zone;
                 n.data = (c.data||[]).slice(); n.tech = (c.tech||[]).slice();
                 n.attrs = Object.assign({}, c.attrs); }
        V.C.draw(); V.C.props();
      } else {
        V.C.dropNode(s, ev.clientX, ev.clientY);
      }
      touched(); refreshEmpty();
    });

    bindCanvasKeys(V.C, opt.viewId, () => { touched(); refreshEmpty(); });
    wireRail(opt.railId, V.C, {editable:true, reload:open,
      dirty:()=>V.dirty, clean, save, fileId:opt.fileId, importId:opt.importId,
      load:loadFromScan});
    if (opt.filters) opt.filters(dock, V, apply);
  }

  async function loadFromScan(){
    setMsg('<span class="spin"></span> loading…');
    try{
      V.raw = await fetchGraph(true);
      // Fetch the saved layout *before* placing anything. Auto-arranging first
      // and correcting afterwards worked only as long as nothing between the
      // two steps failed quietly; when the layout fetch threw, the whole
      // diagram silently collapsed into one auto-arranged column.
      let saved = null;
      try { saved = (await api('/api/layout')).layout; } catch (e) {}
      apply(saved);
      setMsg(`${V.C.nodes.length} components · ${V.C.edges.length} flows`);
    }catch(e){ setMsg(`<span style="color:var(--crit)">${esc(e.message)}</span>`); }
  }

  function apply(saved){
    if (!V.raw) return;
    if (saved === undefined) saved = V.savedLayout;
    V.savedLayout = saved || null;
    const m = toCanvasModel(V.raw);
    let keep = m.nodes;
    if (opt.filter) keep = opt.filter(dock, m, keep);
    const ids = new Set(keep.map(n => n.id));
    V.C.nodes = keep;
    V.C.edges = m.edges.filter(e => ids.has(e.source) && ids.has(e.target));
    V.C.bounds = m.bounds.map(b => ({...b, members:(b.members||[]).filter(x=>ids.has(x))}))
                         .filter(b => b.members.length > 0);
    V.C.sel = [];

    // A saved position wins. Only components the layout has never seen get
    // arranged automatically, and they are parked to the right of everything
    // else rather than shuffling the diagram somebody laid out by hand.
    const placed = V.C.applyGeometry(saved);
    const loose = V.C.nodes.filter(n => !(saved && (saved.nodes||{})[n.id]));
    if (!placed) {
      V.C.layout();
    } else if (loose.length) {
      const right = Math.max(...V.C.nodes.filter(n => !loose.includes(n))
                                         .map(n => n.x + n.w), 0);
      loose.forEach((n, i) => { n.x = right + 120; n.y = 60 + i * 95; });
    }
    fitBounds(V.C, saved);
    V.C.draw(); V.C.fit(); V.C.props(); refreshEmpty();
  }

  function clearCanvas(){
    if (!confirm('Clear the canvas? Hand-drawn shapes are removed; anything '
               + 'from the scan comes back with Load from scan.')) return;
    V.C.push();
    V.C.nodes = []; V.C.edges = []; V.C.bounds = []; V.C.sel = [];
    V.C.draw(); V.C.props(); touched(); refreshEmpty(); setMsg('Canvas cleared.');
  }

  function renderDockThreats(){
    const box = pane('[data-threats]');
    if (!box) return;
    const id = V.C && V.C.sel.length === 1 ? V.C.sel[0].id : null;
    box.innerHTML = id ? threatsFor(id)
      : '<div class="note">Select a component or a flow to see the threats '
        + 'raised against it.</div>';
  }

  async function save(){
    setMsg('<span class="spin"></span> saving and re-scanning…');
    try{
      const j = await api('/api/overlay',
        {overlay: overlayYamlFor(V.C), layout: V.C.geometry(), rescan:true});
      if ((j.scan||{}).error) throw new Error(j.scan.error);
      await loadFindings(); GRAPH = null; clean();
      const s = (j.scan||{}).summary;
      setMsg(s ? `Saved. ${s.assets} assets, ${s.findings} findings, `
                 + `${s.attack_paths} attack paths.` : 'Saved.');
      toast('Saved');
    }catch(e){ setMsg(`<span style="color:var(--crit)">${esc(e.message)}</span>`); }
  }

  return {open, reset(){ V.C = null; },
          /* Something outside the canvas changed the model on the server. */
          markStale(){ V.autoload = true; },
          load: loadFromScan,
          resize(){ if (V.C) V.C.resize(); },
          apply};
}

/* Give a member-list boundary a rectangle that encloses its members, unless the
   saved layout already has one -- a hand-placed boundary should not be redrawn
   around whatever happens to be inside it today. */
function fitBounds(C, saved){
  const have = (saved && saved.bounds) || {};
  for(const b of C.bounds){
    if (have[b.id]) continue;
    const mem=(b.members||[]).map(id=>C.nodes.find(n=>n.id===id)).filter(Boolean);
    if(!mem.length) continue;
    b.x=Math.min(...mem.map(n=>n.x))-24;
    b.y=Math.min(...mem.map(n=>n.y))-34;
    b.w=Math.max(...mem.map(n=>n.x+n.w))+24-b.x;
    b.h=Math.max(...mem.map(n=>n.y+n.h))+24-b.y;
  }
}

const Diagram = CanvasView({
  svgId:'cv-diagram', dockId:'diagram-dock', railId:'rail-diagram',
  viewId:'v-diagram', emptyId:'d-empty', zoomInId:'d-zin', zoomOutId:'d-zout',
  fileId:'d-file', importId:'d-import',
  filters(dock, V, apply){
    const slot = dock.querySelector('.filters-slot');
    slot.innerHTML = '<div class="sect">Filter</div>'
      + '<select data-dns><option value="">All namespaces</option></select>'
      + '<select data-dfilter><option value="">Everything</option>'
      + '<option value="reachable">Internet-reachable only</option>'
      + '<option value="findings">Only components with findings</option>'
      + '<option value="stores">Data stores and their neighbours</option></select>';
    slot.querySelectorAll('select').forEach(s => s.onchange = apply);
  },
  filter(dock, m, keep){
    const ns = (dock.querySelector('[data-dns]')||{}).value || '';
    const f = (dock.querySelector('[data-dfilter]')||{}).value || '';
    const sel = dock.querySelector('[data-dns]');
    if (sel && sel.options.length <= 1) {
      [...new Set(m.nodes.map(n=>n.namespace).filter(Boolean))].sort()
        .forEach(n => sel.innerHTML += `<option>${esc(n)}</option>`);
    }
    if (ns) keep = keep.filter(n => n.namespace === ns || n.type === 'external_entity');
    if (f === 'reachable') keep = keep.filter(n => n.hops != null);
    if (f === 'findings')  keep = keep.filter(n => n.findings > 0 || n.type === 'external_entity');
    if (f === 'stores') {
      const st = new Set(keep.filter(n => n.type === 'data_store').map(n => n.id));
      const nb = new Set(st);
      m.edges.forEach(e => { if (st.has(e.target)) nb.add(e.source);
                             if (st.has(e.source)) nb.add(e.target); });
      keep = keep.filter(n => nb.has(n.id));
    }
    return keep;
  },
});

const Editor = CanvasView({
  svgId:'cv-editor', dockId:'editor-dock', railId:'rail-editor',
  viewId:'v-editor', emptyId:'e-empty', zoomInId:'e-zin', zoomOutId:'e-zout',
  fileId:'e-file', importId:'e-import',
});


/* ============================ SCAN ============================== */
let SRC='path';
document.querySelectorAll('.src').forEach(el=>el.onclick=()=>{
  document.querySelectorAll('.src').forEach(x=>x.classList.remove('on'));
  document.querySelectorAll('.srcform').forEach(x=>x.classList.remove('on'));
  el.classList.add('on'); SRC=el.dataset.s;
  document.getElementById('f-'+SRC).classList.add('on');
});
const fileToBase64=f=>new Promise((res,rej)=>{const r=new FileReader();
  r.onload=()=>res(String(r.result).split(',')[1]);r.onerror=rej;r.readAsDataURL(f);});

function sourceCard(j){
  const s=j.source||{};
  return `<div class="panel" style="background:var(--panel2)">
    <div class="kv"><b>${esc(s.label||'')}</b> <span class="tag">${esc(s.kind||'')}</span>
      ${j.untrusted?'<span class="pill med">untrusted — chart rendering disabled</span>':''}</div>
    <div class="kv mono">${esc(s.root||'')}</div>
    ${s.url?`<div class="kv">${esc(s.url)} @ ${esc(s.ref||'')}</div>`:''}
    ${s.files?`<div class="kv">${s.files} files extracted, ${s.skipped} skipped</div>`:''}
    <div class="kv">${j.summary.assets} assets · ${j.summary.flows} flows ·
      ${j.summary.attack_paths} attack paths</div>
    ${j.imported_threats?`<div class="kv">${j.imported_threats} threat(s) imported from a
      .tm7 or .drawio, kept as context. They came from a template rather than from
      evidence, so they are not scored as findings.</div>`:''}
    ${(j.warnings||[]).filter(Boolean).map(w=>`<div class="note">• ${esc(w)}</div>`).join('')}
  </div>`;
}

async function doScan(spec){
  const msg=document.getElementById('scanmsg'), btn=document.getElementById('go');
  btn.disabled=true; msg.innerHTML='<span class="spin"></span> scanning…';
  try{
    const j=await api('/api/scan', spec?{source:spec}:{});
    BOOT.source=j.source;
    const brand=document.getElementById('brand');
    if(brand) brand.title=`ThreatForge · ${j.source.label}\n${j.source.root}`;
    const cp=document.getElementById('curpath');
    if(cp) cp.textContent=j.source.label+' · '+j.source.root;
    document.getElementById('srcinfo').innerHTML=sourceCard(j);
    msg.textContent=`${j.summary.findings} findings · ${j.delta.new} new · `
      +`${j.delta.resolved} resolved`;
    await loadFindings(); GRAPH=null; Diagram.reset(); Editor.reset();
    toast('Scan complete');
  }catch(e){ msg.innerHTML=`<span style="color:var(--crit)">${esc(e.message)}</span>`; }
  finally{ btn.disabled=false; }
}
document.getElementById('go').onclick=async()=>{
  if(SRC==='path'){const v=document.getElementById('in-path').value.trim();
    return v?doScan({kind:'path',path:v}):toast('Enter a path');}
  if(SRC==='git'){const u=document.getElementById('in-git').value.trim();
    return u?doScan({kind:'git',url:u,ref:document.getElementById('in-ref').value.trim()})
            :toast('Enter a repository');}
  const f=document.getElementById('in-zip').files[0];
  if(!f) return toast('Choose a .zip');
  document.getElementById('scanmsg').innerHTML='<span class="spin"></span> reading…';
  doScan({kind:'upload',name:f.name.replace(/\.zip$/i,''),data:await fileToBase64(f)});
};

/* ---------------------------- EXPORTS ---------------------------- */
const EXPORT_LABELS={
  xlsx:'Threat register (Excel)', executive:'Executive summary (HTML)',
  html:'Full technical report (HTML)', markdown:'Threat model (Markdown)',
  tfm:'ThreatForge model (.tfm)', tm7:'Microsoft TMT (.tm7)',
  drawio:'draw.io (.drawio)', thf:'Interchange (.thf)',
  json:'Model (JSON)', sarif:'SARIF (for CI)', mermaid:'DFD (Mermaid)'};
const EXPORT_ORDER=['xlsx','executive','html','markdown','tfm','tm7','drawio',
  'thf','json','sarif','mermaid'];
const EXPORT_SHARE=['xlsx','executive','html','markdown'];

function renderExports(){
  const box=document.getElementById('exports');
  if(box) box.innerHTML=(BOOT.exports||[]).map(f=>
    `<button onclick="location='/api/export/${f}'">${EXPORT_LABELS[f]||f}</button>`).join(' ');
  const hosts=document.getElementById('githosts');
  if(hosts) hosts.textContent='Allowed hosts: '+(BOOT.allowed_git_hosts||[]).join(', ');
}
function buildExportMenu(){
  const have=new Set(BOOT.exports||[]);
  const m=document.getElementById('exportmenu');
  m.innerHTML='<div class="sec">Share with stakeholders</div>'
    + EXPORT_ORDER.filter(f=>have.has(f)&&EXPORT_SHARE.includes(f))
        .map(f=>`<button data-x="${f}">${EXPORT_LABELS[f]}</button>`).join('')
    + '<div class="sec">Other tools</div>'
    + EXPORT_ORDER.filter(f=>have.has(f)&&!EXPORT_SHARE.includes(f))
        .map(f=>`<button data-x="${f}">${EXPORT_LABELS[f]}</button>`).join('');
  m.querySelectorAll('[data-x]').forEach(b=>b.onclick=()=>{
    location='/api/export/'+b.dataset.x; m.classList.remove('on'); });
}
document.getElementById('h-export').onclick=ev=>{
  ev.stopPropagation();
  document.getElementById('exportmenu').classList.toggle('on');
};
document.addEventListener('click',()=>
  document.getElementById('exportmenu').classList.remove('on'));
document.getElementById('h-save').onclick=()=>location='/api/export/tfm';
document.getElementById('h-open').onclick=()=>document.getElementById('h-file').click();
document.getElementById('h-file').onchange=async ev=>{
  const f=ev.target.files[0]; if(!f) return;
  ev.target.value='';
  if(!confirm(`Open ${f.name}? This replaces the current model, layout and triage.`)) return;
  try{
    const r=await api('/api/import',{document:JSON.parse(await f.text())});
    GRAPH=null; await loadFindings();
    Diagram.markStale(); Editor.markStale();
    const on=document.querySelector('.nav.on');
    if(on && CANVAS_VIEWS.includes(on.dataset.v)) on.click();
    else document.querySelector('.nav[data-v="editor"]').click();
    toast(`Opened ${f.name} — ${r.restored} decision(s) restored`);
  }catch(err){ toast('Could not open: '+err.message); }
};
document.getElementById('t-left').onclick=()=>togglePane('left');
document.getElementById('t-right').onclick=()=>togglePane('right');
document.addEventListener('keydown', ev=>{
  if(!(ev.ctrlKey||ev.metaKey) || ev.target.matches('input,textarea,select')) return;
  if(ev.key.toLowerCase()==='b'){ ev.preventDefault(); togglePane('left'); }
  if(ev.key.toLowerCase()==='j'){ ev.preventDefault(); togglePane('right'); }
});

/* Re-scanning is reachable from the Scan view and from Run STRIDE analysis on
   the canvas rail. There is no separate button for it in the navigation. */
async function rescanNow(){
  const state=document.getElementById('scanstate');
  if(state) state.innerHTML='<span class="spin"></span> scanning';
  try{
    const j=await api('/api/scan',{});
    await loadFindings(); GRAPH=null; Diagram.reset(); Editor.reset();
    if(state) state.textContent =
      `${j.delta.new} new · ${j.delta.resolved} resolved · ${j.delta.reopened} reopened`;
    toast('Scan complete');
  }catch(e){
    if(state) state.textContent='';
    toast('Scan failed: '+e.message);
  }
}

/* ---------------------------- FINDINGS --------------------------- */
async function loadFindings(){
  FIND=(await api('/api/findings')).findings;
  renderCards(); renderRows();
  if(document.getElementById('v-threats').classList.contains('on')) renderThreats();
}
function renderCards(){
  const closed=['resolved','accepted','false_positive','suppressed'];
  const open=FIND.filter(f=>!closed.includes(f.status));
  const n=l=>open.filter(f=>f.risk_level===l).length;
  const br=open.filter(f=>f.sla.breached).length;
  const set=(id,v)=>{const e=document.getElementById(id); if(e) e.textContent=v;};
  set('n-find', open.length); set('n-sla', br); set('n-threats', open.length);
  document.getElementById('cards').innerHTML=[
    ['Critical',n('critical'),'var(--crit)'],['High',n('high'),'var(--high)'],
    ['Medium',n('medium'),'var(--med)'],['Low',n('low'),'var(--low)'],
    ['SLA breached',br,br?'var(--crit)':'var(--ok)'],
    ['Unassigned',open.filter(f=>!f.owner).length,'var(--muted)'],
    ['Resolved',FIND.length-open.length,'var(--ok)']
  ].map(([l,v,c])=>`<div class="card"><div class="n" style="color:${c}">${v}</div>
    <div class="l">${l}</div></div>`).join('');
}
function visible(){
  const q=document.getElementById('q').value.toLowerCase();
  const lv=document.getElementById('fLevel').value, st=document.getElementById('fStatus').value;
  const sl=document.getElementById('fSla').value, ow=document.getElementById('fOwner').value;
  const closed=['resolved','accepted','false_positive','suppressed'];
  return FIND.filter(f=>{
    if(st==='open_only'&&closed.includes(f.status))return false;
    if(lv&&f.risk_level!==lv)return false;
    if(sl&&f.sla.state!==sl)return false;
    if(ow==='__none__'&&f.owner)return false;
    if(ow&&ow!=='__none__'&&f.owner!==ow)return false;
    if(q&&!(f.title+' '+f.component+' '+f.rule_id+' '+(f.evidence_file||''))
        .toLowerCase().includes(q))return false;
    return true;});
}
function renderRows(){
  const list=visible();
  document.getElementById('count').textContent=`${list.length} of ${FIND.length}`;
  document.getElementById('rows').innerHTML=list.map((f,i)=>{
    const s=f.sla;
    const loc=f.evidence_file?`${esc(f.evidence_file)}${f.evidence_line?':'+f.evidence_line:''}`:'—';
    const days=s.days_remaining==null?'—':(s.days_remaining<0?`${-s.days_remaining}d over`
                                                             :`${s.days_remaining}d left`);
    return `<tr class="row" data-i="${i}">
      <td><span class="pill ${cls(f.risk_level)}">${f.risk_score}</span></td>
      <td><span class="pill sla-${s.state}">${s.state.replace('_',' ')}</span>
          <div class="note">${days}</div></td>
      <td><b>${esc(f.title)}</b><div class="note mono">${f.rule_id} · ${loc}</div></td>
      <td class="mono">${esc(f.component)}</td>
      <td><select class="js-status" data-id="${f.id}">${
        BOOT.statuses.map(x=>`<option ${x===f.status?'selected':''}>${x}</option>`).join('')}</select></td>
      <td><input class="js-owner" data-id="${f.id}" style="width:118px"
            value="${esc(f.owner||'')}" placeholder="unassigned"></td>
      <td class="note">${s.age_days==null?'—':s.age_days+'d'}</td></tr>
      <tr class="detail" id="d${i}"><td colspan="7">${detail(f)}</td></tr>`;
  }).join('')||'<tr><td colspan="7" class="note">Nothing matches.</td></tr>';
  document.querySelectorAll('#rows tr.row').forEach(tr=>tr.onclick=e=>{
    if(e.target.closest('select,input,button,textarea'))return;
    document.getElementById('d'+tr.dataset.i).classList.toggle('on');});
  document.querySelectorAll('.js-status').forEach(el=>el.onchange=e=>
    saveFinding(e.target.dataset.id,{status:e.target.value}));
  document.querySelectorAll('.js-owner').forEach(el=>el.onchange=e=>
    saveFinding(e.target.dataset.id,{owner:e.target.value}));
  document.querySelectorAll('.js-note').forEach(el=>el.onclick=e=>
    saveFinding(e.target.dataset.id,
      {notes:document.getElementById('note-'+e.target.dataset.id).value}));
}
function detail(f){
  const refs=Object.entries(f.references||{}).filter(([,v])=>v&&v.length)
    .map(([k,v])=>`<div class="kv"><b>${k.toUpperCase()}</b> ${esc(v.join(', '))}</div>`).join('');
  return `<div class="dgrid"><div>
    <div class="note" style="margin-bottom:8px">${esc(f.description)}</div>
    <div class="kv"><b>Evidence</b> <span class="mono">${esc(f.evidence_file||'—')}${
      f.evidence_line?':'+f.evidence_line:''}</span></div>
    <div class="kv"><b>STRIDE</b> ${(f.stride||'').split(',').filter(Boolean)
      .map(s=>`<span class="tag" title="${STRIDE[s]||''}">${s} — ${STRIDE[s]||''}</span>`).join('')}</div>
    <div class="kv"><b>Confidence</b> ${esc(f.confidence)}</div>${refs}
    ${f.remediation?`<div class="kv" style="margin-top:8px"><b>Remediation</b></div>
      <div class="note">${esc(f.remediation)}</div>`:''}
  </div><div>
    <div class="kv"><b>First seen</b> ${esc((f.first_seen||'').slice(0,10))} ·
      <b>Last seen</b> ${esc((f.last_seen||'').slice(0,10))}</div>
    <div class="kv"><b>Due</b> ${esc(f.sla.due_date||'no SLA')} · <b>${esc(f.sla.state)}</b></div>
    <label class="fld">Notes</label>
    <textarea id="note-${f.id}" rows="3" style="width:100%">${esc(f.notes||'')}</textarea>
    <button class="js-note" data-id="${f.id}" style="margin-top:6px">Save note</button>
    <div class="kv mono note" style="margin-top:9px">${f.id}</div></div></div>`;
}
async function saveFinding(id,patch){
  try{ const j=await api('/api/findings/'+encodeURIComponent(id),patch);
    const i=FIND.findIndex(x=>x.id===id); if(i>=0&&j.finding)FIND[i]=j.finding;
    renderCards(); toast('Saved');
  }catch(e){ toast('Failed: '+e.message); }
}
['q','fLevel','fStatus','fSla','fOwner'].forEach(id=>{
  const el=document.getElementById(id);
  if(el) el.addEventListener('input',renderRows);
});

/* ------------------------------ SLA ------------------------------ */
async function loadSla(){
  SLA=await api('/api/sla'); const b=SLA.buckets;
  document.getElementById('slacards').innerHTML=[
    ['Compliance',SLA.compliance_pct+'%',SLA.compliance_pct>=90?'var(--ok)':'var(--high)'],
    ['Breached',SLA.breached,SLA.breached?'var(--crit)':'var(--ok)'],
    ['Due soon',b.due_soon,'var(--med)'],['On track',b.on_track,'var(--ok)'],
    ['Open',SLA.open,'var(--text)'],
    ['Median fix',SLA.median_resolution_days==null?'—':SLA.median_resolution_days+'d','var(--text)']
  ].map(([l,v,c])=>`<div class="card"><div class="n" style="color:${c}">${v}</div>
    <div class="l">${l}</div></div>`).join('');
  document.getElementById('overdue').innerHTML=SLA.overdue.length
    ? `<table><thead><tr><th>Days over</th><th>Risk</th><th>Finding</th><th>Component</th>
       <th>Owner</th><th>Due</th></tr></thead><tbody>`+SLA.overdue.map(o=>
      `<tr><td><span class="pill crit">${o.days_overdue}</span></td>
       <td><span class="pill ${cls(o.risk_level)}">${o.risk_level}</span></td>
       <td>${esc(o.title)}<div class="note mono">${o.rule_id}</div></td>
       <td class="mono">${esc(o.component)}</td><td>${esc(o.owner)}</td>
       <td class="note">${esc(o.due_date||'—')}</td></tr>`).join('')+'</tbody></table>'
    : '<div class="note">Nothing overdue.</div>';
  document.getElementById('byowner').innerHTML=Object.entries(SLA.by_owner).length
    ? Object.entries(SLA.by_owner).map(([o,v])=>{
        const pct=v.open?Math.round(100*(v.open-v.breached)/v.open):100;
        return `<div class="kv"><b>${esc(o)}</b> — ${v.open} open, ${v.breached} breached,
          ${v.closed} closed <span class="right">${pct}%</span>
          <div class="bar"><i style="width:${pct}%;background:${
            v.breached?'var(--crit)':'var(--ok)'}"></i></div></div>`;}).join('')
    : '<div class="note">No findings yet.</div>';
  document.getElementById('policy').innerHTML =
    `<div class="note" style="margin-bottom:7px">Days from <b>first seen</b> to remediation.</div>`+
    Object.entries(SLA.policy).map(([k,v])=>
      `<span class="tag">${k}: ${v==null?'no SLA':v+' days'}</span>`).join('');
}

/* -------------------------- ATTACK PATHS ------------------------- */
async function loadPaths(){
  let j; try{ j=await api('/api/dfd'); }
  catch(e){ document.getElementById('paths').innerHTML=
    '<div class="panel note">Run a scan first.</div>'; return; }
  const np=document.getElementById('n-paths');
  if(np) np.textContent=j.attack_paths.length;
  if(!j.attack_paths.length){
    document.getElementById('paths').innerHTML =
      '<div class="panel note">No complete attack path found. A path needs an '
      + 'external entry point, a reachable component, and a finding that lets '
      + 'an attacker move on from it.</div>';
    return;
  }
  document.getElementById('paths').innerHTML = j.attack_paths.map((p,i)=>`
    <div class="panel" style="margin-bottom:10px">
      <div class="acc" data-acc="${i}">
        <span class="caret">▶</span>
        <span class="pill ${cls(p.level)}">score ${p.score}</span>
        <b>${esc(p.hop_labels[0])} → ${esc(p.hop_labels[p.hop_labels.length-1])}</b>
        <span class="note">${p.length} hops · ${p.findings.length} enabling
          finding${p.findings.length===1?'':'s'}</span>
        <div class="grow"></div><span class="note">click to expand</span>
      </div>
      <div class="accbody" id="acc-${i}">${attackTree(p, i)}</div>
    </div>`).join('')
    + `<div class="note" style="margin-top:6px"><button id="acc-all">Expand all</button></div>`;
  document.querySelectorAll('[data-acc]').forEach(h=>h.onclick=()=>{
    h.classList.toggle('open');
    document.getElementById('acc-'+h.dataset.acc).classList.toggle('on');
  });
  document.getElementById('acc-all').onclick=ev=>{
    const open=ev.target.textContent==='Expand all';
    document.querySelectorAll('[data-acc]').forEach(h=>{
      h.classList.toggle('open', open);
      document.getElementById('acc-'+h.dataset.acc).classList.toggle('on', open);
    });
    ev.target.textContent = open ? 'Collapse all' : 'Expand all';
  };
}

/* An attack tree, not a bullet list. The goal sits at the root and each hop is
   the precondition for the one above it, which is the direction an attacker
   reasons in -- and it makes the cheapest branch to cut obvious. */
function attackTree(p, idx){
  const W=250, H=54, GAP=30;
  const hops=p.hop_labels.slice().reverse();
  const notes=(p.narrative||[]).slice().reverse();
  const height=hops.length*(H+GAP);
  let s=`<svg viewBox="0 0 ${W+430} ${height}" style="width:100%;height:${height}px">
    <defs><marker id="atk${idx}" viewBox="0 0 10 10" refX="9" refY="5"
      markerWidth="7" markerHeight="7" orient="auto">
      <path d="M0,0 L10,5 L0,10 z" fill="#ef4444"/></marker></defs>`;
  hops.forEach((label,i)=>{
    const y=i*(H+GAP), goal=i===0;
    const fill=goal?'#7f1d1d':'#101017', stroke=goal?'#ef4444':'#4f9cf9';
    s+=`<rect x="10" y="${y}" width="${W}" height="${H}" rx="7"
          fill="${fill}" stroke="${stroke}" stroke-width="2"/>
        <text x="22" y="${y+21}" style="font-size:12px;fill:#e9e9ef">
          ${esc(goal?'GOAL':'step '+(hops.length-i-1))}</text>
        <text x="22" y="${y+38}" style="font-size:11px;fill:#8b8b9a">
          ${esc(String(label).slice(0,32))}</text>`;
    if(notes[i]) s+=`<text x="${W+26}" y="${y+24}"
        style="font-size:11px;fill:#9a9aab">${esc(String(notes[i]).slice(0,62))}</text>`;
    if(i<hops.length-1){
      const y2=(i+1)*(H+GAP);
      s+=`<path d="M${10+W/2},${y2} L${10+W/2},${y+H+6}"
            stroke="#ef4444" stroke-width="1.6" marker-end="url(#atk${idx})"/>
          <text x="${18+W/2}" y="${y+H+22}" style="font-size:10px;fill:#8b8b9a">
            requires</text>`;
    }
  });
  s+='</svg>';
  if((p.findings||[]).length){
    s+=`<div class="note" style="margin-top:6px">Cut any one of these and the
      path breaks: ${p.findings.slice(0,6).map(f=>
        `<span class="tag mono">${esc(f)}</span>`).join('')}</div>`;
  }
  return s;
}

/* --------------------------- SCAN HISTORY ------------------------ */
function renderHistory(){
  const s=BOOT.scans||[];
  document.getElementById('history').innerHTML=s.length
    ? `<table><thead><tr><th>When</th><th>Findings</th><th>Critical</th><th>High</th>
       <th>Assets</th><th>Flows</th><th>Paths</th></tr></thead><tbody>`+s.map(x=>
      `<tr><td class="mono">${esc((x.started_at||'').replace('T',' ').slice(0,16))}</td>
       <td>${x.findings}</td><td><span class="pill crit">${x.critical}</span></td>
       <td><span class="pill high">${x.high}</span></td><td>${x.assets}</td>
       <td>${x.flows}</td><td>${x.attack_paths}</td></tr>`).join('')+'</tbody></table>'
    : '<div class="note">No scans recorded yet.</div>';
}

/* ------------------------------ BOOT ----------------------------- */
async function boot(){
  BOOT=await api('/api/bootstrap');
  await loadCatalog();
  const own=document.getElementById('fOwner');
  (BOOT.owners||[]).forEach(o=>own.innerHTML+=`<option>${esc(o)}</option>`);
  const inPath=document.getElementById('in-path');
  if(inPath) inPath.value = BOOT.source?BOOT.source.root:BOOT.base_root;
  const cp=document.getElementById('curpath');
  if(cp && BOOT.source) cp.textContent=BOOT.source.label+' · '+BOOT.source.root;
  renderExports(); buildExportMenu(); applyPanes();
  // The build fingerprint is off the chrome now. It still rides on every API
  // response as X-ThreatForge-Build, is served at /api/version, and is printed
  // at start-up -- so a stale page is still answerable, just not on screen.
  const brandEl=document.getElementById('brand');
  if(brandEl) brandEl.title =
    `ThreatForge · build ${BOOT.build||'?'}\n`
    + (BOOT.source ? `${BOOT.source.label}\n${BOOT.source.root}` : '');
  await loadFindings();
}

/* ---------------------------- THREATS ----------------------------
   The same findings the scanner produced, arranged the way a threat model is
   read: by STRIDE category, with the weakness and technique each one maps to.
   Nothing new is invented here -- if a threat has no CWE it is shown without
   one rather than given a plausible-looking guess. */
const STRIDE_FULL = {S:'Spoofing', T:'Tampering', R:'Repudiation',
  I:'Information disclosure', D:'Denial of service', E:'Elevation of privilege'};

function threatRows(){
  const st=document.getElementById('th-stride').value;
  const sv=document.getElementById('th-sev').value;
  const q=(document.getElementById('th-q').value||'').toLowerCase();
  const closed=['resolved','accepted','false_positive','suppressed'];
  return FIND.filter(f=>{
    if(closed.includes(f.status)) return false;
    if(st && !(f.stride||'').includes(st)) return false;
    if(sv && f.risk_level!==sv) return false;
    if(q){
      const hay=[f.title,f.component,f.rule_id,
        JSON.stringify(f.references||{})].join(' ').toLowerCase();
      if(!hay.includes(q)) return false;
    }
    return true;
  });
}

function renderThreats(){
  const rows=threatRows();
  const order={critical:0,high:1,medium:2,low:3,info:4};
  rows.sort((a,b)=>order[a.risk_level]-order[b.risk_level]);
  document.getElementById('th-count').textContent =
    `${rows.length} threat${rows.length===1?'':'s'}`;
  const nt=document.getElementById('n-threats');
  if(nt) nt.textContent=rows.length;

  // STRIDE coverage: which letters this model has actually reasoned about.
  const per={};
  for(const k of Object.keys(STRIDE_FULL)) per[k]=0;
  FIND.forEach(f=>(f.stride||'').split(',').filter(Boolean)
    .forEach(s=>{ if(per[s]!=null) per[s]++; }));
  document.getElementById('th-cover').innerHTML =
    '<div class="cards">' + Object.entries(STRIDE_FULL).map(([k,v])=>
      `<div class="card"><div class="n" style="color:${per[k]?'var(--text)':'var(--muted)'}">
        ${per[k]}</div><div class="l">${k} · ${esc(v)}</div></div>`).join('') + '</div>';

  const ref=(f,k)=>((f.references||{})[k]||[]).join(', ');
  document.getElementById('th-rows').innerHTML = rows.map(f=>`
    <tr class="row">
      <td><div class="strides">${(f.stride||'').split(',').filter(Boolean).map(s=>
        `<span class="tag" title="${esc(STRIDE_FULL[s]||'')}">${esc(s)}</span>`).join('')
        || '<span class="note">—</span>'}</div></td>
      <td class="sevcell"><span class="pill ${cls(f.risk_level)}">${f.risk_level}</span>
        <div class="note">${f.risk_score}/25</div></td>
      <td><b>${esc(f.title)}</b>
        <div class="note mono">${esc(f.rule_id)}</div></td>
      <td class="mono">${esc(f.component)}</td>
      <td class="note">${esc(ref(f,'cwe')||'—')}
        ${ref(f,'owasp')?`<div>${esc(ref(f,'owasp'))}</div>`:''}</td>
      <td class="note">${esc(ref(f,'mitre')||'—')}
        ${ref(f,'nist')?`<div>${esc(ref(f,'nist'))}</div>`:''}</td>
    </tr>`).join('') ||
    '<tr><td colspan="6" class="note">No threats match. Run a scan, or answer '
    + 'design attributes in the DFD editor so the design rules can decide.</td></tr>';
}
['th-stride','th-sev','th-q'].forEach(id=>{
  const el=document.getElementById(id);
  if(el) el.addEventListener('input', renderThreats);
});

async function runStride(){
  const btn=document.getElementById('th-run');
  document.querySelector('.nav[data-v="threats"]').click();
  if(btn){ btn.disabled=true; btn.textContent='Analysing…'; }
  try{
    // Reset first, so the result is the threats this model has now rather than
    // an accumulation across every run since the store was created.
    const j=(await api('/api/reset',{rescan:true})).scan;
    await loadFindings(); GRAPH=null; Diagram.reset(); renderThreats();
    toast(`${j.summary.findings} threats · ${j.delta.new} new`);
  }catch(e){ toast('Analysis failed: '+e.message); }
  finally{ if(btn){ btn.disabled=false; btn.textContent='Run STRIDE analysis'; } }
}
const thRun=document.getElementById('th-run');
if(thRun) thRun.onclick=runStride;

/* Clearing is destructive and total: every finding, scan and audit event. The
   diagram, overlay and document survive -- this removes what the analysis
   produced, not what you drew. */
const thClear=document.getElementById('th-clear');
if(thClear) thClear.onclick=async()=>{
  if(!confirm('Delete every finding, scan and audit event?\n\n'
    + 'Owners, statuses and notes go with them. The diagram, overlay and '
    + 'document are kept. This cannot be undone.')) return;
  thClear.disabled=true;
  try{
    const r=await api('/api/reset',{});
    await loadFindings(); GRAPH=null; Diagram.reset(); Editor.reset();
    renderThreats();
    toast(`Cleared ${r.cleared.findings} findings and ${r.cleared.scans} scans`);
  }catch(e){ toast('Could not clear: '+e.message); }
  finally{ thClear.disabled=false; }
};

/* --------------------------- DOCUMENT ---------------------------- */
let DOC={fields:{},answers:{}};
async function loadDoc(){
  try{ DOC=(await api('/api/doc')).doc || {fields:{},answers:{}}; }catch(e){}
  DOC.fields=DOC.fields||{}; DOC.answers=DOC.answers||{};
  document.getElementById('doc-fields').innerHTML =
    (CATALOG.doc_fields||[]).map(f=>`
      <label class="fld">${esc(f.label)}</label>
      ${f.kind==='textarea'
        ? `<textarea data-doc="${esc(f.key)}" rows="3" style="width:100%"
             placeholder="${esc(f.hint||'')}">${esc(DOC.fields[f.key]||'')}</textarea>`
        : `<input data-doc="${esc(f.key)}" style="width:100%"
             placeholder="${esc(f.hint||'')}" value="${esc(DOC.fields[f.key]||'')}">`}
    `).join('');
  document.getElementById('doc-questions').innerHTML =
    (CATALOG.security_questions||[]).map(q=>{
      const a=DOC.answers[q.id]||'';
      return `<div class="tcard">
        <div><span class="tag" title="${esc(STRIDE_FULL[q.stride]||'')}">${esc(q.stride)}</span>
          <b style="margin-left:5px">${esc(q.q)}</b></div>
        <textarea data-ans="${esc(q.id)}" rows="2" style="width:100%;margin-top:6px"
          placeholder="${a?'':'Unanswered'}">${esc(a)}</textarea></div>`;
    }).join('');
  document.querySelectorAll('[data-doc]').forEach(el=>
    el.oninput=()=>{ DOC.fields[el.dataset.doc]=el.value; });
  document.querySelectorAll('[data-ans]').forEach(el=>
    el.oninput=()=>{ DOC.answers[el.dataset.ans]=el.value; });
  const open=(CATALOG.security_questions||[])
    .filter(q=>!(DOC.answers[q.id]||'').trim()).length;
  document.getElementById('doc-msg').textContent =
    open ? `${open} question(s) unanswered` : 'All questions answered';
}
const docSave=document.getElementById('doc-save');
if(docSave) docSave.onclick=async()=>{
  try{ await api('/api/doc',{doc:DOC}); toast('Document saved'); loadDoc(); }
  catch(e){ toast('Save failed: '+e.message); }
};

boot().catch(e=>toast('Failed to load: '+e.message));
</script>
</body></html>
"""

PAGE = (_PAGE_TEMPLATE
        .replace("__CANVAS_CSS__", CANVAS_CSS)
        .replace("__CANVAS_JS__", CANVAS_JS)
        .replace("__LIBRARY_JS__", LIBRARY_JS)
        .replace("__PROPS_JS__", PROPS_JS)
        .replace("__DOCK_EDITOR__", DOCK_HTML.replace("__ID__", "editor"))
        .replace("__DOCK_DIAGRAM__", DOCK_HTML.replace("__ID__", "diagram"))
        .replace("__RAIL_EDITOR__", RAIL_HTML.replace("__ID__", "rail-editor"))
        .replace("__RAIL_DIAGRAM__", RAIL_HTML.replace("__ID__", "rail-diagram")))
