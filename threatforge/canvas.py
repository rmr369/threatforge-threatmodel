# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""
The diagramming surface.

Split out of `webui.py` because it is a real editor rather than a picture: a
shape palette, snap-to-grid, resize handles, rubber-band selection, orthogonal
connector routing, and trust boundaries you draw as rectangles instead of
declaring as a member list.

Two design decisions are worth stating because they are not obvious:

**Geometry is not part of the model.** Where a box sits is stored separately in
`layout.json` and merged in on load. If position lived in the overlay YAML,
nudging a shape would show up as a change to the threat model, and the review
of a real change would drown in coordinates.

**Boundary membership is geometric.** A component is inside a trust boundary
because it is drawn inside the rectangle, exactly as Microsoft TMT and draw.io
behave. Containment is recomputed on every save, so dragging a service into the
DMZ changes the analysis without anyone editing a list.

The read-only Diagram tab and the editable DFD editor are the same code with
`editable` off. Two renderers would drift, and the picture you review has to be
the picture you edited.
"""

CANVAS_CSS = r"""
/* Canvas, dock, rail. Everything that is not the drawing lives in the dock,
   so the diagram gets the whole area rather than what a toolbar leaves behind. */
.stage{display:grid;grid-template-columns:1fr 340px 44px;gap:8px;
 height:100%;min-height:0}
.stage.no-right{grid-template-columns:1fr 44px}
.stage.no-right>.dock{display:none}
@media(max-width:1100px){.stage{grid-template-columns:1fr 44px}}

.dock{background:var(--panel2);border:1px solid var(--line);border-radius:10px;
 display:flex;flex-direction:column;min-height:0;overflow:hidden}
.dock .dtabs{display:flex;gap:2px;padding:6px 6px 0;border-bottom:1px solid var(--line)}
.dock .dtab{flex:1;text-align:center;font-size:11.5px;padding:6px 4px;cursor:pointer;
 border-radius:7px 7px 0 0;color:var(--muted);white-space:nowrap}
.dock .dtab:hover{background:var(--hover);color:var(--text)}
.dock .dtab.on{background:var(--accent);color:#04223f;font-weight:600}
.dock .dbody{flex:1;min-height:0;overflow:auto;padding:11px 12px}
.dock .dpane{display:none}.dock .dpane.on{display:block}
.dock .row{display:flex;gap:5px;flex-wrap:wrap;margin-bottom:8px}
.dock .row button{flex:1;min-width:70px}
.dock .row button.on{background:var(--accent);color:#04223f;border-color:var(--accent);
 font-weight:600}
.dock label.chk{display:flex;align-items:center;gap:7px;font-size:12.5px;
 color:var(--muted);margin-bottom:5px}
.dock label.chk input{width:auto}
.dock .lg{font-size:11px;color:var(--muted);line-height:1.9;margin-top:4px}
.dock .lg i{display:inline-block;width:9px;height:9px;border-radius:2px;margin-right:5px}
.dock select{width:100%;margin-bottom:6px}

/* Stencil library, now a dock pane rather than its own column. */
.palette{display:flex;flex-direction:column;min-height:0}
.palette h3{margin:9px 0 5px;font-size:10px;text-transform:uppercase;
 letter-spacing:.07em;color:var(--muted);font-weight:600}
.palette h3:first-child{margin-top:0}
.plist{margin:0 -3px;padding:0 3px}
.pcats{display:flex;flex-wrap:wrap;gap:3px;margin:7px 0}
.pcat{font-size:10.5px;padding:2px 7px;border-radius:20px;border:1px solid var(--line);
 background:#1414194d;cursor:pointer;color:var(--muted)}
.pcat.on{background:var(--accent);color:#04223f;border-color:var(--accent);font-weight:600}
.pitem{display:flex;align-items:center;gap:8px;padding:6px 7px;margin-bottom:4px;
 border:1px solid transparent;border-radius:7px;cursor:grab;
 font-size:12px;user-select:none}
.pitem:hover{background:var(--hover);border-color:var(--accent)}
.pitem:active{cursor:grabbing}
.pitem svg{flex:none;stroke:var(--muted);fill:none;stroke-width:1.4}
.pitem:hover svg{stroke:var(--accent)}
.pitem .pl{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}

.canvaswrap{background:var(--sunken);border:1px solid var(--line);border-radius:10px;
 position:relative;overflow:hidden}
svg.cv{display:block;width:100%;height:100%;min-height:520px;cursor:grab;
 touch-action:none}
svg.cv.marquee-tool{cursor:default}
svg.cv.panning{cursor:grabbing}
svg.cv.connect,svg.cv.drawing{cursor:crosshair}
.zoombar{position:absolute;right:10px;top:10px;display:flex;gap:4px}
.zoombar button{padding:3px 9px;font-size:12px;background:#000000cc}
.empty{position:absolute;inset:0;display:flex;align-items:center;
 justify-content:center;pointer-events:none;color:#4a4a58;font-size:13px;
 text-align:center;line-height:1.9}

/* Action rail: the verbs, always in the same place. */
.rail{background:var(--panel2);border:1px solid var(--line);border-radius:10px;
 padding:5px 4px;display:flex;flex-direction:column;gap:3px;align-items:center;
 overflow:auto}
.rail button{width:34px;height:32px;padding:0;display:flex;align-items:center;
 justify-content:center;background:transparent;border:1px solid transparent;
 color:var(--muted)}
.rail button:hover{background:var(--hover);color:var(--text);border-color:var(--line)}
.rail button.on{background:var(--accent);color:#04223f;border-color:var(--accent)}
.rail button.danger{color:#e88}
.rail button.go{background:var(--accent);color:#04223f;border-color:var(--accent)}
.rail button svg{stroke:currentColor;fill:none;stroke-width:1.6}
.rail .rsep{width:22px;height:1px;background:var(--line);margin:4px 0}
.palette{background:var(--panel2);border:1px solid var(--line);border-radius:10px;
 padding:9px;display:flex;flex-direction:column;min-height:0;overflow:hidden}
.palette .plist{flex:1 1 auto}
.palette h3{margin:8px 0 6px;font-size:10px;text-transform:uppercase;
 letter-spacing:.07em;color:var(--muted);font-weight:600}
.palette h3:first-child{margin-top:0}
.plist{overflow:auto;flex:1;min-height:0;margin:0 -3px;padding:0 3px}
.pcats{display:flex;flex-wrap:wrap;gap:3px;margin-bottom:7px}
.pcat{font-size:10.5px;padding:2px 7px;border-radius:20px;border:1px solid var(--line);
 background:#1414194d;cursor:pointer;color:var(--muted)}
.pcat.on{background:var(--accent);color:#06101f;border-color:var(--accent);font-weight:600}
.pitem{display:flex;align-items:center;gap:8px;padding:6px 7px;margin-bottom:4px;
 border:1px solid transparent;border-radius:7px;cursor:grab;
 font-size:12px;user-select:none}
.pitem:hover{background:var(--hover);border-color:var(--accent)}
.pitem:active{cursor:grabbing}
.pitem svg{flex:none;stroke:var(--muted);fill:none;stroke-width:1.4}
.pitem:hover svg{stroke:var(--accent)}
.pitem .pl{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.itabs{display:flex;gap:4px;margin-bottom:9px;border-bottom:1px solid var(--line);
 padding-bottom:8px}
.itab{font-size:12px;padding:4px 10px;border-radius:6px;cursor:pointer;
 border:1px solid var(--line);background:#1414194d}
.itab.on{background:var(--accent);color:#06101f;border-color:var(--accent);font-weight:600}
.sect{margin:13px 0 4px;font-size:10px;text-transform:uppercase;letter-spacing:.07em;
 color:var(--muted);font-weight:700;border-top:1px solid var(--line);padding-top:10px}
.sect:first-child{border-top:none;margin-top:0;padding-top:0}
.arow{display:grid;grid-template-columns:1fr 118px;gap:6px;align-items:center;
 margin-bottom:5px}
.arow label{font-size:11.5px;color:var(--muted);line-height:1.3}
.arow select,.arow input{padding:3px 6px;font-size:12px;width:100%}
.arow.risky label{color:#fbbf24}
.arow select.unset{color:var(--muted);font-style:italic}
.crow{display:grid;grid-template-columns:1fr 1fr 26px;gap:5px;margin-bottom:5px}
.crow input{padding:3px 6px;font-size:12px}
.crow button{padding:2px 6px;font-size:12px;line-height:1}
.tcard{border:1px solid var(--line);border-radius:8px;padding:9px 11px;
 margin-bottom:7px;background:#1414194d}
.tcard b{font-size:12.5px}
.oos{background:#2a0f0f88;border:1px solid #7f1d1d;border-radius:7px;
 padding:8px 10px;margin-top:9px}
.canvaswrap{background:var(--sunken);border:1px solid var(--line);border-radius:10px;
 position:relative;overflow:hidden}
svg.cv{display:block;width:100%;height:100%;min-height:520px;cursor:grab;
 touch-action:none}
svg.cv.marquee-tool{cursor:default}
svg.cv.panning{cursor:grabbing}
svg.cv.connect{cursor:crosshair}
svg.cv.drawing{cursor:crosshair}
/* Rulers are drawn in screen space, so they stay put while the diagram moves
   under them -- the same way a ruler behaves in any drawing tool. */
.ruler-tick{stroke:#3a3a46;stroke-width:1}
.ruler-tick.major{stroke:#565663}
.ruler-label{font-size:9px;fill:#7a7a88;font-family:ui-monospace,monospace}
.ruler-cursor{stroke:#4f9cf9;stroke-width:1;opacity:.85}
.gnode .shape{stroke-width:2}
.gnode.sel .shape{stroke:#4f9cf9;stroke-width:3}
.gnode text{font-size:11px;fill:#e9e9ef;pointer-events:none;
 font-family:ui-sans-serif,system-ui}
.gnode .sub{font-size:9px;fill:#8b8b9a}
.gnode .ic{fill:#8b8b9a;pointer-events:none}
.gedge{stroke:#7c8296;stroke-width:1.7;fill:none}
.gedge.sel{stroke:#4f9cf9;stroke-width:3}
.gedge.plain{stroke:#ef4444}
.gedge.unknown{stroke-dasharray:6 4}
.gedge.hit{stroke:transparent;stroke-width:16;cursor:pointer;fill:none}
.glabel{font-size:10px;fill:#9a9aab;pointer-events:none}
.glabel-bg{fill:#000;stroke:none}
.gbound{fill:#8a6a9c14;stroke:#8a6a9c;stroke-width:1.7;stroke-dasharray:9 6;
 cursor:move}
.gbound.sel{stroke:#4f9cf9;stroke-dasharray:none;stroke-width:2.5}
.gbound-l{font-size:11px;fill:#b9a3dd;font-style:italic;pointer-events:none}
.handle{fill:#4f9cf9;stroke:#000000;stroke-width:1.5;cursor:nwse-resize}
.handle.n,.handle.s{cursor:ns-resize}.handle.e,.handle.w{cursor:ew-resize}
.handle.ne,.handle.sw{cursor:nesw-resize}
.anchor{fill:#22c55e;stroke:#000000;stroke-width:1.5;opacity:0;cursor:crosshair}
.gnode:hover .anchor{opacity:1}
.marquee{fill:#4f9cf91f;stroke:#4f9cf9;stroke-width:1;stroke-dasharray:4 3}
.legend{position:absolute;right:10px;bottom:10px;background:#000000e0;
 border:1px solid var(--line);border-radius:8px;padding:8px 10px;font-size:11px;
 color:var(--muted);pointer-events:none;line-height:1.7}
.legend i{display:inline-block;width:9px;height:9px;border-radius:2px;margin-right:5px}
.props{background:var(--panel2);border:1px solid var(--line);border-radius:10px;
 padding:12px 14px;overflow:auto;min-height:0;display:flex;flex-direction:column}
.props .pbody{overflow:auto;flex:1;min-height:0;margin:0 -4px;padding:0 4px}
.hint{position:absolute;left:10px;top:10px;background:#000000e0;
 border:1px solid var(--line);border-radius:8px;padding:6px 10px;font-size:11px;
 color:var(--muted);pointer-events:none;max-width:60%}
.zoombar{position:absolute;right:10px;top:10px;display:flex;gap:4px}
.zoombar button{padding:3px 9px;font-size:12px;background:#000000e0}
.tbar{display:flex;gap:6px;flex-wrap:wrap;align-items:center;margin-bottom:10px}
.tbar .sep{width:1px;height:22px;background:var(--line);margin:0 3px}
.tbar button.on{background:var(--accent);color:#06101f;border-color:var(--accent);
 font-weight:600}
"""

# ---------------------------------------------------------------------------

CANVAS_JS = r"""
/* =====================================================================
   Diagramming surface. Shared by the Diagram tab (read-only) and the DFD
   editor (editable). See canvas.py for why geometry and membership work
   the way they do.
   ===================================================================== */
const GRID = 10;
const RISK_STROKE = {critical:'#ef4444',high:'#f97316',medium:'#eab308',
                     low:'#3b82f6',info:'#22c55e'};
const RISK_FILL = {critical:'#7f1d1d',high:'#7c2d12',medium:'#713f12',
                   low:'#1e3a5f',info:'#14532d'};
const TYPE_STROKE = {process:'#4f9cf9',data_store:'#a855f7',
                     external_entity:'#94a3b8'};
const DEF = {process:{w:150,h:60}, data_store:{w:150,h:56},
             external_entity:{w:140,h:54}};

const snap = v => Math.round(v / GRID) * GRID;
const uid  = p => p + Math.random().toString(36).slice(2, 9);

/* Shape geometry. A process is a rounded rectangle, a data store is drawn
   with open sides, an external entity is a plain rectangle. These are the
   DFD conventions; using them means the diagram reads correctly in any
   threat-modelling review without a legend. */
function shapePath(n){
  const {w, h} = n;
  if (n.type === 'process')
    return `<rect class="shape" width="${w}" height="${h}" rx="${Math.min(h/2,26)}"/>`;
  if (n.type === 'data_store')
    return `<path class="shape" d="M0,0 h${w} M0,${h} h${w} M0,0 v${h} M${w},0 v${h}"
             style="fill:none"/><rect class="shape" width="${w}" height="${h}"
             style="stroke:none"/>`;
  return `<rect class="shape" width="${w}" height="${h}" rx="3"/>`;
}

/* Orthogonal routing. Leave from the side facing the target, travel to the
   midpoint of the gap, then across. This is how architecture diagrams are
   drawn; bezier curves through the middle of other shapes are not. */
function route(a, b){
  const ax = a.x, ay = a.y, aw = a.w, ah = a.h;
  const bx = b.x, by = b.y, bw = b.w, bh = b.h;
  const acx = ax + aw/2, acy = ay + ah/2, bcx = bx + bw/2, bcy = by + bh/2;
  const dx = bcx - acx, dy = bcy - acy;
  let p1, p2, pts;
  if (Math.abs(dx) >= Math.abs(dy)) {
    const sx = dx >= 0 ? ax + aw : ax;
    const tx = dx >= 0 ? bx : bx + bw;
    p1 = {x:sx, y:acy}; p2 = {x:tx, y:bcy};
    const mx = (p1.x + p2.x) / 2;
    pts = [p1, {x:mx, y:p1.y}, {x:mx, y:p2.y}, p2];
  } else {
    const sy = dy >= 0 ? ay + ah : ay;
    const ty = dy >= 0 ? by : by + bh;
    p1 = {x:acx, y:sy}; p2 = {x:bcx, y:ty};
    const my = (p1.y + p2.y) / 2;
    pts = [p1, {x:p1.x, y:my}, {x:p2.x, y:my}, p2];
  }
  return pts;
}
function polyPath(pts, r){
  r = r == null ? 8 : r;
  let d = `M${pts[0].x},${pts[0].y}`;
  for (let i = 1; i < pts.length - 1; i++) {
    const p = pts[i], prev = pts[i-1], next = pts[i+1];
    const v1 = {x:p.x-prev.x, y:p.y-prev.y}, v2 = {x:next.x-p.x, y:next.y-p.y};
    const l1 = Math.hypot(v1.x, v1.y) || 1, l2 = Math.hypot(v2.x, v2.y) || 1;
    const rr = Math.min(r, l1/2, l2/2);
    d += ` L${p.x - v1.x/l1*rr},${p.y - v1.y/l1*rr}`;
    d += ` Q${p.x},${p.y} ${p.x + v2.x/l2*rr},${p.y + v2.y/l2*rr}`;
  }
  const e = pts[pts.length-1];
  return d + ` L${e.x},${e.y}`;
}
function midOf(pts){
  let total = 0; const segs = [];
  for (let i = 0; i < pts.length-1; i++){
    const l = Math.hypot(pts[i+1].x-pts[i].x, pts[i+1].y-pts[i].y);
    segs.push(l); total += l;
  }
  let want = total/2;
  for (let i = 0; i < segs.length; i++){
    if (want <= segs[i]) {
      const t = segs[i] ? want/segs[i] : 0;
      return {x: pts[i].x + (pts[i+1].x-pts[i].x)*t,
              y: pts[i].y + (pts[i+1].y-pts[i].y)*t};
    }
    want -= segs[i];
  }
  return pts[0];
}

/* Tick spacing that stays legible at any zoom: step up the 1-2-5 ladder until
   a division is at least 60 screen pixels apart. Fixed spacing either crowds
   into a grey band when zoomed out, or spreads to two ticks when zoomed in. */
function tickStep(k){
  const steps = [1,2,5,10,25,50,100,250,500,1000,2500,5000];
  for (const s of steps) if (s * k >= 60) return s;
  return steps[steps.length - 1];
}

function rulerSvg(view, w, h, pointer){
  const R = 20;                       // ruler thickness, screen pixels
  const step = tickStep(view.k);
  const minor = step / 5;
  // Ticks and numbers only. A framed gutter boxes the drawing in for no
  // benefit; the marks alone tell you where you are.
  let s = '<g class="rulers">';

  // horizontal
  const x0 = (0 - view.x) / view.k, x1 = (w - view.x) / view.k;
  for (let v = Math.floor(x0 / minor) * minor; v <= x1; v += minor) {
    const sx = Math.round(view.x + v * view.k) + 0.5;
    if (sx < R) continue;
    const major = Math.abs(v % step) < 1e-6;
    s += `<path class="ruler-tick${major ? ' major' : ''}" d="M${sx},${
      major ? 6 : 13} V${R}"/>`;
    if (major) s += `<text class="ruler-label" x="${sx + 3}" y="10">${Math.round(v)}</text>`;
  }
  // vertical
  const y0 = (0 - view.y) / view.k, y1 = (h - view.y) / view.k;
  for (let v = Math.floor(y0 / minor) * minor; v <= y1; v += minor) {
    const sy = Math.round(view.y + v * view.k) + 0.5;
    if (sy < R) continue;
    const major = Math.abs(v % step) < 1e-6;
    s += `<path class="ruler-tick${major ? ' major' : ''}" d="M${
      major ? 6 : 13},${sy} H${R}"/>`;
    if (major)
      s += `<text class="ruler-label" x="2" y="${sy - 3}"
             transform="rotate(-90 2 ${sy - 3})">${Math.round(v)}</text>`;
  }
  // where the pointer is, on both rulers
  if (pointer) {
    const px = view.x + pointer.x * view.k, py = view.y + pointer.y * view.k;
    if (px >= R) s += `<path class="ruler-cursor" d="M${px + 0.5},0 V${R}"/>`;
    if (py >= R) s += `<path class="ruler-cursor" d="M0,${py + 0.5} H${R}"/>`;
  }
  return s + '</g>';
}

function rectsOverlap(a, b){
  return !(a.x+a.w < b.x || b.x+b.w < a.x || a.y+a.h < b.y || b.y+b.h < a.y);
}
function contains(outer, inner){
  return inner.x >= outer.x && inner.y >= outer.y &&
         inner.x + inner.w <= outer.x + outer.w &&
         inner.y + inner.h <= outer.y + outer.h;
}

/* ------------------------------------------------------------------ */
function Canvas(svgId, propsId, legendId, opts){
  const svg = document.getElementById(svgId);
  const S = {
    svg, nodes:[], edges:[], bounds:[],
    sel:[],                       // [{kind,id}] -- multi-select
    view:{x:0, y:0, k:1},
    mode:'select',                // select | connect | boundary
    pending:null,
    editable: !!opts.editable,
    onChange: opts.onChange || (()=>{}),
    onSelect: opts.onSelect || (()=>{}),
    showBounds:true, showLabels:true, showGrid:true, showRulers:true,
    pointer:null,
    clipboard:null,
  };
  const undoStack = [], redoStack = [];

  const byId = () => Object.fromEntries(S.nodes.map(n=>[n.id,n]));
  const isSel = (kind,id) => S.sel.some(s=>s.kind===kind && s.id===id);
  const selNodes = () => S.sel.filter(s=>s.kind==='node')
                          .map(s=>S.nodes.find(n=>n.id===s.id)).filter(Boolean);
  const selBounds = () => S.sel.filter(s=>s.kind==='boundary')
                          .map(s=>S.bounds.find(b=>b.id===s.id)).filter(Boolean);
  S.selNodes = selNodes; S.selBounds = selBounds; S.isSel = isSel;

  function snapshot(){ return JSON.stringify({n:S.nodes, e:S.edges, b:S.bounds}); }
  function push(){
    undoStack.push(snapshot());
    if (undoStack.length > 60) undoStack.shift();
    redoStack.length = 0;
  }
  function restore(str){
    const s = JSON.parse(str);
    S.nodes = s.n; S.edges = s.e; S.bounds = s.b;
    S.sel = []; S.draw(); S.props(); S.onChange();
  }
  S.push = push;
  S.undo = () => { if(!undoStack.length) return toast('Nothing to undo');
                   redoStack.push(snapshot()); restore(undoStack.pop()); };
  S.redo = () => { if(!redoStack.length) return toast('Nothing to redo');
                   undoStack.push(snapshot()); restore(redoStack.pop()); };

  /* -------------------------------- render ------------------------- */
  S.draw = function(){
    const v = S.view, N = byId();
    let s = `<defs>
      <marker id="ar" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7"
        markerHeight="7" orient="auto"><path d="M0,0 L10,5 L0,10 z" fill="#7c8296"/></marker>
      <marker id="arR" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7"
        markerHeight="7" orient="auto"><path d="M0,0 L10,5 L0,10 z" fill="#ef4444"/></marker>
      <marker id="arS" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7"
        markerHeight="7" orient="auto"><path d="M0,0 L10,5 L0,10 z" fill="#4f9cf9"/></marker>
      <pattern id="grid" width="${GRID*4}" height="${GRID*4}" patternUnits="userSpaceOnUse">
        <path d="M ${GRID*4} 0 L 0 0 0 ${GRID*4}" fill="none" stroke="#17171d" stroke-width="1"/>
      </pattern></defs>`;
    if (S.showGrid && S.editable) {
      s += `<rect class="gridbg" x="0" y="0" width="100%" height="100%" fill="url(#grid)"
             transform="translate(${v.x % (GRID*4*v.k)},${v.y % (GRID*4*v.k)})"/>`;
    }
    s += `<g transform="translate(${v.x},${v.y}) scale(${v.k})">`;

    // Boundaries first: they sit behind everything.
    if (S.showBounds) {
      for (const b of S.bounds) {
        const k = isSel('boundary', b.id) ? 'gbound sel' : 'gbound';
        s += `<g data-boundary="${esc(b.id)}">
          <rect class="${k}" x="${b.x}" y="${b.y}" width="${b.w}" height="${b.h}" rx="10"/>
          <text class="gbound-l" x="${b.x+12}" y="${b.y+19}">${esc(b.name)}${
            b.trust_level!=null ? ' · trust '+b.trust_level : ''}</text></g>`;
      }
    }

    // Edges.
    for (const e of S.edges) {
      const a = N[e.source], b = N[e.target];
      if (!a || !b) continue;
      const pts = route(a, b);
      const d = polyPath(pts);
      const sel = isSel('edge', e.id);
      const plain = e.encrypted === false;
      const unk = e.encrypted == null;
      const k = ['gedge', plain?'plain':'', unk?'unknown':'', sel?'sel':''].join(' ');
      const mk = sel ? 'arS' : (plain ? 'arR' : 'ar');
      s += `<path class="${k}" d="${d}" marker-end="url(#${mk})"/>`;
      s += `<path class="gedge hit" d="${d}" data-edge="${esc(e.id)}"/>`;
      if (S.showLabels) {
        const txt = [e.name, e.protocol ? '('+e.protocol+')' : ''].filter(Boolean)
                    .join(' ').slice(0, 34);
        if (txt) {
          const m = midOf(pts);
          s += `<rect class="glabel-bg" x="${m.x - txt.length*2.7 - 4}" y="${m.y-8}"
                 width="${txt.length*5.4 + 8}" height="15" rx="3"/>
                <text class="glabel" x="${m.x}" y="${m.y+3}"
                 text-anchor="middle">${esc(txt)}</text>`;
        }
      }
    }

    // Nodes.
    for (const n of S.nodes) {
      const stroke = n.risk ? RISK_STROKE[n.risk] : (TYPE_STROKE[n.type] || '#4f9cf9');
      const fill = n.risk ? RISK_FILL[n.risk] : '#101017';
      const sel = isSel('node', n.id);
      const meta = [n.hops==null ? 'not reachable' : n.hops+' hops',
                    n.findings ? n.findings+' findings' : ''].filter(Boolean).join(' · ');
      const nm = (n.name||'').length > 22 ? (n.name||'').slice(0,21)+'…' : (n.name||'');
      s += `<g class="gnode ${sel?'sel':''}" data-node="${esc(n.id)}"
              transform="translate(${n.x},${n.y})" style="--st:${stroke}">
        <g style="fill:${fill};stroke:${stroke}">${shapePath(n)}</g>
        <text x="${n.w/2}" y="${n.h/2 - 1}" text-anchor="middle">${esc(nm)}</text>
        <text class="sub" x="${n.w/2}" y="${n.h/2 + 13}" text-anchor="middle">${esc(meta)}</text>
        ${n.hand ? `<circle cx="${n.w-10}" cy="10" r="4" fill="#22c55e"/>` : ''}`;
      if (S.editable) {
        for (const [ax, ay] of [[n.w/2,0],[n.w,n.h/2],[n.w/2,n.h],[0,n.h/2]])
          s += `<circle class="anchor" cx="${ax}" cy="${ay}" r="4.5"
                 data-anchor="${esc(n.id)}"/>`;
      }
      s += `</g>`;
    }

    // Resize handles on a single selection.
    if (S.editable && S.sel.length === 1) {
      const one = S.sel[0];
      const t = one.kind === 'node' ? N[one.id]
              : one.kind === 'boundary' ? S.bounds.find(b=>b.id===one.id) : null;
      if (t && (one.kind === 'boundary' || t.hand)) {
        const H = [['nw',t.x,t.y],['n',t.x+t.w/2,t.y],['ne',t.x+t.w,t.y],
                   ['e',t.x+t.w,t.y+t.h/2],['se',t.x+t.w,t.y+t.h],
                   ['s',t.x+t.w/2,t.y+t.h],['sw',t.x,t.y+t.h],['w',t.x,t.y+t.h/2]];
        for (const [dir,hx,hy] of H)
          s += `<rect class="handle ${dir}" x="${hx-4}" y="${hy-4}" width="8" height="8"
                 data-handle="${dir}" data-hk="${one.kind}" data-hid="${esc(one.id)}"/>`;
      }
    }
    if (S._marquee) {
      const m = S._marquee;
      s += `<rect class="marquee" x="${Math.min(m.x0,m.x1)}" y="${Math.min(m.y0,m.y1)}"
             width="${Math.abs(m.x1-m.x0)}" height="${Math.abs(m.y1-m.y0)}"/>`;
    }
    if (S._draft) {
      const d = S._draft;
      s += `<rect class="marquee" x="${Math.min(d.x0,d.x1)}" y="${Math.min(d.y0,d.y1)}"
             width="${Math.abs(d.x1-d.x0)}" height="${Math.abs(d.y1-d.y0)}"/>`;
    }
    if (S._wire) {
      s += `<path class="gedge" style="stroke:#22c55e;stroke-dasharray:5 4"
             d="M${S._wire.x0},${S._wire.y0} L${S._wire.x1},${S._wire.y1}"/>`;
    }
    s += '</g>';
    if (S.showRulers) {
      const r = svg.getBoundingClientRect();
      s += rulerSvg(v, r.width || 900, r.height || 600, S.pointer);
    }
    svg.innerHTML = s;
    wire();
    legend();
  };

  function legend(){
    const el = document.getElementById(legendId);
    if (!el) return;
    el.innerHTML =
      `<div><i style="background:${RISK_STROKE.critical}"></i>critical
        <i style="background:${RISK_STROKE.high};margin-left:7px"></i>high
        <i style="background:${RISK_STROKE.medium};margin-left:7px"></i>medium</div>
       <div>▭ process &nbsp; ▤ data store &nbsp; ▢ external entity</div>
       <div><span style="color:#ef4444">──</span> unencrypted &nbsp;
        <span style="color:#7c8296">╌╌</span> encryption unknown &nbsp;
        <span style="color:#22c55e">●</span> hand-added</div>`;
  }

  /* ------------------------------ geometry ------------------------- */
  function toWorld(ev){
    const r = svg.getBoundingClientRect();
    return {x: (ev.clientX - r.left - S.view.x) / S.view.k,
            y: (ev.clientY - r.top  - S.view.y) / S.view.k};
  }
  S.toWorld = toWorld;

  /* Membership is geometric: a node is in a boundary if it is drawn inside
     it. Recomputed on demand so dragging a service into the DMZ changes the
     model without anyone editing a list. */
  S.membersOf = function(b){
    return S.nodes.filter(n => contains(b, n)).map(n => n.id);
  };

  /* ----------------------------- interaction ----------------------- */
  function wire(){
    if (!S.editable) {
      svg.querySelectorAll('[data-node]').forEach(g =>
        g.addEventListener('mousedown', ev => {
          ev.stopPropagation();
          S.sel = [{kind:'node', id:g.dataset.node}]; S.draw(); S.props(); }));
      svg.querySelectorAll('[data-edge]').forEach(p =>
        p.addEventListener('mousedown', ev => {
          ev.stopPropagation();
          S.sel = [{kind:'edge', id:p.dataset.edge}]; S.draw(); S.props(); }));
      return;
    }

    svg.querySelectorAll('[data-anchor]').forEach(c =>
      c.addEventListener('mousedown', ev => { ev.stopPropagation();
        startWire(c.dataset.anchor, ev); }));

    svg.querySelectorAll('[data-handle]').forEach(h =>
      h.addEventListener('mousedown', ev => { ev.stopPropagation();
        startResize(h.dataset.hk, h.dataset.hid, h.dataset.handle, ev); }));

    svg.querySelectorAll('[data-node]').forEach(g =>
      g.addEventListener('mousedown', ev => { ev.stopPropagation();
        onPick('node', g.dataset.node, ev); }));

    svg.querySelectorAll('[data-boundary]').forEach(g =>
      g.addEventListener('mousedown', ev => { ev.stopPropagation();
        onPick('boundary', g.dataset.boundary, ev); }));

    svg.querySelectorAll('[data-edge]').forEach(p =>
      p.addEventListener('mousedown', ev => { ev.stopPropagation();
        if (!ev.shiftKey) S.sel = [];
        S.sel.push({kind:'edge', id:p.dataset.edge});
        S.draw(); S.props(); }));

    svg.querySelectorAll('[data-node],[data-edge]').forEach(g =>
      g.addEventListener('dblclick', ev => { ev.stopPropagation();
        const f = document.querySelector('#'+propsId+' input');
        if (f) { f.focus(); f.select(); } }));
  }

  function onPick(kind, id, ev){
    if (S.mode === 'connect' && kind === 'node') {
      if (!S.pending) { S.pending = id; S.sel = [{kind:'node', id}]; }
      else if (S.pending !== id) { addEdge(S.pending, id); S.pending = null; setMode('select'); }
      S.draw(); S.props(); return;
    }
    if (ev.shiftKey) {
      if (isSel(kind, id)) S.sel = S.sel.filter(s => !(s.kind===kind && s.id===id));
      else S.sel.push({kind, id});
    } else if (!isSel(kind, id)) {
      S.sel = [{kind, id}];
    }
    S.draw(); S.props();
    startDrag(ev);
  }

  function startDrag(ev){
    const start = toWorld(ev);
    const nodes = selNodes().filter(n => n.hand || true);
    const bnds  = selBounds();
    const origin = new Map();
    nodes.forEach(n => origin.set('n'+n.id, {x:n.x, y:n.y}));
    bnds.forEach(b => origin.set('b'+b.id, {x:b.x, y:b.y}));
    // Dragging a boundary carries whatever it currently contains.
    const carried = new Map();
    bnds.forEach(b => S.nodes.filter(n => contains(b, n))
                     .forEach(n => carried.set(n.id, {x:n.x, y:n.y})));
    let moved = false;
    const mv = e2 => {
      const p = toWorld(e2);
      const dx = snap(p.x - start.x), dy = snap(p.y - start.y);
      if (!moved && (Math.abs(dx) > 1 || Math.abs(dy) > 1)) { push(); moved = true; }
      if (!moved) return;
      nodes.forEach(n => { const o = origin.get('n'+n.id);
                           n.x = snap(o.x+dx); n.y = snap(o.y+dy); });
      bnds.forEach(b => { const o = origin.get('b'+b.id);
                          b.x = snap(o.x+dx); b.y = snap(o.y+dy); });
      carried.forEach((o, id) => { const n = S.nodes.find(x=>x.id===id);
                                   if (n && !origin.has('n'+id)) {
                                     n.x = snap(o.x+dx); n.y = snap(o.y+dy); } });
      S.draw();
    };
    const up = () => { document.removeEventListener('mousemove', mv);
                       document.removeEventListener('mouseup', up);
                       if (moved) { S.draw(); S.onChange(); } };
    document.addEventListener('mousemove', mv);
    document.addEventListener('mouseup', up);
  }

  function startResize(kind, id, dir, ev){
    const t = kind === 'node' ? S.nodes.find(n=>n.id===id)
                              : S.bounds.find(b=>b.id===id);
    if (!t) return;
    push();
    const o = {x:t.x, y:t.y, w:t.w, h:t.h}, start = toWorld(ev);
    const MINW = 60, MINH = 36;
    const mv = e2 => {
      const p = toWorld(e2);
      let dx = snap(p.x - start.x), dy = snap(p.y - start.y);
      if (dir.includes('e')) t.w = Math.max(MINW, o.w + dx);
      if (dir.includes('s')) t.h = Math.max(MINH, o.h + dy);
      if (dir.includes('w')) { const w = Math.max(MINW, o.w - dx);
                               t.x = o.x + (o.w - w); t.w = w; }
      if (dir.includes('n')) { const h = Math.max(MINH, o.h - dy);
                               t.y = o.y + (o.h - h); t.h = h; }
      S.draw();
    };
    const up = () => { document.removeEventListener('mousemove', mv);
                       document.removeEventListener('mouseup', up);
                       S.draw(); S.props(); S.onChange(); };
    document.addEventListener('mousemove', mv);
    document.addEventListener('mouseup', up);
  }

  function startWire(fromId, ev){
    const a = S.nodes.find(n=>n.id===fromId); if (!a) return;
    const p0 = {x:a.x + a.w/2, y:a.y + a.h/2};
    const mv = e2 => { const p = toWorld(e2);
      S._wire = {x0:p0.x, y0:p0.y, x1:p.x, y1:p.y}; S.draw(); };
    const up = e2 => {
      document.removeEventListener('mousemove', mv);
      document.removeEventListener('mouseup', up);
      S._wire = null;
      const p = toWorld(e2);
      const hit = S.nodes.find(n => p.x>=n.x && p.x<=n.x+n.w &&
                                    p.y>=n.y && p.y<=n.y+n.h && n.id!==fromId);
      if (hit) addEdge(fromId, hit.id); else S.draw();
    };
    document.addEventListener('mousemove', mv);
    document.addEventListener('mouseup', up);
  }

  function addEdge(source, target){
    if (S.edges.some(e => e.source===source && e.target===target))
      return toast('That flow already exists');
    push();
    const id = uid('e');
    S.edges.push({id, source, target, name:'', protocol:'', encrypted:null, hand:true});
    S.sel = [{kind:'edge', id}];
    S.draw(); S.props(); S.onChange();
  }
  S.addEdge = addEdge;

  /* background: marquee select, boundary draw, or pan with space/middle */
  svg.addEventListener('mousedown', ev => {
    if (ev.target.closest('[data-node],[data-edge],[data-boundary],[data-handle],[data-anchor]'))
      return;
    const start = toWorld(ev);

    if (S.editable && S.mode === 'boundary') {
      S._draft = {x0:start.x, y0:start.y, x1:start.x, y1:start.y};
      const mv = e2 => { const p = toWorld(e2);
        S._draft.x1 = p.x; S._draft.y1 = p.y; S.draw(); };
      const up = () => {
        document.removeEventListener('mousemove', mv);
        document.removeEventListener('mouseup', up);
        const d = S._draft; S._draft = null;
        const w = Math.abs(d.x1-d.x0), h = Math.abs(d.y1-d.y0);
        if (w > 40 && h > 40) {
          push();
          const id = 'boundary:manual:' + uid('b');
          S.bounds.push({id, name:'New trust boundary', trust_level:50, hand:true,
                         x:snap(Math.min(d.x0,d.x1)), y:snap(Math.min(d.y0,d.y1)),
                         w:snap(w), h:snap(h)});
          S.sel = [{kind:'boundary', id}];
          S.onChange();
        }
        setMode('select'); S.draw(); S.props();
      };
      document.addEventListener('mousemove', mv);
      document.addEventListener('mouseup', up);
      return;
    }

    // Drag the empty canvas to pan. Every diagramming tool behaves this way and
    // requiring a modifier for the most common gesture was simply wrong. In the
    // editor, marquee selection moves to Shift-drag and to the marquee tool.
    const wantsPan = !S.editable || S.mode === 'pan' || S.space
                     || ev.button === 1 || ev.altKey || ev.ctrlKey || ev.metaKey
                     || (S.mode !== 'marquee' && !ev.shiftKey);
    if (wantsPan) {
      const o = {x:S.view.x, y:S.view.y, cx:ev.clientX, cy:ev.clientY};
      svg.classList.add('panning');
      const mv = e2 => { S.view.x = o.x + e2.clientX - o.cx;
                         S.view.y = o.y + e2.clientY - o.cy; S.draw(); };
      const up = () => { svg.classList.remove('panning');
        document.removeEventListener('mousemove', mv);
        document.removeEventListener('mouseup', up); };
      document.addEventListener('mousemove', mv);
      document.addEventListener('mouseup', up);
      return;
    }

    // marquee: Shift-drag, or the marquee tool
    if (!ev.shiftKey) { S.sel = []; S.props(); }
    S._marquee = {x0:start.x, y0:start.y, x1:start.x, y1:start.y};
    S.draw();
    const mv = e2 => { const p = toWorld(e2);
      S._marquee.x1 = p.x; S._marquee.y1 = p.y; S.draw(); };
    const up = () => {
      document.removeEventListener('mousemove', mv);
      document.removeEventListener('mouseup', up);
      const m = S._marquee; S._marquee = null;
      const box = {x:Math.min(m.x0,m.x1), y:Math.min(m.y0,m.y1),
                   w:Math.abs(m.x1-m.x0), h:Math.abs(m.y1-m.y0)};
      if (box.w > 5 && box.h > 5) {
        S.nodes.filter(n => rectsOverlap(box, n))
               .forEach(n => { if (!isSel('node', n.id)) S.sel.push({kind:'node', id:n.id}); });
      }
      S.draw(); S.props();
    };
    document.addEventListener('mousemove', mv);
    document.addEventListener('mouseup', up);
  });

  // The pointer marker is the reason a ruler is useful rather than decorative:
  // it answers "where is this shape" without dragging anything.
  svg.addEventListener('mousemove', ev => {
    if (!S.showRulers) return;
    const p = toWorld(ev);
    const last = S.pointer;
    if (last && Math.abs(last.x - p.x) < 2 && Math.abs(last.y - p.y) < 2) return;
    S.pointer = p;
    if (!S._rulerFrame) {
      S._rulerFrame = requestAnimationFrame(() => { S._rulerFrame = 0; S.draw(); });
    }
  });
  svg.addEventListener('mouseleave', () => {
    if (S.pointer) { S.pointer = null; S.draw(); }
  });

  svg.addEventListener('wheel', ev => {
    ev.preventDefault();
    const r = svg.getBoundingClientRect();
    const mx = ev.clientX - r.left, my = ev.clientY - r.top;
    const f = ev.deltaY < 0 ? 1.12 : 1/1.12;
    const k = Math.max(0.15, Math.min(3, S.view.k * f));
    S.view.x = mx - (mx - S.view.x) * (k / S.view.k);
    S.view.y = my - (my - S.view.y) * (k / S.view.k);
    S.view.k = k; S.draw();
  }, {passive:false});

  /* ------------------------------- commands ------------------------ */
  function setMode(m){
    S.mode = m; S.pending = null;
    svg.classList.toggle('connect', m === 'connect');
    svg.classList.toggle('drawing', m === 'boundary');
    svg.classList.toggle('marquee-tool', m === 'marquee');
    document.querySelectorAll('[data-mode]').forEach(b =>
      b.classList.toggle('on', b.dataset.mode === m));
  }
  S.setMode = setMode;
  S.space = false;
  document.addEventListener('keydown', ev => {
    if (ev.code === 'Space' && !ev.target.matches('input,textarea,select')) {
      ev.preventDefault(); S.space = true; svg.style.cursor = 'grab';
    }
  });
  document.addEventListener('keyup', ev => {
    if (ev.code === 'Space') { S.space = false; svg.style.cursor = ''; }
  });

  S.addNode = function(type){
    push();
    const r = svg.getBoundingClientRect();
    const c = {x: (r.width/2 - S.view.x)/S.view.k, y: (r.height/2 - S.view.y)/S.view.k};
    const d = DEF[type] || DEF.process;
    const id = uid('tf-');
    S.nodes.push({id, name:'New ' + type.replace('_',' '), type, hand:true,
                  zone:'internal', desc:'', data:[], tags:[],
                  hops:null, blast:0, findings:0,
                  x:snap(c.x - d.w/2), y:snap(c.y - d.h/2), w:d.w, h:d.h});
    S.sel = [{kind:'node', id}];
    S.draw(); S.props(); S.onChange();
    return id;
  };

  S.dropNode = function(type, clientX, clientY){
    push();
    const r = svg.getBoundingClientRect();
    const p = {x:(clientX - r.left - S.view.x)/S.view.k,
               y:(clientY - r.top  - S.view.y)/S.view.k};
    const d = DEF[type] || DEF.process;
    if (type === 'boundary') {
      const id = 'boundary:manual:' + uid('b');
      S.bounds.push({id, name:'New trust boundary', trust_level:50, hand:true,
                     x:snap(p.x-130), y:snap(p.y-90), w:260, h:180});
      S.sel = [{kind:'boundary', id}];
    } else {
      const id = uid('tf-');
      S.nodes.push({id, name:'New ' + type.replace('_',' '), type, hand:true,
                    zone:'internal', desc:'', data:[], tags:[],
                    hops:null, blast:0, findings:0,
                    x:snap(p.x - d.w/2), y:snap(p.y - d.h/2), w:d.w, h:d.h});
      S.sel = [{kind:'node', id}];
    }
    S.draw(); S.props(); S.onChange();
  };

  S.remove = function(){
    if (!S.sel.length) return toast('Select something first');
    const locked = S.sel.filter(s => {
      if (s.kind === 'node') { const n = S.nodes.find(x=>x.id===s.id); return n && !n.hand; }
      if (s.kind === 'edge') { const e = S.edges.find(x=>x.id===s.id); return e && !e.hand; }
      return false;
    });
    if (locked.length === S.sel.length)
      return toast('Scanned elements are owned by their manifest');
    push();
    for (const s of S.sel) {
      if (s.kind === 'node') {
        const n = S.nodes.find(x=>x.id===s.id); if (!n || !n.hand) continue;
        S.nodes = S.nodes.filter(x=>x.id!==s.id);
        S.edges = S.edges.filter(e=>e.source!==s.id && e.target!==s.id);
      } else if (s.kind === 'edge') {
        const e = S.edges.find(x=>x.id===s.id); if (!e || !e.hand) continue;
        S.edges = S.edges.filter(x=>x.id!==s.id);
      } else {
        S.bounds = S.bounds.filter(x=>x.id!==s.id);
      }
    }
    S.sel = []; S.draw(); S.props(); S.onChange();
    if (locked.length) toast(locked.length + ' scanned element(s) kept');
  };

  S.copy = function(){
    const ns = selNodes();
    if (!ns.length) return toast('Select shapes to copy');
    S.clipboard = JSON.parse(JSON.stringify(ns));
    toast(ns.length + ' copied');
  };
  S.paste = function(){
    if (!S.clipboard || !S.clipboard.length) return toast('Clipboard is empty');
    push();
    const fresh = [];
    for (const n of S.clipboard) {
      const id = uid('tf-');
      fresh.push({...n, id, hand:true, risk:null, findings:0, hops:null,
                  name:n.name + ' copy', x:snap(n.x+20), y:snap(n.y+20)});
    }
    S.nodes.push(...fresh);
    S.sel = fresh.map(n => ({kind:'node', id:n.id}));
    S.draw(); S.props(); S.onChange();
  };
  S.duplicate = function(){ S.copy(); S.paste(); };

  S.align = function(how){
    const ns = selNodes();
    if (ns.length < 2) return toast('Select two or more shapes');
    push();
    if (how === 'left')   { const v = Math.min(...ns.map(n=>n.x)); ns.forEach(n=>n.x=v); }
    if (how === 'right')  { const v = Math.max(...ns.map(n=>n.x+n.w)); ns.forEach(n=>n.x=v-n.w); }
    if (how === 'top')    { const v = Math.min(...ns.map(n=>n.y)); ns.forEach(n=>n.y=v); }
    if (how === 'bottom') { const v = Math.max(...ns.map(n=>n.y+n.h)); ns.forEach(n=>n.y=v-n.h); }
    if (how === 'cx')     { const v = ns.reduce((a,n)=>a+n.x+n.w/2,0)/ns.length;
                            ns.forEach(n=>n.x=snap(v-n.w/2)); }
    if (how === 'cy')     { const v = ns.reduce((a,n)=>a+n.y+n.h/2,0)/ns.length;
                            ns.forEach(n=>n.y=snap(v-n.h/2)); }
    if (how === 'hgap' || how === 'vgap') {
      const key = how === 'hgap' ? 'x' : 'y', dim = how === 'hgap' ? 'w' : 'h';
      const sorted = [...ns].sort((a,b)=>a[key]-b[key]);
      const first = sorted[0][key];
      const last = sorted[sorted.length-1][key] + sorted[sorted.length-1][dim];
      const total = sorted.reduce((a,n)=>a+n[dim], 0);
      const gap = (last - first - total) / (sorted.length - 1);
      let cur = first;
      sorted.forEach(n => { n[key] = snap(cur); cur += n[dim] + gap; });
    }
    S.draw(); S.onChange();
  };

  S.fit = function(){
    const boxes = [...S.nodes, ...S.bounds];
    if (!boxes.length) return;
    const r = svg.getBoundingClientRect();
    const x1 = Math.min(...boxes.map(n=>n.x)) - 40;
    const y1 = Math.min(...boxes.map(n=>n.y)) - 40;
    const x2 = Math.max(...boxes.map(n=>n.x+n.w)) + 40;
    const y2 = Math.max(...boxes.map(n=>n.y+n.h)) + 40;
    const k = Math.max(0.15, Math.min(1.7, Math.min(r.width/(x2-x1), r.height/(y2-y1))));
    S.view = {k, x: -x1*k + (r.width-(x2-x1)*k)/2, y: -y1*k + (r.height-(y2-y1)*k)/2};
    S.draw();
  };
  S.zoom = function(f){
    const r = svg.getBoundingClientRect(), mx = r.width/2, my = r.height/2;
    const k = Math.max(0.15, Math.min(3, S.view.k * f));
    S.view.x = mx - (mx - S.view.x) * (k / S.view.k);
    S.view.y = my - (my - S.view.y) * (k / S.view.k);
    S.view.k = k; S.draw();
  };

  /* Layered layout: columns by hops from the internet -- the order an
     attacker walks the estate. Only used when there is no saved layout. */
  S.layout = function(){
    const cols = {};
    for (const n of S.nodes) {
      const c = n.hops == null ? 9 : Math.min(n.hops, 8);
      (cols[c] = cols[c] || []).push(n);
    }
    Object.keys(cols).sort((a,b)=>a-b).forEach(c => {
      cols[c].sort((a,b)=>(a.name||'').localeCompare(b.name||''));
      cols[c].forEach((n,i) => { n.x = snap(60 + (+c)*250); n.y = snap(60 + i*95); });
    });
    // Re-fit any boundary around whatever it now contains.
    for (const b of S.bounds) {
      const mem = (b.members||[]).map(id => S.nodes.find(n=>n.id===id)).filter(Boolean);
      if (!mem.length) continue;
      b.x = Math.min(...mem.map(n=>n.x)) - 24;
      b.y = Math.min(...mem.map(n=>n.y)) - 34;
      b.w = Math.max(...mem.map(n=>n.x+n.w)) + 24 - b.x;
      b.h = Math.max(...mem.map(n=>n.y+n.h)) + 24 - b.y;
    }
    S.draw(); S.fit();
  };

  S.geometry = function(){
    const out = {nodes:{}, bounds:{}};
    S.nodes.forEach(n => out.nodes[n.id] = {x:n.x, y:n.y, w:n.w, h:n.h});
    S.bounds.forEach(b => out.bounds[b.id] =
      {x:b.x, y:b.y, w:b.w, h:b.h, name:b.name, trust_level:b.trust_level,
       hand:!!b.hand});
    return out;
  };
  S.applyGeometry = function(g){
    if (!g) return false;
    let hit = 0;
    (S.nodes||[]).forEach(n => { const s = (g.nodes||{})[n.id];
      if (s) { n.x=s.x; n.y=s.y; n.w=s.w||n.w; n.h=s.h||n.h; hit++; } });
    (S.bounds||[]).forEach(b => { const s = (g.bounds||{})[b.id];
      if (s) { b.x=s.x; b.y=s.y; b.w=s.w; b.h=s.h; hit++; } });
    // Boundaries the user drew that no longer match a scanned one.
    Object.entries(g.bounds||{}).forEach(([id, s]) => {
      if (s.hand && !S.bounds.some(b => b.id === id))
        S.bounds.push({id, name:s.name||'Trust boundary',
                       trust_level:s.trust_level==null?50:s.trust_level,
                       hand:true, x:s.x, y:s.y, w:s.w, h:s.h});
    });
    return hit > 0;
  };

  /* Called when the surrounding grid changes. The SVG is 100%-width, so the
     element resizes on its own; the drawing has to be re-issued because the
     viewport transform was computed against the old box. */
  S.resize = function(){ S.draw(); };

  S.props = function(){
    const el = document.getElementById(propsId);
    if (el) el.innerHTML = renderProps(S);
    S.onSelect(S);
  };
  return S;
}
"""

# ---------------------------------------------------------------------------

PROPS_JS = r"""
/* The inspector. Two tabs: what this element is, and what is wrong with it.

   Scanned elements are read-only because they are owned by a manifest, and
   letting someone "edit" one here would produce a change that silently
   disappears on the next scan. */
const ZONES = ['external','dmz','partner','internal','restricted','management'];
let INSPECT = 'props';

function attrControl(spec, value, ro){
  const id = 'pa-' + spec.key;
  const risky = spec.rule && (value === false || value === 'none' ||
                              value === 'root' || value === 'administrator' ||
                              value === 'any_remote');
  const title = spec.hint || (spec.rule ? 'Answering this can raise ' + spec.rule : '');
  let ctl;
  if (spec.kind === 'bool') {
    ctl = `<select id="${id}" data-attr="${esc(spec.key)}" ${ro?'disabled':''}
            class="${value==null?'unset':''}">
      <option value="" ${value==null?'selected':''}>unanswered</option>
      <option value="true" ${value===true?'selected':''}>yes</option>
      <option value="false" ${value===false?'selected':''}>no</option></select>`;
  } else if (spec.kind === 'enum') {
    ctl = `<select id="${id}" data-attr="${esc(spec.key)}" ${ro?'disabled':''}
            class="${value==null?'unset':''}">
      <option value="" ${value==null?'selected':''}>unanswered</option>
      ${spec.values.map(v=>`<option value="${esc(v)}" ${v===value?'selected':''}
        >${esc(v.replace(/_/g,' '))}</option>`).join('')}</select>`;
  } else {
    ctl = `<input id="${id}" data-attr="${esc(spec.key)}" value="${esc(value||'')}"
            ${ro?'disabled':''}>`;
  }
  return `<div class="arow ${risky?'risky':''}" title="${esc(title)}">
    <label for="${id}">${esc(spec.label)}${spec.rule?' <span class="note">•</span>':''}</label>
    ${ctl}</div>`;
}

function attrSection(element, obj, ro){
  const spec = (CATALOG.attributes||{})[element] || [];
  if (!spec.length) return '';
  const attrs = obj.attrs || {};
  const open = spec.filter(s => s.rule && attrs[s.key] == null).length;
  return `<div class="sect">Design attributes${
      open ? ` <span class="note">· ${open} unanswered</span>` : ''}</div>
    ${spec.map(s => attrControl(s, attrs[s.key], ro)).join('')}
    <div class="note" style="font-size:11px;margin-top:5px">
      <span class="note">•</span> marks a question a rule reads. Leaving one
      unanswered is reported as a coverage gap, never assumed safe.</div>`;
}

function customSection(obj, ro){
  const rows = Object.entries(obj.custom || {});
  return `<div class="sect">Custom attributes</div>
    <div id="pc-rows">${rows.map(([k,v],i)=>`
      <div class="crow">
        <input data-ck="${i}" value="${esc(k)}" placeholder="name" ${ro?'disabled':''}>
        <input data-cv="${i}" value="${esc(v)}" placeholder="value" ${ro?'disabled':''}>
        <button data-cdel="${i}" ${ro?'disabled':''}>×</button></div>`).join('')}</div>
    ${ro?'':'<button id="pc-add" style="padding:3px 9px;font-size:12px">+ attribute</button>'}
    <div class="note" style="font-size:11px;margin-top:5px">
      Recorded as <span class="mono">custom.&lt;name&gt;</span> facts. No built-in
      rule reads them; write your own rule pack against them.</div>`;
}

function scopeSection(obj, ro){
  const oos = (obj.attrs||{}).out_of_scope === true;
  return `<div class="sect">Scope</div>
    <label class="note" style="display:flex;gap:7px;align-items:center">
      <input type="checkbox" id="pa-oos" ${oos?'checked':''} ${ro?'disabled':''}
        style="width:auto"> Out of scope</label>
    ${oos?`<div class="oos">
      <label class="fld" style="margin-top:0">Reason (recorded in the report)</label>
      <input id="pa-oosr" style="width:100%" ${ro?'disabled':''}
        value="${esc((obj.attrs||{}).out_of_scope_reason||'')}"
        placeholder="why this is excluded">
      <div class="note" style="margin-top:6px">Findings are marked suppressed
        with this reason, not deleted — the decision stays reviewable.</div>
    </div>`:''}`;
}

function threatsFor(id){
  const mine = (typeof FIND !== 'undefined' ? FIND : []).filter(f => f.component === id);
  if (!mine.length)
    return `<div class="note">No findings against this element.<br><br>
      That is only meaningful if its design attributes are answered — an
      unanswered question produces no finding either.</div>`;
  const order = {critical:0,high:1,medium:2,low:3,info:4};
  mine.sort((a,b)=>(order[a.risk_level]-order[b.risk_level]));
  return mine.map(f=>`<div class="tcard">
    <div><span class="pill ${cls(f.risk_level)}">${f.risk_level}</span>
      <b style="margin-left:6px">${esc(f.title)}</b></div>
    <div class="note mono" style="margin:3px 0">${esc(f.rule_id)}${
      f.evidence_file?' · '+esc(f.evidence_file):''}${
      f.suppressed?' · SUPPRESSED':''}</div>
    <div class="note">${esc((f.description||'').slice(0,190))}</div>
    ${(f.stride||'').split(',').filter(Boolean).map(s=>
      `<span class="tag">${esc(s)}</span>`).join('')}
  </div>`).join('');
}

function renderProps(C){
  const tabs = sel => `<div class="itabs">
    <span class="itab ${INSPECT==='props'?'on':''}" data-itab="props">Properties</span>
    <span class="itab ${INSPECT==='threats'?'on':''}" data-itab="threats">Threats${
      sel ? ' ' + ((typeof FIND !== 'undefined' ? FIND : [])
                   .filter(f=>f.component===sel).length) : ''}</span>
  </div>`;

  if (!C.sel.length)
    return tabs(null) + `<div class="pbody"><div class="note">${
      C.editable
        ? 'Nothing selected.<br><br>Drag a component from the library, or draw a '
          + 'trust boundary. Marquee-drag selects several; shift-click adds.'
        : 'Click a component or a flow to inspect it.'}</div></div>`;

  if (C.sel.length > 1) {
    const ns = C.selNodes(), es = C.sel.filter(s=>s.kind==='edge');
    return tabs(null) + `<div class="pbody">
      <div class="kv"><b>${C.sel.length} selected</b></div>
      <div class="note">${ns.length} shape(s), ${es.length} flow(s)</div>
      ${C.editable ? `<div class="sect">Align</div>
      <div style="display:flex;gap:4px;flex-wrap:wrap">
        ${['left','cx','right','top','cy','bottom'].map(a=>
          `<button data-align="${a}">${a}</button>`).join('')}</div>
      <div class="sect">Distribute</div>
      <div style="display:flex;gap:4px">
        <button data-align="hgap">horizontal</button>
        <button data-align="vgap">vertical</button></div>
      <div class="sect">Apply to all</div>
      <div class="arow"><label>Trust zone</label>
      <select id="pf-bulkzone"><option value="">— unchanged —</option>
        ${ZONES.map(z=>`<option>${z}</option>`).join('')}</select></div>` : ''}
    </div>`;
  }

  const s = C.sel[0];

  if (s.kind === 'boundary') {
    const b = C.bounds.find(x=>x.id===s.id);
    if (!b) return tabs(null) + '<div class="pbody">Gone.</div>';
    const inside = C.membersOf(b);
    const ro = !C.editable || !b.hand;
    return tabs(null) + `<div class="pbody">
      <div class="kv"><b>Trust boundary</b></div>
      <label class="fld">Name</label>
      <input id="pf-bname" style="width:100%" value="${esc(b.name)}" ${ro?'disabled':''}>
      <label class="fld">Trust level — 0 is the internet, 95 the most trusted</label>
      <input id="pf-btrust" type="number" min="0" max="95" style="width:100%"
        value="${b.trust_level==null?50:b.trust_level}" ${ro?'disabled':''}>
      <div class="sect">Contains ${inside.length} component(s)</div>
      <div class="note">Membership follows the rectangle. Drag a component
        inside to add it; there is no list to maintain.</div>
      <div style="margin-top:6px">${inside.slice(0,14).map(id=>{
        const n = C.nodes.find(x=>x.id===id);
        return `<span class="tag">${esc(n?n.name:id)}</span>`;}).join('')}
        ${inside.length>14?`<span class="tag">+${inside.length-14}</span>`:''}</div>
      ${ro?'<div class="note" style="margin-top:9px">Derived from the scan.</div>':''}
    </div>`;
  }

  if (s.kind === 'node') {
    const n = C.nodes.find(x=>x.id===s.id);
    if (!n) return tabs(null) + '<div class="pbody">Gone.</div>';
    if (INSPECT === 'threats')
      return tabs(n.id) + `<div class="pbody">${threatsFor(n.id)}</div>`;
    const ro = !C.editable || !n.hand;
    const inb = C.bounds.filter(b => C.membersOf(b).includes(n.id));
    const lib = (CATALOG.components||[]).filter(c => c.element === n.type);
    const oos = (n.attrs||{}).out_of_scope === true;
    return tabs(n.id) + `<div class="pbody">
      <div class="kv"><b>${esc(n.name)}</b>${oos?' <span class="pill info">out of scope</span>':''}</div>
      <div class="kv mono note" style="word-break:break-all">${esc(n.id)}</div>
      ${n.risk?`<div class="kv" style="margin-top:6px">
        <span class="pill ${cls(n.risk)}">${n.risk}</span>
        <a href="#" data-itab="threats" style="color:var(--accent);margin-left:7px"
          >${n.findings} finding${n.findings===1?'':'s'} →</a></div>`:''}

      <div class="sect">Identity</div>
      <div class="arow"><label>Name</label>
        <input id="pf-name" value="${esc(n.name)}" ${ro?'disabled':''}></div>
      <div class="arow"><label>Library type</label>
        <select id="pf-lib" ${ro?'disabled':''}>
          <option value="">— generic —</option>
          ${lib.map(c=>`<option value="${esc(c.id)}" ${c.id===n.libType?'selected':''}
            >${esc(c.label)}</option>`).join('')}</select></div>
      <div class="arow"><label>DFD element</label>
        <select id="pf-type" ${ro?'disabled':''}>
          ${['process','data_store','external_entity'].map(x=>
            `<option value="${x}" ${x===n.type?'selected':''}>${x.replace('_',' ')}</option>`
          ).join('')}</select></div>
      <div class="arow"><label>Trust zone</label>
        <select id="pf-zone" ${ro?'disabled':''}>
          ${ZONES.map(z=>`<option ${z===(n.zone||'internal')?'selected':''}>${z}</option>`).join('')}
        </select></div>
      <label class="fld">Data handled</label>
      <input id="pf-data" style="width:100%" value="${esc((n.data||[]).join(', '))}"
        placeholder="pii, pci, secret, phi" ${ro?'disabled':''}>
      <label class="fld">Technologies</label>
      <input id="pf-tech" style="width:100%" value="${esc((n.tech||[]).join(', '))}"
        placeholder="nginx, tls, oauth" ${ro?'disabled':''}>
      <label class="fld">Description</label>
      <textarea id="pf-desc" rows="2" style="width:100%" ${ro?'disabled':''}
        >${esc(n.desc||'')}</textarea>

      ${attrSection(n.type, n, ro)}
      ${scopeSection(n, ro)}
      ${customSection(n, ro)}

      <div class="sect">Analysis</div>
      <div class="kv">
        Exposure: <b>${n.hops==null?'not reachable from the internet':n.hops+' hops'}</b><br>
        Blast radius: <b>${n.blast||0}</b>
        ${n.namespace?`<br>Namespace: <b>${esc(n.namespace)}</b>`:''}
        ${n.kind?`<br>Kind: <b>${esc(n.kind)}</b>`:''}
        ${inb.length?`<br>Inside: <b>${inb.map(b=>esc(b.name)).join(', ')}</b>`:''}</div>
      ${(n.tags||[]).map(x=>`<span class="tag">${esc(x)}</span>`).join('')}

      ${C.editable && !ro ? `<div class="sect">Size</div>
      <div style="display:flex;gap:6px">
        <input id="pf-w" type="number" style="width:50%" value="${n.w}">
        <input id="pf-h" type="number" style="width:50%" value="${n.h}"></div>` : ''}
      ${ro&&C.editable?`<div class="note" style="margin-top:10px">
        Discovered by the scan — change the manifest, not the diagram.</div>`:''}
    </div>`;
  }

  const e = C.edges.find(x=>x.id===s.id);
  if (!e) return tabs(null) + '<div class="pbody">Gone.</div>';
  if (INSPECT === 'threats')
    return tabs(e.id) + `<div class="pbody">${threatsFor(e.id)}</div>`;
  const a = C.nodes.find(x=>x.id===e.source), b2 = C.nodes.find(x=>x.id===e.target);
  const ro = !C.editable || !e.hand;
  return tabs(e.id) + `<div class="pbody">
    <div class="kv"><b>${esc(a?a.name:e.source)}</b><br>
      <span class="note">↓ ${esc(e.kind||'calls')}</span><br>
      <b>${esc(b2?b2.name:e.target)}</b></div>
    <div class="sect">Identity</div>
    <div class="arow"><label>Label</label>
      <input id="pf-ename" value="${esc(e.name||'')}" ${ro?'disabled':''}></div>
    <div class="arow"><label>Protocol</label>
      <input id="pf-proto" value="${esc(e.protocol||'')}" placeholder="https, sql"
        ${ro?'disabled':''}></div>
    <div class="arow"><label>Encrypted</label>
      <select id="pf-enc" ${ro?'disabled':''} class="${e.encrypted==null?'unset':''}">
        <option value="" ${e.encrypted==null?'selected':''}>unanswered</option>
        <option value="yes" ${e.encrypted===true?'selected':''}>yes</option>
        <option value="no" ${e.encrypted===false?'selected':''}>no</option></select></div>
    ${C.editable&&!ro?`<button data-swap="${esc(e.id)}" style="margin-top:6px">
      Swap source and target</button>`:''}
    ${attrSection('data_flow', e, ro)}
    <div class="sect">Analysis</div>
    <div class="kv">${e.crosses
      ? '<span class="pill med">crosses a trust boundary</span>'
      : 'stays within one trust zone'}</div>
    ${ro&&C.editable?'<div class="note" style="margin-top:9px">Derived from the scan.</div>':''}
  </div>`;
}

function bindProps(C){
  const g = id => document.getElementById(id);
  const on = (id, ev, fn) => { const el = g(id); if (el) el.addEventListener(ev, fn); };

  document.querySelectorAll('[data-itab]').forEach(el =>
    el.onclick = ev => { ev.preventDefault(); INSPECT = el.dataset.itab; C.props(); });
  document.querySelectorAll('[data-align]').forEach(b =>
    b.onclick = () => C.align(b.dataset.align));
  const bulk = g('pf-bulkzone');
  if (bulk) bulk.onchange = ev => {
    if (!ev.target.value) return;
    C.push(); C.selNodes().filter(n=>n.hand).forEach(n => n.zone = ev.target.value);
    C.onChange(); toast('Trust zone applied');
  };
  document.querySelectorAll('[data-swap]').forEach(b => b.onclick = () => {
    const e = C.edges.find(x=>x.id===b.dataset.swap); if (!e) return;
    C.push(); const t2 = e.source; e.source = e.target; e.target = t2;
    C.draw(); C.props(); C.onChange();
  });

  if (C.sel.length !== 1) return;
  const s = C.sel[0];

  if (s.kind === 'boundary') {
    const b = C.bounds.find(x=>x.id===s.id); if (!b) return;
    on('pf-bname','input', ev => { b.name = ev.target.value; C.draw(); C.onChange(); });
    on('pf-btrust','input', ev => {
      const v = parseInt(ev.target.value,10);
      b.trust_level = isNaN(v) ? 50 : Math.max(0, Math.min(95, v));
      C.draw(); C.onChange(); });
    return;
  }

  const obj = s.kind === 'node' ? C.nodes.find(x=>x.id===s.id)
                                : C.edges.find(x=>x.id===s.id);
  if (!obj) return;

  /* Attribute controls. The empty string means unanswered and must delete the
     key rather than store "", or a blanked answer would read as a real one. */
  document.querySelectorAll('[data-attr]').forEach(el => el.onchange = ev => {
    const key = el.dataset.attr, raw = ev.target.value;
    obj.attrs = obj.attrs || {};
    if (raw === '') delete obj.attrs[key];
    else if (raw === 'true') obj.attrs[key] = true;
    else if (raw === 'false') obj.attrs[key] = false;
    else obj.attrs[key] = raw;
    C.onChange(); C.props();
  });
  on('pa-oos','change', ev => {
    obj.attrs = obj.attrs || {};
    if (ev.target.checked) obj.attrs.out_of_scope = true;
    else { delete obj.attrs.out_of_scope; delete obj.attrs.out_of_scope_reason; }
    C.onChange(); C.props();
  });
  on('pa-oosr','input', ev => {
    obj.attrs = obj.attrs || {};
    obj.attrs.out_of_scope_reason = ev.target.value; C.onChange();
  });

  // custom attributes
  const rows = () => Object.entries(obj.custom || {});
  const writeRow = (i, k, v) => {
    const list = rows(); const next = {};
    list.forEach(([ok, ov], j) => {
      if (j === i) { if (k) next[k] = v; }
      else next[ok] = ov;
    });
    obj.custom = next; C.onChange();
  };
  document.querySelectorAll('[data-ck]').forEach(el => el.onchange = ev => {
    const i = +el.dataset.ck, cur = rows()[i];
    writeRow(i, ev.target.value.trim(), cur ? cur[1] : ''); C.props(); });
  document.querySelectorAll('[data-cv]').forEach(el => el.oninput = ev => {
    const i = +el.dataset.cv, cur = rows()[i];
    if (cur) writeRow(i, cur[0], ev.target.value); });
  document.querySelectorAll('[data-cdel]').forEach(el => el.onclick = () => {
    const i = +el.dataset.cdel, list = rows(); const next = {};
    list.forEach(([k,v], j) => { if (j !== i) next[k] = v; });
    obj.custom = next; C.onChange(); C.props(); });
  on('pc-add','click', () => {
    obj.custom = obj.custom || {};
    let n = 1; while (obj.custom['attribute ' + n]) n++;
    obj.custom['attribute ' + n] = ''; C.onChange(); C.props(); });

  if (s.kind === 'node') {
    const n = obj;
    on('pf-name','input', ev => { n.name = ev.target.value; C.draw(); C.onChange(); });
    on('pf-type','change', ev => { n.type = ev.target.value; C.draw(); C.props(); C.onChange(); });
    on('pf-zone','change', ev => { n.zone = ev.target.value; C.onChange(); });
    on('pf-data','input', ev => {
      n.data = ev.target.value.split(',').map(x=>x.trim()).filter(Boolean); C.onChange(); });
    on('pf-tech','input', ev => {
      n.tech = ev.target.value.split(',').map(x=>x.trim()).filter(Boolean); C.onChange(); });
    on('pf-desc','input', ev => { n.desc = ev.target.value; C.onChange(); });
    on('pf-w','input', ev => { n.w = Math.max(60, +ev.target.value||n.w); C.draw(); C.onChange(); });
    on('pf-h','input', ev => { n.h = Math.max(36, +ev.target.value||n.h); C.draw(); C.onChange(); });
    /* Choosing a library type adopts its defaults, but never overwrites an
       answer the user already gave -- picking "Web server" should not silently
       undo a considered decision three fields up. */
    on('pf-lib','change', ev => {
      const c = (CATALOG.components||[]).find(x => x.id === ev.target.value);
      C.push(); n.libType = ev.target.value || null;
      if (c) {
        if (!n.name || /^New /.test(n.name)) n.name = c.label;
        n.type = c.element;
        if (!n.zone || n.zone === 'internal') n.zone = c.zone;
        if (!(n.data||[]).length) n.data = (c.data||[]).slice();
        if (!(n.tech||[]).length) n.tech = (c.tech||[]).slice();
        n.attrs = Object.assign({}, c.attrs, n.attrs || {});
      }
      C.draw(); C.props(); C.onChange();
    });
    return;
  }
  on('pf-ename','input', ev => { obj.name = ev.target.value; C.draw(); C.onChange(); });
  on('pf-proto','input', ev => { obj.protocol = ev.target.value; C.draw(); C.onChange(); });
  on('pf-enc','change', ev => {
    obj.encrypted = ev.target.value==='yes' ? true : ev.target.value==='no' ? false : null;
    C.draw(); C.onChange(); });
}
"""

DOCK_HTML = r"""
<div class="dock" id="__ID__-dock">
  <div class="dtabs">
    <span class="dtab on" data-dtab="tools">Tools</span>
    <span class="dtab" data-dtab="stencils">Stencils</span>
    <span class="dtab" data-dtab="props">Properties</span>
    <span class="dtab" data-dtab="threats">Threats</span>
  </div>
  <div class="dbody">
    <div class="dpane on" data-dpane="tools">
      <div class="sect" style="border:none;padding:0;margin:0 0 6px">Tool</div>
      <div class="row" data-tools="__ID__">
        <button data-mode="select" class="on">Pan</button>
        <button data-mode="marquee">Select</button>
        <button data-mode="connect">Connect</button>
        <button data-mode="boundary">Boundary</button>
      </div>
      <div class="sect">Show</div>
      <label class="chk"><input type="checkbox" data-show="grid" checked> Grid</label>
      <label class="chk"><input type="checkbox" data-show="rulers" checked> Rulers</label>
      <label class="chk"><input type="checkbox" data-show="bounds" checked> Trust boundaries</label>
      <label class="chk"><input type="checkbox" data-show="labels" checked> Flow labels</label>
      <div class="filters-slot"></div>
      <div class="sect">Model</div>
      <div class="row">
        <button data-tool="load">Load from scan</button>
        <button data-tool="clear">Clear canvas</button>
      </div>
      <div class="row">
        <button data-tool="discard">Discard</button>
        <button class="primary" data-tool="save">Save &amp; re-scan</button>
      </div>
      <div class="note" data-msg="1" style="margin-top:6px"></div>
      <div class="sect">Legend</div>
      <div class="lg">
        <div><i style="background:#ef4444"></i>critical
          <i style="background:#f97316;margin-left:7px"></i>high
          <i style="background:#eab308;margin-left:7px"></i>medium</div>
        <div>&#9645; process &nbsp; &#9636; data store &nbsp; &#9744; external entity</div>
        <div><span style="color:#ef4444">&#8212;</span> unencrypted &nbsp;
          <span style="color:#7c8296">&#8212;&#8212;</span> encryption unknown</div>
        <div><span style="color:#22c55e">&#9679;</span> hand-added &mdash;
          only these can be edited</div>
      </div>
      <div class="note" style="margin-top:8px;font-size:11px"
        title="Del remove · Ctrl+Z/Y undo and redo · Ctrl+C/V/D copy, paste, duplicate
Ctrl+A select all · drag to pan · hold Space to pan · Esc cancel">keyboard shortcuts</div>
    </div>

    <div class="dpane" data-dpane="stencils">
      <div class="palette">
        <input type="search" data-libq="1" placeholder="Search components…"
               style="width:100%">
        <div class="pcats" data-libcats="1"></div>
        <div class="plist" data-liblist="1"></div>
      </div>
    </div>

    <div class="dpane" data-dpane="props"><div id="__ID__-props"></div></div>
    <div class="dpane" data-dpane="threats"><div data-threats="1"></div></div>
  </div>
</div>
"""

LIBRARY_JS = r"""
/* The palette is built from the same catalogue the properties form and the
   overlay writer use, fetched once at boot. Adding a component type is a single
   edit in library.py, not four edits that drift. */
let CATALOG = {components:[], categories:[], icons:{}, attributes:{}, universal:[]};

function icon(name, size){
  const d = CATALOG.icons[name] || CATALOG.icons.box || '';
  const s = size || 17;
  return `<svg width="${s}" height="${s}" viewBox="0 0 20 20"><path d="${d}"
    stroke-linecap="round" stroke-linejoin="round"/></svg>`;
}

/* One library per dock, each with its own filter state -- two canvases that
   shared a filter would fight over it. */
function renderLibrary(dock){
  if (!dock) return;
  dock._cat = dock._cat || 'All';
  dock._q = dock._q || '';
  const LIB_CAT = dock._cat, LIB_Q = dock._q;
  const cats = dock.querySelector('[data-libcats]');
  if (cats) cats.innerHTML = ['All', ...CATALOG.categories].map(c =>
    `<span class="pcat ${c===LIB_CAT?'on':''}" data-cat="${esc(c)}">${esc(c)}</span>`
  ).join('');

  const q = LIB_Q.toLowerCase();
  let items = CATALOG.components.filter(c =>
    (LIB_CAT === 'All' || c.category === LIB_CAT) &&
    (!q || c.label.toLowerCase().includes(q) || c.id.includes(q) ||
     (c.tech||[]).some(t => t.includes(q)) || c.category.toLowerCase().includes(q)));

  const list = dock.querySelector('[data-liblist]');
  if (!list) return;
  let html = `<h3>Boundaries</h3>
    <div class="pitem" draggable="true" data-shape="boundary">
      ${icon('boundary')}<span class="pl">Trust boundary</span></div>`;
  if (!items.length) {
    html += `<h3>Components</h3><div class="note" style="padding:6px 2px">
             Nothing matches “${esc(LIB_Q)}”.</div>`;
  } else {
    let group = null;
    for (const c of items) {
      if (c.category !== group) { group = c.category; html += `<h3>${esc(group)}</h3>`; }
      html += `<div class="pitem" draggable="true" data-comp="${esc(c.id)}"
                 title="${esc(c.hint || c.label)}">
                 ${icon(c.icon)}<span class="pl">${esc(c.label)}</span></div>`;
    }
  }
  list.innerHTML = html;

  list.querySelectorAll('.pitem').forEach(el => {
    el.addEventListener('dragstart', ev =>
      ev.dataTransfer.setData('text/plain',
        el.dataset.comp ? 'comp:' + el.dataset.comp : el.dataset.shape));
  });
  cats && cats.querySelectorAll('.pcat').forEach(el =>
    el.onclick = () => { dock._cat = el.dataset.cat; renderLibrary(dock); });
}

async function loadCatalog(){
  try { CATALOG = await api('/api/catalog'); } catch (e) {}
  document.querySelectorAll('.dock').forEach(dock => {
    const q = dock.querySelector('[data-libq]');
    if (q) q.addEventListener('input', ev => {
      dock._q = ev.target.value; renderLibrary(dock); });
    renderLibrary(dock);
  });
}
"""

RAIL_HTML = r"""
<div class="rail" id="__ID__">
  <button data-act="new"       title="New diagram">__ic_new__</button>
  <button data-act="open"      title="Open a .tfm model">__ic_open__</button>
  <button data-act="save"      title="Save .tfm">__ic_save__</button>
  <button data-act="import"    title="Import .tm7 or .drawio">__ic_import__</button>
  <button data-act="tmt"       title="Export for Microsoft TMT (.tm7)">__ic_tmt__</button>
  <button data-act="report"    title="Threat register (Excel)">__ic_xls__</button>
  <span class="rsep"></span>
  <button data-act="stencils"  title="Show or hide the stencil library">__ic_lib__</button>
  <button data-act="inspector" title="Show or hide the inspector">__ic_insp__</button>
  <span class="rsep"></span>
  <button data-act="duplicate" title="Duplicate (Ctrl+D)">__ic_dup__</button>
  <button data-act="delete" class="danger" title="Delete (Del)">__ic_del__</button>
  <button data-act="undo"      title="Undo (Ctrl+Z)">__ic_undo__</button>
  <button data-act="redo"      title="Redo (Ctrl+Y)">__ic_redo__</button>
  <span class="rsep"></span>
  <button data-act="fit"       title="Fit to view">__ic_fit__</button>
  <button data-act="arrange"   title="Auto-arrange by hops from the internet">__ic_arr__</button>
  <span class="rsep"></span>
  <button data-act="stride" class="go" title="Run STRIDE analysis">__ic_run__</button>
</div>
"""

_S = '<svg width="16" height="16" viewBox="0 0 20 20">'
_RAIL_ICONS = {
    "__ic_new__":    _S + '<path d="M4 2h8l4 4v12H4z"/><path d="M10 8v6M7 11h6"/></svg>',
    "__ic_open__":   _S + '<path d="M2 5h6l2 2h8v9H2z"/></svg>',
    "__ic_save__":   _S + '<path d="M3 3h11l3 3v11H3z"/><path d="M6 3v5h7V3M6 17v-5h8v5"/></svg>',
    "__ic_import__": _S + '<path d="M10 3v10M10 13l-3.5-3.5M10 13l3.5-3.5"/><path d="M3 15v2h14v-2"/></svg>',
    "__ic_tmt__":    _S + '<path d="M3 4h14v12H3z"/><path d="M3 8h14M7 8v8"/></svg>',
    "__ic_xls__":    _S + '<path d="M4 2h8l4 4v12H4z"/><path d="M7 10l5 5M12 10l-5 5"/></svg>',
    "__ic_lib__":    _S + '<rect x="2.5" y="3.5" width="15" height="13" rx="2"/><path d="M7.5 3.5v13"/></svg>',
    "__ic_insp__":   _S + '<rect x="2.5" y="3.5" width="15" height="13" rx="2"/><path d="M12.5 3.5v13"/></svg>',
    "__ic_dup__":    _S + '<rect x="6" y="6" width="10" height="10" rx="1.5"/><path d="M13 6V4H4v9h2"/></svg>',
    "__ic_del__":    _S + '<path d="M4 6h12M8 6V4h4v2M6 6l1 11h6l1-11"/></svg>',
    "__ic_undo__":   _S + '<path d="M7 6L3 10l4 4"/><path d="M3 10h9a5 5 0 010 10H8"/></svg>',
    "__ic_redo__":   _S + '<path d="M13 6l4 4-4 4"/><path d="M17 10H8a5 5 0 000 10h4"/></svg>',
    "__ic_fit__":    _S + '<path d="M3 7V3h4M17 7V3h-4M3 13v4h4M17 13v4h-4"/></svg>',
    "__ic_arr__":    _S + '<rect x="2" y="3" width="5" height="4" rx="1"/><rect x="13" y="3" width="5" height="4" rx="1"/><rect x="7.5" y="13" width="5" height="4" rx="1"/><path d="M4.5 7v3h11V7M10 10v3"/></svg>',
    "__ic_run__":    _S + '<path d="M6 4l10 6-10 6z"/></svg>',
}
for _k, _v in _RAIL_ICONS.items():
    RAIL_HTML = RAIL_HTML.replace(_k, _v)
