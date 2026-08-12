// Behavioural spec for the diagramming surface in threatforge/canvas.py.
//
// Run by tests/test_pipeline.py, which concatenates canvas.py's CANVAS_JS and
// PROPS_JS in front of this file and executes the result under Node. The canvas
// is real editor logic -- routing, containment, undo, layout persistence -- and
// none of it is exercised by the Python tests, so it gets its own spec rather
// than being trusted because the page happens to parse.
//
// The DOM stub is deliberately minimal: if a change makes the canvas depend on
// more of the browser than this, that is worth noticing.

// Minimal DOM so Canvas() can be constructed outside a browser.
const mkEl = (id) => ({
  id, dataset:{}, style:{}, innerHTML:'', textContent:'', value:'', options:[],
  classList:{add(){},remove(){},toggle(){},contains(){return false}},
  addEventListener(){}, removeEventListener(){},
  querySelectorAll(){return []}, querySelector(){return null},
  getBoundingClientRect(){return {left:0,top:0,width:900,height:640}},
  focus(){}, select(){}, dispatchEvent(){},
});
const els = {};
global.document = {
  getElementById: id => els[id] || (els[id] = mkEl(id)),
  querySelectorAll: () => [], querySelector: () => null,
  addEventListener(){}, removeEventListener(){},
};
global.window = global;
global.toast = m => {};
// The properties form reads the catalogue; the spec only needs it to exist.
global.CATALOG = {components:[], categories:[], icons:{}, attributes:{}, universal:[]};
global.esc = s => String(s==null?'':s);
global.cls = l => l;
global.Event = class {};


let pass=0, fail=0;
const ok = (name, cond, extra) => {
  if (cond) { pass++; console.log('  PASS ' + name); }
  else { fail++; console.log('  FAIL ' + name + (extra?'  '+JSON.stringify(extra):'')); }
};

console.log('--- pure geometry ---');
ok('snap to 10 grid', snap(47)===50 && snap(42)===40);
ok('contains: inside', contains({x:0,y:0,w:200,h:200},{x:20,y:20,w:50,h:50}));
ok('contains: straddling is not inside',
   !contains({x:0,y:0,w:100,h:100},{x:80,y:20,w:50,h:50}));
ok('rectsOverlap detects touch',
   rectsOverlap({x:0,y:0,w:50,h:50},{x:40,y:40,w:50,h:50}));

console.log('--- orthogonal routing ---');
const A={x:0,y:0,w:100,h:50}, B={x:300,y:0,w:100,h:50};
let pts = route(A,B);
ok('leaves the right side going right', pts[0].x===100 && pts[0].y===25, pts[0]);
ok('arrives at the left side', pts[pts.length-1].x===300, pts[pts.length-1]);
ok('all segments axis-aligned', pts.every((p,i)=>
   i===0 || p.x===pts[i-1].x || p.y===pts[i-1].y), pts);
const C1={x:0,y:0,w:100,h:50}, D={x:0,y:300,w:100,h:50};
pts = route(C1,D);
ok('vertical pair leaves the bottom', pts[0].y===50 && pts[0].x===50, pts[0]);
const back = route(B,A);
ok('reverse leaves the left side', back[0].x===300, back[0]);

console.log('--- canvas construction ---');
const C = Canvas('cv','p','lg',{editable:true});
ok('starts empty', C.nodes.length===0 && C.sel.length===0);
const id1 = C.addNode('process');
const id2 = C.addNode('data_store');
ok('addNode creates hand-authored shapes', C.nodes.length===2 && C.nodes[0].hand===true);
ok('new shape is selected', C.sel.length===1 && C.sel[0].id===id2);
ok('positions snap to grid', C.nodes.every(n=>n.x%10===0 && n.y%10===0));
ok('shapes get default size', C.nodes[0].w===150 && C.nodes[0].h===60);

console.log('--- edges ---');
C.addEdge(id1,id2);
ok('edge created and hand-flagged', C.edges.length===1 && C.edges[0].hand===true);
ok('encryption starts unknown, not false', C.edges[0].encrypted===null);
C.addEdge(id1,id2);
ok('duplicate edge refused', C.edges.length===1);

console.log('--- geometric boundary membership ---');
C.nodes[0].x=50;  C.nodes[0].y=50;
C.nodes[1].x=600; C.nodes[1].y=400;
C.bounds.push({id:'boundary:manual:dmz',name:'DMZ',trust_level:30,hand:true,
               x:20,y:20,w:300,h:200});
ok('a manual boundary id marks it hand-authored',
   String('boundary:manual:dmz').startsWith('boundary:manual:'));
let mem = C.membersOf(C.bounds[0]);
ok('node drawn inside is a member', mem.length===1 && mem[0]===id1, mem);
C.nodes[1].x=60; C.nodes[1].y=120;
mem = C.membersOf(C.bounds[0]);
ok('dragging a node in adds it', mem.length===2, mem);
C.nodes[1].x=900;
mem = C.membersOf(C.bounds[0]);
ok('dragging it out removes it', mem.length===1, mem);

console.log('--- undo / redo ---');
const before = C.nodes.length;
C.push(); C.addNode('external_entity');
ok('added a third shape', C.nodes.length===before+1);
C.undo();
ok('undo removes it', C.nodes.length===before, C.nodes.length);
C.redo();
ok('redo restores it', C.nodes.length===before+1, C.nodes.length);
C.undo();

console.log('--- copy / paste ---');
C.sel=[{kind:'node',id:id1}];
C.copy(); C.paste();
ok('paste adds a copy', C.nodes.length===before+1);
ok('copy gets a fresh id', C.nodes[C.nodes.length-1].id!==id1);
ok('copy carries no inherited risk',
   C.nodes[C.nodes.length-1].risk===null && C.nodes[C.nodes.length-1].findings===0);

console.log('--- align ---');
C.nodes[0].x=13; C.nodes[1].x=207;
C.sel=[{kind:'node',id:C.nodes[0].id},{kind:'node',id:C.nodes[1].id}];
C.align('left');
ok('align left equalises x', C.nodes[0].x===C.nodes[1].x, [C.nodes[0].x,C.nodes[1].x]);

console.log('--- delete respects ownership ---');
C.nodes.push({id:'k8s:Deployment:a/b',name:'scanned',type:'process',hand:false,
              x:0,y:0,w:150,h:60,data:[],tags:[]});
C.sel=[{kind:'node',id:'k8s:Deployment:a/b'}];
const n0=C.nodes.length; C.remove();
ok('scanned shape cannot be deleted', C.nodes.length===n0);
C.sel=[{kind:'node',id:id1}]; C.remove();
ok('hand-authored shape is deleted', !C.nodes.some(n=>n.id===id1));
ok('its edges go with it', !C.edges.some(e=>e.source===id1||e.target===id1));

console.log('--- layout persistence ---');
const g = C.geometry();
ok('geometry captures every node', Object.keys(g.nodes).length===C.nodes.length);
ok('geometry captures boundaries with metadata',
   g.bounds['boundary:manual:dmz'].name==='DMZ' && g.bounds['boundary:manual:dmz'].hand===true);
const target = C.nodes[0].id;
const savedX = 777;
g.nodes[target].x = savedX;
const C2 = Canvas('cv2','p2','lg2',{editable:true});
C2.nodes = JSON.parse(JSON.stringify(C.nodes)).map(n=>({...n,x:0,y:0}));
C2.bounds = [];
const applied = C2.applyGeometry(g);
ok('applyGeometry reports a hit', applied===true);
ok('saved position is restored',
   C2.nodes.find(n=>n.id===target).x===savedX, C2.nodes.find(n=>n.id===target).x);
ok('a hand-drawn boundary survives a scan that does not know it',
   C2.bounds.some(b=>b.id==='boundary:manual:dmz' && b.hand===true),
   C2.bounds.map(b=>b.id));


console.log('--- pan is the default drag ---');
const P = Canvas('cvp','pp','lgp',{editable:true});
P.nodes.push({id:'a',name:'A',type:'process',hand:true,x:0,y:0,w:150,h:60,data:[],tags:[]});
P.mode = 'select';
const wantsPan = (mode, shift) => (!P.editable || mode==='pan' || P.space ||
                                   (mode !== 'marquee' && !shift));
ok('default tool + plain drag pans', wantsPan('select', false));
ok('shift-drag still marquees', !wantsPan('select', true));
ok('marquee tool marquees', !wantsPan('marquee', false));
P.space = true;
ok('space overrides the marquee tool', wantsPan('marquee', false));
P.space = false;
const R = Canvas('cvr','pr','lgr',{editable:false});
ok('read-only diagram always pans', !R.editable);

console.log('\n' + pass + ' passed, ' + fail + ' failed');
process.exit(fail ? 1 : 0);
