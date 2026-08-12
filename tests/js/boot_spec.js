// Boots the served page in a real DOM and fails on any runtime error.
//
// `node --check` only proves the file parses. A ReferenceError on line one
// of boot() leaves a page that renders its static markup and does nothing
// else -- which looks identical to 'the change did not work', and is the
// failure mode this project hit repeatedly. Syntax was never the problem.
//
// Run by tests/test_pipeline.py. Requires jsdom; skipped when absent.

const {JSDOM}=require('jsdom');
const fs=require('fs');
const errors=[];
const dom=new JSDOM(fs.readFileSync(process.argv[2],'utf8'),{
  runScripts:'dangerously', pretendToBeVisual:true, url:'http://127.0.0.1:8787/',
  beforeParse(w){
    w.fetch = async (path,opt)=>{
      const data = {
        '/api/bootstrap':{project:'demo',source:{label:'demo',root:'/tmp'},
          base_root:'/tmp',owners:[],statuses:['open','accepted'],policy:{},
          stats:{},has_model:true,scans:[],exports:['xlsx','executive','tm7','tfm','drawio','thf','html','markdown','json','sarif','mermaid'],
          allowed_git_hosts:['github.com'],build:'test'},
        '/api/findings':{findings:[{id:'TF-1',rule_id:'TF-K8S-001',title:'Privileged container',
          component:'k8s:Container:a/b',risk_level:'critical',risk_score:25,status:'open',
          stride:'E,T',owner:'',notes:'',description:'d',evidence_file:'f.yaml',
          evidence_line:3,references:{cwe:['CWE-250'],mitre:['T1611']},
          sla:{state:'on_track',days_remaining:5,age_days:1,due_date:'2026-09-01'},
          first_seen:'2026-08-01',last_seen:'2026-08-11',confidence:'confirmed'}],count:1},
        '/api/catalog':{components:[{id:'process',label:'Process',category:'Generic',
          element:'process',icon:'cube',tech:[],zone:'internal',data:[],attrs:{},hint:''}],
          categories:['Generic'],icons:{cube:'M1 1h2',boundary:'M1 1h2'},
          attributes:{process:[],data_store:[],external_entity:[],data_flow:[]},
          universal:[],doc_fields:[{key:'title',label:'Title',kind:'text',values:[],rule:'',hint:''}],
          security_questions:[{id:'authn',stride:'S',q:'How?'}]},
        '/api/graph':{elements:[{id:'a',name:'A',type:'process',kind:'Deployment',
          namespace:'x',hops:1,blast:2,hand:false,risk:'critical',findings:1,
          zone:'internal',desc:'',data:[],own_data:null,tech:[],lib_type:null,
          attrs:{},custom:{},unanswered:[],tags:[],boundaries:[]}],
          flows:[],boundaries:[]},
        '/api/layout':{layout:{nodes:{},bounds:{}}},
        '/api/doc':{doc:{fields:{},answers:{}}},
        '/api/sla':{as_of:'',policy:{},buckets:{due_soon:0,on_track:1},compliance_pct:100,
          breached:0,open:1,median_resolution_days:null,overdue:[],by_owner:{}},
        '/api/dfd':{dfd:'',boundaries:[],attack_paths:[{id:'p1',score:9,level:'high',
          hops:['a','b'],hop_labels:['Internet','DB'],findings:['TF-1'],
          narrative:['step one','step two'],length:2}]},
        '/api/scans':{scans:[]},
      }[path.split('?')[0]] || {ok:true};
      return {ok:true, json:async()=>data};
    };
    w.addEventListener('error', e=>errors.push('window error: '+(e.error&&e.error.stack||e.message)));
    w.onerror=(m,s,l,c,err)=>errors.push('onerror: '+(err&&err.stack||m));
  }
});
const vc=dom.virtualConsole || null;
setTimeout(()=>{
  const d=dom.window.document;
  console.log('--- runtime errors ---');
  console.log(errors.length? errors.slice(0,4).join('\n\n') : '  none');
  console.log('\n--- did the app actually boot? ---');
  console.log('  nav items rendered  :', d.querySelectorAll('.nav').length);
  console.log('  library items       :', d.querySelectorAll('.pitem').length);
  console.log('  rail buttons        :', d.querySelectorAll('.rail button').length);
  console.log('  findings rows       :', d.querySelectorAll('#rows tr.row').length);
  console.log('  KPI cards           :', d.querySelectorAll('#cards .card').length);
  console.log('  export menu entries :', d.querySelectorAll('#exportmenu [data-x]').length);
  console.log('  brand tooltip       :',
    ((d.getElementById('brand')||{}).title||'').split('\n')[0]);
  // Exercise the canvas views: they must build, start empty, and offer the
  // dock. A view that throws on open renders nothing and says nothing.
  let viewErr = '';
  try {
    d.querySelector('.nav[data-v="editor"]').dispatchEvent(
      new dom.window.Event('click', {bubbles:true}));
    d.querySelector('.nav[data-v="diagram"]').dispatchEvent(
      new dom.window.Event('click', {bubbles:true}));
  } catch (e) { viewErr = String(e && e.stack || e); }
  if (viewErr) { console.log('\nVIEW SWITCH THREW:\n' + viewErr); errors.push(viewErr); }

  const checks = {
    docks: d.querySelectorAll('.dock').length === 2,
    dockTabs: d.querySelectorAll('#editor-dock .dtab').length === 4,
    tools: d.querySelectorAll('#editor-dock [data-mode]').length === 4,
    emptyState: !!d.getElementById('e-empty'),
    nav: d.querySelectorAll('.nav').length >= 8,
    library: d.querySelectorAll('.pitem').length >= 1,
    rail: d.querySelectorAll('.rail button').length >= 14,
    findings: d.querySelectorAll('#rows tr.row').length >= 1,
    cards: d.querySelectorAll('#cards .card').length >= 5,
    exports: d.querySelectorAll('#exportmenu [data-x]').length >= 5,
  };
  const failed = Object.entries(checks).filter(([,v])=>!v).map(([k])=>k);
  if (failed.length) console.log('\nDID NOT RENDER:', failed.join(', '));
  process.exit(errors.length || failed.length ? 1 : 0);
}, 1200);
