// A saved layout must win over auto-arrange.
//
// Auto-arrange places by hops from the internet. A hand-drawn model has no
// hops at all, so every component lands in one column -- which is exactly
// what a user saw after importing a carefully laid-out sample. The loader
// now fetches the layout before placing anything; this asserts it.

const {JSDOM}=require('jsdom');
const fs=require('fs');
const sample=JSON.parse(fs.readFileSync(
 process.argv[3],'utf8'));
const L=sample.layout;
const ids=Object.keys(L.nodes);
// hops all null, as they are for a hand-drawn model with no scanned manifests --
// exactly the case where auto-arrange stacks everything into one column.
const elements=ids.map(id=>({id,name:id.split(':').pop(),type:'process',kind:'Manual',
  namespace:null,hops:null,blast:0,hand:true,risk:null,findings:0,zone:'internal',
  desc:'',data:[],own_data:null,tech:[],lib_type:null,attrs:{},custom:{},
  unanswered:[],tags:[],boundaries:[]}));
const boundaries=Object.keys(L.bounds).map(id=>({id,name:L.bounds[id].name,
  trust_level:L.bounds[id].trust_level,members:ids.slice(0,3)}));
let imported=false;
const errors=[];
const dom=new JSDOM(fs.readFileSync(process.argv[2],'utf8'),{
 runScripts:'dangerously',pretendToBeVisual:true,url:'http://127.0.0.1:8787/',
 beforeParse(w){
  w.confirm=()=>true;
  w.fetch=async(path)=>{
   const p=path.split('?')[0];
   if(p==='/api/import'){imported=true;return{ok:true,json:async()=>({ok:true,restored:0})};}
   const data={
    '/api/bootstrap':{project:'d',source:{label:'d',root:'/tmp'},base_root:'/tmp',owners:[],
      statuses:['open'],policy:{},stats:{},has_model:true,scans:[],exports:['tfm'],
      allowed_git_hosts:[],build:'t'},
    '/api/findings':{findings:[],count:0},
    '/api/catalog':{components:[],categories:[],icons:{boundary:'M1 1h2'},
      attributes:{process:[],data_store:[],external_entity:[],data_flow:[]},
      universal:[],doc_fields:[],security_questions:[]},
    '/api/graph':{elements:imported?elements:[],flows:[],boundaries:imported?boundaries:[]},
    '/api/layout':{layout:imported?L:{nodes:{},bounds:{}}},
    '/api/doc':{doc:{fields:{},answers:{}}},'/api/dfd':{attack_paths:[]},'/api/scans':{scans:[]},
   }[p]||{ok:true};
   return {ok:true,json:async()=>data};
  };
  w.onerror=(m,s,l,c,e)=>errors.push(String(e&&e.stack||m));
 }});
setTimeout(async()=>{
 const d=dom.window.document;
 const input=d.getElementById('h-file');
 Object.defineProperty(input,'files',{value:[{name:'s.tfm',
   text:async()=>JSON.stringify(sample)}],configurable:true});
 input.dispatchEvent(new dom.window.Event('change'));
 await new Promise(r=>setTimeout(r,600));
 const nodes=[...d.querySelectorAll('#cv-editor .gnode')];
 const xs=nodes.map(n=>{const m=/translate\(([-\d.]+),/.exec(n.getAttribute('transform'));
   return m?Math.round(+m[1]):null;});
 const cols=[...new Set(xs)].sort((a,b)=>a-b);
 const want=[...new Set(Object.values(L.nodes).map(n=>n.x))].sort((a,b)=>a-b);
 console.log('runtime errors :', errors.length?errors[0].slice(0,200):'none');
 console.log('shapes rendered:', nodes.length);
 console.log('columns drawn  :', cols);
 console.log('columns in file:', want);
 const ok = !errors.length && nodes.length===ids.length &&
            JSON.stringify(cols)===JSON.stringify(want);
 console.log(ok?'\nSAVED LAYOUT IS USED':'\nSTILL AUTO-ARRANGING');
 process.exit(ok?0:1);
},1200);
