/* Run node tests/test_incident_ui.cjs. Pure DOM fixture, no browser or network.
   Exercises the actual dashboard scripts and controls against API fixtures. */
const fs=require('node:fs'), vm=require('node:vm'), assert=require('node:assert/strict'), path=require('node:path');
const elements=new Map();
class Element {
    constructor(id='',attrs={}) {this.id=id;this.attrs=attrs;this.children=[];this.listeners={};this.value='';this.textContent='';this.dataset={};this._html='';this.classList={add(){},remove(){},toggle(){}};for(const [k,v] of Object.entries(attrs))if(k.startsWith('data-'))this.dataset[k.slice(5)]=v;}
    set innerHTML(value) {this._html=value;for(const c of this.children)if(c.id)elements.delete(c.id);this.children=[];for(const match of value.matchAll(/<[a-z][a-z0-9-]*\b([^>]*)>/gi)) {const attrs={};for(const a of match[1].matchAll(/([a-z][a-z0-9-]*)="([^"]*)"/gi))attrs[a[1]]=a[2];const c=new Element(attrs.id,attrs);if(c.id)elements.set(c.id,c);this.children.push(c);}}
    get innerHTML(){return this._html;}
    addEventListener(name,handler){this.listeners[name]=handler;}
    setAttribute(name,value){this.attrs[name]=value;}
    querySelectorAll(selector){return this.children.filter(e=>selector.startsWith('.')?(e.attrs.class||'').split(' ').includes(selector.slice(1)):selector.startsWith('[')?Object.hasOwn(e.attrs,selector.slice(1,-1)):false);}
    async fire(name){return this.listeners[name]?.({preventDefault(){},target:this});}
}
for(const id of ['app','login','login-form','login-error','logout','refresh','login-password','toggle-password','overview-page','alerts-page','setup-page','message','alert-count','breadcrumb'])elements.set(id,new Element(id));
const row=(id,status,severity='critical')=>({id,node:'server1',node_name:'aivid42',metric:'gpu_temperature:GPU-42',label:'GPU temperature',resource:'GPU-42',status,severity,opened_at:100,resolved_at:status==='closed'?200:null,duration_seconds:100,last_observed:150,value:94.5,timeline:[{id:'email-'+id,kind:'open',created_at:100,status:'sent',detail:'GPU hot',detail_delivery:'SMTP accepted'}],latest_delivery:'sent',delivery_pending:0});
const rows=[row('first','open'),row('second','open','warning'),...Array.from({length:30},(_,i)=>row('closed-'+i,'closed'))];
const summary={open:2,closed:30,all:32,unknown:0,critical:1,warning:1};let requests=[];
const state={incident_summary:summary,delivery_summary:{total:32,pending:0},active_incidents:2,leader:'server1',is_leader:true,nodes:[{id:'server1',name:'aivid42'}]};
const document={getElementById:id=>elements.get(id)||null,querySelectorAll:()=>[]};
const context=vm.createContext({document,URLSearchParams,console,Date,Math,Number,String,Set,FormData:class{},setInterval(){},window:{scrollTo(){}},confirm:()=>true,fetch:async url=>{
    if(url==='/api/session')return {ok:false,status:401,json:async()=>({detail:'Fixture login'})};
    const u=new URL(url,'https://fixture');requests.push(u);let items=rows.filter(r=>u.searchParams.get('status')==='all'||r.status===u.searchParams.get('status'));
    for(const k of ['node','severity'])if(u.searchParams.get(k))items=items.filter(r=>r[k]===u.searchParams.get(k));
    if(u.searchParams.get('q'))items=items.filter(r=>(r.node_name+' '+r.resource).includes(u.searchParams.get('q')));
    const total=items.length,offset=Number(u.searchParams.get('offset')),limit=Number(u.searchParams.get('limit'));
    return {ok:true,json:async()=>({items:items.slice(offset,offset+limit),offset,limit,total,summary})};
}});
const source=path.join(__dirname,'../backend/src/aivid_health/static');
vm.runInContext(fs.readFileSync(path.join(source,'incidents.js'),'utf8'),context);
vm.runInContext(fs.readFileSync(path.join(source,'app.js'),'utf8'),context);
const settle=async()=>{for(let i=0;i<10;i++)await Promise.resolve();};
let checks=0;const check=(name,condition)=>{assert(condition,name);checks++;console.log('PASS '+name);};
(async()=>{
    await settle();context.fixtureState=state;vm.runInContext('state=fixtureState;csrf="test";page="alerts";renderAlerts()',context);await settle();
    check('Open tab shows two unresolved incidents',elements.get('incident-results').innerHTML.match(/class="incident-row"/g).length===2);
    check('Sent email remains a separate label from Open',elements.get('incident-results').innerHTML.includes('Awaiting confirmed recovery')&&elements.get('incident-results').innerHTML.includes('sent'));
    check('Category counts match the response',elements.get('incident-open-total').textContent===2&&elements.get('incident-count-closed').textContent===30);
    await elements.get('alerts-page').querySelectorAll('[data-category]').find(e=>e.dataset.category==='closed').fire('click');await settle();
    check('Closed category displays confirmed recoveries',elements.get('incident-results').innerHTML.includes('Recovery confirmed')&&!elements.get('incident-results').innerHTML.includes('Awaiting confirmed recovery'));
    check('First closed page displays 25 of 30',elements.get('incident-list-status').textContent==='Showing 1–25 of 30 records');
    await elements.get('incident-next').fire('click');await settle();
    check('Next page displays the remaining five',elements.get('incident-list-status').textContent==='Showing 26–30 of 30 records');
    elements.get('incident-severity').value='warning';await elements.get('incident-filters').fire('submit');await settle();
    check('Filters reset pagination and show empty state',requests.at(-1).searchParams.get('offset')==='0'&&elements.get('incident-results').innerHTML.includes('No records match these filters'));
    await elements.get('incident-reset').fire('click');await settle();
    check('Clear filters restores closed results',elements.get('incident-list-status').textContent==='Showing 1–25 of 30 records');
    await elements.get('incident-results').querySelectorAll('.incident-expand')[0].fire('click');await settle();
    check('Details reveal notification timeline',elements.get('incident-results').innerHTML.includes('incident-timeline')&&elements.get('incident-results').innerHTML.includes('SMTP accepted'));
    context.hostileRow={...row('unsafe','open'),node_name:'<img src=x onerror=alert(1)>',resource:'<script>bad</script>',detail:'<b>unsafe</b>'};
    const safe=vm.runInContext('incidentTableRow(hostileRow)',context);
    check('User-controlled names and resource labels are escaped',!safe.includes('<img src=x')&&safe.includes('&lt;script&gt;bad&lt;/script&gt;'));
    check('Duration formatter supports long incidents',vm.runInContext('elapsed(90061)',context)==='1d 1h 1m');
    check('Dismissed email uses notification wording',vm.runInContext('deliveryTableRow({kind:"open",label:"CPU",status:"uncertain",id:"x",created_at:1,severity:"critical",attempts:1})',context).includes('Dismiss notification'));
    console.log(JSON.stringify({checks,result:'PASS',scope:'DOM fixture; no visual browser coverage'}));
})().catch(e=>{console.error(e);process.exitCode=1});
