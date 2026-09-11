"""Console HTTP layer: three tabs over the repo's CLIs, bound to loopback by default.

    python3 -m console --port 8010
    open http://127.0.0.1:8010/

Rails, because this is a control plane that runs mutating jobs:

- **loopback bind** unless `--allow-nonlocal` is passed explicitly.
- **Host/Origin checked** on every request: DNS rebinding would otherwise let a page in
  your browser drive a local endpoint that regenerates your database.
- **no free-form commands.** A job is an enum plus validated scalars; the argv in
  `console.ops` is what actually runs. There is no field that takes a URL, a shell
  string, a SQL fragment, or a path outside `var/`.
- **tokens are masked** in the dump viewer unless `reveal=1` is asked for.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import re
import sys
import threading
import time
import webbrowser
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

from load.accounts import main as accounts_main
from seeds import roster as roster_mod

from . import ops
from .settings import Settings, SettingsError, apply_updates
from .settings import load as load_settings
from .settings import save as save_settings

MAX_BODY = 64 * 1024
DUMP_NAME = re.compile(r"^accounts-[A-Za-z0-9._-]+\.txt$")

PAGE = """<!doctype html><meta charset=utf-8><title>signup fixture console</title>
<style>
:root{--bg:#0d1117;--panel:#161b22;--line:#21262d;--fg:#c9d1d9;--dim:#8b949e;--acc:#79c0ff;--ok:#3fb950;
--warn:#d29922;--bad:#f85149;--tag:#1f6feb22;--tagline:#1f6feb55}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.55 ui-monospace,SFMono-Regular,Menlo,monospace}
header{display:flex;align-items:baseline;gap:1rem;padding:16px 22px;border-bottom:1px solid var(--line);
position:sticky;top:0;background:var(--bg);z-index:5;flex-wrap:wrap}
h1{font-size:1.05rem;margin:0}
nav{display:flex;gap:.4rem;margin-left:auto}
nav button{background:var(--panel);color:var(--dim);border:1px solid var(--line);padding:.35rem .75rem;
border-radius:.4rem;font:inherit;cursor:pointer}
nav button.on{color:var(--fg);border-color:var(--acc);background:var(--tag)}
main{padding:18px 22px 60px;max-width:76rem}
section{display:none}section.on{display:block}
.card{background:var(--panel);border:1px solid var(--line);border-radius:.55rem;padding:14px 16px;margin:0 0 14px}
.card h2{font-size:.95rem;margin:0 0 .2rem}
.card h3{font-size:.82rem;margin:1rem 0 .3rem;color:var(--dim);text-transform:uppercase;letter-spacing:.04em}
p.hint{color:var(--dim);font-size:.82rem;margin:.15rem 0 .8rem}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(11rem,1fr));gap:.6rem .9rem}
label{display:block;font-size:.75rem;color:var(--dim);margin-bottom:.15rem}
input[type=number],input[type=text],input[type=checkbox],select{width:100%;background:#0d1117;color:var(--fg);
border:1px solid var(--line);border-radius:.35rem;padding:.32rem .4rem;font:inherit}
input[type=checkbox]{width:auto}
.row{display:flex;gap:.5rem;flex-wrap:wrap;align-items:center;margin-top:.8rem}
button.act{background:#238636;border:0;color:#fff;padding:.4rem .85rem;border-radius:.35rem;font:inherit;
cursor:pointer}
button.act.sec{background:#21262d;border:1px solid var(--line);color:var(--fg)}
button.act.warn{background:#9e6a03}
button.act:disabled{opacity:.45;cursor:not-allowed}
table{border-collapse:collapse;width:100%;margin:.5rem 0;font-size:.85rem}
th,td{text-align:left;padding:.28rem .6rem .28rem 0;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--dim);font-weight:400}
td.n,th.n{text-align:right}
.tag{background:var(--tag);border:1px solid var(--tagline);padding:0 .35rem;border-radius:.3rem;font-size:.78rem}
pre{background:#0d1117;border:1px solid var(--line);border-radius:.4rem;padding:.6rem .7rem;overflow:auto;
font-size:.8rem;max-height:16rem;margin:.4rem 0 0}
.kv{display:flex;gap:.45rem;flex-wrap:wrap;margin:.3rem 0 0}
.kv span{border:1px solid var(--line);border-radius:.3rem;padding:.05rem .4rem;font-size:.8rem;background:#0d1117}
.err{color:var(--bad)}.ok{color:var(--ok)}.warn{color:var(--warn)}
small{color:var(--dim)}
.tabs-note{border-left:3px solid var(--acc);padding:.1rem .7rem;margin:0 0 1rem;color:var(--dim);font-size:.82rem}
</style>
<header>
 <h1>signup fixture console</h1>
 <small id=stat>loading…</small>
 <nav>
  <button data-tab=gen class=on>Generator Mode</button>
  <button data-tab=ops>Operational Mode</button>
  <button data-tab=set>Settings</button>
 </nav>
</header>
<main>
<p class=tabs-note><b>Generator Mode</b> builds the accounts. <b>Operational Mode</b> drives them
(the two options: <i>server join</i> and <i>account token file</i>) against the mock API this console
starts. <b>Settings</b> holds the tool defaults both read. Everything is a loopback target and a
fixture database — there is no field for a URL, an invite link, or a database outside <code>var/</code>.</p>

<section id=gen class=on>
 <div class=card>
  <h2>Generate fixture accounts</h2>
  <p class=hint>Runs <code>python3 -m seeds.seed</code> with these numbers. Rows go to the settings
   <code>db</code>. <b>append</b> keeps every account already in the database and adds to it (the new names are
   appended to the account list too); <b>replace</b> truncates the tables first.</p>
  <div class=grid id=gen-fields></div>
  <h3>command it will run</h3><pre id=gen-cmd>…</pre>
  <div class=row>
   <button class=act data-job=generate>Generate accounts</button>
   <button class=act sec data-job=scan>Run abuse scan</button>
   <span id=gen-status></span>
  </div>
 </div>
 <div class=card>
  <h2>Export bulk artifacts</h2>
  <p class=hint>CSV in Postgres <code>\\copy</code> shape + JSONL + manifest, into <code>var/out</code>.
   Loaded into staging by <code>var/out/import.postgres.sql</code>.</p>
  <div class=grid>
   <div><label>tables</label><input type=text id=exp-tables value="users,credentials,servers,memberships"></div>
   <div><label>formats</label><input type=text id=exp-formats value="csv,jsonl"></div>
  </div>
  <div class=row><button class=act data-job=export>Export</button><span id=exp-status></span></div>
 </div>
 <div class=card><h2>What the database holds now</h2><div class=kv id=counts></div><pre id=gen-log>idle</pre></div>
</section>

<section id=ops>
 <div class=card>
  <h2>Target</h2>
  <p class=hint>The console owns this process: start it, drive it, stop it. <code id=api-url></code></p>
  <div class=kv id=api-kv></div>
  <div class=row><button class=act data-job=api-start>Start mock API</button>
   <button class=act sec data-job=api-stop>Stop</button><span id=api-status></span></div>
 </div>

 <div class=card>
  <h2>Option A — accounts info</h2>
  <p class=hint">Two files out of the account list: <code>user:pass</code> (the fixture's shared
   password) or <code>user:token</code> (a live session of the mock API above). Both are written
   next to the roster at <code>0600</code>, both are local-only, and neither is a credential for
   any service you do not run.</p>
  <div class=grid>
   <div><label>format</label><select id=info-kind>
     <option value=userpass>user:pass</option><option value=token>user:browser account token</option>
    </select></div>
   <div><label>from</label><select id=info-scope>
     <option value=roster>the account list only</option><option value=fixture>every active fixture account</option>
    </select></div>
   <div><label>max lines</label><input type=number id=info-limit value=0 min=0 max=200000
     title="0 = no cap"></div>
  </div>
  <div class=row><button class=act data-job=accounts-info>Write the file</button>
   <button class=act sec data-job=info-show>Show it (masked)</button>
   <button class=act warn data-job=info-revoke>Revoke those tokens</button><span id=info-status></span></div>
  <pre id=info-log>idle</pre>
  <h3>run dumps</h3>
  <p class=hint>Every load run also emits <code>accounts-&lt;stamp&gt;.txt</code> (worker identity + bearer).
   Those are what option B can join with, and what <code>--token-file</code> feeds back in.</p>
  <table id=dumps><tr><th>dump</th><th class=n>tokens</th><th>actions</th></tr></table>
 </div>

 <div class=card>
  <h2>Option B — server join</h2>
  <p class=hint">Joins <i>this fixture's</i> servers, chosen by id, through
   <code>POST /servers/&lt;id&gt;/join</code>. There is no link field: a URL here would point the
   tool at somebody else's room, and that part is not what this is for. Membership lands in
   <code>memberships</code>, so your own queries, member lists and moderation queue have something
   to chew on, and <i>Undo</i> is a button over the ids the join reported — not a timer.</p>
  <div class=grid>
   <div><label>server</label><select id=join-server></select></div>
   <div><label>accounts from</label><select id=join-source>
     <option value=roster>the account list (accounts.txt)</option>
     <option value=token-file>a run's token dump</option><option value=fixture-logins>newest fixture logins</option>
    </select></div>
   <div id=dump-row><label>token file</label><select id=join-dump></select></div>
   <div><label>how many join</label><input type=number id=join-limit value=5 min=1 max=2000></div>
   <div><label>pacing ms</label><input type=number id=join-pace value=0 min=0 max=60000></div>
  </div>
  <div class=row><button class=act data-job=join>Join server</button>
   <button class=act warn data-job=leave>Undo: those accounts leave</button>
   <span id=join-status></span></div>
  <pre id=join-log>idle</pre>
 </div>

 <div class=card>
  <h2>Load run</h2>
  <p class=hint>Stages and SLO come from Settings; the target is fixed to the loopback URL above.</p>
  <div class=row><button class=act data-job=load>Run load</button>
   <label style="display:inline"><input type=checkbox id=load-tokens checked> use newest token file</label>
   <span id=load-status></span></div>
  <pre id=load-log>idle</pre>
 </div>
</section>

<section id=set>
 <div class=card>
  <h2>Settings</h2>
  <p class=hint>Persisted to <code>var/console.json</code>, one file, same keys the Makefile exposes.
   Invalid values are refused with the reason, not coerced.</p>
  <div class=grid id=set-fields></div>
  <div class=row><button class=act data-job=save>Save</button>
   <button class=act sec data-job=reset>Reset to defaults</button><span id=set-status></span></div>
 </div>
 <div class=card>
  <h2>Account list <code id=roster-path></code></h2>
  <p class=hint>The list is a plain text file: one username (or email) per line. Edit it in any
   editor to pick which accounts the Operational tab may use, then <b>Sync</b> to delete the ones
   you removed — fixture rows go with them (credentials, sessions, events, memberships), and a
   server they owned is handed to a surviving account instead of vanishing. Sync is never a
   surprise: <b>Preview removal</b> prints the count first.</p>
  <div class=kv id=roster-kv></div>
  <div class=row><button class=act sec data-job=roster>Preview removal</button>
   <button class=act warn data-job=roster-sync>Sync: delete what the file omits</button>
   <button class=act sec data-job=roster-rewrite>Rewrite file from fixture</button>
   <button class=act sec data-job=roster-seed>Seed from newest accounts</button>
   <button class=act sec data-job=roster-show>View file</button><span id=roster-status></span></div>
  <pre id=roster-log>idle</pre>
 </div>
 <div class=card><h2>Recent jobs</h2><table id=jobs><tr><th>#</th><th>kind</th><th>state</th>
  <th class=n>secs</th><th>result</th></tr></table></div>
</section>
</main>
<script>
const S={settings:{},fixture:{},api:{},jobs:[]};
const FIELDS=[
 ["db","text"],["accounts_dir","text"],["users","number"],["days","number"],["seed","number"],
 ["bots","number"],["servers","number"],["events","number"],["hash_algo","select:sha256_fast,pbkdf2_sha256"],
 ["pbkdf2_iterations","number"],["min_password_length","number"],["register_domain","text"],
 ["test_password","text"],["write_mode","select:append,replace"],["account_list","text"],
 ["bootstrap_accounts","number"],
 ["api_port","number"],["console_port","number"],["stages","text"],["slo","text"],["warmup_seconds","number"],
 ["rate_limit_per_min","number"],["login_rate_limit_per_min","number"],["join_rate_limit_per_min","number"],
 ["max_inflight","number"],["block_disposable","bool"],["require_email_verify","bool"],["latency_ms","number"]];
const GEN=[["users","number"],["days","number"],["seed","number"],["bots","number"],["servers","number"],
 ["events","number"],["hash_algo","select"],["min_password_length","number"],["register_domain","text"],
 ["db","text"],["write_mode","select:append,replace"]];
const $=(s)=>document.querySelector(s);
function el(tag,attrs,kids){const n=document.createElement(tag);
 for(const k in attrs){if(k==='text')n.textContent=attrs[k];else if(k==='html')n.innerHTML=attrs[k];
  else n.setAttribute(k,attrs[k]);} (kids||[]).forEach(c=>n.appendChild(c));return n;}
function field(name,type,val,host){
 const w=el('div'),lab=el('label',{text:name});w.appendChild(lab);
 let i;
 if(type.startsWith('select')){i=el('select');
  (type.split(':')[1]?type.split(':')[1].split(','):[String(val)]).forEach(o=>i.appendChild(el('option',{value:o,text:o})));}
 else if(type==='bool'){i=el('input',{type:'checkbox'});i.checked=!!val;}
 else{i=el('input',{type:type==='number'?'number':'text'});if(val!==undefined&&val!==null)i.value=val;}
 i.id='f-'+name;i.dataset.name=name;w.appendChild(i);host.appendChild(w);return i;}
function renderGen(){const host=$('#gen-fields');host.innerHTML='';
 GEN.forEach(([n,t])=>{const type=t==='select'?'select:pbkdf2_sha256,sha256_fast':t;
  const i=field(n,type,S.settings[n],host);
  i.addEventListener('input',preview);i.addEventListener('change',preview);});preview();}
function body(){const out={};document.querySelectorAll('#gen-fields [data-name]').forEach(i=>{
 out[i.dataset.name]=i.type==='checkbox'?i.checked:i.value});return out;}
async function preview(){try{const r=await fetch('/api/preview',{method:'POST',
 headers:{'content-type':'application/json'},body:JSON.stringify(body())});
 const j=await r.json();$('#gen-cmd').textContent=j.command||j.error||'?';}catch(e){$('#gen-cmd').textContent='-'}}
function renderSet(){const host=$('#set-fields');host.innerHTML='';
 FIELDS.forEach(([n,t])=>field(n,t,S.settings[n],host));}
function fillSelect(sel,items,fmt){sel.innerHTML='';
 items.forEach(it=>sel.appendChild(el('option',{value:fmt[0](it),text:fmt[1](it)})));}
function counts(){const t=(S.fixture.tables||{});const host=$('#counts');host.innerHTML='';
 Object.keys(t).forEach(k=>host.appendChild(el('span',{text:k+': '+(t[k]<0?'—':t[k].toLocaleString())})));}
function renderOps(){
 $('#api-url').textContent=S.api.url||'';
 const R=(S.fixture||{}).roster||{};const rkv=$('#roster-kv');
 if(rkv){rkv.innerHTML='';
  [['file',R.path],['listed in file',R.listed],['in the fixture',R.in_fixture],
   ['not listed (Sync would delete)',R.unlisted_count||0],['names not in the fixture',(R.unknown||[]).length]]
   .forEach(([k,v])=>rkv.appendChild(el('span',{text:k+': '+(v===undefined?'-':v)})));
  const rp=$('#roster-path');if(rp)rp.textContent=R.path||'';}
 const jsrc=$('#join-source'),drow=$('#dump-row');
 if(drow)drow.style.display=(jsrc&&jsrc.value==='token-file')?'':'none';
 const kv=$('#api-kv');kv.innerHTML='';
 const bits=[['state',S.api.running?'running':'stopped']];
 if(S.api.metrics){bits.push(['requests',S.api.metrics.requests||0],['throttled',S.api.metrics.throttled||0],
  ['by status',JSON.stringify(S.api.metrics.by_status||{})]);}
 if(S.api.health&&S.api.health.users!==undefined)bits.push(['users',S.api.health.users]);
 bits.forEach(([k,v])=>kv.appendChild(el('span',{text:k+': '+v})));
 const servers=S.fixture.servers||[];
 fillSelect($('#join-server'),servers,[s=>s.id,s=>'#'+s.id+' '+s.name+'  ('+s.members+' members'+
  (s.capacity!=null?'/'+s.capacity:'')+(s.private?', private':'')+')']);
 if(!servers.length)$('#join-server').appendChild(el('option',{value:'',text:'no servers — generate first'}));
 const dumps=S.fixture.dumps||[];
 fillSelect($('#join-dump'),dumps,[d=>d.name,d=>d.name+'  ('+d.tokens+' tokens)']);
 if(!dumps.length)$('#join-dump').appendChild(el('option',{value:'',text:'none yet — run a load'}));
 const tbl=$('#dumps');tbl.innerHTML='<tr><th>dump</th><th class=n>tokens</th><th>actions</th></tr>';
 dumps.forEach(d=>{const tr=el('tr');
  tr.appendChild(el('td',{},[el('code',{text:d.name})]));
  tr.appendChild(el('td',{class:'n'},[el('span',{text:String(d.tokens)})]));
  const acts=el('td',{},[el('button',{class:'act sec',text:'view',onclick:()=>viewDump(d.name)}),
   el('span',{text:' '}),el('button',{class:'act warn',text:'revoke',onclick:()=>revoke(d.name)})]);
  tr.appendChild(acts);tbl.appendChild(tr);});
 if(!dumps.length)tbl.appendChild(el('tr',{},[el('td',{colspan:3,class:'err',text:'no token dumps in '+
  (S.settings.accounts_dir||'var/reports')})]));}
let lastJob=0;
function renderJobs(){const t=$('#jobs');t.innerHTML='<tr><th>#</th><th>kind</th><th>state</th><th class=n>secs</th>'
 +'<th>result</th></tr>';
 (S.jobs||[]).forEach(j=>{const tr=el('tr');
  tr.appendChild(el('td',{text:'#'+j.id}));tr.appendChild(el('td',{text:j.kind}));
  const cls=j.state==='failed'?'err':(j.state==='done'?'ok':'warn');
  tr.appendChild(el('td',{},[el('span',{class:cls,text:j.state+(j.code?'('+j.code+')':'')})]));
  tr.appendChild(el('td',{class:'n',text:String(j.seconds)}));
  tr.appendChild(el('td',{},[el('small',{text:JSON.stringify(j.result).slice(0,180)})]));
  t.appendChild(tr);
  if(j.id>lastJob)lastJob=j.id;});
 const running=(S.jobs||[]).filter(j=>j.state==='running'||j.state==='queued');
 $('#stat').textContent=(S.fixture&&S.fixture.fixture_hash?('fixture '+S.fixture.fixture_hash):'no fixture')+
  ' · '+(S.api.running?'api up':'api down')+(running.length?(' · '+running.length+' job(s) active'):'');
 document.querySelectorAll('[data-job]').forEach(b=>b.disabled=running.length>0);}
async function refresh(){try{const r=await fetch('/api/state');const j=await r.json();
 Object.assign(S,j);renderOps();renderJobs();counts();}catch(e){$('#stat').textContent='console offline'}}
function log(jobId,host){if(!jobId)return;const j=(S.jobs||[]).find(x=>x.id===jobId);if(!j)return;
 const res=j.result&&Object.keys(j.result).length?'\n» '+JSON.stringify(j.result):'';
 host.textContent=((j.log_tail||[]).join('\\n')||'…')+res;}
function pollJob(id,host){const tick=setInterval(async()=>{await refresh();
 const j=S.jobs.find(x=>x.id===id);if(j){log(id,host);
  if(j.state==='done'||j.state==='failed'){clearInterval(tick);
   host.className=j.state==='failed'?'err':'ok';}}},1200);refresh();}
async function viewDump(name){const r=await fetch('/api/dump?name='+encodeURIComponent(name));
 const t=await r.text();const w=window.open('','_blank');if(w){w.document.write(
 '<pre>'+t.replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'})[c])+'</pre>');}}
async function revoke(name){if(!confirm('revoke every session token in '+name+'?'))return;
 const r=await fetch('/api/revoke',{method:'POST',headers:{'content-type':'application/json'},
  body:JSON.stringify({name})});const j=await r.json();alert(j.output||j.error||'?');refresh();}
async function showText(url,host){const r=await fetch(url);const text=await r.text();
 $(host).textContent=text.split('\n').slice(0,240).join('\n');$(host).className='';}
async function submit(kind){const hosts={generate:'#gen-log',scan:'#gen-log',export:'#gen-log',join:'#join-log',
 leave:'#join-log',load:'#load-log','api-start':'#api-status','api-stop':'#api-status',
 'accounts-info':'#info-log','roster-revoke':'#info-log',roster:'#roster-log'};
 const payload={kind};
 if(kind==='roster')payload.params={action:'preview'};
 if(kind.startsWith('roster-')){const action=kind.split('-')[1];
  if(action==='show')return showText('/api/roster','#roster-log');payload.params={action};payload.kind='roster';}
 if(kind==='info-show')return showText('/api/roster?view='+$('#info-kind').value,'#info-log');
 if(kind==='info-revoke'){payload.kind='roster-revoke';payload.params={kind:$('#info-kind').value};}
 if(kind==='accounts-info')payload.params={kind:$('#info-kind').value,
  scope:$('#info-scope').value,limit:$('#info-limit').value};
 if(kind==='generate')payload.params=body();
 if(kind==='export')payload.params={tables:$('#exp-tables').value,formats:$('#exp-formats').value};
 if(kind==='join')payload.params={server_id:$('#join-server').value,source:$('#join-source').value,
  token_file:$('#join-dump').value,limit:$('#join-limit').value,pacing_ms:$('#join-pace').value};
 if(kind==='leave')payload.params={server_id:$('#join-server').value};
 if(kind==='join'&&$('#join-source').value!=='token-file')payload.params.token_file='';
 if(kind==='load')payload.params={use_tokens:$('#load-tokens').checked?'newest':''};
 const r=await fetch('/api/job',{method:'POST',headers:{'content-type':'application/json'},
  body:JSON.stringify(payload)});
 const j=await r.json();const host=$(hosts[kind]||'#gen-log');
 if(j.error){host.textContent=j.error;host.className='err';return;}
 host.textContent='queued #'+j.id;host.className='';pollJob(j.id,host);}
async function saveSettings(){const out={};
 document.querySelectorAll('#set-fields [data-name]').forEach(i=>{out[i.dataset.name]=
  i.type==='checkbox'?i.checked:i.value});
 const r=await fetch('/api/settings',{method:'POST',headers:{'content-type':'application/json'},
  body:JSON.stringify(out)});const j=await r.json();const s=$('#set-status');
 if(j.error){s.textContent=j.error;s.className='err';}else{s.textContent='saved to var/console.json';
  s.className='ok';await refresh();renderGen();}}
async function resetSettings(){const r=await fetch('/api/settings/reset',{method:'POST',
  headers:{'Content-Type':'application/json'},body:'{}'});const j=await r.json();
 if(!r.ok||j.error){$('#set-status').textContent=j.error||('http '+r.status);$('#set-status').className='err';return;}
 await refresh();renderSet();renderGen();$('#set-status').textContent='reset to defaults in '+j.saved;
 $('#set-status').className='ok';}
document.querySelectorAll('nav button').forEach(b=>b.addEventListener('click',()=>{
 document.querySelectorAll('nav button').forEach(x=>x.classList.remove('on'));b.classList.add('on');
 document.querySelectorAll('main section').forEach(s=>s.classList.remove('on'));
 $('#'+b.dataset.tab).classList.add('on');}));
document.addEventListener('click',(e)=>{const b=e.target.closest('[data-job]');if(!b)return;e.preventDefault();
 if(b.dataset.job==='save')return saveSettings();if(b.dataset.job==='reset')return resetSettings();
 submit(b.dataset.job);});
refresh().then(()=>{renderGen();renderSet();setInterval(refresh,2500);});
</script>
"""


class Handler(BaseHTTPRequestHandler):
    settings_path: Path
    server_version = "fixture-console/1.0"
    allow_nonlocal = False
    bind_host = "127.0.0.1"

    # ------------------------------------------------------------------ plumbing
    def log_message(self, fmt: str, *args: object) -> None:  # quiet by default
        if getattr(self.server.cfg, "verbose", False):  # type: ignore[attr-defined]
            # os.write(2, ...), not sys.stderr: a running job redirects sys.stderr into its
            # own log buffer, and access lines from *this* thread would be filed under it.
            os.write(2, ("console: " + (fmt % args) + "\n").encode())

    LOCAL_HOSTS = ("127.0.0.1", "localhost", "::1", "[::1]")

    def _guard(self) -> str:
        """Returns "" when the request may proceed, else the reason it may not.

        Blocks DNS rebinding: a page on another site must not be able to drive a local
        endpoint that truncates your database. The rule is on the *Host header*, not the
        socket — a rebinding attack arrives at a loopback socket with the attacker's
        hostname in Host, which is what the first check below rejects. `--allow-nonlocal`
        relaxes that check only, so an operator on a LAN they own can open the tab; the
        two browser signals stay on either way and cost a real operator nothing.
        """
        raw_host = self.headers.get("Host") or ""
        host = raw_host.split(":")[0].strip().lower().strip("[]")
        if not self.allow_nonlocal and host not in self.LOCAL_HOSTS and host != self.bind_host:
            return (f"Host must be 127.0.0.1:{self.server.server_address[1]} to reach this console "
                    f"(got {raw_host!r}); it runs jobs that rewrite your fixture")
        origin = self.headers.get("Origin")
        if origin and unquote(origin).rstrip("/") != f"http://{raw_host}".rstrip("/"):
            return f"Origin {origin!r} does not match Host {raw_host!r}"
        if (self.headers.get("Sec-Fetch-Site") or "").lower() == "cross-site":
            return "cross-site request refused (Sec-Fetch-Site: cross-site)"
        return ""

    def _send(self, status: int, payload: object, ctype: str = "application/json") -> None:
        body = payload.encode() if isinstance(payload, str) else json.dumps(payload, default=str).encode()
        self.send_response(status)
        self.send_header("Content-Type", f"{ctype}; charset=utf-8" if ctype != "text/plain" else ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'")
        self.end_headers()
        self.wfile.write(body)

    def _json_in(self) -> dict:
        ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        if ctype != "application/json":
            # a form POST from another site is the attack; a JSON body requires a
            # preflight, which the same-origin check above already gates
            raise ValueError("expected application/json")
        raw = self.rfile.read(min(MAX_BODY, int(self.headers.get("Content-Length") or 0)))
        if not raw:
            return {}
        data = json.loads(raw)
        if not isinstance(data, dict):
            raise ValueError("expected a JSON object")
        return data

    # --------------------------------------------------------------------- routes
    def do_GET(self) -> None:  # noqa: N802
        if (reason := self._guard()) != "":
            return self._send(403, {"error": reason})
        parts = urlsplit(self.path)
        if parts.path == "/":
            return self._send(200, PAGE, "text/html")
        if parts.path == "/api/state":
            return self._send(200, self._state())
        if parts.path == "/api/dump":
            return self._send(200, self._dump(parse_qs(parts.query)), "text/plain")
        if parts.path == "/api/roster":
            return self._send(200, self._roster_view(parse_qs(parts.query)), "text/plain")
        return self._send(404, {"error": "no such path",
                                "routes": "/ , /api/state, /api/dump, /api/roster, /api/job"})

    def do_POST(self) -> None:  # noqa: N802
        if (reason := self._guard()) != "":
            return self._send(403, {"error": reason})
        parts = urlsplit(self.path)
        try:
            payload = self._json_in()
        except (ValueError, json.JSONDecodeError) as exc:
            return self._send(400, {"error": str(exc)})
        if parts.path == "/api/settings":
            return self._send(*self._save_settings(payload))
        if parts.path == "/api/settings/reset":
            return self._send(*self._reset_settings())
        if parts.path == "/api/preview":
            return self._send(*self._preview(payload))
        if parts.path == "/api/job":
            return self._send(*self._job(payload))
        if parts.path == "/api/revoke":
            return self._send(*self._revoke(payload))
        return self._send(404, {"error": "no such path"})

    # ------------------------------------------------------------------ handlers
    def _settings_or_error(self) -> tuple[Settings | None, tuple[int, dict] | None]:
        """Returns `(settings, error)`; exactly one of the two is set.

        A corrupt settings file must be a 400 with the reason, never a dropped
        connection: the file is user-editable, so hand-editing var/console.json reaches
        this path, and a control plane that closes the socket teaches the user nothing.
        """
        try:
            return load_settings(self.settings_path), None
        except SettingsError as exc:
            return None, (400, {"error": f"settings file unreadable: {exc}"})

    def _state(self) -> dict:
        settings, err = self._settings_or_error()
        if err is not None or settings is None:
            return {"settings": {}, "fixture": {"error": (err or {}).get("error", ""), "tables": {},
                                                "servers": [], "dumps": [], "fixture_hash": ""},
                    "api": {"running": False}, "jobs": [], "busy": None}
        try:
            fixture = ops.fixture_status(settings)
        except Exception as exc:  # a half-written db must not blank the page
            fixture = {"db": settings.db, "error": f"{type(exc).__name__}: {exc}", "tables": {}, "servers": [],
                       "dumps": [], "fixture_hash": ""}
        return {"settings": settings.to_json_dict(), "fixture": fixture, "api": ops.API.status(settings),
                "jobs": ops.JOBS.snapshot(), "busy": ops.JOBS.busy()}

    def _save_settings(self, patch: dict) -> tuple[int, dict]:
        path = self.settings_path
        note = ""
        try:
            settings = load_settings(path)
        except SettingsError as exc:
            # A broken file has to stay fixable from the UI: the patch is applied to
            # defaults and replaces it, with the reason reported instead of a silent reset.
            settings, note = Settings(), f"previous file was unreadable ({exc}); defaults restored"
        try:
            merged = apply_updates(settings, patch)
        except SettingsError as exc:
            return 400, {"error": str(exc)}
        save_settings(path, merged)
        return 200, {"saved": str(path), "settings": merged.to_json_dict()} | ({"note": note} if note else {})

    def _reset_settings(self) -> tuple[int, dict]:
        save_settings(self.settings_path, Settings())
        return 200, {"saved": str(self.settings_path), "settings": Settings().to_json_dict()}

    def _preview(self, patch: dict) -> tuple[int, dict]:
        """What the Generate button will run, computed from the same validation the
        save path uses, so the preview cannot lie about the command."""
        settings, err = self._settings_or_error()
        if err is not None:
            return err
        try:
            merged = apply_updates(settings, {k: v for k, v in patch.items() if v not in (None, "")})
        except SettingsError as exc:
            return 400, {"error": str(exc)}
        return 200, {"command": "python3 -m seeds.seed " + " ".join(merged.base_argv())}

    def _roster_view(self, qs: dict) -> str:
        """The account list itself, or one of the two derived exports, secrets masked.

        There is no path parameter here on purpose: the file shown is always the one the
        settings name (plus its `-userpass`/`-tokens` siblings), so this cannot be pointed
        at an arbitrary file the way a `?file=` parameter would be.
        """
        settings, err = self._settings_or_error()
        if err is not None or settings is None:
            return f"refused: {err[1].get('error') if err else 'no settings'}"
        view = (qs.get("view") or [""])[0]
        if view and view not in ("userpass", "token"):
            return "refused: view must be userpass or token"
        path = ops.roster_export_path(settings, view) if view else Path(settings.account_list)
        if not path.exists():
            return f"no such file: {path}"
        reveal = (qs.get("reveal") or ["0"])[0] == "1"
        out = []
        for line in path.read_text().splitlines():
            if not line.strip():
                continue
            out.append(line if (line.startswith("#") or reveal) else roster_mod.mask(line))
        return "\n".join(out) + "\n"

    def _dump(self, qs: dict) -> str:
        name = (qs.get("name") or [""])[0]
        settings, err = self._settings_or_error()
        if err is not None or settings is None:
            return f"refused: {err[1].get('error') if err else 'no settings'}"
        if not DUMP_NAME.fullmatch(name):
            return "refused: name must look like accounts-<stamp>.txt (no path separators)"
        if name in ops.protected_names(settings):
            return f"refused: {name} is the account list or one of its exports, not a run dump"
        path = Path(settings.accounts_dir) / name
        if not path.exists():
            return f"no such dump: {name}"
        reveal = (qs.get("reveal") or ["0"])[0] == "1"
        out = []
        for line in path.read_text().splitlines():
            if not line.strip():
                continue
            if line.startswith("#") or reveal:
                out.append(line)
            else:
                head, _, _tail = line.partition("\t")
                out.append(f"{head}\t<token hidden; ?reveal=1 for the raw file>")
        return "\n".join(out) + "\n"

    def _revoke(self, payload: dict) -> tuple[int, dict]:
        name = str(payload.get("name") or "")
        settings, err = self._settings_or_error()
        if err is not None or settings is None:
            return err or (400, {"error": "settings unreadable"})
        if not DUMP_NAME.fullmatch(name):
            return 400, {"error": "refused: name must look like accounts-<stamp>.txt"}
        if name in ops.protected_names(settings):
            return 400, {"error": f"refused: {name} is the account list or one of its exports; "
                                  f"revoking its sessions is Option A > Revoke those tokens"}
        path = Path(settings.accounts_dir) / name
        if not path.exists():
            return 404, {"error": f"no such dump: {name}"}
        args = ["--revoke", str(path), "--db", settings.db]
        if payload.get("delete"):
            args.append("--delete")
        with contextlib.redirect_stdout(io.StringIO()) as cap, contextlib.redirect_stderr(io.StringIO()):
            code = accounts_main(args)
        out = cap.getvalue().strip()
        return (200 if code == 0 else 400), {"output": out or f"exit {code}"}

    def _job(self, payload: dict) -> tuple[int, dict]:
        kind = str(payload.get("kind") or "")
        params = payload.get("params") or {}
        settings, err = self._settings_or_error()
        if err is not None:
            return err
        try:
            fn = self._build(kind, params, settings)
        except (ValueError, RuntimeError) as exc:  # SettingsError is a ValueError
            return 400, {"error": str(exc)}
        job = ops.JOBS.submit(kind, fn)
        return 202, {"id": job.id, "kind": kind}

    def _build(self, kind: str, params: dict, settings: Settings) -> Callable[[ops.Job], dict]:
        def num(name: str, lo: int, hi: int, default: int = 0) -> int:
            raw = params.get(name, default)
            try:
                n = int(str(raw).strip())
            except (TypeError, ValueError):
                raise ValueError(f"{name} must be a whole number") from None
            if not lo <= n <= hi:
                raise ValueError(f"{name} must be between {lo} and {hi}")
            return n

        def name_or(key: str, default: str = "") -> str:
            text = str(params.get(key) or default).strip()
            if text and ("/" in text or "\\" in text or ".." in text):
                raise ValueError(f"{key} must be a file name inside the accounts dir, not a path")
            return text

        if kind == "generate":
            patched = apply_updates(settings, {k: v for k, v in params.items() if k != "unknown"})
            save_settings(self.settings_path, patched)
            return ops.job_generate(patched)
        if kind == "export":
            return ops.job_export(settings, str(params.get("tables") or "users,credentials"),
                                  str(params.get("formats") or "csv,jsonl"))
        if kind == "scan":
            return ops.job_scan(settings)
        if kind == "load":
            token_file = ""
            if str(params.get("use_tokens") or ""):
                dumps = ops.fixture_status(settings).get("dumps") or []
                if not dumps:
                    raise ValueError("no token dumps to reuse yet")
                token_file = dumps[0]["name"]
            return ops.job_load(settings, token_file)
        if kind == "api-start":
            return ops.job_start_api(settings)
        if kind == "api-stop":
            return ops.job_stop_api(settings)
        if kind == "join":
            source = str(params.get("source") or "roster")
            if source not in ("roster", "token-file", "fixture-logins"):
                raise ValueError("accounts must come from the roster file, a run's token dump, "
                                 "or fixture logins")
            return ops.job_join(settings, num("server_id", 1, 1_000_000), source,
                                 name_or("token_file"), num("limit", 1, 2000, 25),
                                 num("pacing_ms", 0, 60000))
        if kind == "accounts-info":
            which = str(params.get("kind") or "userpass")
            if which not in ("userpass", "token"):
                raise ValueError("format must be userpass or user:token")
            return ops.job_accounts_info(settings, which, num("limit", 0, 200_000),
                                         str(params.get("scope") or "roster") == "roster")
        if kind == "roster":
            action = str(params.get("action") or "preview")
            if action not in ("preview", "sync", "rewrite", "seed"):
                raise ValueError("roster action must be preview, sync, rewrite or seed")
            return ops.job_roster(settings, action)
        if kind == "roster-revoke":
            # the *format*, not a filename: the export's name is derived from wherever the
            # account list lives, so a renamed list keeps its own cleanup button working
            which = str(params.get("kind") or "")
            if which not in ("token", "userpass"):
                raise ValueError("nothing to revoke: pick which export to clean up "
                                 "(token or userpass) under Option A first")
            return ops.job_roster_revoke(settings, which)
        if kind == "leave":
            # the ids a join reported: an explicit undo, not a timer. Newest first, but the
            # newest join is often one that added nothing (a retry that came back
            # already-member), and "undo" then means the join that actually moved accounts.
            join_jobs = [j for j in ops.JOBS.snapshot(20) if j["kind"] == "join" and j["result"]]
            if not join_jobs:
                raise ValueError("nothing to undo: no join job has run in this session")
            target = next((j for j in join_jobs if (j["result"].get("joined_user_ids") or [])), None)
            if target is None:
                raise ValueError("nothing to undo: no join in this session created memberships "
                                 f"(the last one reported {join_jobs[0]['result'].get('counts')})")
            result = target["result"]
            ids = [int(u) for u in result["joined_user_ids"]]
            server_id = int(result.get("server_id") or num("server_id", 1, 1_000_000))
            return ops.job_leave(settings, server_id, ids, note=f"undo of join #{target['id']}")
        raise ValueError(f"unknown job {kind!r}; expected one of generate, export, scan, load, "
                         f"api-start, api-stop, join, leave, accounts-info, roster, roster-revoke")


def serve(port: int, host: str, settings_path: Path, verbose: bool = False,
          allow_nonlocal: bool = False) -> ThreadingHTTPServer:
    Handler.settings_path = settings_path
    Handler.bind_host = host
    Handler.allow_nonlocal = allow_nonlocal
    httpd = ThreadingHTTPServer((host, port), Handler)
    httpd.cfg = type("C", (), {"verbose": verbose})()  # type: ignore[attr-defined]
    httpd.daemon_threads = True
    return httpd


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m console",
                                description="generator / operational / settings tabs over this repo's CLIs")
    p.add_argument("--port", type=int, default=8010, help="port to listen on (default 8010); any free port works")
    p.add_argument("--host", default="127.0.0.1", help="loopback unless you mean otherwise")
    p.add_argument("--allow-nonlocal", action="store_true",
                   help="permit a non-loopback bind (the console runs mutating jobs; do this on a LAN you own). "
                        "Relaxes the Host-name check only: cross-origin and cross-site requests are still refused")
    p.add_argument("--settings", default="var/console.json")
    p.add_argument("--verbose", action="store_true", help="log each request")
    frozen = getattr(sys, "frozen", False)  # set by the PyInstaller build (build_exe.bat)
    # A double-clicked .exe has no place to type flags, so the two things a launcher would
    # pass are the defaults there. From source, both stay opt-in.
    p.add_argument("--bootstrap", action="store_true", default=frozen,
                   help="first-run setup: if the fixture db is missing, generate the "
                        "configured number of accounts (Settings > bootstrap_accounts) and "
                        "seed the account list from them")
    p.add_argument("--open-browser", action="store_true", default=frozen,
                   help="open the page once it is listening")
    a = p.parse_args(argv)

    if a.host not in ("127.0.0.1", "localhost", "::1") and not a.allow_nonlocal:
        print(f"refusing to bind {a.host}:{a.port}: the console runs mutating jobs.\n"
              "Pass --allow-nonlocal if this is a network you own.", file=sys.stderr)
        return 2
    path = Path(a.settings)
    if not path.exists():
        save_settings(path, Settings())
    try:
        settings = load_settings(path)
    except SettingsError as exc:
        print(f"{path}: {exc}", file=sys.stderr)
        return 2
    if a.bootstrap and not Path(settings.db).exists():
        # Double-clicking the tool should leave you with accounts to look at, not a form.
        n = max(1, settings.bootstrap_accounts)
        print(f"first run  generating {n} account(s) into {settings.db} (append mode keeps them from now on)")
        setup = settings if settings.users >= n else Settings(**{**settings.to_json_dict(), "users": n})
        code = ops.job_generate(setup)(ops.Job(id=0, kind="bootstrap"))
        if code.get("__code__"):
            print(f"refusing to serve: the generator exited {code.get('__code__')}: "
                  f"{str(code)[:200]}", file=sys.stderr)
            return 2
        roster = ops.job_roster(setup, "seed")(ops.Job(id=0, kind="roster-seed"))
        print(f"first run  account list: {roster.get('written')} listed -> {setup.account_list}")

    httpd = serve(a.port, a.host, path, verbose=a.verbose, allow_nonlocal=a.allow_nonlocal)
    url = f"http://{'127.0.0.1' if a.host in ('0.0.0.0', '::') else a.host}:{a.port}/"
    print(f"console   {url}   settings={path}")
    if a.open_browser:
        # after the socket is up, so the page never loads into a refused connection
        def _open() -> None:
            try:
                webbrowser.open(url)
            except Exception as exc:  # headless box, no handler, sandbox: the server is still up
                print(f"(could not open a browser: {type(exc).__name__}: {exc} — open {url})",
                      file=sys.stderr)

        threading.Timer(0.4, _open).start()
    if a.allow_nonlocal and a.host not in ("127.0.0.1", "localhost", "::1"):
        print(f"WARNING   bound to {a.host}: anyone who can reach port {a.port} can run these jobs. "
              "The loopback Host check is off; cross-site/cross-origin requests are still refused.",
              file=sys.stderr)
    print(f"fixture   {settings.db}   mock api target {settings.api_url()}")
    print("stop with Ctrl-C; the mock API it started stops with it")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopping")
    finally:
        if ops.API.running:
            ops.JOBS.submit("api-stop", ops.job_stop_api(settings))
            time.sleep(0.4)
        httpd.shutdown()
        httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
