"""Actual signed .run installation, permissions, chosen login, pairing and migration."""
import json, os, re, shutil, sqlite3, ssl, subprocess, sys, time
from pathlib import Path
import httpx
from aivid_installer.cluster import make_cluster
from aivid_health.web import password_hash
from integration_cluster import free_port
runfile=Path(sys.argv[1]).resolve();root=Path(sys.argv[2]).resolve();root.mkdir(parents=True)
env={k:v for k,v in os.environ.items() if k not in ('PYTHONPATH','LD_PRELOAD')};env['PYTHONDONTWRITEBYTECODE']='1';checks=[]
credentials=root/'test-credentials.json';credentials.write_text(json.dumps({'username':'aivid.ops','password':'Q7z#'}));credentials.chmod(0o600)
def check(name,ok):
 assert ok,name
 checks.append(name);print('PASS '+name,flush=True)
def install(prefix,*extra):
 log=root/(prefix.name+'-'+str(len(checks))+'.log')
 with log.open('w') as f:subprocess.run(['bash',str(runfile),'--prefix',str(prefix),'--no-systemd',*extra],stdin=subprocess.DEVNULL,stdout=f,stderr=subprocess.STDOUT,check=True,env=env,umask=0o077)
 return log.read_text()
fresh=root/'fresh';port=8282;result=install(fresh,'--address','https://127.0.0.1','--port',str(port),'--credentials-file',str(credentials))
file=fresh/'etc/aivid-health/node.json';c=json.loads(file.read_text())
check('Fresh .run uses chosen login and prints pairing code',len(c['nodes'])==1 and 'AIVID2.' in result and c['admin_username']=='aivid.ops' and c['admin_password_chosen'])
check('One fixed HTTPS port for installed configuration',c['port']==port and c['nodes'][0]['url']==f'https://127.0.0.1:{port}')
check('No plaintext login password is printed','Q7z#' not in result and 'Initial password:' not in result)
check('Metrics and history have light defaults',c['metrics_seconds']==30 and c['history_seconds']==60)
check('Data is under opt and disks are automatic',c['state_dir']==str(fresh/'opt/aivid-healthmonitor/data') and c['disk_mode']=='auto' and 'disk_paths' not in c)
check('Fresh priority is blank',c['nodes'][0]['priority'] is None)
check('Private config and public executable modes survive umask 077',file.stat().st_mode&0o777==0o640 and all((fresh/p).stat().st_mode&0o777==0o755 for p in ['opt/aivid-health','opt/aivid-health/releases','opt/aivid-health/current','opt/aivid-health/current/venv/bin/aivid-monitor']))
code=re.search(r'AIVID2\.[A-Za-z0-9_-]+',result)[0];python=fresh/'opt/aivid-health/current/venv/bin/python'
log=(root/'fresh-server.log').open('w');process=subprocess.Popen([str(python),str(Path(__file__).with_name('listener_runner.py')),str(file),str(root/'fresh.binds.jsonl')],stdout=log,stderr=subprocess.STDOUT,env=env)
client=httpx.Client(base_url=c['nodes'][0]['url'],verify=ssl.create_default_context(cafile=str(file.parent/c['ca_file'])),timeout=2,trust_env=False)
try:
 for _ in range(100):
  try:
   if client.get('/readyz').status_code==200:break
  except httpx.HTTPError:pass
  time.sleep(.1)
 else:raise AssertionError('installed runtime not ready')
 login=client.post('/api/login',json={'username':'aivid.ops','password':'Q7z#'})
 check('Chosen login works immediately over HTTPS',login.status_code==200 and not login.json()['must_change'])
 listeners=[b['address'][1] for b in map(json.loads,(root/'fresh.binds.jsonl').read_text().splitlines())]
 check('Installed daemon opens exactly one TCP listener on 8282',listeners==[8282])
 check('Dashboard and pairing share the same verified HTTPS listener',client.get('/').status_code==200 and client.get('/api/setup').json()['listen_port']==8282)
 check('Dashboard pairing code matches installer',client.get('/api/setup/pair-code').json()['code']==code)
 repeated=install(fresh)
 check('Same-build rerun retains login config and pairing code','already installed' in repeated and json.loads(file.read_text())==c and code in repeated)
finally:client.close();process.terminate();process.wait(timeout=25);log.close()
partial=root/'partial';conf=partial/'etc/aivid-health';conf.mkdir(parents=True)
nodes=[{'id':f'server{i}','name':f'Server {i}','url':f'https://127.0.0.{i+20}','priority':i} for i in range(1,4)];make_cluster(root/'old-setup',nodes)
for p in (root/'old-setup/server1').iterdir():
 if p.name!='credentials.txt':shutil.copy(p,conf/p.name)
f=conf/'node.json';old=json.loads(f.read_text());old.update(admin_username='saved.ops',admin_password_hash=password_hash('previous-chosen-password'),admin_password_chosen=True);f.write_text(json.dumps(old));install(partial);new=json.loads(f.read_text())
check('Unfinished installation recovers as one node',len(new['nodes'])==1 and new['node_id']=='server1')
check('Recovery retains chosen login',new['admin_password_hash']==old['admin_password_hash'] and new['admin_username']=='saved.ops')
check('Recovery backs up original configuration',json.loads((conf/'node.before-dashboard.json').read_text())==old)
upgrade=root/'upgrade';conf=upgrade/'etc/aivid-health';conf.mkdir(parents=True)
for p in (root/'old-setup/server2').iterdir():
 if p.name!='credentials.txt':shutil.copy(p,conf/p.name)
f=conf/'node.json';c=json.loads(f.read_text());state=upgrade/'var/lib/aivid-health';state.mkdir(parents=True);c.update(state_dir=str(state),admin_password_chosen=True);f.write_text(json.dumps(c))
release=upgrade/'opt/aivid-health/releases/previous';release.mkdir(parents=True);(release/'release.json').write_text(json.dumps({'build_id':'previous'}));(release.parent.parent/'current').symlink_to(release)
with sqlite3.connect(state/'monitor.sqlite3') as db:
 db.execute('CREATE TABLE kv (key TEXT PRIMARY KEY,value TEXT NOT NULL)');db.execute('CREATE TABLE history (ts REAL NOT NULL,node TEXT NOT NULL,data TEXT NOT NULL)')
 db.execute('INSERT INTO kv VALUES (?,?)',('admin',json.dumps({'username':'retained.ops','password_hash':password_hash('retained-password'),'must_change':False})));db.execute('INSERT INTO history VALUES (1,?,?)',('server2','{"cpu_percent":12}'));db.execute('INSERT INTO kv VALUES (?,?)',('config_override',json.dumps({'metrics_seconds':90,'nodes':nodes,'port':443})))
upgrade_output=install(upgrade);new=json.loads(f.read_text());newstate=Path(new['state_dir'])
from aivid_health.config import Config
effective=Config(f)
with sqlite3.connect(newstate/'monitor.sqlite3') as db:effective.apply(json.loads(db.execute("SELECT value FROM kv WHERE key='config_override'").fetchone()[0]))
check('Upgrade applies 8282 to saved dashboard peer overrides',effective.data['port']==8282 and all(n['url'].endswith(':8282') for n in effective.nodes) and 'Dashboard: https://127.0.0.22:8282' in upgrade_output)
with sqlite3.connect(newstate/'monitor.sqlite3') as db:
 check('Upgrade migrates history into opt',db.execute('SELECT COUNT(*) FROM history').fetchone()[0]==1)
 check('Upgrade preserves saved login and settings',json.loads(db.execute("SELECT value FROM kv WHERE key='admin'").fetchone()[0])['username']=='retained.ops' and json.loads(db.execute("SELECT value FROM kv WHERE key='config_override'").fetchone()[0])['metrics_seconds']==90)
check('Upgrade retains membership and original database',len(new['nodes'])==3 and (state/'monitor.sqlite3').exists())
upgrade_python=upgrade/'opt/aivid-health/current/venv/bin/python'
upgrade_log=(root/'upgrade-server.log').open('w')
process=subprocess.Popen([str(upgrade_python),str(Path(__file__).with_name('listener_runner.py')),str(f),str(root/'upgrade.binds.jsonl')],stdout=upgrade_log,stderr=subprocess.STDOUT,env=env)
client=httpx.Client(base_url=effective.local['url'],verify=ssl.create_default_context(cafile=str(f.parent/new['ca_file'])),timeout=2,trust_env=False)
try:
 for _ in range(100):
  try:
   if client.get('/readyz').status_code==200:break
  except httpx.HTTPError:pass
  time.sleep(.1)
 else:raise AssertionError('upgraded runtime not ready on 8282')
 login=client.post('/api/login',json={'username':'retained.ops','password':'retained-password'})
 check('Retained dashboard login works on 8282 after upgrade',login.status_code==200)
 setup=client.get('/api/setup').json()
 check('Upgraded dashboard advertises only 8282 for all saved peers',setup['listen_port']==8282 and all(n['url'].endswith(':8282') for n in setup['nodes']))
 check('Upgraded daemon has no legacy or additional listener',[b['address'][1] for b in map(json.loads,(root/'upgrade.binds.jsonl').read_text().splitlines())]==[8282])
finally:client.close();process.terminate();process.wait(timeout=25);upgrade_log.close()

low=root/'low';file=root/'old-setup/server3/node.json';c=json.loads(file.read_text());c['port']=443;file.write_text(json.dumps(c));install(low,'--config',str(file));unit=(low/'etc/systemd/system/aivid-health.service').read_text()
check('Old 443 configuration migrates to 8282 without privileged bind capability',json.loads((low/'etc/aivid-health/node.json').read_text())['port']==8282 and 'CAP_NET_BIND_SERVICE' not in unit and 'CapabilityBoundingSet=\n' in unit)
check('Unit writes in new data directory','ReadWritePaths='+str(low/'opt/aivid-healthmonitor/data') in unit and '/var/lib/aivid-health' not in unit)
(root/'results.json').write_text(json.dumps({'checks':checks,'count':len(checks)},indent=2))
