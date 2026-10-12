"""Install the previous .run, seed legacy data, upgrade, and check installed wheels.

Runs only in a supplied isolated prefix with --no-systemd. No production paths
or SMTP servers are used. Invoke: python tests/integration_incident_upgrade.py
OLD.run NEW.run NEW_OUTPUT_DIRECTORY
"""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import time

from aivid_health.config import Config, DEFAULT_SETTINGS
from aivid_health.engine import Engine
from aivid_health.store import Store

old_run,new_run,root=map(lambda x:Path(x).resolve(),sys.argv[1:])
root.mkdir(parents=True)
prefix=root/'host';checks=[]
env={k:v for k,v in os.environ.items() if k not in ('PYTHONPATH','LD_PRELOAD')}
env['PYTHONDONTWRITEBYTECODE']='1'
credentials=root/'credentials.json';credentials.write_text(json.dumps({'username':'retained.ops','password':'TestOnlyUpgrade'}));credentials.chmod(0o600)
def check(name,ok=True):
    assert ok,name
    checks.append(name);print('PASS '+name,flush=True)
def install(runfile,label,*args):
    with (root/(label+'.log')).open('w') as log:
        subprocess.run(['bash',str(runfile),'--prefix',str(prefix),'--no-systemd',*args],env=env,stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT,check=True)
install(old_run,'old-install','--address','https://127.0.0.1','--credentials-file',str(credentials))
current=prefix/'opt/aivid-health/current';old_target=current.resolve()
file=prefix/'etc/aivid-health/node.json';cfg=Config(file)
identity={k:cfg.data[k] for k in ('node_id','peer_secret','encryption_key','admin_password_hash')}
certificates={p.name:p.read_bytes() for p in file.parent.iterdir() if p.suffix in ('.crt','.key')}
db=Store(cfg.state_dir/'monitor.sqlite3',cfg.lease_ttl);record=db.record();now=time.time()
record['settings']=copy.deepcopy(DEFAULT_SETTINGS)
record['settings']['smtp'].update(host='smtp.example.test',username='saved@example.test',password_encrypted=cfg.encrypt('TestOnlySavedSMTP'),sender='health@example.test',recipients=['ops@example.test'])
record['settings']['branding']['customer_name']='Saved customer'
record['settings']['email']['subject']='Saved subject {server_name}'
record['settings']['thresholds']['cpu_percent']={'warning':86,'critical':96}
events=[]
for kind,metric,age,severity in [('open','cpu_percent',600,'warning'),('escalated','cpu_percent',300,'critical'),('open','disk_percent:/',900,'warning'),('recovered','disk_percent:/',700,'info')]:
    e=Engine.new_event(cfg.local,metric,kind,severity,'Saved history')
    e.update(created_at=now-age,status='sent',sender=cfg.node_id,attempts=1,detail_delivery='SMTP accepted')
    events.append(e)
record['events']=sorted(events,key=lambda e:e['created_at'])
record['incidents']={cfg.node_id+'/cpu_percent':{'active':True,'severity':'critical','opened_at':now-300,'bad':3,'good':0},cfg.node_id+'/disk_percent:/':{'active':False,'severity':'healthy','opened_at':now-900,'resolved_at':now-700,'bad':0,'good':2}}
db.put('cluster_record',record)
db.put('config_override',{'metrics_seconds':90})
db.close()
unrelated=prefix/'opt/existing-application/keep.txt';unrelated.parent.mkdir(parents=True);unrelated.write_bytes(b'UNRELATED SOFTWARE MUST REMAIN UNCHANGED\n')
install(new_run,'new-install')
check('New build activates and retains previous release',current.resolve()!=old_target and old_target.is_dir())
newcfg=Config(file)
check('Node identity, encryption key and chosen login preserved',all(newcfg.data[k]==v for k,v in identity.items()))
check('TLS keys and certificates preserved',all((file.parent/name).read_bytes()==raw for name,raw in certificates.items()))
check('Unrelated application sentinel unchanged',unrelated.read_bytes()==b'UNRELATED SOFTWARE MUST REMAIN UNCHANGED\n')
db=Store(newcfg.state_dir/'monitor.sqlite3',newcfg.lease_ttl)
check('Legacy incident ledger, notifications, SMTP, branding and thresholds preserved exactly',db.record()==record)
check('Saved local collection setting preserved',db.get('config_override')['metrics_seconds']==90)
check('Saved SMTP password remains decryptable',newcfg.decrypt(db.record()['settings']['smtp']['password_encrypted'])=='TestOnlySavedSMTP')
db.close()
verify=root/'verify-installed.py'
verify.write_text('''import asyncio,json,sys
import httpx
from aivid_health import __version__
from aivid_health.web import create_app
async def run():
 app=create_app(sys.argv[1],start_engine=False)
 async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='https://127.0.0.1:8282') as c:
  login=await c.post('/api/login',json={'username':'retained.ops','password':'TestOnlyUpgrade'})
  assert login.status_code==200
  status=(await c.get('/api/status')).json()
  assert __version__=='1.1.0' and status['version']=='1.1.0'
  assert status['active_incidents']==1 and status['incident_summary']['closed']==1
  opened=(await c.get('/api/incidents?status=open')).json()['items']
  assert len(opened)==1 and opened[0]['severity']=='critical' and len(opened[0]['timeline'])==2
  assert opened[0]['opened_at']==opened[0]['timeline'][0]['created_at']
  assert all(e['status']=='sent' for e in opened[0]['timeline'])
  closed=(await c.get('/api/incidents?status=closed')).json()['items']
  assert len(closed)==1 and closed[0]['duration_seconds']==200
  html=(await c.get('/')).text
  assert 'Health Monitor 1.1.0' in html and '/static/incidents.js' in html
  assert (await c.get('/static/incidents.js')).status_code==200
 await app.state.engine.close();app.state.store.close()
 print('Installed API and dashboard assets verified')
asyncio.run(run())
''')
python=current/'venv/bin/python'
subprocess.run([str(python),str(verify),str(file)],check=True,env=env)
check('Installed 1.1.0 API classifies legacy Open and Closed correctly and serves new assets')
subprocess.run([str(python),str(Path(__file__).with_name('test_mail_transport.py')),'-q'],check=True,env=env)
check('All five email wire-format regressions pass against installed wheel')
install(new_run,'repeat-install')
check('Same-build rerun succeeds without resetting data','already installed' in (root/'repeat-install.log').read_text())
(root/'results.json').write_text(json.dumps({'checks':checks,'count':len(checks),'result':'PASS'},indent=2))
