"""Actual HTTPS processes: dashboard pairing, variable membership and restart recovery."""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import time
import httpx
from aivid_health.web import password_hash
from aivid_installer.cluster import make_cluster
from integration_cluster import free_port


def run(root, release=None):
    root.mkdir(parents=True)
    processes, clients, tokens, logs, configs, pythons = {}, {}, {}, {}, {}, {}
    checks = []
    def check(name, ok=True):
        assert ok, name
        checks.append(name); print('PASS '+name, flush=True)
    def wait(fn, why, timeout=35):
        until = time.monotonic()+timeout; last=None
        while time.monotonic()<until:
            try:
                last=fn()
                if last: return last
            except Exception as e: last=str(e)
            time.sleep(.2)
        raise AssertionError(why+': '+str(last))
    def start(i):
        logs[i]=(root/f'node{i}.log').open('a')
        env={**os.environ, 'PYTHONDONTWRITEBYTECODE':'1'}
        if release: env.pop('PYTHONPATH',None)
        processes[i]=subprocess.Popen([str(pythons[i]),str(Path(__file__).with_name('listener_runner.py')),str(configs[i]),str(root/f'node{i}.binds.jsonl')],stdout=logs[i],stderr=subprocess.STDOUT,env=env)
        wait(lambda: clients[i].get('/readyz').status_code==200,'node ready')
        response=clients[i].post('/api/login',json={'username':'admin','password':'dashboard-test-password'})
        assert response.status_code==200, response.text
        tokens[i]=response.json()['csrf']
    def stop(i):
        processes[i].terminate(); processes[i].wait(timeout=20); logs[i].close()
    def get(i, path='/api/status'):return clients[i].get(path).json()
    def post(i,path,body):return clients[i].post(path,json=body,headers={'x-csrf-token':tokens[i]})
    try:
        for i in range(1,6):
            port=8282; url=f'https://127.0.0.{i+10}:{port}'; folder=root/f'generated{i}'
            make_cluster(folder,[{'id':f'server{i}','name':f'Server {i}','url':url,'priority':None}],interval=.5,timeout=.5,lease=4,offline_samples=2)
            file=folder/f'server{i}/node.json'; c=json.loads(file.read_text()); c.update(admin_password_hash=password_hash('dashboard-test-password'),admin_password_chosen=True,metrics_seconds=.5,listen=f'127.0.0.{i+10}',fixed_https_port=8282)
            file.write_text(json.dumps(c)); configs[i]=file; pythons[i]=Path(sys.executable)
            if release:
                prefix=root/f'installed{i}'
                env={k:v for k,v in os.environ.items() if k not in ('PYTHONPATH','LD_PRELOAD')}
                with (root/f'install{i}.log').open('w') as log:
                    subprocess.run(['bash',str(release/'install.sh'),'--config',str(file),'--prefix',str(prefix),'--no-systemd'],check=True,stdout=log,stderr=subprocess.STDOUT,env=env)
                configs[i]=prefix/'etc/aivid-health/node.json'; pythons[i]=prefix/'opt/aivid-health/current/venv/bin/python'
            clients[i]=httpx.Client(base_url=url,verify=ssl.create_default_context(cafile=str(folder/'cluster-ca.crt')),timeout=8,trust_env=False)
            start(i)
        wait(lambda:get(1)['is_leader'],'singleton sender')
        bindings=[json.loads(line) for i in range(1,6) for line in (root/f'node{i}.binds.jsonl').read_text().splitlines()]
        check('Five monitors each bind only TCP 8282',len(bindings)==5 and all(b['address'][1]==8282 and b['type']==socket.SOCK_STREAM for b in bindings))
        check('One-node dashboard works and can elect a resource-alert sender')
        check('Dashboard rejects a second port for pairing',post(1,'/api/setup/pair-code',{'url':'https://127.0.0.11:443'}).status_code==400)
        check('Directory rejects a different internal port before changing membership',post(1,'/api/setup/servers',{'node_id':'server1','name':'First','url':'https://127.0.0.11:8443','priority':None}).status_code==400 and not get(1)['membership']['pending'])
        import base64
        bare=post(2,'/api/setup/pair-code',{'url':'https://127.0.0.12'}).json()['code']
        decoded=json.loads(base64.urlsafe_b64decode(bare[7:]+'='*(-len(bare[7:])%4)))
        check('Bare peer addresses automatically use 8282',decoded['url']=='https://127.0.0.12:8282')
        decoded['url']='https://127.0.0.12'
        old_code='AIVID2.'+base64.urlsafe_b64encode(json.dumps(decoded).encode()).decode().rstrip('=')
        check('Old-port pairing codes rejected before sending the secret',post(1,'/api/setup/servers',{'pair_code':old_code,'name':'Old code','priority':None}).status_code==400 and len(get(1)['nodes'])==1)

        response=post(1,'/api/setup/local',{'gpu_required':False,'metrics_seconds':10})
        check('Automatic disks, GPU and collection settings saved through dashboard',response.status_code==200)
        check('Removed disk path field rejected',post(1,'/api/setup/local',{'disk_paths':['/does-not-exist-test'],'gpu_required':False,'metrics_seconds':10}).status_code==400)
        for i in range(2,6):
            wait(lambda:get(1)['is_leader'] and not get(1,'/api/setup')['membership']['pending'],'leader before pairing')
            code=post(i,'/api/setup/pair-code',{'url':str(clients[i].base_url)}).json()['code']
            result=post(1,'/api/setup/servers',{'pair_code':code,'name':f'Compute {i}','priority':None})
            check(f'Server {i} accepted through dashboard',result.status_code==200)
            if i==4:
                # Crash the coordinator after its durable prepare; restart resumes it.
                processes[1].kill();processes[1].wait();logs[1].close();start(1)
            wait(lambda:all(len(get(j)['nodes'])==i and not get(j)['membership']['pending'] for j in range(1,i+1)),f'{i}-node convergence',60)
            wait(lambda:get(1)['is_leader'],'priority leader after join',40)
            check(f'{i}-node membership converges over independent pinned HTTPS certificates')
            check(f'Server {i} code cannot add the same server twice',post(1,'/api/setup/servers',{'pair_code':code,'name':'duplicate','priority':9}).status_code==400)
            if i==2:
                stop(2)
                wait(lambda:not get(1)['is_leader'],'two-node quorum fencing')
                check('Two-node cluster pauses alert sending with one server offline')
                start(2);wait(lambda:get(1)['is_leader'],'two-node recovery')
            if i==4: check('Coordinator crash during a saved change resumes after restart')
        response=post(1,'/api/setup/servers',{'node_id':'server5','name':'GPU Worker','url':str(clients[5].base_url),'priority':1})
        check('Optional manual priority saved through dashboard',response.status_code==200)
        wait(lambda:all(any(n['name']=='GPU Worker' for n in get(j)['nodes']) and not get(j)['membership']['pending'] for j in range(1,6)),'directory edits converge')
        wait(lambda:get(5)['is_leader'],'explicit priority preferred over automatic',40)
        check('Manual priority takes precedence over automatic registration order')
        response=post(5,'/api/setup/servers',{'node_id':'server5','name':'GPU Worker','url':str(clients[5].base_url),'priority':None})
        check('Manual priority can be cleared back to automatic',response.status_code==200)
        wait(lambda:all(all(n['priority'] is None for n in get(j)['nodes']) and not get(j)['membership']['pending'] for j in range(1,6)),'automatic directory converges')
        wait(lambda:get(1)['is_leader'],'automatic first registered sender',40)
        check('All five dashboards restore automatic registration order')
        stop(1); stop(2)
        wait(lambda:get(3)['is_leader'],'five-node failure takeover',40)
        check('Five-node cluster elects third registered server with two servers down')
        stop(4)
        wait(lambda:not get(3)['is_leader'],'five-node minority fencing')
        check('Five-node minority of two cannot send alerts')
        start(1);start(2);start(4)
        wait(lambda:get(1)['is_leader'],'restored preferred sender',40)
        check('Membership and dashboard options survive process restart',len(get(1)['nodes'])==5 and get(1,'/api/setup')['metrics_seconds']==10)
        stop(5)
        r=post(1,'/api/setup/servers',{'node_id':'server1','name':'Changed','url':str(clients[1].base_url),'priority':1})
        check('Directory change blocked before freeze when an existing server is offline',r.status_code==400 and not get(1)['membership']['pending'])
        start(5)
        check('Remote history is fetched on demand',clients[1].get('/api/history/server5').status_code==200)
        check('No private TLS keys or shared secret exposed in dashboard status','PRIVATE KEY' not in clients[1].get('/api/status').text and 'peer_secret' not in clients[1].get('/api/setup').text)
        (root/'results.json').write_text(json.dumps({'checks':checks,'count':len(checks)},indent=2))
    finally:
        for i,p in processes.items():
            if p.poll() is None:
                p.terminate()
                try:p.wait(timeout=20)
                except subprocess.TimeoutExpired:p.kill();p.wait()
        for c in clients.values():c.close()
        for l in logs.values():l.close()

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('destination',type=Path);p.add_argument('--release',type=Path)
    a=p.parse_args();run(a.destination.resolve(),a.release.resolve() if a.release else None)
