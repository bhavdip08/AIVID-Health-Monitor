"""Local browser-test fixture; synthetic data, no collector or SMTP sender runs."""
import copy
import json
from pathlib import Path
import sys
import time

import uvicorn
from aivid_installer.cluster import make_cluster
from aivid_health.config import DEFAULT_SETTINGS
from aivid_health.web import create_app, password_hash


def fixture(root):
    nodes=[{'id':f'server{i+1}','name':name,'url':f'https://127.0.0.{i+1}:18828','priority':i+1}
           for i,name in enumerate(['aivid40','aivid42','devops'])]
    make_cluster(root/'cluster',nodes)
    path=root/'cluster/server1/node.json'
    data=json.loads(path.read_text());data.update(admin_password_hash=password_hash('BrowserTestOnly'),admin_password_chosen=True)
    path.write_text(json.dumps(data))
    app=create_app(path,start_engine=False);eng=app.state.engine;db=app.state.store
    eng.leader='server1';eng.deadline=time.monotonic()+7200;eng.quorum=3;eng.last_tick=time.time()
    sample={'sampled_at':time.time(),'cpu_percent':34.2,'memory_percent':51.7,'disks':[{'path':'/','disk_percent':46,'status':'ok'}],'gpu':{'status':'ok','devices':[]},'uptime_seconds':36000}
    eng.sample=sample
    for peer in eng.peers.values():peer.update(status='online',snapshot={'sample':sample},last_seen=time.time(),misses=0)
    record=db.record();record['settings']=copy.deepcopy(DEFAULT_SETTINGS);record['settings']['smtp']['enabled']=True
    record['settings']['branding']['customer_name']='AIVID Operations'
    now=time.time()
    def episode(node,metric,start,end=None,severity='warning',delivery='sent',value=88):
        e=eng.new_event(nodes[node-1],metric,'open',severity,f'{metric}: threshold exceeded')
        e.update(created_at=start,status=delivery,sender='server1',attempts=1,detail_delivery='SMTP accepted' if delivery=='sent' else 'SMTP result needs review',observed_value=value)
        record['events'].append(e)
        state={'active':end is None,'opened_at':start,'severity':severity if end is None else 'healthy','peak_severity':severity,'value':value,'last_observed':now-12}
        if end:
            recovery=eng.new_event(nodes[node-1],metric,'recovered','info',f'{metric}: confirmed healthy')
            recovery.update(created_at=end,status='sent',sender='server1',attempts=1,detail_delivery='SMTP accepted',observed_value=40)
            record['events'].append(recovery);state['resolved_at']=end
        record['incidents'][nodes[node-1]['id']+'/'+metric]=state
    episode(1,'gpu_temperature:GPU-6c4bafbd-5373-5239-5e2b-a7f4c06d1862',now-4620,severity='critical',value=93)
    episode(2,'disk_percent:/data',now-7320,severity='critical',delivery='uncertain',value=96.4)
    episode(3,'memory_percent',now-1230,value=87.1)
    for i in range(31):episode(2,'disk_percent:/archive/'+str(i),now-86400-i*8000,now-83400-i*8000)
    episode(1,'cpu_percent',now-18000,now-15200,severity='critical')
    test=eng.new_event(nodes[0],'email test','test','info','Administrator requested test email')
    test.update(status='sent',sender='server1',attempts=1,detail_delivery='SMTP accepted')
    record['events'].append(test);record['events'].sort(key=lambda e:e['created_at']);db.put('cluster_record',record)
    async def replicate(rec):db.put('cluster_record',rec);return True
    eng.replicate=replicate
    return app,eng.config


if __name__=='__main__':
    root=Path(sys.argv[1]);root.mkdir(parents=True)
    app,cfg=fixture(root)
    uvicorn.run(app,host='127.0.0.1',port=18828,ssl_certfile=str(cfg.cert),ssl_keyfile=str(cfg.key),log_level='warning')
