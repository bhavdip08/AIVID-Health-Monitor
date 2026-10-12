"""Reproducible idle benchmark; reports CPU as percent of one logical CPU."""
import json
import os
from pathlib import Path
import statistics
import subprocess
import sys
import time
import psutil
from aivid_installer.cluster import make_cluster
from integration_cluster import free_port

root=Path(sys.argv[1]).resolve();root.mkdir(parents=True)
nodes=[{'id':f'server{i}','name':f'Server {i}','url':f'https://127.0.0.1:{free_port()}','priority':i} for i in range(1,6)]
make_cluster(root/'cluster',nodes)
for n in nodes:n['certificate']=(root/'cluster'/n['id']/'server.crt').read_text()
processes=[];handles=[]
try:
 for n in nodes:
  file=root/'cluster'/n['id']/'node.json';c=json.loads(file.read_text());c.update(nodes=nodes,metrics_seconds=30,history_seconds=60);file.write_text(json.dumps(c))
  log=(root/(n['id']+'.log')).open('w');handles.append(log)
  processes.append(subprocess.Popen([sys.executable,'-m','aivid_health.cli','serve','--config',str(file)],stdout=log,stderr=subprocess.STDOUT,env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1'}))
 print('Five monitors started; warming up for 20 seconds',flush=True)
 for _ in range(20):time.sleep(1)
 tracked=[]
 for n in nodes:
  config=str(root/"cluster"/n["id"]/"node.json")
  matches=[p for p in psutil.process_iter(["cmdline"]) if config in (p.info["cmdline"] or []) and "aivid_health.cli" in p.info["cmdline"]]
  if len(matches)!=1:raise RuntimeError("Cannot identify benchmark process in procfs: "+n["id"])
  tracked.append(matches[0])
 start=time.monotonic();before=[sum(p.cpu_times()[:2]) for p in tracked];rss=[[] for _ in tracked]
 for _ in range(60):
  time.sleep(1)
  for i,p in enumerate(tracked):rss[i].append(p.memory_info().rss/1024**2)
 elapsed=time.monotonic()-start
 report={'nodes':5,'seconds':elapsed,'sample_seconds':30,'peer_seconds':10,'gpu_cache_seconds':60,'history_seconds':60,
         'environment':{'platform':sys.platform,'python':sys.version.split()[0],'logical_cpus':psutil.cpu_count(),'gpu':'No NVIDIA hardware available','dashboard':'Closed'},
         'results':[{'node':nodes[i]['id'],'cpu_percent_one_core':round((sum(p.cpu_times()[:2])-before[i])/elapsed*100,3),'rss_mean_mib':round(statistics.mean(rss[i]),2),'rss_peak_mib':round(max(rss[i]),2)} for i,p in enumerate(tracked)]}
 (root/'results.json').write_text(json.dumps(report,indent=2));print(json.dumps(report),flush=True)
finally:
 for p in processes:
  p.terminate()
 for p in processes:
  try:p.wait(timeout=20)
  except subprocess.TimeoutExpired:p.kill();p.wait()
 for h in handles:h.close()
