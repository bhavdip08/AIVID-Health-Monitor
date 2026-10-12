"""Real three-process HTTPS/SQLite/SMTP acceptance tests, no external email.

Pass --release /path/to/extracted/release to prepare and install three clean
nodes from the actual signed archive before exercising the installed wheels.
"""
from __future__ import annotations
import copy
from email import policy
from email.parser import Parser
import base64
import json
import os
from pathlib import Path
import socket
import socketserver
import ssl
import subprocess
import sys
import tempfile
import threading
import time

import httpx
from aivid_installer.cluster import make_cluster


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class SMTP(socketserver.StreamRequestHandler):
    def handle(self):
        def reply(text):
            self.wfile.write(text.encode() + b"\r\n"); self.wfile.flush()
        try:
            reply("220 local acceptance-test SMTP")
            while line := self.rfile.readline():
                command = line.decode(errors="replace").strip().upper()
                if command.startswith(("EHLO", "HELO")):
                    reply("250 local-test")
                elif command.startswith(("MAIL", "RCPT", "RSET", "NOOP")):
                    reply("250 OK")
                elif command == "DATA":
                    reply("354 End with a dot")
                    data = []
                    while (line := self.rfile.readline()) not in (b".\r\n", b".\n", b""):
                        data.append(line)
                    self.server.messages.append(b"".join(data).decode(errors="replace"))
                    self.server.received.set()
                    if self.server.hold:
                        self.server.release.wait(12)
                    reply("250 accepted")
                elif command == "QUIT":
                    reply("221 bye"); return
                else:
                    reply("502 unknown")
        except (BrokenPipeError, ConnectionResetError):
            pass


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def run_tests(root, release=None, deny_network=None, automatic=False):
    root.mkdir(parents=True, exist_ok=True)
    smtp = Server(("127.0.0.1", 0), SMTP)
    smtp.messages = []; smtp.hold = False; smtp.release = threading.Event(); smtp.received = threading.Event()
    threading.Thread(target=smtp.serve_forever, daemon=True).start()
    ports = [8282] * 3
    nodes = [{"id": f"server{i+1}", "name": f"Server {i+1}", "url": f"https://127.0.0.{i+21}:{ports[i]}", "priority": None if automatic else i+1} for i in range(3)]
    config_dir = root / "cluster"
    runtime_env = {k:v for k,v in os.environ.items() if k not in ("PYTHONPATH", "LD_PRELOAD")} if release else dict(os.environ)
    installed = {}
    if release:
        install_env = dict(runtime_env)
        if deny_network:
            install_env["LD_PRELOAD"] = str(deny_network)
        with (root / "prepare.log").open("w") as log:
            subprocess.run(["bash",str(release / "prepare-cluster.sh"), *[x for n in nodes for x in ("--node",n["id"]+"="+n["url"])],"--output",str(config_dir)],check=True,env=install_env,stdout=log,stderr=subprocess.STDOUT)
        # Accelerate failure timing only in these private test configurations.
        for i in range(1,4):
            f=config_dir / f"server{i}/node.json"
            c=json.loads(f.read_text());c["nodes"]=nodes;c.update(interval_seconds=.5,peer_timeout_seconds=.3,lease_seconds=4,offline_samples=2,listen=f"127.0.0.{i+20}",fixed_https_port=8282)
            f.write_text(json.dumps(c))
            prefix=root/f"installed{i}"
            with (root/f"install{i}.log").open("w") as log:
                subprocess.run(["bash",str(release/"install.sh"),"--config",str(f),"--prefix",str(prefix),"--no-systemd"],check=True,env=install_env,stdout=log,stderr=subprocess.STDOUT)
            installed[i] = (prefix/"opt/aivid-health/current/venv/bin/python", prefix/"etc/aivid-health/node.json")
            print(f"PASS clean offline installation of server{i}",flush=True)
    else:
        make_cluster(config_dir, nodes, interval=.5, timeout=.3, lease=4, offline_samples=2)
    if not release:
        for i in range(1,4):
            file=config_dir/f"server{i}/node.json"; c=json.loads(file.read_text()); c.update(listen=f"127.0.0.{i+20}",fixed_https_port=8282); file.write_text(json.dumps(c))
    processes, logs, clients, csrf = {}, {}, {}, {}
    checks = []
    if release:
        checks.extend({"check":f"clean offline archive installation server{i}","result":"PASS"} for i in range(1,4))
    runner = Path(__file__).with_name("node_runner.py")
    for i in range(1, 4):
        (root / f"control{i}.json").write_text("{}")
        clients[i] = httpx.Client(base_url=nodes[i-1]["url"], verify=ssl.create_default_context(cafile=str(config_dir / "cluster-ca.crt")), timeout=2, trust_env=False)

    def start(i):
        logs[i] = open(root / f"server{i}.log", "a")
        python,config = installed.get(i,(sys.executable,config_dir/f"server{i}/node.json"))
        processes[i] = subprocess.Popen([str(python), str(runner), str(config), str(root / f"control{i}.json")], stdout=logs[i], stderr=subprocess.STDOUT, env={**runtime_env, "PYTHONDONTWRITEBYTECODE": "1"})

    def stop(i):
        if i in processes and processes[i].poll() is None:
            processes[i].kill(); processes[i].wait(timeout=5)
        if i in logs:
            logs[i].close()

    def until(label, predicate, timeout=20):
        start_time = time.time(); last = None
        while time.time() - start_time < timeout:
            try:
                value = predicate()
                if value:
                    checks.append({"check": label, "result": "PASS", "seconds": round(time.time()-start_time, 2)})
                    print("PASS", label, flush=True)
                    return value
            except (httpx.HTTPError, KeyError, AssertionError) as exc:
                last = type(exc).__name__
            time.sleep(.15)
        raise AssertionError(label + " timed out " + str(last))

    def status(i):
        r = clients[i].get("/api/status"); r.raise_for_status(); return r.json()

    def post(i, url, payload):
        r = clients[i].post(url, json=payload, headers={"x-csrf-token": csrf[i]}); r.raise_for_status(); return r.json()

    def event(i, node, metric, kind):
        return [e for e in status(i)["events"] if e["node"] == node and e["metric"] == metric and e["kind"] == kind]

    def incidents(i, category, node=None, metric=None):
        response = clients[i].get('/api/incidents', params={'status': category})
        response.raise_for_status()
        return [r for r in response.json()['items'] if (node is None or r['node'] == node) and (metric is None or r['metric'] == metric)]

    try:
        for i in range(1,4): start(i)
        for i in range(1,4):
            until(f"server{i} verified TLS and readiness", lambda i=i: clients[i].get("/readyz").status_code == 200)
            password=(config_dir / f"server{i}/credentials.txt").read_text().split("Initial password: ")[1].splitlines()[0]
            r=clients[i].post("/api/login",json={"username":"admin","password":password});r.raise_for_status();csrf[i]=r.json()["csrf"]
            post(i,"/api/password",{"current":password,"new":"IntegrationPassword123"})
            r=clients[i].post("/api/login",json={"username":"admin","password":"IntegrationPassword123"});r.raise_for_status();csrf[i]=r.json()["csrf"]
        until("priority 1 elected with all three nodes online",lambda: status(1)["is_leader"] and all(n["status"]=="online" for n in status(1)["nodes"]))
        settings=clients[1].get("/api/settings").json()
        settings["smtp"].update(enabled=True,host="127.0.0.1",port=smtp.server_address[1],security="plain",sender="monitor@example.com",recipients=["ops@example.com"])
        settings['email']['offline_subject']='Customer offline | {server_name} | {sender_name}'
        settings['branding']['customer_name']='Acceptance Customer'
        logo=Path(__import__('aivid_health').__file__).with_name('static').joinpath('aivid-logo.png').read_bytes()
        settings['branding']['customer_logo']={'data':base64.b64encode(logo).decode(),'mime':'image/png'}
        post(1,"/api/settings",settings)
        until("SMTP settings replicated to both followers",lambda: all(status(i)["smtp_enabled"] for i in (2,3)))
        until("email design and both brands replicated to followers",lambda:all(clients[i].get('/api/settings').json()['branding']==settings['branding'] and clients[i].get('/api/settings').json()['email']==settings['email'] for i in (2,3)))
        test=post(1,"/api/test-email",{})
        until("real local SMTP test accepted",lambda: any(e["id"]==test["event_id"] and e["status"]=="sent" for e in status(1)["events"]))
        setup=clients[1].get("/api/setup").json()
        assert setup["smtp_enabled"] and setup["last_test"]["id"]==test["event_id"] and setup["last_test"]["status"]=="sent"
        checks.append({"check":"Setup page reports the accepted SMTP test","result":"PASS"})
        assert len(smtp.messages)==1
        checks.append({"check":"exactly one SMTP test message","result":"PASS"})

        stop(2)
        until("server 2 outage delivered by server 1",lambda: any(e["status"]=="sent" and e.get("sender")=="server1" for e in event(1,"server2","availability","open")))
        until("sent outage remains Open on both surviving dashboards",lambda:all(len(incidents(i,'open','server2','availability'))==1 for i in (1,3)))
        outage_incident = incidents(1,'open','server2','availability')[0]['id']
        time.sleep(1)
        outage=event(1,"server2","availability","open")
        assert len(outage)==1 and sum(outage[0]["id"] in m for m in smtp.messages)==1
        checks.append({"check":"server 3 does not duplicate server 2 outage email","result":"PASS"})
        start(2)
        until("server 2 recovery delivered once",lambda: any(e["status"]=="sent" for e in event(1,"server2","availability","recovered")))
        assert len(event(1,"server2","availability","recovered"))==1
        until("recovery moves the same incident to Closed on all three dashboards",lambda:all(not incidents(i,'open','server2','availability') and any(r['id']==outage_incident for r in incidents(i,'closed','server2','availability')) for i in (1,2,3)))

        (root / "control3.json").write_text('{"cpu":99}')
        until("sustained CPU critical email for server 3",lambda:any(e["status"]=="sent" for e in event(1,"server3","cpu_percent","open")))
        (root / "control3.json").write_text('{}')
        until("CPU recovery email after hysteresis",lambda:any(e["status"]=="sent" for e in event(1,"server3","cpu_percent","recovered")))

        (root / "control3.json").write_text('{"cpu":99}')
        until("CPU recurrence opens a new incident before sender failover",lambda:len(event(1,'server3','cpu_percent','open'))==2 and len(incidents(1,'open','server3','cpu_percent'))==1)
        cpu_incident = incidents(1,'open','server3','cpu_percent')[0]
        assert cpu_incident['id'] != incidents(1,'closed','server3','cpu_percent')[0]['id']

        stop(1)
        until("priority 2 takes over failed priority 1",lambda:status(2)["is_leader"])
        until("primary outage email sent by server 2",lambda:any(e["status"]=="sent" and e.get("sender")=="server2" for e in event(2,"server1","availability","open")))
        until("sender failover preserves open incident identity and start time",lambda:all(any(r['id']==cpu_incident['id'] and r['opened_at']==cpu_incident['opened_at'] for r in incidents(i,'open','server3','cpu_percent')) for i in (2,3)))
        (root / "control3.json").write_text('{}')
        until("new sender closes the existing incident after recovery",lambda:any(r['id']==cpu_incident['id'] and r['status']=='closed' for r in incidents(2,'closed','server3','cpu_percent')))
        time.sleep(1)
        primary_outage=event(2,"server1","availability","open")
        assert len(primary_outage)==1 and sum(primary_outage[0]["id"] in m for m in smtp.messages)==1
        assert not status(3)["is_leader"]
        raw=next(m for m in smtp.messages if primary_outage[0]['id'] in m)
        mail=Parser(policy=policy.default).parsestr(raw)
        assert str(mail['Subject'])=='Customer offline | Server 1 | Server 2',str(mail['Subject'])
        text=mail.get_body(preferencelist=('plain',)).get_content()
        html=mail.get_body(preferencelist=('html',)).get_content()
        assert 'Alert sender: Server 2' in text and 'server1' not in text and 'server2' not in text
        assert 'Acceptance Customer' in html and 'cid:aivid-customer' in html
        assert {p.get('Content-ID') for p in mail.walk()} >= {'<aivid-vendor>','<aivid-customer>'}
        checks.append({'check':'offline failover email retains custom subject, server names, customer branding and embedded logos','result':'PASS'})
        checks.append({"check":"server 1 outage sent exactly once by server 2; server 3 remains standby","result":"PASS"})
        for message in smtp.messages:
            mid=next(x for x in message.splitlines() if x.startswith("Message-ID:"))
            assert sum(mid in m for m in smtp.messages)==1
        checks.append({"check":"failover does not resend already delivered events","result":"PASS"})
        start(1)
        until("higher priority server resumes after lease handover",lambda:status(1)["is_leader"],timeout=25)
        until("primary recovery recorded",lambda:any(e["status"]=="sent" for e in event(1,"server1","availability","recovered")))

        # Asymmetric visibility is exercised through explicit transport failures.
        (root / "control1.json").write_text('{"blocked":["server2","server3"]}')
        (root / "control2.json").write_text('{"blocked":["server1"]}')
        (root / "control3.json").write_text('{"blocked":["server1"]}')
        until("partitioned minority loses sending authority",lambda:not status(1)["is_leader"])
        until("majority elects server 2 during network partition",lambda:status(2)["is_leader"])
        until("partition outage accepted exactly once",lambda:len([e for e in event(2,"server1","availability","open") if e["status"]=="sent"])==2)
        assert not status(1)["is_leader"]
        for i in (1,2,3):(root / f"control{i}.json").write_text('{}')
        until("cluster reconnects and converges after partition",lambda:status(1)["is_leader"] and all(n["status"]=="online" for n in status(1)["nodes"]),timeout=25)

        # Retain a majority delivery intent, then kill the sender after SMTP DATA.
        smtp.hold=True;smtp.received.clear();smtp.release.clear()
        pending=post(1,"/api/test-email",{})["event_id"]
        until("SMTP received the message before sender crash",lambda:any(pending in m for m in smtp.messages))
        stop(1);smtp.release.set();smtp.hold=False
        until("sender crash yields uncertain record on next leader",lambda:status(2)["is_leader"] and any(e["id"]==pending and e["status"]=="uncertain" for e in status(2)["events"]))
        time.sleep(1)
        assert sum(pending in m for m in smtp.messages)==1
        checks.append({"check":"no automatic duplicate after ambiguous SMTP sender crash","result":"PASS"})
        start(1)
        until("cluster recovers after SMTP crash scenario",lambda:status(1)["is_leader"],timeout=25)
        stop(2);stop(3)
        until("single surviving node suppresses email without quorum",lambda:not status(1)["is_leader"])
        count=len(smtp.messages);time.sleep(2);assert len(smtp.messages)==count
        checks.append({"check":"no minority emails while two nodes are down","result":"PASS"})
        checks.append({"check":"all accepted SMTP messages have unique Message-IDs","result":"PASS"})
        ids=[next(x for x in m.splitlines() if x.startswith("Message-ID:")) for m in smtp.messages]
        assert len(ids)==len(set(ids))
        print(json.dumps({"checks":len(checks),"smtp_messages":len(smtp.messages),"result":"PASS"}),flush=True)
        return {"checks":checks,"smtp_messages":len(smtp.messages),"result":"PASS"}
    finally:
        for i in range(1,4):stop(i)
        for c in clients.values():c.close()
        smtp.release.set();smtp.shutdown();smtp.server_close()


if __name__ == "__main__":
    import argparse
    parser=argparse.ArgumentParser()
    parser.add_argument("destination",type=Path)
    parser.add_argument("--release",type=Path)
    parser.add_argument("--automatic",action="store_true",help="Test blank priority registration order")
    parser.add_argument("--deny-network",type=Path,help="Optional Linux preload library that denies internet connects during installation")
    args=parser.parse_args()
    destination=args.destination.resolve()
    report=run_tests(destination,args.release.resolve() if args.release else None,args.deny_network.resolve() if args.deny_network else None,args.automatic)
    (destination / "results.json").write_text(json.dumps(report,indent=2))
