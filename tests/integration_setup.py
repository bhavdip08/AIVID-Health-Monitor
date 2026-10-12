"""Exercise the actual .run installer, interactive input and HTTPS enrollment.

All host service writes are isolated with --prefix/--no-systemd. No public email.
"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import time
import httpx


def port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0)); return s.getsockname()[1]


def run(installer, dest):
    dest.mkdir(parents=True, exist_ok=False)
    ports = [port() for _ in range(3)]
    urls = [f"https://127.0.0.1:{p}" for p in ports]
    prefixes = [dest / f"node{i}" for i in (1, 2, 3)]
    env = {k:v for k,v in os.environ.items() if k not in ("PYTHONPATH", "LD_PRELOAD")}
    checks, procs, clients, logs = [], [], [], []
    password = "test-setup-pass-2026"

    def check(name, condition=True):
        assert condition, name
        checks.append({"check":name,"result":"PASS"}); print("PASS " + name, flush=True)

    def install(i, answers, label, expected=0):
        log = dest / f"{label}.log"
        with log.open("w") as f:
            proc = subprocess.run(["bash", str(installer), "--prefix", str(prefixes[i]), "--no-systemd"], input=answers, text=True, env=env, stdout=f, stderr=subprocess.STDOUT, timeout=120)
        assert proc.returncode == expected, log
        return log.read_text()

    def wait(fn, label, timeout=60):
        start = time.time()
        while time.time()-start < timeout:
            try:
                if fn(): check(label); return
            except (httpx.HTTPError, KeyError): pass
            time.sleep(.25)
        raise AssertionError(label)

    def start(i):
        conf = prefixes[i] / "etc/aivid-health/node.json"
        py = prefixes[i] / "opt/aivid-health/current/venv/bin/python"
        f = (dest / f"server{i+1}.log").open("w"); logs.append(f)
        procs.append(subprocess.Popen([str(py), "-m", "aivid_health.cli", "serve", "--config", str(conf)], env=env, stdout=f, stderr=subprocess.STDOUT))
        ca = prefixes[0] / "etc/aivid-health/cluster-ca.crt"
        client = httpx.Client(base_url=urls[i], verify=ssl.create_default_context(cafile=str(ca)), trust_env=False, timeout=2)
        clients.append(client)
        wait(lambda: client.get("/readyz").status_code == 200, f"server{i+1} installed wheels serve verified HTTPS")
        response = client.post("/api/login",json={"username":"admin","password":password}); response.raise_for_status()
        client.headers["X-CSRF-Token"] = response.json()["csrf"]
        check(f"server{i+1} accepts chosen password without forced reset", not response.json()["must_change"])

    try:
        install(0, "1\n" + "\n".join(urls) + "\ny\n/\nn\n" + password + "\n" + password + "\n", "first")
        check("one-file first-server wizard installs without manual JSON or certificate commands")
        start(0)
        codes = json.loads((prefixes[0] / "var/lib/aivid-health-setup/join-codes.json").read_text())
        r = clients[0].get("/api/setup"); r.raise_for_status()
        check("setup page data exposes two invitations", set(r.json()["invitations"]) == {"server2","server3"})
        install(1, "2\n" + codes["server2"] + "\n", "join2-interrupted", expected=1)
        check("interrupted join preserves downloaded configuration", (prefixes[1] / "var/lib/aivid-health-setup/resume.json").is_file())
        text = install(1, "/\nn\n" + password + "\n" + password + "\n", "join2-resumed")
        check("join resumes without reusing a consumed code", "Resuming saved setup" in text)
        start(1)
        invite = clients[0].post("/api/setup/invite/server3"); invite.raise_for_status()
        install(2, "2\n" + invite.json()["code"] + "\n/\nn\n" + password + "\n" + password + "\n", "join3")
        check("dashboard-issued code joins server3 over pinned TLS")
        start(2)
        wait(lambda: all(n["status"] == "online" for n in clients[0].get("/api/setup").json()["nodes"]), "setup reports all three nodes online")
        wait(lambda: clients[0].get("/api/status").json()["leader"] == "server1", "default production timings elect priority1")
        check("invitation for an online server is refused", clients[0].post("/api/setup/invite/server2").status_code == 409)
        check("public browser CA download succeeds", clients[0].get("/api/setup/ca").status_code == 200)
        text = install(2, "", "rerun")
        check("rerunning the same installer retains existing setup", "already installed" in text)
        check("old dashboard login still works after rerun", clients[2].get("/api/setup").status_code == 200)
        value = {"result":"PASS", "checks":checks}
        (dest / "results.json").write_text(json.dumps(value,indent=2))
        return value
    finally:
        for p in procs:
            if p.poll() is None: p.terminate()
        for p in procs:
            try: p.wait(timeout=20)
            except subprocess.TimeoutExpired: p.kill(); p.wait()
        for c in clients: c.close()
        for f in logs: f.close()


if __name__ == "__main__":
    p = argparse.ArgumentParser(); p.add_argument("installer",type=Path); p.add_argument("destination",type=Path)
    a=p.parse_args(); run(a.installer.resolve(), a.destination.resolve())
