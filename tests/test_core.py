from __future__ import annotations
import asyncio
import copy
import hashlib
import json
import smtplib
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import httpx

from aivid_installer.cluster import make_cluster
from aivid_health.config import Config, DEFAULT_SETTINGS, validate_settings
from aivid_health.collectors import Collector, gpu_sample, metrics
from aivid_health.engine import Engine, authenticate_peer, signed_headers
from aivid_health.mail import MailError, deliver, make_message
from aivid_health.store import Store
from aivid_health.web import create_app


class Fixture:
    def setup(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.nodes = [{"id": f"server{i}", "name": f"Server {i}", "url": f"https://127.0.0.1:{18000+i}", "priority": i} for i in range(1,4)]
        make_cluster(root / "cluster", self.nodes, interval=.3, timeout=.2, lease=4, offline_samples=2)
        self.config = Config(root / "cluster/server1/node.json")
        self.store = Store(self.config.state_dir / "test.sqlite3", 4)
        self.engine = Engine(self.config, self.store)

    def teardown(self):
        self.store.close()
        self.tmp.cleanup()


def sample(cpu=10, mem=20):
    return {"sampled_at": time.time(), "cpu_percent": cpu, "memory_percent": mem,
            "disks": [{"path": "/", "disk_percent": 20, "status": "ok"}], "gpu": {"status": "unavailable", "devices": []}}


class CoreTests(Fixture, unittest.TestCase):
    def setUp(self): self.setup()
    def tearDown(self):
        asyncio.run(self.engine.close())
        self.teardown()

    def test_exclusive_votes_and_reboot_protection(self):
        self.assertTrue(self.store.grant("server1", "a", 4))
        self.assertFalse(self.store.grant("server2", "b", 4))
        self.assertTrue(self.store.grant("server1", "a", 4))
        path = self.store.path
        self.store.close()
        self.store = Store(path, 4)
        self.assertFalse(self.store.grant("server2", "b", 4))
        self.store.vote_deadline = 0
        self.assertTrue(self.store.grant("server2", "b", 4, 2))

    def test_stale_writer_cannot_replace_record(self):
        self.store.grant("server1", "a", 4)
        r = self.store.record(); r["revision"] = 2; r["epoch"] = 1
        self.assertFalse(self.store.accept_record("server2", "b", r))
        self.assertTrue(self.store.accept_record("server1", "a", r))
        r["revision"] = 1
        self.assertFalse(self.store.accept_record("server1", "a", r))
        self.store.vote_deadline = 0
        self.assertFalse(self.store.accept_record("server1", "a", r))

    def test_peer_hmac_replay_cluster_and_tamper(self):
        h = {k.lower(): v for k,v in signed_headers(self.config,"POST","/peer/vote",b"{}").items()}
        self.assertEqual(authenticate_peer(self.config,self.store,"POST","/peer/vote",h,b"{}"),"server1")
        with self.assertRaises(ValueError): authenticate_peer(self.config,self.store,"POST","/peer/vote",h,b"{}")
        h = {k.lower(): v for k,v in signed_headers(self.config,"POST","/peer/vote",b"{}").items()}
        with self.assertRaises(ValueError): authenticate_peer(self.config,self.store,"POST","/peer/vote",h,b'{"x":1}')
        h["x-aivid-cluster"] = "other"
        with self.assertRaises(ValueError): authenticate_peer(self.config,self.store,"POST","/peer/vote",h,b"{}")

    def test_password_is_encrypted_and_thresholds_are_validated(self):
        encrypted = self.config.encrypt("private-smtp-password")
        self.assertNotIn("private-smtp-password", encrypted)
        self.assertEqual(self.config.decrypt(encrypted), "private-smtp-password")
        s = copy.deepcopy(DEFAULT_SETTINGS); s["thresholds"]["cpu_percent"] = {"warning": 98, "critical": 90}
        with self.assertRaises(ValueError): validate_settings(s)
        s = copy.deepcopy(DEFAULT_SETTINGS); s["smtp"]["security"] = "plain"; s["smtp"]["username"] = "name"
        with self.assertRaises(ValueError): validate_settings(s)

    def test_resource_sustain_escalation_hysteresis_recovery(self):
        e = self.engine; e.sample = sample(cpu=90)
        r = self.store.record()
        def evaluate():
            e.sample["sampled_at"] = time.time()
            e.evaluate(r)
        evaluate(); evaluate()
        self.assertEqual(len(r["events"]), 0)
        evaluate()
        self.assertEqual([x["kind"] for x in r["events"]], ["open"])
        for _ in range(5): evaluate()
        self.assertEqual(len(r["events"]), 1)
        e.sample = sample(cpu=99)
        for _ in range(3): evaluate()
        self.assertEqual(r["events"][-1]["kind"], "escalated")
        e.sample = sample(cpu=82)
        for _ in range(3): evaluate()
        self.assertEqual(len(r["events"]), 2)
        e.sample = sample(cpu=20)
        evaluate(); evaluate()
        self.assertEqual(r["events"][-1]["kind"], "recovered")
        self.assertFalse(r["incidents"]["server1/cpu_percent"]["active"])

    def test_cached_resource_sample_cannot_trigger_sustained_alert(self):
        self.engine.sample = sample(cpu=99)
        r = self.store.record()
        for _ in range(10):
            self.engine.evaluate(r)
        self.assertEqual(r["events"], [])

    def test_outage_requires_two_observers_and_recovers_once(self):
        e = self.engine; e.sample = sample()
        e.peers["server2"].update(status="unreachable",misses=2)
        e.peers["server3"].update(status="online",misses=0,snapshot={"sample":sample(),"observations":{"server2":{"status":"online","misses":0}}})
        r = self.store.record(); e.evaluate(r)
        self.assertEqual(e.node_views()[1]["status"], "path_issue")
        self.assertEqual(len(r["events"]),0)
        e.peers["server3"]["snapshot"]["observations"]["server2"]={"status":"unreachable","misses":2}
        e.evaluate(r); e.evaluate(r)
        self.assertEqual(len(r["events"]),1)
        e.peers["server2"].update(status="online",misses=0,snapshot={"sample":sample()})
        e.evaluate(r); e.evaluate(r); e.evaluate(r)
        self.assertEqual([x["kind"] for x in r["events"]],["open","recovered"])

    def test_gpu_missing_error_and_multiple_gpu_parse(self):
        with patch("aivid_health.collectors.shutil.which", return_value=None):
            self.assertEqual(gpu_sample()["status"],"unavailable")
        class Output:
            returncode=0
            stdout='GPU-1, RTX 4090, 25, 12000, 24000, 60, 123.4\nGPU-2, Tesla T4, [N/A], 1024, 16384, 71, [N/A]\n'
        with patch("aivid_health.collectors.shutil.which",return_value="/usr/bin/nvidia-smi"), patch("aivid_health.collectors.subprocess.run",return_value=Output()):
            result=gpu_sample()
        self.assertEqual(len(result["devices"]),2)
        self.assertEqual(result["devices"][0]["gpu_memory_percent"],50)
        self.assertIsNone(result["devices"][1]["gpu_percent"])
        Output.returncode=1
        with patch("aivid_health.collectors.shutil.which",return_value="/usr/bin/nvidia-smi"), patch("aivid_health.collectors.subprocess.run",return_value=Output()):
            self.assertEqual(gpu_sample()["status"],"error")

    def test_real_local_resource_collection(self):
        result = Collector(self.config).collect()
        self.assertGreater(result["memory_total_bytes"],0)
        self.assertGreater(result["cpu_count"],0)
        self.assertGreater(result["disks"][0]["total_bytes"],0)
        self.assertTrue(0 <= result["memory_percent"] <= 100)

    def test_stable_email_id_and_html_escaping(self):
        event=self.engine.new_event(self.nodes[0],"<script>","open","critical","<b>unsafe</b>")
        s=copy.deepcopy(DEFAULT_SETTINGS["smtp"]);s.update(sender="monitor@example.com",recipients=["ops@example.com"])
        msg=make_message(event,s,"server1")
        self.assertEqual(msg["Message-ID"],f"<{event['id']}@aivid-health.local>")
        self.assertIn("&lt;b&gt;unsafe&lt;/b&gt;",msg.get_body(preferencelist=("html",)).get_content())


class AsyncTests(Fixture, unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self): self.setup()
    async def asyncTearDown(self):
        await self.engine.close();self.teardown()

    async def test_minority_cannot_send(self):
        self.engine.sample=sample()
        await self.engine.elect()
        self.assertFalse(self.engine.is_leader)
        self.assertIsNone(self.engine.leader)

    async def test_auth_csrf_initial_password_and_settings(self):
        app=create_app(config=self.config,store=self.store,engine=self.engine,start_engine=False)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url="https://127.0.0.1:18001") as client:
            self.assertEqual((await client.get("/api/status")).status_code,401)
            password=(self.config.path.parent/"credentials.txt").read_text().split("Initial password: ")[1].splitlines()[0]
            r=await client.post("/api/login",json={"username":"admin","password":password})
            self.assertEqual(r.status_code,200)
            self.assertIn("Secure",r.headers["set-cookie"])
            self.assertEqual((await client.get("/api/status")).status_code,403)
            self.assertEqual((await client.post("/api/password",json={"current":password,"new":"BetterPasswordHere123"})).status_code,403)
            r2=await client.post("/api/password",json={"current":password,"new":"BetterPasswordHere123"},headers={"x-csrf-token":r.json()["csrf"]})
            self.assertEqual(r2.status_code,200)
            self.assertEqual((await client.get("/api/status")).status_code,401)
            await client.post("/api/login",json={"username":"admin","password":"BetterPasswordHere123"})
            r3=await client.get("/api/settings")
            self.assertEqual(r3.status_code,200)
            self.assertNotIn("password_encrypted",r3.text)
            self.assertEqual((await client.get("/peer/snapshot")).status_code,401)
            self.assertEqual((await client.get("/static/app.js")).status_code,200)

    async def test_login_rate_limit_and_cross_origin(self):
        app=create_app(config=self.config,store=self.store,engine=self.engine,start_engine=False)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url="https://127.0.0.1:18001") as client:
            for _ in range(8):
                self.assertEqual((await client.post("/api/login",json={"username":"admin","password":"invalid-password"})).status_code,401)
            self.assertEqual((await client.post("/api/login",json={"username":"admin","password":"invalid-password"})).status_code,429)
            self.assertEqual((await client.post("/api/login",json={},headers={"origin":"https://attacker.example"})).status_code,403)

    async def test_unconfirmed_replication_never_calls_smtp(self):
        e=self.engine;e.leader="server1";e.deadline=time.monotonic()+10;e.epoch=1
        self.store.grant("server1",e.term,4)
        r=self.store.record();r["settings"]=copy.deepcopy(DEFAULT_SETTINGS);r["settings"]["smtp"]["enabled"]=True
        r["events"].append(e.new_event(self.nodes[0],"availability","open","critical","down"))
        self.store.put("cluster_record",r)
        calls=[];e.sender=lambda *a:calls.append(a)
        await e.dispatch()
        self.assertEqual(calls,[])
        self.assertFalse(e.is_leader)

    async def test_handover_epoch_fences_unseen_partial_revision(self):
        cfg = Config(self.config.path.parent.parent / "server2/node.json")
        db = Store(cfg.state_dir / "test.sqlite3", 4)
        e = Engine(cfg, db)
        base = db.record(); base.update(revision=10,epoch=1); db.put("cluster_record", base)
        # The unavailable old writer has an arbitrarily high local-only revision
        # in epoch 1. A new committed epoch must always order after that record.
        e.peers["server1"].update(status="unreachable",misses=3)
        e.peers["server3"].update(status="online",misses=0)
        accepted = []
        async def fake_request(node, path, payload=None):
            if node == "server1":
                raise httpx.ConnectError("old writer unavailable")
            if path == "/peer/prepare":
                return {"epoch": 1}
            if path == "/peer/vote":
                return {"granted": True, "record": copy.deepcopy(base)}
            accepted.append(payload["record"]["revision"])
            return {"accepted": True}
        e.request = fake_request
        try:
            await e.elect()
            self.assertTrue(e.is_leader)
            self.assertEqual(db.record()["epoch"], 2)
            self.assertEqual(db.record()["revision"], 11)
            stale = copy.deepcopy(base); stale["revision"] = 100
            self.assertFalse(db.accept_record(cfg.node_id,e.term,stale))
            self.assertEqual(accepted, [11])
        finally:
            await e.close();db.close()


class MailTests(unittest.TestCase):
    def smtp(self):
        s=copy.deepcopy(DEFAULT_SETTINGS["smtp"]);s.update(security="plain",host="localhost",port=25,sender="a@example.com",recipients=["b@example.com"])
        return s
    def event(self):
        return Engine.new_event({"id":"server2","name":"server2"},"availability","open","critical","down")

    def client(self, data=None):
        from unittest.mock import MagicMock
        c=MagicMock();c.mail.return_value=(250,b"ok");c.rcpt.return_value=(250,b"ok");c.data.return_value=(250,b"accepted")
        if data:c.data.side_effect=data
        return c

    def test_smtp_acceptance_is_success_even_if_quit_would_fail(self):
        c=self.client();c.quit.side_effect=OSError("socket lost")
        with patch("aivid_health.mail.smtplib.SMTP",return_value=c):
            self.assertEqual(deliver(self.event(),self.smtp(),"","server1")["status"],"sent")
        c.quit.assert_not_called()

    def test_smtp_disconnect_during_data_is_uncertain(self):
        c=self.client(smtplib.SMTPServerDisconnected("lost"))
        with patch("aivid_health.mail.smtplib.SMTP",return_value=c), self.assertRaises(MailError) as error:
            deliver(self.event(),self.smtp(),"","server1")
        self.assertTrue(error.exception.uncertain)

    def test_explicit_data_rejection_is_retryable(self):
        c=self.client(smtplib.SMTPDataError(451,b"temporary"))
        with patch("aivid_health.mail.smtplib.SMTP",return_value=c), self.assertRaises(MailError) as error:
            deliver(self.event(),self.smtp(),"","server1")
        self.assertFalse(error.exception.uncertain)

    def test_certificate_failure_is_retryable_and_secret_safe(self):
        import ssl
        s=self.smtp();s["security"]="tls"
        with patch("aivid_health.mail.smtplib.SMTP_SSL",side_effect=ssl.SSLCertVerificationError("private-password")),self.assertRaises(MailError) as error:
            deliver(self.event(),s,"private-password","server1")
        self.assertFalse(error.exception.uncertain)
        self.assertNotIn("private-password",str(error.exception))

    def test_partial_recipient_rejection_does_not_retry_accepted_mail(self):
        c=self.client();c.rcpt.side_effect=[(250,b"ok"),(550,b"rejected")]
        s=self.smtp();s["recipients"].append("c@example.com")
        with patch("aivid_health.mail.smtplib.SMTP",return_value=c):
            result=deliver(self.event(),s,"","server1")
        self.assertEqual(result["status"],"sent")
        self.assertIn("1 recipient",result["detail"])


if __name__ == "__main__": unittest.main(verbosity=2)
