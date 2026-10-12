"""Lifecycle, legacy history and authenticated dashboard acceptance checks."""
import asyncio
import copy
import time
import unittest

from aivid_health.incidents import incident_rows, incident_summary
from test_core import Fixture, sample
import test_dashboard


class IncidentTests(Fixture, unittest.TestCase):
    def setUp(self): self.setup()
    def tearDown(self):
        asyncio.run(self.engine.close())
        self.teardown()

    def observe(self, record, cpu, count=3):
        for _ in range(count):
            self.engine.sample = sample(cpu=cpu)
            self.engine.evaluate(record)

    def test_full_cycle_escalation_and_recurrence_are_separate_episodes(self):
        r = self.store.record()
        self.observe(r, 90)
        identifier, opened = r["events"][0]["incident_id"], r["events"][0]["created_at"]
        r["events"][0]["status"] = "sent"
        self.assertEqual(incident_summary(incident_rows(r, self.config))["open"], 1)
        self.observe(r, 99)
        self.assertEqual(r["incidents"]["server1/cpu_percent"]["opened_at"], opened)
        self.assertEqual(r["events"][1]["incident_id"], identifier)
        self.observe(r, 20, 1)
        self.assertEqual(incident_rows(r, self.config)[0]["status"], "open")
        self.observe(r, 20, 1)
        closed = incident_rows(r, self.config)[0]
        self.assertEqual((closed["status"], closed["severity"]), ("closed", "critical"))
        self.assertEqual(closed["opened_at"], opened)
        self.assertEqual([e["kind"] for e in closed["timeline"]], ["open", "escalated", "recovered"])
        self.assertEqual({e["incident_id"] for e in closed["timeline"]}, {identifier})
        self.assertGreaterEqual(closed["duration_seconds"], 0)
        # A queued recovery email is a closed incident, not an open incident.
        self.assertEqual(closed["latest_delivery"], "pending")
        self.observe(r, 90)
        rows = incident_rows(r, self.config)
        self.assertEqual(incident_summary(rows)["open"], 1)
        self.assertEqual(incident_summary(rows)["closed"], 1)
        self.assertNotEqual(rows[0]["id"], identifier)
        self.assertIsNone(r["incidents"]["server1/cpu_percent"]["resolved_at"])

    def legacy_event(self, kind, at, metric="cpu_percent", severity="warning"):
        e = self.engine.new_event(self.config.local, metric, kind, severity, kind)
        e.update(created_at=at, status="sent")
        return e

    def test_legacy_cycles_do_not_confuse_old_open_emails_with_current_state(self):
        now = time.time(); r = self.store.record()
        r["events"] = [self.legacy_event(k, now-100+i*10) for i,k in enumerate(["open","escalated","recovered","open"])]
        r["incidents"]["server1/cpu_percent"] = {"active":True,"severity":"warning","opened_at":now-70}
        before = copy.deepcopy(r)
        rows = incident_rows(r, self.config)
        self.assertEqual(incident_summary(rows), {"open":1,"closed":1,"unknown":0,"critical":0,"warning":1,"all":2})
        self.assertEqual(rows[1]["opened_at"], now-100)
        self.assertEqual(len(rows[1]["timeline"]), 3)
        self.assertEqual(r, before, "read-only projection must not rewrite old records")

    def test_upgrade_recovers_legacy_episode_and_preserves_original_open_time(self):
        now = time.time(); r = self.store.record()
        first = self.legacy_event("open",now-100)
        r["events"] = [first,self.legacy_event("escalated",now-50,severity="critical")]
        r["incidents"]["server1/cpu_percent"] = {"active":True,"severity":"critical","opened_at":now-50,"bad":3,"good":0}
        self.observe(r,20,2)
        rows=incident_rows(r,self.config)
        self.assertEqual(len(rows),1)
        self.assertEqual(rows[0]["status"],"closed")
        self.assertEqual(rows[0]["opened_at"],now-100)
        self.assertEqual(r["events"][-1]["incident_id"],"legacy-"+first["id"])

    def test_partial_history_is_not_falsely_open_or_falsely_recovered(self):
        now=time.time();r=self.store.record()
        r["events"]=[self.legacy_event("open",now-200),self.legacy_event("open",now-100)]
        r["incidents"]["server1/cpu_percent"]={"active":False,"opened_at":now-100,"resolved_at":now-10,"severity":"healthy"}
        rows=incident_rows(r,self.config)
        counts=incident_summary(rows)
        self.assertEqual((counts["open"],counts["closed"],counts["unknown"]),(0,1,1))
        self.assertIsNone(rows[1]["duration_seconds"])

    def test_pruned_active_history_and_recovery_keep_duration(self):
        now=time.time();r=self.store.record()
        r["incidents"]["server1/cpu_percent"]={"active":True,"opened_at":now-100*86400,"severity":"critical","bad":3,"good":0}
        rows=incident_rows(r,self.config)
        self.assertEqual(len(rows),1);self.assertEqual(rows[0]["status"],"open")
        self.observe(r,20,2)
        closed=incident_rows(r,self.config)[0]
        self.assertEqual(closed["status"],"closed")
        self.assertEqual(closed["opened_at"],now-100*86400)
        self.assertTrue(closed["history_partial"])
        self.assertGreater(closed["duration_seconds"],99*86400)

    def test_recovery_without_retained_open_event_has_unknown_start(self):
        r=self.store.record();r["events"]=[self.legacy_event("recovered",time.time())]
        row=incident_rows(r,self.config)[0]
        self.assertEqual(row["status"],"closed");self.assertIsNone(row["opened_at"])
        self.assertIsNone(row["duration_seconds"])

    def test_resources_do_not_merge_and_test_emails_are_excluded(self):
        r=self.store.record();now=time.time()
        for resource in ["disk_percent:/","disk_percent:/data","gpu_temperature:GPU-1","gpu_temperature:GPU-2"]:
            r["events"].append(self.legacy_event("open",now,resource))
            r["incidents"]["server1/"+resource]={"active":True,"severity":"critical","opened_at":now}
        r["events"].append(self.legacy_event("test",now,"email test"))
        rows=incident_rows(r,self.config)
        self.assertEqual(len(rows),4);self.assertEqual(incident_summary(rows)["open"],4)
        self.assertEqual({x["resource"] for x in rows},{"/","/data","GPU-1","GPU-2"})

    def test_closed_retention_does_not_remove_current_open_incidents(self):
        now=time.time();r=self.store.record()
        r["events"]=[self.legacy_event("open",now-92*86400),self.legacy_event("recovered",now-91*86400)]
        r["incidents"]["server1/cpu_percent"]={"active":True,"severity":"critical","opened_at":now-90*86400}
        rows=incident_rows(r,self.config)
        self.assertEqual(len(rows),1);self.assertEqual(rows[0]["status"],"open")

    def test_missing_samples_do_not_close_an_active_incident(self):
        r=self.store.record();self.observe(r,99)
        self.engine.sample=None
        for _ in range(4):self.engine.evaluate(r)
        self.assertEqual(incident_summary(incident_rows(r,self.config))["open"],1)


class IncidentAPITests(unittest.IsolatedAsyncioTestCase):
    # Reuse fixture only, not the unrelated inherited tests.
    asyncSetUp=test_dashboard.DashboardTests.asyncSetUp
    asyncTearDown=test_dashboard.DashboardTests.asyncTearDown

    async def test_counts_and_pagination_include_more_than_250_events(self):
        r=self.db.record();now=time.time()
        for i in range(151):
            resource=f"disk_percent:/data/{i}"
            opened=self.eng.new_event(self.cfg.local,resource,"open","warning","disk high")
            recovered=self.eng.new_event(self.cfg.local,resource,"recovered","info","disk recovered")
            opened.update(created_at=now-1000+i,status="sent")
            recovered.update(created_at=now-500+i,status="sent")
            r["events"].extend([opened,recovered])
            r["incidents"][self.cfg.node_id+"/"+resource]={"active":False,"opened_at":opened["created_at"],"resolved_at":recovered["created_at"]}
        live=self.eng.new_event(self.cfg.local,"cpu_percent","open","critical","CPU high")
        r["events"].append(live);r["incidents"][self.cfg.node_id+"/cpu_percent"]={"active":True,"severity":"critical","opened_at":live["created_at"]}
        self.db.put("cluster_record",r)
        status=(await self.client.get("/api/status")).json()
        self.assertEqual(len(status["events"]),250)
        self.assertEqual(status["incident_summary"]["closed"],151)
        self.assertEqual(status["active_incidents"],1)
        self.assertEqual(status["delivery_summary"],{"total":303,"pending":1,"uncertain":0})
        result=(await self.client.get("/api/incidents?status=closed&limit=25&offset=150")).json()
        self.assertEqual(result["total"],151);self.assertEqual(len(result["items"]),1)
        self.assertEqual(result["offset"],150)
        deliveries=(await self.client.get("/api/deliveries?offset=300&limit=25")).json()
        self.assertEqual(deliveries["total"],303);self.assertEqual(len(deliveries["items"]),3)
        self.assertNotIn("password",str(result))
        self.assertEqual(self.db.record(),r)

    async def test_filters_authentication_and_delivery_review_do_not_close_incident(self):
        r=self.db.record();e=self.eng.new_event(self.cfg.local,"gpu_temperature:GPU-42","open","critical","hot")
        e["status"]="uncertain";r["events"].append(e)
        r["incidents"][self.cfg.node_id+"/gpu_temperature:GPU-42"]={"active":True,"severity":"critical","opened_at":e["created_at"]}
        self.db.put("cluster_record",r)
        result=await self.client.get("/api/incidents?node=server1&severity=critical&q=GPU-42")
        self.assertEqual(result.json()["total"],1)
        self.assertEqual((await self.client.get("/api/incidents?severity=warning")).json()["total"],0)
        self.assertEqual((await self.client.get("/api/incidents?status=invalid")).status_code,400)
        self.assertEqual((await self.client.get("/api/incidents?limit=500")).status_code,422)
        self.eng.leader=self.cfg.node_id;self.eng.deadline=time.monotonic()+30
        async def replicate(rec):self.db.put("cluster_record",rec);return True
        self.eng.replicate=replicate
        response=await self.client.post('/api/events/'+e['id']+'/review',json={},headers=self.headers)
        self.assertEqual(response.status_code,200)
        result=(await self.client.get("/api/incidents")).json()
        self.assertEqual(result["summary"]["open"],1)
        self.assertEqual(result["items"][0]["latest_delivery"],"cancelled")
        self.client.cookies.clear()
        for path in ("/api/incidents","/api/deliveries"):
            self.assertEqual((await self.client.get(path)).status_code,401)

