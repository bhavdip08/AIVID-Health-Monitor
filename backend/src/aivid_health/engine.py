"""Variable-size peer monitoring and quorum-fenced alert delivery.

This is a single-writer replicated state service with all-member changes, not a general
Raft implementation. Every vote and delivery intent is persisted before use.
"""
from __future__ import annotations

import asyncio
import copy
import hashlib
import hmac
import logging
import secrets
import ssl
import time
import uuid

import httpx

from .collectors import Collector, metrics
from .config import DEFAULT_SETTINGS, canonical
from .mail import MailError, deliver
from .presentation import normalize_settings, event_view, server_name

LOG = logging.getLogger("aivid.health")


def signed_headers(config, method, path, body=b""):
    stamp, nonce = str(int(time.time())), secrets.token_hex(16)
    raw = b"\n".join([method.encode(), path.encode(), config.node_id.encode(), stamp.encode(), nonce.encode(), body])
    generation = str(config.data.get("generation", 0))
    raw += b"\n" + generation.encode()
    return {"X-Aivid-Generation": generation, "X-Aivid-Node": config.node_id, "X-Aivid-Time": stamp, "X-Aivid-Nonce": nonce,
            "X-Aivid-Cluster": config.fingerprint,
            "X-Aivid-Signature": hmac.new(config.data["peer_secret"].encode(), raw, hashlib.sha256).hexdigest()}


def authenticate_peer(config, store, method, path, headers, body):
    sender = headers.get("x-aivid-node", "")
    stamp, nonce = headers.get("x-aivid-time", ""), headers.get("x-aivid-nonce", "")
    if sender not in config.by_id or headers.get("x-aivid-cluster") != config.fingerprint:
        raise ValueError("Unknown node or different cluster configuration")
    try:
        if abs(time.time() - int(stamp)) > 60 or len(nonce) != 32:
            raise ValueError("Expired peer request")
    except (ValueError, OverflowError) as exc:
        raise ValueError("Invalid peer timestamp") from exc
    raw = b"\n".join([method.encode(), path.encode(), sender.encode(), stamp.encode(), nonce.encode(), body])
    raw += b"\n" + headers.get("x-aivid-generation", "0").encode()
    if not path.startswith("/peer/reconfigure") and headers.get("x-aivid-generation", "0") != str(config.data.get("generation", 0)):
        raise ValueError("Configuration synchronization in progress")
    expected = hmac.new(config.data["peer_secret"].encode(), raw, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, headers.get("x-aivid-signature", "")):
        raise ValueError("Invalid peer signature")
    if not store.nonce(sender + ":" + nonce, time.time() + 120):
        raise ValueError("Peer request replay")
    return sender


class Engine:
    def __init__(self, config, store, collector=None, sender=deliver):
        self.config, self.store = config, store
        self.collector, self.sender = collector or Collector(config), sender
        self.term = uuid.uuid4().hex
        self.epoch = 0
        self.deadline = 0
        self.leader = None
        self.quorum = 0
        self.sample = None
        self.last_tick = 0
        self.start_time = time.time()
        self.peers = {n["id"]: {"misses": 0, "successes": 0, "last_seen": None, "snapshot": None,
                                  "status": "starting", "error": ""} for n in config.nodes if n["id"] != config.node_id}
        self.lock = asyncio.Lock()
        self.client = httpx.AsyncClient(verify=ssl.create_default_context(cafile=str(config.ca)), timeout=config.timeout,
                                        trust_env=False, follow_redirects=False)
        self.stop = asyncio.Event()
        self.last_error = ""
        self._pruned_at = 0
        self._history_at = 0
        self.clients = {}
        self.semaphore = asyncio.Semaphore(8)
        from .membership import Membership
        self.membership = Membership(self)

    @property
    def is_leader(self):
        return not self.membership.blocked and time.monotonic() < self.deadline and self.leader == self.config.node_id

    def presentation_settings(self, stored):
        value = stored or {k: v for k, v in DEFAULT_SETTINGS.items() if k != "branding"}
        legacy = self.config.resolve(self.config.data["logo_file"]) if self.config.data.get("logo_file") else None
        return normalize_settings(value, legacy)

    def settings(self):
        return self.presentation_settings(self.store.record().get("settings"))

    def snapshot(self):
        vote = self.store.get("vote", {})
        return {"node_id": self.config.node_id, "sample": self.sample, "tick_at": self.last_tick,
                "leader": self.leader, "quorum": self.quorum, "leader_active": self.is_leader,
                "vote": vote if time.monotonic() < self.store.vote_deadline else {},
                "record_revision": self.store.record()["revision"],
                "observations": {key: {"misses": p["misses"], "last_seen": p["last_seen"],
                    "status": p["status"]} for key, p in self.peers.items()}}

    async def reconfigure(self):
        self.deadline = 0
        self.leader = None
        self.peers = {n["id"]: self.peers.get(n["id"], {"misses": 0, "successes": 0, "last_seen": None, "snapshot": None, "status": "starting", "error": ""}) for n in self.config.nodes if n["id"] != self.config.node_id}

    async def request(self, node_id, path, payload=None):
        return await self.request_node(self.config.by_id[node_id], path, payload)

    async def request_node(self, node, path, payload=None):
        body = canonical(payload) if payload is not None else b""
        method = "POST" if payload is not None else "GET"
        headers = signed_headers(self.config, method, path, body)
        headers["Content-Type"] = "application/json"
        client = self.client
        if node.get("certificate"):
            from .membership import pinned_context
            key = (node["url"], node["certificate"])
            if key not in self.clients:
                self.clients[key] = httpx.AsyncClient(verify=pinned_context(node["certificate"]), timeout=self.config.timeout, trust_env=False, follow_redirects=False)
            client = self.clients[key]
        async with self.semaphore:
            r = await client.request(method, node["url"].rstrip("/") + path, content=body, headers=headers)
        r.raise_for_status()
        if len(r.content) > 4_000_000:
            raise ValueError("Peer response too large")
        return r.json()

    async def poll(self, node_id):
        p = self.peers[node_id]
        try:
            response = await self.request(node_id, "/peer/snapshot")
            if response.get("node_id") != node_id:
                raise ValueError("Node identity mismatch")
            if not response.get("tick_at") or time.time() - response["tick_at"] > max(20, self.config.interval * 3):
                raise ValueError("Monitoring loop is stale")
            p.update(snapshot=response, last_seen=time.time(), misses=0, successes=p["successes"] + 1, error="")
            if p["successes"] >= 2 or p["status"] == "starting":
                p["status"] = "online"
        except (httpx.HTTPError, ValueError, KeyError, TypeError):
            p.update(misses=p["misses"] + 1, successes=0, error="Peer endpoint unavailable, stale, or authentication failed")
            if p["misses"] >= self.config.fail_samples:
                p["status"] = "unreachable"

    async def elect(self):
        if self.membership.blocked:
            self.deadline = 0
            self.leader = None
            return
        live = [self.config.local] + [self.config.by_id[k] for k, p in self.peers.items()
                                      if p["status"] == "online" and p["misses"] == 0]
        preferred = min(live, key=self.config.priority_key)["id"]
        previous = self.is_leader
        if preferred != self.config.node_id or len(live) < self.config.majority:
            self.deadline = 0
            self.quorum = 0
            active = [(p.get("snapshot") or {}).get("leader") for p in self.peers.values()
                      if p["misses"] == 0 and (p.get("snapshot") or {}).get("leader_active")]
            self.leader = active[0] if active else None
            return
        started = time.monotonic()
        records = []
        if not previous:
            # Persisted epochs fence out even an unseen partial write by an older
            # sender. Read a majority's promises before selecting a new epoch.
            epochs = [self.store.get("vote", {}).get("epoch", 0)]
            async def prepare(n):
                try:
                    response = await self.request(n, "/peer/prepare")
                    epochs.append(response["epoch"])
                except (httpx.HTTPError, ValueError, KeyError):
                    pass
            await asyncio.gather(*(prepare(n) for n in self.peers))
            if len(epochs) < self.config.majority:
                self.deadline = 0
                self.leader = None
                return
            self.epoch = max(epochs) + 1
            self.term = uuid.uuid4().hex
        if not self.store.grant(self.config.node_id, self.term, self.config.lease_ttl, self.epoch):
            self.deadline = 0
            self.leader = self.store.get("vote", {}).get("owner")
            return
        records.append(self.store.record())

        async def vote(n):
            try:
                answer = await self.request(n, "/peer/vote", {"term": self.term, "epoch": self.epoch})
                if answer["granted"]:
                    records.append(answer["record"])
            except (httpx.HTTPError, ValueError, KeyError):
                pass
        await asyncio.gather(*(vote(n) for n in self.peers))
        self.quorum = len(records)
        if self.quorum < self.config.majority:
            self.deadline = 0
            self.leader = None
            return
        self.deadline = started + self.config.lease_ttl - max(2, self.config.timeout * 2)
        self.leader = self.config.node_id
        best = max(records, key=lambda r: (r["epoch"], r["revision"]))
        # Equal revisions with unequal content indicate a broken invariant; fail closed.
        if any((r["epoch"], r["revision"]) == (best["epoch"], best["revision"]) and canonical(r) != canonical(best) for r in records):
            self.deadline = 0
            raise RuntimeError("Conflicting replicated records; sending paused")
        if not previous:
            self.store.audit("leader_elected", self.config.node_id)
            # An interrupted send cannot safely be replayed with ordinary SMTP.
            changed = copy.deepcopy(best)
            for event in changed["events"]:
                if event["status"] == "sending":
                    event.update(status="uncertain", detail_delivery="Previous sender stopped during SMTP delivery; check the mailbox")
            # Commit a majority barrier in the new epoch before evaluating alerts.
            await self.replicate(changed)
        elif (best["epoch"], best["revision"]) > (self.store.record()["epoch"], self.store.record()["revision"]):
            self.deadline = 0
            raise RuntimeError("A newer writer was observed; sending paused")

    async def replicate(self, record):
        if not self.is_leader:
            return False
        record = copy.deepcopy(record)
        record["epoch"] = self.epoch
        record["revision"] = max(self.store.record()["revision"], record["revision"]) + 1
        if not self.store.accept_record(self.config.node_id, self.term, record):
            self.deadline = 0
            return False
        votes = 1

        async def write(n):
            nonlocal votes
            try:
                r = await self.request(n, "/peer/record", {"term": self.term, "record": record})
                if r.get("accepted"):
                    votes += 1
            except (httpx.HTTPError, ValueError):
                pass
        await asyncio.gather(*(write(n) for n in self.peers))
        if votes < self.config.majority or not self.is_leader:
            self.deadline = 0
            self.leader = None
            return False
        return True

    def node_views(self):
        rows = []
        for n in sorted(self.config.nodes, key=self.config.priority_key):
            if n["id"] == self.config.node_id:
                row = {"status": "online" if self.sample else "starting", "last_seen": self.last_tick or None,
                       "sample": self.sample, "misses": 0}
            else:
                p = self.peers[n["id"]]
                row = {"status": p["status"], "last_seen": p["last_seen"], "sample": (p["snapshot"] or {}).get("sample"),
                       "misses": p["misses"], "error": p["error"]}
                if row["status"] == "unreachable":
                    for other, observation in self.peers.items():
                        if other == n["id"] or observation["misses"] or observation["status"] != "online":
                            continue
                        report = (observation["snapshot"] or {}).get("observations", {}).get(n["id"], {})
                        if report.get("status") == "online" and report.get("misses", 99) == 0:
                            row["status"] = "path_issue"
            rows.append({**{k: v for k, v in n.items() if k != "certificate"}, **row, "local": n["id"] == self.config.node_id})
        return rows

    def confirmed_offline(self, node):
        if node["status"] != "unreachable":
            return False
        # Two independent observers must agree before calling the target offline.
        for other, p in self.peers.items():
            if other == node["id"] or p["status"] != "online" or p["misses"]:
                continue
            report = (p["snapshot"] or {}).get("observations", {}).get(node["id"], {})
            if report.get("misses", 0) >= self.config.fail_samples:
                return True
        return False

    @staticmethod
    def new_event(node, metric, kind, severity, detail):
        return {"id": uuid.uuid4().hex, "node": node["id"], "node_name": node["name"], "metric": metric, "kind": kind,
                "severity": severity, "title": f"{node['name']} — {metric.replace('_', ' ')} — {kind}",
                "detail": detail, "created_at": time.time(), "status": "pending", "attempts": 0,
                "next_attempt": 0, "detail_delivery": "Waiting for SMTP"}

    def evaluate(self, record):
        settings = self.presentation_settings(record.get("settings"))
        record["settings"] = settings
        for node in self.node_views():
            values = {}
            if node["local"] or (node["status"] == "online" and node["misses"] == 0):
                values["availability"] = ("availability", 0)
                if node["sample"]:
                    values.update(metrics(node["sample"]))
            elif self.confirmed_offline(node):
                values["availability"] = ("availability", 1)
            for resource, (metric, value) in values.items():
                if value is None:
                    continue
                key = node["id"] + "/" + resource
                incident = record["incidents"].setdefault(key, {"active": False, "bad": 0, "good": 0, "severity": "healthy"})
                observed = time.time() if metric == "availability" else (node["sample"] or {}).get("sampled_at", 0)
                if observed <= incident.get("last_observed", -1):
                    continue
                incident["last_observed"] = observed
                if metric in ("availability", "sensor_error"):
                    severity = "critical" if value else "healthy"
                    healthy = not value
                else:
                    threshold = settings["thresholds"][metric]
                    severity = "critical" if value >= threshold["critical"] else "warning" if value >= threshold["warning"] else "healthy"
                    healthy = value < threshold["warning"] - settings["hysteresis"] if incident["active"] else severity == "healthy"
                incident["value"] = value
                if severity != "healthy":
                    incident["good"] = 0
                    incident["bad"] = incident["bad"] + 1 if incident.get("candidate") == severity else 1
                    incident["candidate"] = severity
                    required = 1 if metric == "availability" else settings["sustain_samples"]
                    if incident["bad"] >= required:
                        kind = "open" if not incident["active"] else "escalated" if severity == "critical" and incident["severity"] == "warning" else None
                        if kind:
                            detail = "Unreachable from two independent monitors; power loss and network failure cannot be distinguished" if metric == "availability" else f"{resource}: {value}; configured limit: {settings['thresholds'].get(metric, 'collector error')}"
                            from .incidents import episode_context
                            event = self.new_event(node, resource, kind, severity, detail)
                            identifier, opened = (event["id"], event["created_at"]) if kind == "open" else episode_context(record, node["id"], resource, incident)
                            event.update(incident_id=identifier, incident_opened_at=opened,
                                         incident_severity=severity, observed_value=value)
                            record["events"].append(event)
                            incident.update(active=True, severity=severity, peak_severity=severity,
                                            incident_id=identifier, opened_at=opened, resolved_at=None)
                elif healthy:
                    incident.update(bad=0, candidate="healthy", good=incident["good"] + 1)
                    if incident["active"] and incident["good"] >= settings["recovery_samples"]:
                        from .incidents import episode_context
                        identifier, opened = episode_context(record, node["id"], resource, incident)
                        event = self.new_event(node, resource, "recovered", "info", f"{resource} recovered; current value: {value}")
                        event.update(incident_id=identifier, incident_opened_at=opened,
                                     incident_severity=incident["severity"], observed_value=value)
                        record["events"].append(event)
                        incident.update(active=False, peak_severity=incident["severity"], severity="healthy",
                                        incident_id=identifier, opened_at=opened, resolved_at=event["created_at"])
                else:
                    incident.update(bad=0, good=0, candidate="healthy")
        # Keep unresolved delivery records; retain completed event history for 90 days.
        record["events"] = [e for e in record["events"] if e["created_at"] > time.time() - 90 * 86400 or e["status"] not in ("sent", "cancelled")]
        if len(canonical(record)) > 3_000_000:
            raise RuntimeError("Alert history reached its safety limit; archive records before continuing")

    async def dispatch(self):
        settings = self.settings()
        smtp = {**settings["smtp"], "email": settings["email"], "branding": settings["branding"]}
        if not smtp["enabled"]:
            return
        eligible = [e["id"] for e in self.store.record()["events"] if e["status"] in ("pending", "retry") and e["next_attempt"] <= time.time()][:5]
        for event_id in eligible:
            if not self.is_leader:
                return
            record = self.store.record()
            event = next(e for e in record["events"] if e["id"] == event_id)
            event.update(status="sending", attempts=event["attempts"] + 1, sender=self.config.node_id, sender_name=self.config.local["name"])
            if not await self.replicate(record):
                return
            try:
                result = await asyncio.to_thread(self.sender, {**event_view(self.config, event), "dashboard_url": self.config.local["url"]}, smtp, self.config.decrypt(smtp["password_encrypted"]), self.config.local["name"])
                event.update(status="sent", detail_delivery=result["detail"], sent_at=time.time())
            except MailError as exc:
                event.update(status="uncertain" if exc.uncertain else "retry", detail_delivery=str(exc),
                             next_attempt=time.time() + min(3600, 15 * 2 ** min(event["attempts"] - 1, 8)))
            except Exception:
                event.update(status="uncertain", detail_delivery="Unexpected sender failure; check the recipient mailbox")
            # If the lease expires during SMTP, a future leader will see durable
            # 'sending' and require review instead of resending the message.
            if self.is_leader:
                await self.replicate(record)

    async def tick(self):
        await self.membership.progress()
        if not self.sample or time.time() - self.sample["sampled_at"] >= self.config.data.get("metrics_seconds", self.config.interval):
            self.sample = await asyncio.to_thread(self.collector.collect)
        self.last_tick = time.time()
        await asyncio.gather(*(self.poll(n) for n in self.peers))
        if time.time() - self._history_at >= self.config.data.get("history_seconds", 60):
            self.store.sample(self.config.node_id, self.sample)
            self._history_at = time.time()
        async with self.lock:
            await self.elect()
            if self.is_leader:
                record = self.store.record()
                self.evaluate(record)
                if await self.replicate(record):
                    await self.dispatch()
        if time.time() - self._pruned_at > 3600:
            self.store.prune()
            self._pruned_at = time.time()

    async def run(self):
        while not self.stop.is_set():
            started = time.monotonic()
            try:
                await self.tick()
                self.last_error = ""
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self.deadline = 0
                self.last_error = f"Monitoring error: {type(exc).__name__}"
                LOG.exception("monitoring cycle failed")
            try:
                await asyncio.wait_for(self.stop.wait(), timeout=max(0.05, self.config.interval - (time.monotonic() - started)))
            except TimeoutError:
                pass

    async def close(self):
        self.stop.set()
        self.deadline = 0
        await self.client.aclose()
        for client in self.clients.values():
            await client.aclose()
