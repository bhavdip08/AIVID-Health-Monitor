"""Durable votes, replicated alert state, local sessions and observations."""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from contextlib import contextmanager


class Store:
    def __init__(self, path, lease_ttl=45):
        self.path = path
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self.db = sqlite3.connect(path, check_same_thread=False, timeout=10)
        self.db.row_factory = sqlite3.Row
        self.db.executescript("""
        PRAGMA journal_mode=WAL;
        PRAGMA synchronous=FULL;
        CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS nonce (id TEXT PRIMARY KEY, expiry REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS history (ts REAL NOT NULL, node TEXT NOT NULL, data TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS history_time ON history(ts);
        CREATE TABLE IF NOT EXISTS audit (ts REAL NOT NULL, action TEXT NOT NULL, detail TEXT NOT NULL);
        """)
        self.db.commit()
        path.chmod(0o600)
        # A reboot must never erase a live vote. Conservatively hold the previous
        # owner for a full TTL after process restart, regardless of wall-clock jumps.
        old = self.get("vote")
        self.vote_deadline = time.monotonic() + lease_ttl if old else 0

    @contextmanager
    def transaction(self):
        with self.lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                yield
                self.db.commit()
            except BaseException:
                self.db.rollback()
                raise

    def get(self, key, default=None):
        with self.lock:
            row = self.db.execute("SELECT value FROM kv WHERE key=?", (key,)).fetchone()
            return json.loads(row[0]) if row else default

    def _put(self, key, value):
        self.db.execute("INSERT INTO kv VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, json.dumps(value, allow_nan=False)))

    def put(self, key, value):
        with self.transaction():
            self._put(key, value)

    def grant(self, owner, term, ttl, epoch=1):
        with self.transaction():
            vote = self.get("vote")
            if vote and self.vote_deadline > time.monotonic() and (vote["owner"], vote["term"]) != (owner, term):
                return False
            if vote and (epoch < vote.get("epoch", 0) or (epoch == vote.get("epoch", 0) and (vote["owner"], vote["term"]) != (owner, term))):
                return False
            self._put("vote", {"owner": owner, "term": term, "epoch": epoch})
            self.vote_deadline = time.monotonic() + ttl
            return True

    def voted_for(self, owner, term):
        with self.lock:
            v = self.get("vote", {})
            return v.get("owner") == owner and v.get("term") == term and time.monotonic() < self.vote_deadline

    def record(self):
        return self.get("cluster_record", {"epoch": 0, "revision": 0, "incidents": {}, "events": [], "settings": None})

    def accept_record(self, owner, term, record):
        with self.transaction():
            if not self.voted_for(owner, term):
                return False
            if record["epoch"] != self.get("vote")["epoch"]:
                return False
            current = self.record()
            tag = (record["epoch"], record["revision"])
            old_tag = (current["epoch"], current["revision"])
            if tag < old_tag:
                return False
            if tag == old_tag and current != record:
                return False
            self._put("cluster_record", record)
            return True

    def nonce(self, key, expiry):
        with self.transaction():
            self.db.execute("DELETE FROM nonce WHERE expiry<?", (time.time(),))
            try:
                self.db.execute("INSERT INTO nonce VALUES (?,?)", (key, expiry))
                return True
            except sqlite3.IntegrityError:
                return False

    def history(self, node, limit=120):
        with self.lock:
            rows = self.db.execute("SELECT ts,data FROM history WHERE node=? ORDER BY ts DESC LIMIT ?", (node, limit)).fetchall()
            return [{"ts": r[0], **json.loads(r[1])} for r in reversed(rows)]

    def sample(self, node, data):
        with self.transaction():
            self.db.execute("INSERT INTO history VALUES (?,?,?)", (time.time(), node, json.dumps(data)))

    def audit(self, action, detail=""):
        with self.transaction():
            self.db.execute("INSERT INTO audit VALUES (?,?,?)", (time.time(), action, detail[:300]))

    def prune(self):
        with self.transaction():
            self.db.execute("DELETE FROM history WHERE ts<?", (time.time() - 7 * 86400,))
            self.db.execute("DELETE FROM audit WHERE ts<?", (time.time() - 90 * 86400,))

    def close(self):
        with self.lock:
            self.db.close()
