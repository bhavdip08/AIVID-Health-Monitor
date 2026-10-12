"""Integration-test harness only; the installed service does not load this file."""
import json
import os
from pathlib import Path
import sys

import httpx
import uvicorn

from aivid_health.collectors import Collector
from aivid_health.config import Config
from aivid_health.engine import Engine
from aivid_health.store import Store
from aivid_health.web import create_app

config = Config(sys.argv[1])
control = Path(sys.argv[2])


def controls():
    try:
        return json.loads(control.read_text())
    except (OSError, ValueError):
        return {}


class TestCollector(Collector):
    def collect(self):
        result = super().collect()
        result["cpu_percent"] = controls().get("cpu", 10)
        result["memory_percent"] = 20
        return result


class FaultEngine(Engine):
    async def request(self, node_id, path, payload=None):
        if node_id in controls().get("blocked", []):
            raise httpx.ConnectError("Test-only network partition")
        return await super().request(node_id, path, payload)


store = Store(config.state_dir / "monitor.sqlite3", config.lease_ttl)
engine = FaultEngine(config, store, collector=TestCollector(config))
app = create_app(config=config, store=store, engine=engine)
uvicorn.run(app, host=config.data.get("listen", "127.0.0.1"), port=config.data["port"], ssl_certfile=str(config.cert), ssl_keyfile=str(config.key), access_log=False, log_level="warning")
