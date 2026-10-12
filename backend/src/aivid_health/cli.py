from __future__ import annotations

import argparse
import getpass
import fcntl
import json
import logging
import os
import sqlite3
from pathlib import Path

import uvicorn

from .config import Config
from .store import Store
from .web import create_app, password_hash


def main(argv=None):
    parser = argparse.ArgumentParser(prog="aivid-monitor")
    parser.add_argument("command", choices=["serve", "check", "reset-password", "backup", "pair-code"])
    parser.add_argument("--config", default="/etc/aivid-health/node.json")
    parser.add_argument("--output")
    args = parser.parse_args(argv)
    cfg = Config(args.config)
    os.umask(0o077)
    if args.command == "serve":
        cfg.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        daemon_lock = (cfg.state_dir / "daemon.lock").open("a")
        try:
            fcntl.flock(daemon_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise SystemExit("Another monitor already owns this node state directory")
        logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
        logging.getLogger("httpx").setLevel(logging.WARNING)
        app = create_app(config=cfg)
        uvicorn.run(app, host=cfg.data.get("listen", "0.0.0.0"), port=cfg.data["port"],
                    ssl_certfile=str(cfg.cert), ssl_keyfile=str(cfg.key), access_log=False,
                    server_header=False, workers=1, timeout_graceful_shutdown=15)
        return 0
    if args.command == "check":
        for name, path in (("ca", cfg.ca), ("certificate", cfg.cert), ("key", cfg.key)):
            if not path.is_file():
                raise SystemExit(f"Missing {name}: {path}")
            path.read_bytes()
        import ssl
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(cfg.cert), str(cfg.key))
        if not cfg.state_dir.is_dir() or not os.access(cfg.state_dir, os.W_OK | os.X_OK):
            raise SystemExit(f"State directory is not writable: {cfg.state_dir}")
        print(json.dumps({"configuration": "valid", "node": cfg.node_id, "nodes": [n["id"] for n in cfg.nodes], "priority": cfg.local["priority"]}, indent=2))
        return 0
    if args.command == "pair-code":
        from .membership import issue_pairing_code
        db = Store(cfg.state_dir / "monitor.sqlite3", cfg.lease_ttl)
        try:
            result = issue_pairing_code(cfg, db)
            print(result['code'])
        finally:
            db.close()
        return 0
    if args.command == "backup":
        if not args.output:
            parser.error("--output is required for backup")
        target = Path(args.output)
        if target.exists():
            parser.error("Backup destination already exists")
        with sqlite3.connect(cfg.state_dir / "monitor.sqlite3") as source, sqlite3.connect(target) as dest:
            source.backup(dest)
        target.chmod(0o600)
        print("Database backup saved. Also preserve the node configuration and certificates securely.")
        return 0
    password = getpass.getpass("New admin password (no minimum length): ")
    if password != getpass.getpass("Confirm password: "):
        raise SystemExit("Passwords do not match")
    hashed = password_hash(password)
    # Do not construct Store here: its vote restart protection belongs only to the daemon.
    with sqlite3.connect(cfg.state_dir / "monitor.sqlite3", timeout=10) as db:
        row = db.execute("SELECT value FROM kv WHERE key='admin'").fetchone()
        admin = json.loads(row[0]) if row else {"username": cfg.data.get("admin_username", "admin")}
        admin.update(password_hash=hashed, must_change=False)
        db.execute("INSERT INTO kv VALUES ('admin',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (json.dumps(admin),))
        db.execute("UPDATE kv SET value='{}' WHERE key='sessions'")
    print("Admin password reset and sessions revoked")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
