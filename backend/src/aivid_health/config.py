from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from urllib.parse import urlsplit

from cryptography.fernet import Fernet
from .presentation import DEFAULT_BRANDING, DEFAULT_EMAIL, normalize_settings, validate_presentation

HTTPS_PORT = 8282


def monitor_origin(value, *, migrate=False, explicit=False):
    """One public/listening port; migration preserves the hostname and TLS identity."""
    value = str(value).strip().rstrip('/')
    if '://' not in value:
        value = 'https://' + value
    u = urlsplit(value)
    if u.scheme != 'https' or not u.hostname or u.username or u.password or u.path or u.query or u.fragment or any(c.isspace() for c in value):
        raise ValueError('Enter an HTTPS server address, without a path or credentials')
    port = u.port
    if port is not None and not 1 <= port <= 65535:
        raise ValueError('Invalid HTTPS port')
    if not migrate and (port not in (None, HTTPS_PORT) or explicit and port != HTTPS_PORT):
        raise ValueError('Health Monitor uses HTTPS port 8282 only. Update the server and generate a new pairing code if needed.')
    host = u.hostname.lower()
    host = f'[{host}]' if ':' in host else host
    return f'https://{host}:{HTTPS_PORT}'


DEFAULT_SETTINGS = {
    "branding": DEFAULT_BRANDING, "email": DEFAULT_EMAIL,
    "thresholds": {
        "cpu_percent": {"warning": 85, "critical": 95},
        "memory_percent": {"warning": 85, "critical": 95},
        "disk_percent": {"warning": 85, "critical": 95},
        "gpu_percent": {"warning": 95, "critical": 99},
        "gpu_memory_percent": {"warning": 90, "critical": 98},
        "gpu_temperature": {"warning": 80, "critical": 90},
    },
    "sustain_samples": 3,
    "recovery_samples": 2,
    "hysteresis": 5,
    "smtp": {
        "enabled": False, "host": "", "port": 587, "security": "starttls",
        "username": "", "password_encrypted": "", "sender": "", "recipients": [],
    },
}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


class Config:
    def __init__(self, path):
        self.path = Path(path).resolve()
        self.data = json.loads(self.path.read_text())
        self.fixed_port = self.data.get('fixed_https_port')
        if self.fixed_port not in (None, HTTPS_PORT):
            raise ValueError('Health Monitor uses HTTPS port 8282 only')
        self.apply({})

    def apply(self, changes):
        self.data.update(changes)
        c = self.data
        if self.fixed_port:
            # Old dashboard overrides can contain :443 or a custom port. Apply
            # policy without rewriting durable state so installer rollback is safe.
            c['port'] = c['fixed_https_port'] = HTTPS_PORT
            c['nodes'] = [{**n, 'url': monitor_origin(n['url'], migrate=True)} for n in c['nodes']]
        self.node_id = c["node_id"]
        self.nodes = c["nodes"]
        if not 1 <= len(self.nodes) <= 32 or len({n["id"] for n in self.nodes}) != len(self.nodes):
            raise ValueError("Use 1 to 32 distinct nodes")
        explicit = [n.get("priority") for n in self.nodes if n.get("priority") is not None]
        if len(set(explicit)) != len(explicit):
            raise ValueError("Node priorities must be unique")
        for n in self.nodes:
            u = urlsplit(n["url"])
            if not re.fullmatch(r"[A-Za-z0-9_-]{1,40}", n["id"]):
                raise ValueError("Invalid node ID")
            if u.scheme != "https" or not u.hostname or u.username or u.password or u.path not in ("", "/") or u.query or u.fragment:
                raise ValueError("Every node URL must be an HTTPS origin")
            if n.get("priority") is not None and (type(n["priority"]) is not int or not 1 <= n["priority"] <= 100):
                raise ValueError("Priority must be blank or an integer from 1 to 100")
        if len({n["url"].rstrip("/") for n in self.nodes}) != len(self.nodes):
            raise ValueError("Node addresses must be unique")
        self.by_id = {n["id"]: n for n in self.nodes}
        self.local = self.by_id[self.node_id]
        if len(c["peer_secret"]) < 64:
            raise ValueError("Peer key is too short")
        self.fernet = Fernet(c["encryption_key"].encode())
        self.interval = float(c.get("interval_seconds", 10))
        self.timeout = float(c.get("peer_timeout_seconds", 2))
        self.lease_ttl = float(c.get("lease_seconds", 45))
        self.fail_samples = int(c.get("offline_samples", 3))
        if not (0.2 <= self.interval <= 60 and 0.1 <= self.timeout <= 5 and self.fail_samples >= 2):
            raise ValueError("Invalid collection timing")
        if self.lease_ttl < max(self.interval * 3, self.timeout * 6) or self.lease_ttl > 180:
            raise ValueError("Lease must cover three intervals and six peer timeouts; maximum 180 seconds")
        self.fingerprint = c.get("auth_fingerprint") or hashlib.sha256(canonical({k: c.get(k) for k in (
            "cluster_id", "nodes", "interval_seconds", "peer_timeout_seconds", "lease_seconds", "offline_samples"
        )})).hexdigest()
        self.state_dir = self.resolve(c.get("state_dir", "state"))
        self.ca = self.resolve(c["ca_file"])
        self.cert = self.resolve(c["cert_file"])
        self.key = self.resolve(c["key_file"])
        self.disks = c.get("disk_paths", ["/"])
        if not self.disks or any(not Path(x).is_absolute() for x in self.disks):
            raise ValueError("Disk paths must be absolute")

    def priority_key(self, node):
        """Explicit priorities first; automatic servers follow registration order."""
        index = next(i for i, n in enumerate(self.nodes) if n["id"] == node["id"])
        p = node.get("priority")
        return (p is None, p if p is not None else index, node["id"])

    @property
    def majority(self):
        return len(self.nodes) // 2 + 1

    def resolve(self, path):
        p = Path(path)
        return p if p.is_absolute() else self.path.parent / p

    def encrypt(self, text):
        return self.fernet.encrypt(text.encode()).decode() if text else ""

    def decrypt(self, text):
        return self.fernet.decrypt(text.encode()).decode() if text else ""


def validate_settings(value):
    value = normalize_settings(json.loads(json.dumps(value, allow_nan=False)))
    validate_presentation(value)
    if set(value) != set(DEFAULT_SETTINGS):
        raise ValueError("Unexpected settings fields")
    if set(value["thresholds"]) != set(DEFAULT_SETTINGS["thresholds"]):
        raise ValueError("All six metric thresholds are required")
    for t in value["thresholds"].values():
        if set(t) != {"warning", "critical"} or not 0 <= t["warning"] < t["critical"] <= 120:
            raise ValueError("Thresholds must satisfy 0 <= warning < critical <= 120")
    for name in ("sustain_samples", "recovery_samples"):
        if type(value[name]) is not int or not 1 <= value[name] <= 60:
            raise ValueError("Sample counts must be integers from 1 to 60")
    if not 0 <= value["hysteresis"] <= 20:
        raise ValueError("Hysteresis must be between 0 and 20")
    s = value["smtp"]
    if set(s) != set(DEFAULT_SETTINGS["smtp"]):
        raise ValueError("Unexpected SMTP fields")
    if s["security"] not in ("starttls", "tls", "plain") or type(s["port"]) is not int or not 1 <= s["port"] <= 65535:
        raise ValueError("Invalid SMTP transport")
    if len(s["recipients"]) > 30 or not isinstance(s["recipients"], list):
        raise ValueError("At most 30 recipients are supported")
    for field in ("host", "username", "sender"):
        if not isinstance(s[field], str) or len(s[field]) > 254 or any(x in s[field] for x in "\r\n\x00"):
            raise ValueError("Invalid SMTP field")
    addresses = [s["sender"], *s["recipients"]] if s["enabled"] else s["recipients"]
    if any(not re.fullmatch(r"[^\s<>@,;]+@[^\s<>@,;]+\.[^\s<>@,;]+", a) for a in addresses):
        raise ValueError("Use complete email addresses without display names")
    if s["enabled"] and (not s["host"] or not s["recipients"]):
        raise ValueError("SMTP host, sender and recipients are required")
    if s["security"] == "plain" and s["username"]:
        raise ValueError("SMTP authentication requires TLS or STARTTLS")
    return value
