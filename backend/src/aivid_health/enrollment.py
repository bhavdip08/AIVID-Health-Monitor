"""Single-use, expiring node enrollment, authenticated by a pinned TLS certificate."""
from __future__ import annotations
import base64
import hashlib
import hmac
import http.client
import json
from pathlib import Path
import re
import secrets
import ssl
import time
from urllib.parse import urlsplit

from .config import Config


def pack_node(directory):
    config = json.loads((directory / "node.json").read_text())
    names = {"node.json", config["ca_file"], config["cert_file"], config["key_file"]}
    if config.get("logo_file"):
        names.add(config["logo_file"])
    return {name: base64.b64encode((directory / name).read_bytes()).decode() for name in names}


def unpack_node(package, directory):
    if not isinstance(package, dict) or not 4 <= len(package) <= 5:
        raise ValueError("Invalid server configuration package")
    files = {}
    for name, encoded in package.items():
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", name) or name.startswith("."):
            raise ValueError("Invalid configuration filename")
        raw = base64.b64decode(encoded, validate=True)
        if len(raw) > 2_100_000:
            raise ValueError("Configuration file is too large")
        files[name] = raw
    config = json.loads(files["node.json"])
    expected = {"node.json", config["ca_file"], config["cert_file"], config["key_file"]}
    if config.get("logo_file"):
        expected.add(config["logo_file"])
    if set(files) != expected:
        raise ValueError("Unexpected configuration files")
    # Remote packages cannot choose arbitrary local paths.
    config["state_dir"] = "state"
    files["node.json"] = json.dumps(config, indent=2).encode()
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    for name, raw in files.items():
        (directory / name).write_bytes(raw)
        (directory / name).chmod(0o600)
    Config(directory / "node.json")
    return directory / "node.json"


def cert_fingerprint(cert):
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(Path(cert).read_text())).hexdigest()


def issue(cfg, entry, node_id, *, now=None):
    now = time.time() if now is None else now
    token = secrets.token_hex(32)
    entry.update(token_hash=hashlib.sha256(token.encode()).hexdigest(), expires=now + 86400, used=None)
    data = {"v": 1, "url": cfg.local["url"], "node": node_id,
            "target": cfg.by_id[node_id]["url"], "pin": cert_fingerprint(cfg.cert), "token": token}
    code = "AIVID1." + base64.urlsafe_b64encode(json.dumps(data, separators=(",", ":")).encode()).decode().rstrip("=")
    return code


def decode_code(code):
    try:
        if not code.startswith("AIVID1.") or len(code) > 2048:
            raise ValueError()
        text = code[7:]
        data = json.loads(base64.b64decode(text + "=" * (-len(text) % 4), altchars=b"-_", validate=True))
        if data["v"] != 1 or not re.fullmatch(r"[A-Za-z0-9_-]{1,40}", data["node"]):
            raise ValueError()
        for field in ("pin", "token"):
            if not re.fullmatch(r"[a-f0-9]{64}", data[field]):
                raise ValueError()
        for field in ("url", "target"):
            u = urlsplit(data[field])
            if u.scheme != "https" or not u.hostname or u.username or u.password or u.query or u.fragment or u.path not in ("", "/"):
                raise ValueError()
            if not 1 <= (u.port or 443) <= 65535:
                raise ValueError()
        return data
    except (ValueError, KeyError, TypeError, AttributeError) as exc:
        raise ValueError("Invalid join code. Copy the complete AIVID1 code from Server 1.") from exc


def fetch_node(code, timeout=10):
    data = decode_code(code)
    u = urlsplit(data["url"])
    # The code is the out-of-band trust anchor. Check the exact certificate on
    # this socket BEFORE sending any token, rather than disabling verification
    # on an ordinary request or accepting an unauthenticated CA download.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    conn = http.client.HTTPSConnection(u.hostname, u.port or 443, timeout=timeout, context=context)
    try:
        conn.connect()
        actual = hashlib.sha256(conn.sock.getpeercert(binary_form=True)).hexdigest()
        if not hmac.compare_digest(actual, data["pin"]):
            raise ValueError("Server identity does not match the join code. No join token was sent.")
        body = json.dumps({"node": data["node"], "token": data["token"]})
        conn.request("POST", "/setup/enroll", body, {"Content-Type": "application/json"})
        response = conn.getresponse()
        raw = response.read(4_000_001)
        if len(raw) > 4_000_000:
            raise ValueError("Enrollment response is too large")
        if response.status != 200:
            raise ValueError("Join code expired, was already used, or is not accepted. Create a new code on Server 1.")
        package = json.loads(raw)["package"]
        config = json.loads(base64.b64decode(package["node.json"], validate=True))
        local = next(n for n in config["nodes"] if n["id"] == config["node_id"])
        if config["node_id"] != data["node"] or local["url"] != data["target"]:
            raise ValueError("Enrollment returned a different server identity")
        return package
    finally:
        conn.close()


def redeem(cfg, db, node, token):
    if not isinstance(token, str) or not re.fullmatch(r"[a-f0-9]{64}", token) or not isinstance(node, str):
        raise ValueError("Join code not accepted")
    with db.transaction():
        entries = db.get("enrollment", {})
        entry = entries.get(node)
        if not entry or entry.get("used") or entry["expires"] < time.time() or not hmac.compare_digest(entry["token_hash"], hashlib.sha256(token.encode()).hexdigest()):
            raise ValueError("Join code not accepted")
        package = json.loads(cfg.decrypt(entry["package"]))
        entry["used"] = time.time()
        db._put("enrollment", entries)
    db.audit("node_enrollment_redeemed", node)
    return package
