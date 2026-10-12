from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import secrets
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from aivid_health.config import monitor_origin


def make_cluster(output, nodes, *, interval=10, timeout=2, lease=45, offline_samples=3, disks=None, gpu_required=(), logo=None):
    if output.exists():
        raise ValueError("Output directory already exists; choose a new directory to avoid replacing cluster keys")
    if not 1 <= len(nodes) <= 32 or len({n['id'] for n in nodes}) != len(nodes) or len({n['url'] for n in nodes}) != len(nodes):
        raise ValueError("Specify 1 to 32 distinct node IDs and URLs")
    for node in nodes:
        u = urlsplit(node["url"])
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,40}", node["id"]) or u.scheme != "https" or not u.hostname or u.username or u.password or u.path not in ("", "/") or u.query or u.fragment:
            raise ValueError("Use node-id=https://host:8282 for each node")
    if logo and (logo.suffix.lower() not in (".png", ".jpg", ".jpeg", ".webp") or logo.stat().st_size > 2_000_000):
        raise ValueError("Logo must be PNG, JPEG or WebP and no larger than 2 MB")
    ca_key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "AIVID Health private cluster CA")])
    ca_cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(ca_key.public_key())
               .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(days=1))
               .not_valid_after(now + timedelta(days=3650)).add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
               .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
               .sign(ca_key, hashes.SHA256()))
    peer_secret, encryption_key, cluster_id = secrets.token_hex(32), Fernet.generate_key().decode(), secrets.token_hex(16)
    output.mkdir(mode=0o700, parents=True)
    (output / "cluster-ca.crt").write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    for node in nodes:
        directory = output / node["id"]
        directory.mkdir(mode=0o700)
        u = urlsplit(node["url"])
        key = ec.generate_private_key(ec.SECP256R1())
        try:
            san = x509.IPAddress(ipaddress.ip_address(u.hostname))
        except ValueError:
            san = x509.DNSName(u.hostname)
        cert = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, node["id"])]))
                .issuer_name(subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=825))
                .add_extension(x509.SubjectAlternativeName([san]), critical=False)
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
                .sign(ca_key, hashes.SHA256()))
        (directory / "cluster-ca.crt").write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
        (directory / "server.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        (directory / "server.key").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        password, salt = secrets.token_urlsafe(20), secrets.token_hex(16)
        hashed = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=2**14, r=8, p=1).hex()
        config = {"schema": 1, "cluster_id": cluster_id, "node_id": node["id"], "nodes": nodes,
                  "peer_secret": peer_secret, "encryption_key": encryption_key, "interval_seconds": interval,
                  "peer_timeout_seconds": timeout, "lease_seconds": lease, "offline_samples": offline_samples,
                  "port": u.port or 443, "listen": "0.0.0.0", "state_dir": "state", "disk_paths": disks or ["/"],
                  "gpu_required": node["id"] in gpu_required, "ca_file": "cluster-ca.crt", "cert_file": "server.crt",
                  "key_file": "server.key", "admin_password_hash": salt + ":" + hashed}
        if logo:
            filename = "brand-logo" + logo.suffix.lower()
            shutil.copyfile(logo, directory / filename)
            config["logo_file"] = filename
        (directory / "node.json").write_text(json.dumps(config, indent=2) + "\n")
        (directory / "credentials.txt").write_text(f"URL: {node['url']}\nUsername: admin\nInitial password: {password}\nChange this password at first login.\n")
        for file in directory.iterdir():
            file.chmod(0o600)
    # Kept only in the private setup directory for certificate renewal; NEVER in
    # the release archive or the individual node directories.
    (output / "cluster-ca.key").write_bytes(ca_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    (output / "cluster-ca.key").chmod(0o600)
    (output / "README.txt").write_text("Copy each server's own directory to that server over a secure channel.\nKeep this setup directory in a protected backup; the CA key is for certificate renewal only.\nDo not copy cluster-ca.key to monitored servers. Import cluster-ca.crt into administrator browser trust.\n")
    return output


def main(argv=None):
    parser = argparse.ArgumentParser(description="Generate one private configuration directory per server. Argument order sets priority.")
    parser.add_argument("--node", action="append", required=True, help="server1=https://10.0.0.11:8282 (repeat for each server)")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--disk", action="append", help="Mountpoint to monitor on every server; repeat as needed")
    parser.add_argument("--gpu-required", action="append", default=[], help="Node ID on which an absent NVIDIA GPU must alert")
    parser.add_argument("--logo", type=Path, help="AIVID PNG/JPEG/WebP logo")
    args = parser.parse_args(argv)
    os.umask(0o077)
    try:
        nodes = [{"id": item.split("=", 1)[0], "name": item.split("=", 1)[0], "url": monitor_origin(item.split("=", 1)[1]), "priority": index + 1} for index, item in enumerate(args.node)]
        make_cluster(args.output.resolve(), nodes, disks=args.disk, gpu_required=args.gpu_required, logo=args.logo)
    except (ValueError, IndexError, OSError) as exc:
        parser.error(str(exc))
    print(f"Created configurations in {args.output.resolve()}. First node has priority 1. Keep credentials and keys private.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
