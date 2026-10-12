"""Guided setup used by the self-extracting installer and install.sh."""
from __future__ import annotations
import argparse
import getpass
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
from urllib.parse import urlsplit

import psutil
from aivid_health.config import Config, monitor_origin
from aivid_health.enrollment import decode_code, fetch_node, issue, pack_node, unpack_node
from aivid_health.web import password_hash
from .cluster import make_cluster


def ask(prompt, default=None):
    value = input(prompt + (f" [{default}]" if default is not None else "") + ": ").strip()
    return value or default or ""


def address(text):
    text = text.strip().rstrip("/")
    if "://" not in text:
        text = "https://" + text
    u = urlsplit(text)
    if u.scheme != "https" or not u.hostname or u.username or u.password or u.path or u.query or u.fragment or any(c.isspace() for c in text):
        raise ValueError("Enter an IP address or hostname, optionally followed by :port. Example: 203.0.113.10")
    if not 1 <= (u.port or 443) <= 65535:
        raise ValueError("Port must be between 1 and 65535")
    host = u.hostname.lower()
    host = f"[{host}]" if ":" in host else host
    return "https://" + host + (f":{u.port}" if u.port and u.port != 443 else "")


def check_port(port, listen="0.0.0.0"):
    with socket.socket(socket.AF_INET6 if ':' in listen else socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((listen, port))
        except OSError as exc:
            raise ValueError(f"Port {port} is unavailable on this server. Ask your administrator to free this port on the selected address, then retry. Health Monitor will not choose another port or stop unrelated applications.") from exc


def detect_disks():
    paths = ["/"]
    for p in psutil.disk_partitions():
        if p.fstype in {"ext4", "ext3", "xfs", "btrfs", "zfs", "nfs", "nfs4", "cifs"} and not p.mountpoint.startswith(("/boot", "/snap", "/var/lib/docker", "/var/lib/kubelet", "/run", "/dev", "/sys", "/proc")):
            paths.append(p.mountpoint)
    return list(dict.fromkeys(paths))


def configure_local(file, *, input_fn=ask, password_fn=getpass.getpass):
    config = json.loads(file.read_text())
    print("\nLocal monitoring settings")
    disks = input_fn("Disks to monitor (comma separated paths)", ", ".join(detect_disks()))
    paths = [x.strip() for x in disks.split(",") if x.strip()]
    if not paths or any(not Path(x).is_absolute() or not Path(x).is_dir() for x in paths):
        raise ValueError("Every disk path must be an existing absolute directory")
    gpu = bool(shutil.which("nvidia-smi"))
    config["gpu_required"] = input_fn("Should a missing NVIDIA GPU trigger an alert? (y/n)", "y" if gpu else "n").lower() == "y"
    config["disk_paths"] = paths
    while True:
        password = password_fn("Choose this server's dashboard password (no minimum length): ")
        try:
            hashed = password_hash(password)
        except ValueError as exc:
            print(str(exc)); continue
        if password != password_fn("Repeat dashboard password: "):
            print("Passwords do not match. Please try again."); continue
        break
    config.update(admin_password_hash=hashed, admin_password_chosen=True)
    file.write_text(json.dumps(config, indent=2) + "\n")
    file.chmod(0o600)
    (file.parent / "credentials.txt").unlink(missing_ok=True)


def create_first(work, urls, *, interval=10, timeout=2, lease=45):
    if work.exists():
        raise ValueError("A setup backup already exists. Keep it safe and resume its installation; do not overwrite cluster keys.")
    work.parent.mkdir(parents=True, exist_ok=True)
    # Publish complete setup atomically. An interruption while generating keys
    # must not leave a half-created active setup directory.
    with tempfile.TemporaryDirectory(prefix="aivid-setup-", dir=work.parent) as temp:
        staging = Path(temp) / "complete"
        _, codes = _create_first(staging, urls, interval=interval, timeout=timeout, lease=lease)
        (staging / "resume.json").write_text(json.dumps({"config": str(work / "server1/node.json"), "configured": False}))
        staging.rename(work)
    return work / "server1/node.json", codes


def _create_first(work, urls, *, interval=10, timeout=2, lease=45):
    nodes = [{"id": f"server{i+1}", "name": f"Server {i+1}", "url": address(url), "priority": i+1} for i, url in enumerate(urls)]
    if len({n["url"] for n in nodes}) != 3:
        raise ValueError("Use three different server addresses")
    make_cluster(work, nodes, interval=interval, timeout=timeout, lease=lease)
    first = work / "server1/node.json"
    cfg = Config(first)
    entries, codes = {}, {}
    for node in nodes[1:]:
        entry = {"package": cfg.encrypt(json.dumps(pack_node(work / node["id"])))}
        codes[node["id"]] = issue(cfg, entry, node["id"])
        entries[node["id"]] = entry
    (work / "server1/enrollment.json").write_text(json.dumps(entries))
    (work / "server1/enrollment.json").chmod(0o600)
    data = json.loads(first.read_text()); data["enrollment_file"] = "enrollment.json"
    first.write_text(json.dumps(data, indent=2))
    (work / "join-codes.json").write_text(json.dumps(codes, indent=2))
    (work / "join-codes.json").chmod(0o600)
    for f in work.glob("*/credentials.txt"):
        f.unlink()
    return first, codes


def summary(config, codes=None):
    cfg = Config(config)
    print("\nAIVID Health Monitor is installed.")
    print("Dashboard: " + cfg.local["url"])
    print("Username: admin   Password: the password you chose")
    print("Open Setup in the dashboard to check servers and configure email.")
    print("Browser trust certificate: " + str(cfg.ca))
    print("Import this public certificate on your administrator workstation once.")
    if codes:
        for node, code in codes.items():
            print(f"\nJoin code for {node} (single use; expires in 24 hours):\n{code}")
        print("\nOn each remaining server run this installer, choose Join, and paste its code.")
    print("Two communicating monitors are required for email alerts.")


def main(argv=None):
    p = argparse.ArgumentParser(description="AIVID guided installation")
    p.add_argument("--source", type=Path, required=True)
    p.add_argument("--prefix", type=Path)
    p.add_argument("--no-systemd", action="store_true")
    args = p.parse_args(argv)
    if bool(args.prefix) != args.no_systemd:
        p.error("Isolated testing requires --prefix and --no-systemd together")
    if args.prefix and args.prefix.resolve() == Path("/"):
        p.error("An isolated prefix cannot be the filesystem root")
    if not args.prefix and os.geteuid() != 0:
        p.error("Start with sudo bash AIVID-Health-Monitor.run")
    root = args.prefix.resolve() if args.prefix else Path("/")
    os.umask(0o077)
    existing = root / "etc/aivid-health/node.json"
    work = root / "var/lib/aivid-health-setup"
    marker = work / "resume.json"
    extra = ["--prefix", str(root), "--no-systemd"] if args.prefix else []
    from .cli import main as install
    print("\nAIVID Health Monitor — guided setup\n")
    try:
        if existing.exists():
            current = root / "opt/aivid-health/current/release.json"
            release = json.loads((args.source / "RELEASE_MANIFEST.json").read_text())
            if current.exists() and json.loads(current.read_text())["build_id"] == release["build_id"]:
                print("This version is already installed. Your configuration has been retained.")
                summary(existing); return 0
            print("Existing monitor found. This will update the application and retain its settings.")
            if ask("Install this update? (y/n)", "y").lower() != "y":
                return 0
            file = existing
        elif marker.exists():
            saved = json.loads(marker.read_text())
            file = Path(saved["config"])
            print("Resuming saved setup. A new join code is not required.")
            if not saved.get("configured"):
                configure_local(file)
                saved["configured"] = True; marker.write_text(json.dumps(saved))
        else:
            print("1. Set up the first server\n2. Join an existing cluster")
            mode = ask("Choose", "1")
            if mode == "1":
                print("Enter the addresses the servers can reach. Dashboard and peers share HTTPS port 8282.")
                urls = [monitor_origin(ask(f"Server {i} public IP or hostname")) for i in (1, 2, 3)]
                check_port(urlsplit(urls[0]).port or 443)
                print("\nPriority: Server 1, then Server 2, then Server 3.")
                for i, url in enumerate(urls, 1):
                    print(f"Server {i}: {url}")
                if ask("Are these addresses correct? (y/n)", "y").lower() != "y":
                    return 0
                file, _ = create_first(work, urls)
            elif mode == "2":
                code = getpass.getpass("Paste this server's complete join code (hidden): ").strip()
                decoded = decode_code(code)
                check_port(urlsplit(decoded["target"]).port or 443)
                print("Joining " + decoded["node"] + " at " + decoded["target"])
                work.mkdir(mode=0o700, parents=True, exist_ok=False)
                try:
                    package = fetch_node(code)
                except Exception:
                    work.rmdir(); raise
                file = unpack_node(package, work / "local")
            else:
                raise ValueError("Choose 1 or 2")
            marker.write_text(json.dumps({"config": str(file), "configured": False}))
            configure_local(file)
            marker.write_text(json.dumps({"config": str(file), "configured": True}))
        print("\nInstalling and checking the service. Python and dependencies are included.")
        install(["--source", str(args.source), "--config", str(file), *extra])
        codes = json.loads((work / "join-codes.json").read_text()) if (work / "join-codes.json").exists() and file != existing else None
        summary(existing, codes)
        print("Protected setup backup: " + str(work))
        return 0
    except (ValueError, OSError, KeyError, subprocess.CalledProcessError) as exc:
        print("\nSetup needs attention: " + str(exc), file=sys.stderr)
        print("Correct the issue and run the same installer again. Saved setup is retained.", file=sys.stderr)
        return 1
    except (KeyboardInterrupt, EOFError):
        print("\nSetup stopped. Run the installer again to resume saved setup.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
