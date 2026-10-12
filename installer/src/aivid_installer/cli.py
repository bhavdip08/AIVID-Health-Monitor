from __future__ import annotations

import argparse
import grp
import fcntl
import sqlite3
from contextlib import contextmanager
import json
import os
import pwd
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path

from . import __version__
from aivid_health.config import HTTPS_PORT, monitor_origin
from .safety import clear_acl, private_tree, validate_layout, check_host_access, execution_diagnostics


def run(args, **kwargs):
    return subprocess.run([str(x) for x in args], check=True, **kwargs)


def extract_runtime(archive, dest):
    dest.mkdir(parents=True)
    with tarfile.open(archive) as tar:
        for member in tar:
            parts = Path(member.name).parts[1:]
            if not parts:
                continue
            member.name = str(Path(*parts))
            # Python's data filter rejects traversal, devices and escaping links.
            tar.extract(member, dest, filter="data")


def ensure_service_account(state):
    """Reuse an existing group after an interrupted or partially removed install."""
    try:
        grp.getgrnam("aivid-health")
    except KeyError:
        run(["groupadd", "--system", "aivid-health"])
    try:
        user = pwd.getpwnam("aivid-health")
    except KeyError:
        run(["useradd", "--system", "--gid", "aivid-health", "--home-dir", state,
             "--shell", "/usr/sbin/nologin", "aivid-health"])
        user = pwd.getpwnam("aivid-health")
    return user


@contextmanager
def public_build_permissions():
    old = os.umask(0o022)
    try:
        yield
    finally:
        os.umask(old)


def readable_runtime(target):
    # Only public executable code: private config/data are outside the release.
    for p in [target, *target.rglob('*')]:
        if not p.is_symlink():
            clear_acl(p)
            p.chmod(0o755 if p.is_dir() or p.stat().st_mode & 0o111 else 0o644)


def migrate_state(old_state, state):
    """The caller holds the stopped daemon's directory lock."""
    if old_state.resolve() == state.resolve() or not (old_state / 'monitor.sqlite3').exists():
        return False
    if (state / 'monitor.sqlite3').exists():
        raise ValueError('Both data directories contain a database. Preserve both and resolve the interrupted migration before retrying.')
    shutil.copytree(old_state, state, dirs_exist_ok=True,
                    ignore=shutil.ignore_patterns('daemon.lock', 'monitor.sqlite3', 'monitor.sqlite3-wal', 'monitor.sqlite3-shm'))
    with sqlite3.connect('file:' + str(old_state / 'monitor.sqlite3') + '?mode=ro', uri=True) as src, sqlite3.connect(state / 'monitor.sqlite3') as dst:
        src.backup(dst)
    (state / 'monitor.sqlite3').chmod(0o600)
    return True


def check_network_migration(state):
    """Never change the addresses used by an unfinished membership proof."""
    database = state / 'monitor.sqlite3'
    if not database.exists():
        return
    with sqlite3.connect('file:' + str(database) + '?mode=ro', uri=True) as db:
        if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='kv'").fetchone():
            return
        row = db.execute("SELECT value FROM kv WHERE key='membership'").fetchone()
        saved = json.loads(row[0]) if row else {}
        if saved.get('stage') == 'prepared' or saved.get('propagated') is False:
            raise ValueError('Finish the pending server change on the previous build before upgrading to port 8282. Keep all members online.')


def main(argv=None):
    parser = argparse.ArgumentParser(prog="aivid-installer")
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--config", type=Path, help="Use an existing configuration; omit for dashboard setup")
    parser.add_argument("--address", help="Optional HTTPS address for a fresh installation")
    parser.add_argument("--credentials-file", type=Path, help="Private JSON username/password for unattended fresh setup")
    parser.add_argument("--port", type=int, choices=[HTTPS_PORT], default=HTTPS_PORT, help="Dashboard and all peer traffic use HTTPS port 8282")
    parser.add_argument("--prefix", type=Path, help="Isolated installation root; requires --no-systemd")
    parser.add_argument("--no-systemd", action="store_true", help="Install and validate without host service registration")
    parser.add_argument("--check", action="store_true", help="Verify dependencies and inspect host paths without installing or starting anything")
    args = parser.parse_args(argv)
    source = args.source.resolve()
    if args.check:
        root = args.prefix.resolve() if args.prefix else Path('/')
        validate_layout(root)
        if not args.no_systemd:
            check_host_access(root)
        from .wizard import check_port
        if not (root / 'opt/aivid-health/current/release.json').exists():
            check_port(HTTPS_PORT)
        print('Preflight passed: release, dependency imports, monitor paths and shared-parent access. No installation changes made.')
        print('A full service-user check runs before activation. The port is checked again before the monitor starts.')
        return 0
    if args.config is None:
        from .dashboard import main as wizard
        return wizard(["--source", str(source), "--port", str(args.port), *(["--address", args.address] if args.address else []), *(["--credentials-file", str(args.credentials_file)] if args.credentials_file else []), *(["--prefix", str(args.prefix)] if args.prefix else []), *(["--no-systemd"] if args.no_systemd else [])])
    if bool(args.prefix) != bool(args.no_systemd):
        parser.error("Use --prefix and --no-systemd together for an isolated installation")
    if not args.prefix and os.geteuid() != 0:
        parser.error("System installation requires sudo")
    if args.prefix and any(x in str(args.prefix.resolve()) for x in (" ", "\n")):
        parser.error("Prefix cannot contain spaces or newlines")
    root = args.prefix.resolve() if args.prefix else Path("/")
    if args.prefix and root == Path("/"):
        parser.error("An isolated prefix cannot be the filesystem root")
    if not args.no_systemd:
        release = dict(line.split("=", 1) for line in Path("/etc/os-release").read_text().splitlines() if "=" in line)
        os_id = release.get("ID", "").strip('"')
        os_version = release.get("VERSION_ID", "").strip('"')
        if (os_id, os_version) not in {("ubuntu", "22.04"), ("ubuntu", "24.04"), ("debian", "12")}:
            parser.error("Supported system installations: Ubuntu 22.04/24.04 or Debian 12")
        if not Path("/run/systemd/system").is_dir():
            parser.error("System installation requires systemd running as the host init system")
    validate_layout(root)
    if not args.no_systemd:
        check_host_access(root)
    install = root / "opt/aivid-health"
    conf = root / "etc/aivid-health"
    state = root / "opt/aivid-healthmonitor/data"
    manifest = json.loads((source / "RELEASE_MANIFEST.json").read_text())
    if manifest["version"] != __version__:
        parser.error("Installer and release versions differ")
    # Full release verification executes before the installer is loaded by bootstrap.
    config = json.loads(args.config.read_text())
    if (conf / "node.json").exists():
        old = json.loads((conf / "node.json").read_text())
        if (old["node_id"], old["cluster_id"]) != (config["node_id"], config["cluster_id"]):
            parser.error("Existing installation belongs to another node or cluster")
    target = install / "releases" / manifest["build_id"]
    space_root = install
    while not space_root.exists():
        space_root = space_root.parent
    if shutil.disk_usage(space_root).free < 2 * 1024 ** 3:
        parser.error("At least 2 GiB of free disk space is required")
    if target.exists():
        parser.error("This build is already installed; use aivid-healthctl restart or install a new build")
    old_link = (install / "current").resolve() if (install / "current").is_symlink() else None
    with public_build_permissions():
        target.mkdir(parents=True)
    for folder in (install, install / 'releases', target):
        clear_acl(folder)
        folder.chmod(0o755)
    config_backup = None
    unit_target = root / "etc/systemd/system/aivid-health.service"
    unit_backup = unit_target.read_bytes() if unit_target.exists() else None
    command_backups = {}
    service_stopped = activation_started = migrated = False
    old_state = Path(config.get('state_dir', str(root / 'var/lib/aivid-health')))
    if not old_state.is_absolute():
        old_state = args.config.resolve().parent / old_state
    state_lock = None
    try:
        port_migration = config.get('fixed_https_port') != HTTPS_PORT or config.get('port') != HTTPS_PORT
        if port_migration:
            check_network_migration(old_state)
            print('Dashboard and peer communication use HTTPS port 8282. Update every cluster member in the same maintenance window.')
        config.update(port=HTTPS_PORT, fixed_https_port=HTTPS_PORT)
        config['nodes'] = [{**n, 'url': monitor_origin(n['url'], migrate=True)} for n in config['nodes']]
        runtime = json.loads((source / "packaging/runtime/runtime-manifest.json").read_text())["runtimes"]["linux-x86_64"]
        with public_build_permissions():
            extract_runtime(source / "packaging/runtime" / runtime["filename"], target / "runtime")
            python = target / "runtime/bin/python3"
            run([python, "-I", "-m", "venv", "--copies", target / "venv"])
            readable_runtime(target)
            vpy = target / "venv/bin/python"
            run([vpy, "-m", "pip", "install", "--disable-pip-version-check", "--no-input", "--no-index", "--require-hashes", "--find-links", source / "packaging/wheelhouse", "-r", source / "requirements.lock"], stdout=subprocess.DEVNULL)
            run([vpy, "-m", "pip", "check"])
        readable_runtime(target)
        conf.parent.mkdir(parents=True, exist_ok=True)
        if conf.exists():
            config_backup = Path(tempfile.mkdtemp(prefix="aivid-config-backup-")) / "config"
            shutil.copytree(conf, config_backup)
        conf.mkdir(mode=0o750, exist_ok=True)
        private_tree(conf, 0o640)
        conf.chmod(0o750)
        with public_build_permissions():
            state.parent.mkdir(parents=True, exist_ok=True)
        clear_acl(state.parent)
        state.parent.chmod(0o755)
        state.mkdir(mode=0o700, exist_ok=True)
        state.chmod(0o700)
        if not args.no_systemd and (old_link or unit_backup):
            run(['systemctl', 'stop', 'aivid-health.service'])
            service_stopped = True
        if old_state.exists():
            state_lock = (old_state / 'daemon.lock').open('a')
            try:
                fcntl.flock(state_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise ValueError('Stop the running monitor before updating this installation') from exc
        if port_migration:
            check_network_migration(old_state)
        from .wizard import check_port
        check_port(HTTPS_PORT, config.get('listen', '0.0.0.0'))
        migrated = migrate_state(old_state, state)
        private_tree(state)
        private_tree(root / 'opt/aivid-healthmonitor/setup')
        config["state_dir"] = str(state)
        config["disk_mode"] = "auto"
        config.pop("disk_paths", None)
        for field in ("ca_file", "cert_file", "key_file", "logo_file", "enrollment_file"):
            if field not in config:
                continue
            src = Path(config[field])
            src = src if src.is_absolute() else args.config.resolve().parent / src
            dst = conf / src.name
            if src.resolve() != dst.resolve():
                shutil.copyfile(src, dst)
            dst.chmod(0o640)
            config[field] = dst.name
        (conf / "node.json").write_text(json.dumps(config, indent=2) + "\n")
        (conf / "node.json").chmod(0o640)
        # Validate imports, certificate paths, membership and timing before activation.
        run([vpy, "-m", "aivid_health.cli", "check", "--config", conf / "node.json"])
        (target / "release.json").write_text(json.dumps({"version": __version__, "build_id": manifest["build_id"]}))
        if not args.no_systemd:
            user = ensure_service_account(state)
            service_gid = grp.getgrnam("aivid-health").gr_gid
            for folder in (conf, state):
                for p in [folder, *folder.rglob("*")]:
                    os.chown(p, 0 if folder == conf else user.pw_uid, service_gid)
            for name in ("video", "render"):
                try:
                    grp.getgrnam(name)
                    run(["usermod", "-a", "-G", name, "aivid-health"])
                except KeyError:
                    pass
            # Catch service-user execution, import, TLS/key and state access failures.
            try:
                run(["runuser", "-u", "aivid-health", "--", vpy, "-I", "-m", "aivid_health.cli", "check", "--config", conf / "node.json"])
            except subprocess.CalledProcessError:
                execution_diagnostics(vpy)
                raise
        if state_lock:
            state_lock.close()
            state_lock = None
        link = install / "current"
        temporary_link = install / "current.new"
        temporary_link.unlink(missing_ok=True)
        temporary_link.symlink_to(target)
        os.replace(temporary_link, link)
        unit_target = root / "etc/systemd/system/aivid-health.service"
        unit_target.parent.mkdir(parents=True, exist_ok=True)
        unit_text = (source / "packaging/systemd/aivid-health.service").read_text().replace("@@ROOT@@", str(root).rstrip("/"))
        unit_target.write_text(unit_text)
        unit_target.chmod(0o644)
        bin_dir = root / "usr/local/bin"
        bin_dir.mkdir(parents=True, exist_ok=True)
        for cmd in ("aivid-healthctl", "aivid-monitor"):
            path = bin_dir / cmd
            command_backups[path] = path.readlink() if path.is_symlink() else None
            if path.exists() or path.is_symlink():
                if not path.is_symlink() or not str(path.readlink()).startswith(str(install)):
                    raise ValueError(f"Refusing to replace unrelated command: {path}")
                path.unlink()
            path.symlink_to(install / "current/venv/bin" / cmd)
        if not args.no_systemd:
            activation_started = True
            run(["systemctl", "daemon-reload"])
            run(["systemctl", "enable", "aivid-health.service"])
            run(["systemctl", "restart", "aivid-health.service"])
            # Wait for actual TLS/API and background collection, not just systemd's launch result.
            import ssl
            import http.client
            import socket
            from urllib.parse import urlsplit
            context = ssl.create_default_context(cafile=str(conf / config["ca_file"]))
            url = next(n["url"] for n in config["nodes"] if n["id"] == config["node_id"])
            hostname = urlsplit(url).hostname
            ready = False
            for _ in range(20):
                try:
                    # Local readiness must not depend on NAT hairpin support.
                    # Still validate the certificate against the configured public host.
                    connection = http.client.HTTPSConnection(hostname, config["port"], context=context, timeout=3)
                    address = config.get("listen", "0.0.0.0")
                    if address == "0.0.0.0": address = "127.0.0.1"
                    try:
                        connection.sock = context.wrap_socket(socket.create_connection((address, config["port"]), timeout=3), server_hostname=hostname)
                        connection.request("GET", "/readyz")
                        ready = connection.getresponse().status == 200
                    finally:
                        connection.close()
                    if ready:
                        break
                except Exception:
                    time.sleep(1)
            if not ready:
                subprocess.run(["journalctl", "-u", "aivid-health.service", "-n", "30", "--no-pager"], check=False)
                raise RuntimeError("Service did not become ready. Recent logs are above; the previous installation is being restored.")
        (state / "install-state.json").write_text(json.dumps({"version": __version__, "build_id": manifest["build_id"], "node_id": config["node_id"]}, indent=2))
        (state / "install-state.json").chmod(0o640)
        print(json.dumps({"status": "installed", "version": __version__, "node_id": config["node_id"], "config": str(conf / "node.json"), "service_registered": not args.no_systemd}, indent=2))
    except BaseException:
        if state_lock:
            state_lock.close()
            state_lock = None
        if not args.no_systemd and (service_stopped or activation_started) and unit_target.exists():
            subprocess.run(["systemctl", "stop", "aivid-health.service"], check=False)
        if old_link:
            (install / "current").unlink(missing_ok=True)
            (install / "current").symlink_to(old_link)
        elif (install / "current").is_symlink():
            (install / "current").unlink()
        if config_backup:
            shutil.rmtree(conf)
            shutil.copytree(config_backup, conf)
            if not args.no_systemd:
                try:
                    service_gid = grp.getgrnam('aivid-health').gr_gid
                    for p in [conf, *conf.rglob('*')]:
                        os.chown(p, 0, service_gid)
                except KeyError:
                    pass
        for path, previous in command_backups.items():
            if path.is_symlink():
                path.unlink()
                if previous is not None:
                    path.symlink_to(previous)
        if unit_backup is not None:
            unit_target.write_bytes(unit_backup)
            unit_target.chmod(0o644)
        else:
            if not args.no_systemd:
                subprocess.run(['systemctl', 'disable', 'aivid-health.service'], check=False, capture_output=True)
            unit_target.unlink(missing_ok=True)
        if migrated:
            state.rename(state.with_name('data.failed-' + str(time.time_ns())))
        if not args.no_systemd:
            subprocess.run(["systemctl", "daemon-reload"], check=False)
            if old_link and service_stopped:
                subprocess.run(["systemctl", "start", "aivid-health.service"], check=False)
        shutil.rmtree(target, ignore_errors=True)
        raise
    finally:
        if state_lock:
            state_lock.close()
        if config_backup:
            shutil.rmtree(config_backup.parent, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
