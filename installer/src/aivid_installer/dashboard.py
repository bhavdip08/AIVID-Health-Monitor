"""Short local setup with network selection, chosen credentials and pairing."""
from __future__ import annotations
import argparse
import getpass
import ipaddress
import json
import os
from pathlib import Path
import secrets
import socket
import sqlite3
import subprocess
import sys
from urllib.parse import urlsplit
import psutil
from aivid_health.config import Config, HTTPS_PORT, monitor_origin
from aivid_health.web import password_hash, validate_username
from .cluster import make_cluster
from .wizard import check_port


def network_choices():
    choices, seen = [], set()
    stats = psutil.net_if_stats()
    for name, values in psutil.net_if_addrs().items():
        if name.startswith(('lo', 'docker', 'veth', 'br-', 'virbr', 'tun', 'tap', 'wg', 'cni', 'flannel', 'kube', 'tailscale')):
            continue
        if name not in stats or not stats[name].isup:
            continue
        for a in values:
            if a.family != socket.AF_INET:
                continue
            ip = ipaddress.ip_address(a.address)
            if ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_multicast or a.address in seen:
                continue
            choices.append((name, a.address)); seen.add(a.address)
    return sorted(choices)


def ipaddress_loopback(host):
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def selected_address(port, override=None, *, input_fn=input):
    if port != HTTPS_PORT:
        raise ValueError('Health Monitor uses HTTPS port 8282 only')
    try:
        choices = network_choices()
    except OSError:
        choices = []
    if override:
        url = monitor_origin(override)
        host = urlsplit(url).hostname
        return url, host if host in {ip for _, ip in choices} or ipaddress_loopback(host) else '0.0.0.0'
    if not choices:
        raise ValueError('No active LAN/Wi-Fi IPv4 address found. Run again with --address https://YOUR-IP')
    if len(choices) == 1:
        name, host = choices[0]
        print(f'Using {name}: {host}')
    else:
        print('\nChoose the network address for this monitor:')
        for i, (name, host) in enumerate(choices, 1):
            print(f'  {i}. {name}: {host}')
        if not sys.stdin.isatty():
            raise ValueError('Multiple addresses found. Use a terminal to choose one, or provide --address')
        while True:
            choice = input_fn('Network number: ').strip()
            if choice.isdigit() and 1 <= int(choice) <= len(choices):
                name, host = choices[int(choice)-1]; break
            print('Enter one of the network numbers above.')
    return monitor_origin(host), host


def choose_login(credentials_file=None, *, input_fn=input, password_fn=getpass.getpass):
    if credentials_file:
        if credentials_file.stat().st_mode & 0o077:
            raise ValueError('Credentials file must be private: chmod 600 the file before installation')
        values = json.loads(credentials_file.read_text())
        return validate_username(values['username']), password_hash(values['password'])
    if not sys.stdin.isatty():
        raise ValueError('Run in a terminal to choose your login ID and password, or use a private --credentials-file')
    while True:
        try:
            username = validate_username(input_fn('Dashboard login ID [admin]: ').strip() or 'admin')
            break
        except ValueError as exc:
            print(str(exc))
    while True:
        password = password_fn('Dashboard password (hidden; no minimum length): ')
        try:
            hashed = password_hash(password)
        except ValueError as exc:
            print(str(exc)); continue
        if password == password_fn('Repeat password: '):
            return username, hashed
        print('Passwords do not match; try again.')


def main(argv=None):
    p = argparse.ArgumentParser(description='Install locally, then manage servers in the dashboard')
    p.add_argument('--source', type=Path, required=True)
    p.add_argument('--prefix', type=Path)
    p.add_argument('--no-systemd', action='store_true')
    p.add_argument('--address'); p.add_argument('--port', type=int, choices=[HTTPS_PORT], default=HTTPS_PORT)
    p.add_argument('--credentials-file', type=Path)
    a = p.parse_args(argv)
    if bool(a.prefix) != a.no_systemd or a.prefix and a.prefix.resolve() == Path('/'):
        p.error('Use a non-root --prefix with --no-systemd for isolated testing')
    if not a.prefix and os.geteuid() != 0:
        p.error('Run sudo bash AIVID-Health-Monitor.run')
    if not 1 <= a.port <= 65535:
        p.error('Port must be 1 to 65535')
    root = a.prefix.resolve() if a.prefix else Path('/')
    old_umask = os.umask(0o077)
    existing = root / 'etc/aivid-health/node.json'
    current = root / 'opt/aivid-health/current/release.json'
    work = root / 'opt/aivid-healthmonitor/setup'; marker = work / 'local.json'
    extra = ['--prefix', str(root), '--no-systemd'] if a.prefix else []
    from .cli import main as install
    try:
        from .safety import validate_layout, check_host_access, private_tree
        validate_layout(root)
        if not a.no_systemd:
            check_host_access(root)
        private_tree(work)
        if existing.exists():
            file = existing; c = json.loads(existing.read_text())
            state = Path(c.get('state_dir', str(root / 'var/lib/aivid-health')))
            if not state.is_absolute(): state = existing.parent / state
            if not current.exists() and not (state / 'monitor.sqlite3').exists():
                backup = existing.parent / 'node.before-dashboard.json'
                if not backup.exists():
                    backup.write_text(json.dumps(c, indent=2)); backup.chmod(0o600)
                c['nodes'] = [n for n in c['nodes'] if n['id'] == c['node_id']]
                c['nodes'][0]['priority'] = None
                c.pop('enrollment_file', None); c.update(metrics_seconds=30, history_seconds=60)
                if not c.get('admin_password_chosen'):
                    username, hashed = choose_login(a.credentials_file)
                    c.update(admin_username=username, admin_password_hash=hashed, admin_password_chosen=True)
                existing.write_text(json.dumps(c, indent=2))
                print('Recovered unfinished setup. Previous configuration is backed up; add peers in Setup.')
            release = json.loads((a.source / 'RELEASE_MANIFEST.json').read_text())
            if current.exists() and json.loads(current.read_text())['build_id'] == release['build_id']:
                print('This build is already installed. Settings are retained.')
            else:
                print('Installing update; existing configuration and dashboard login are retained.')
                install(['--source', str(a.source), '--config', str(file), *extra])
        else:
            if marker.exists():
                file = Path(json.loads(marker.read_text())['config'])
                print('Resuming saved installation with the login already chosen.')
            else:
                url, listen = selected_address(a.port, a.address)
                check_port(HTTPS_PORT, listen)
                username, hashed = choose_login(a.credentials_file)
                work.mkdir(parents=True, mode=0o700, exist_ok=True); work.chmod(0o700)
                node = 'server-' + secrets.token_hex(4)
                generated = work / ('keys-' + secrets.token_hex(4))
                make_cluster(generated, [{'id': node, 'name': socket.gethostname(), 'url': url, 'priority': None}])
                file = generated / node / 'node.json'; c = json.loads(file.read_text()); c.pop('disk_paths', None)
                c.update(metrics_seconds=30, history_seconds=60, disk_mode='auto', listen=listen,
                         admin_username=username, admin_password_hash=hashed, admin_password_chosen=True)
                file.write_text(json.dumps(c, indent=2))
                (file.parent / 'credentials.txt').unlink(missing_ok=True)
                marker.write_text(json.dumps({'config': str(file)}))
            install(['--source', str(a.source), '--config', str(file), *extra])
        effective = Config(existing); c = effective.data; state = effective.state_dir
        if (state / 'monitor.sqlite3').exists():
            with sqlite3.connect('file:' + str(state / 'monitor.sqlite3') + '?mode=ro', uri=True) as db:
                row = db.execute("SELECT value FROM kv WHERE key='config_override'").fetchone()
                if row: effective.apply(json.loads(row[0]))
                row = db.execute("SELECT value FROM kv WHERE key='admin'").fetchone()
                username = json.loads(row[0]).get('username', 'admin') if row else c.get('admin_username', 'admin')
        else:
            username = c.get('admin_username', 'admin')
        local = next(n for n in c['nodes'] if n['id'] == c['node_id'])
        print('\nAIVID Health Monitor is installed.\nDashboard: ' + local['url'])
        print('Login ID: ' + username + ' | Use the password you chose (existing login retained on upgrade).')
        print('Data: ' + str(state) + '\nLocal disks are detected automatically.')
        command = [str(root / 'opt/aivid-health/current/venv/bin/python'), '-m', 'aivid_health.cli', 'pair-code', '--config', str(existing)]
        if not a.no_systemd: command = ['runuser', '-u', 'aivid-health', '--', *command]
        if len(c['nodes']) == 1:
            result = subprocess.run(command, capture_output=True, text=True)
            if result.returncode == 0:
                print('\nPairing code (private; expires in one hour):\n' + result.stdout.strip())
                print('The same code is in Dashboard > Setup. Paste it on the current alert sender to add this server.')
            else:
                print('Pairing is unavailable while email is enabled or a server change is pending. Open Dashboard > Setup.')
        else:
            print('This server is already paired. Manage its directory in Dashboard > Setup.')
        print('Public TLS certificate: ' + str(existing.parent / c['cert_file']))
        print('Dashboard, pairing and peer checks share HTTPS port 8282. Allow TCP 8282 between servers and from administrator browsers.')
        print('For NAT, forward public TCP 8282 to this server TCP 8282. Upgrade every cluster member before editing servers.')
        if a.no_systemd: print('Isolated test installation: the service has not been started.')
        return 0
    except (OSError, ValueError, KeyError, RuntimeError, EOFError, subprocess.CalledProcessError) as exc:
        print('Installation needs attention: ' + str(exc), file=sys.stderr)
        print('Saved setup is retained. Fix the reported issue and run the installer again.', file=sys.stderr)
        return 1
    finally:
        os.umask(old_umask)

if __name__ == '__main__':
    raise SystemExit(main())
