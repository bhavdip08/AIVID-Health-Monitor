"""Checks and permission repair restricted to this monitor's own files."""
from __future__ import annotations

import errno
import os
from pathlib import Path
import pwd
import shutil
import stat
import subprocess


def clear_acl(path):
    # chmod alone retains named ACL entries, which can still deny this account
    # execution or expose private data after the reported chmod -R 777.
    for name in ('system.posix_acl_access', 'system.posix_acl_default'):
        try:
            os.removexattr(path, name, follow_symlinks=False)
        except OSError as exc:
            if exc.errno not in (errno.ENODATA, errno.ENOTSUP, errno.EOPNOTSUPP):
                raise


def private_tree(path, file_mode=0o600):
    if not path.exists():
        return
    entries = [path, *path.rglob('*')]
    for p in entries:
        mode = p.lstat().st_mode
        if p.is_symlink() or not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
            raise ValueError(f'Refusing to change permissions on a linked or special file: {p}')
        if p.is_file() and p.stat().st_nlink != 1:
            raise ValueError(f'Refusing to change a hard-linked file: {p}')
    for p in entries:
        clear_acl(p)
        p.chmod(0o700 if p.is_dir() else file_mode)


def validate_layout(root):
    install = root / 'opt/aivid-health'
    for rel in ('opt/aivid-health', 'opt/aivid-health/releases',
                'opt/aivid-healthmonitor', 'opt/aivid-healthmonitor/setup',
                'opt/aivid-healthmonitor/data', 'etc/aivid-health',
                'etc/systemd/system/aivid-health.service'):
        path = root / rel
        if path.is_symlink():
            raise ValueError(f'Refusing to replace or change a redirected monitor path: {path}')
    current = install / 'current'
    if current.is_symlink():
        if not current.resolve().is_relative_to((install / 'releases').resolve()):
            raise ValueError('The monitor current link points outside its releases directory')
    elif current.exists():
        raise ValueError('The monitor current path is not a release link; preserve it and inspect before updating')
    temporary = install / 'current.new'
    if temporary.exists() and not temporary.is_symlink():
        raise ValueError('The temporary monitor link is an unrelated file; preserve it before retrying')
    unit = root / 'etc/systemd/system/aivid-health.service'
    if unit.exists():
        text = unit.read_text()
        expected = f'ExecStart={install}/current/venv/bin/aivid-monitor serve --config {root / "etc/aivid-health/node.json"}'
        if expected not in text:
            raise ValueError(f'Refusing to replace an unrecognized service: {unit}')
    for name in ('aivid-monitor', 'aivid-healthctl'):
        command = root / 'usr/local/bin' / name
        if command.exists() or command.is_symlink():
            if not command.is_symlink() or command.readlink() != install / 'current/venv/bin' / name:
                raise ValueError(f'Refusing to replace unrelated command: {command}')


def check_host_access(root):
    """Do not broaden /opt or /etc permissions to work around a site policy."""
    try:
        user = pwd.getpwnam('aivid-health')
    except KeyError:
        # A fresh service account will need other-search access on shared parents.
        for path in (root / 'opt', root / 'etc'):
            if path.exists() and not path.stat().st_mode & stat.S_IXOTH:
                raise ValueError(f'{path} is not traversable by a new service account. Run --diagnose; parent permissions were not changed.')
        return
    if user.pw_uid == 0:
        raise ValueError('Refusing to use a privileged aivid-health account')
    for path in (root / 'opt', root / 'etc'):
        if not path.exists():
            continue
        result = subprocess.run(['runuser', '-u', 'aivid-health', '--', '/usr/bin/test', '-x', str(path)], capture_output=True, text=True)
        if result.returncode:
            raise ValueError(f'Service account cannot traverse {path} (or runuser is restricted). Run --diagnose. No shared-directory permissions were changed.')


def execution_diagnostics(executable):
    for args in (['namei', '-l', str(executable)], ['findmnt', '-no', 'TARGET,FSTYPE,OPTIONS', '-T', str(executable)]):
        if shutil.which(args[0]):
            subprocess.run(args, check=False)
    print('Service-user validation failed. Check directory traversal, named ACLs, noexec and AppArmor/SELinux. Use --diagnose; do not use chmod -R 777.')
