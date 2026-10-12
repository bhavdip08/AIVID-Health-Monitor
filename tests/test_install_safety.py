import errno
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from aivid_installer.cli import readable_runtime
from aivid_installer.safety import private_tree, validate_layout, check_host_access


class SafetyTests(unittest.TestCase):
    def test_private_permissions_do_not_change_neighbour(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); own = root/'setup'; own.mkdir(mode=0o777)
            secret = own/'private.key'; secret.write_text('test'); secret.chmod(0o777)
            neighbour = root/'customer.db'; neighbour.write_text('keep'); neighbour.chmod(0o640)
            private_tree(own)
            self.assertEqual(own.stat().st_mode & 0o777, 0o700)
            self.assertEqual(secret.stat().st_mode & 0o777, 0o600)
            self.assertEqual(neighbour.stat().st_mode & 0o777, 0o640)

    def test_linked_private_file_is_not_followed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); own = root/'data'; own.mkdir()
            other = root/'existing'; other.write_text('keep'); other.chmod(0o644)
            (own/'link').symlink_to(other)
            with self.assertRaisesRegex(ValueError, 'linked'):
                private_tree(own)
            self.assertEqual(other.stat().st_mode & 0o777, 0o644)

    def test_inherited_named_acl_removed_from_code(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); exe = root/'python'; exe.write_text('test'); exe.chmod(0o755)
            # POSIX access ACL: owner rwx, named UID 65534 denied, group/other rx.
            entries = [(1,7,0xffffffff),(2,0,65534),(4,5,0xffffffff),(16,5,0xffffffff),(32,5,0xffffffff)]
            raw = struct.pack('<I',2) + b''.join(struct.pack('<HHI',*e) for e in entries)
            try:
                os.setxattr(exe,'system.posix_acl_access',raw)
            except OSError as exc:
                if exc.errno in (errno.ENOTSUP, errno.EPERM, errno.EINVAL): self.skipTest('POSIX ACL creation unavailable in this test environment: ' + str(exc))
                raise
            self.assertIn('system.posix_acl_access', os.listxattr(exe))
            readable_runtime(root)
            self.assertNotIn('system.posix_acl_access', os.listxattr(exe))
            self.assertEqual(exe.stat().st_mode & 0o777, 0o755)

    def test_shared_parent_access_denial_causes_no_chmod(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); (root/'opt').mkdir(mode=0o700); (root/'etc').mkdir()
            with patch('aivid_installer.safety.pwd.getpwnam',side_effect=KeyError):
                with self.assertRaisesRegex(ValueError, 'not traversable'):
                    check_host_access(root)
            self.assertEqual((root/'opt').stat().st_mode & 0o777, 0o700)

    def test_unrelated_service_and_redirected_paths_fail_before_write(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); unit = root/'etc/systemd/system/aivid-health.service'
            unit.parent.mkdir(parents=True); unit.write_text('[Service]\nExecStart=/opt/existing-app/run\n')
            with self.assertRaisesRegex(ValueError, 'unrecognized service'):
                validate_layout(root)
            self.assertIn('existing-app',unit.read_text())
            unit.unlink(); (root/'opt').mkdir(); (root/'opt/aivid-healthmonitor').symlink_to(root/'etc')
            with self.assertRaisesRegex(ValueError,'redirected'):
                validate_layout(root)

    def test_bootstrap_has_no_rawin_or_signature_bypass(self):
        root = Path(__file__).resolve().parents[1]
        script = (root/'tools/bootstrap.sh.in').read_text()
        self.assertNotIn('-rawin',script)
        self.assertEqual(script.count('openssl dgst -sha256 -verify'),2)
        self.assertIn('sha256sum --check --strict --status SHA256SUMS',script)
