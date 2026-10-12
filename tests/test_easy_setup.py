import json
import os
from pathlib import Path
import socket
import sqlite3
import tempfile
import types
import unittest
from unittest.mock import patch
from aivid_installer.dashboard import selected_address, network_choices, choose_login
from aivid_installer.cli import public_build_permissions, readable_runtime, migrate_state
from aivid_health.collectors import local_disks
from aivid_health.config import Config
from aivid_health.web import password_matches

class EasySetupTests(unittest.TestCase):
    def test_single_interface_no_prompt(self):
        with patch('aivid_installer.dashboard.network_choices',return_value=[('ens1','192.168.1.4')]):
            def fail(_):raise AssertionError('must not prompt')
            self.assertEqual(selected_address(8282,input_fn=fail),('https://192.168.1.4:8282','192.168.1.4'))
    def test_multiple_interfaces_selection(self):
        with patch('aivid_installer.dashboard.network_choices',return_value=[('eth0','10.0.0.4'),('wlan0','192.168.1.4')]),patch('sys.stdin.isatty',return_value=True):
            answers=iter(['bad','3','2'])
            self.assertEqual(selected_address(8282,input_fn=lambda _:next(answers)),('https://192.168.1.4:8282','192.168.1.4'))
    def test_nat_override_port(self):
        with patch('aivid_installer.dashboard.network_choices',return_value=[('eth0','10.0.0.4')]):
            self.assertEqual(selected_address(8282,'203.0.113.4'),('https://203.0.113.4:8282','0.0.0.0'))
            with self.assertRaises(ValueError):selected_address(8282,'https://203.0.113.4:9443')
    def test_enumeration_denied(self):
        with patch('aivid_installer.dashboard.network_choices',side_effect=PermissionError('restricted')):
            self.assertEqual(selected_address(8282,'127.0.0.1'),('https://127.0.0.1:8282','127.0.0.1'))
            with self.assertRaisesRegex(ValueError,'--address'):selected_address(8282)
    def test_active_lan_only(self):
        def a(ip):return types.SimpleNamespace(family=socket.AF_INET,address=ip)
        v={'lo':[a('127.0.0.1')],'eth0':[a('10.0.0.4')],'wlan0':[a('192.168.1.4')],'down0':[a('10.1.1.1')],'docker0':[a('172.17.0.1')],'wg0':[a('10.3.3.3')]}
        with patch('psutil.net_if_addrs',return_value=v),patch('psutil.net_if_stats',return_value={k:types.SimpleNamespace(isup=k!='down0') for k in v}):
            self.assertEqual(network_choices(),[('eth0','10.0.0.4'),('wlan0','192.168.1.4')])
    def test_chosen_credentials(self):
        passwords=iter(['short','wrong-confirm','x','x'])
        with patch('sys.stdin.isatty',return_value=True):
            username, hashed=choose_login(input_fn=lambda _:'aivid.ops',password_fn=lambda _:next(passwords))
        self.assertEqual(username,'aivid.ops');self.assertTrue(password_matches('x',hashed));self.assertNotIn('a-long-enough-password',hashed)
    def test_permissions_with_private_umask(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);old=os.umask(0o077)
            try:
                with public_build_permissions():
                    code=root/'release';code.mkdir();(code/'lib').mkdir();(code/'lib/mod.py').write_text('')
                exe=code/'python';exe.write_text('');exe.chmod(0o700);readable_runtime(code)
                self.assertEqual(code.stat().st_mode&0o777,0o755);self.assertEqual((code/'lib/mod.py').stat().st_mode&0o777,0o644);self.assertEqual(exe.stat().st_mode&0o777,0o755)
                secret=root/'secret';secret.write_text('secret');self.assertEqual(secret.stat().st_mode&0o777,0o600)
            finally:os.umask(old)
    def test_migration_keeps_wal_and_original(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);old=root/'old';old.mkdir();new=root/'new';new.mkdir()
            with sqlite3.connect(old/'monitor.sqlite3') as db:
                db.execute('PRAGMA journal_mode=WAL');db.execute('CREATE TABLE kv (key TEXT,value TEXT)');db.execute("INSERT INTO kv VALUES ('history','retained')");db.commit();self.assertTrue(migrate_state(old,new))
            with sqlite3.connect(new/'monitor.sqlite3') as db:self.assertEqual(db.execute('SELECT value FROM kv').fetchone()[0],'retained')
            self.assertTrue((old/'monitor.sqlite3').exists())
            with self.assertRaises(ValueError):migrate_state(old,new)
    def test_disks_are_local_deduplicated(self):
        def d(dev,mount,fs='ext4'):return types.SimpleNamespace(device=dev,mountpoint=mount,fstype=fs)
        mounts=[d('/dev/sda1','/'),d('/dev/sda1','/bind'),d('/dev/sdb1','/mnt/data'),d('/dev/sdc1','/opt'),d('remote:/','/mnt/network','nfs4'),d('/dev/loop0','/snap/app'),d('overlay','/var/lib/docker/layers','overlay')]
        with patch('psutil.disk_partitions',return_value=mounts):self.assertEqual(local_disks(),['/','/mnt/data','/opt'])
    def test_automatic_order_explicit_precedence(self):
        cfg=object.__new__(Config);cfg.nodes=[{'id':f's{i}','priority':None} for i in range(1,4)]
        self.assertEqual([n['id'] for n in sorted(cfg.nodes,key=cfg.priority_key)],['s1','s2','s3']);self.assertEqual(min(cfg.nodes[1:],key=cfg.priority_key)['id'],'s2')
        cfg.nodes[2]['priority']=2;cfg.nodes[1]['priority']=1
        self.assertEqual([n['id'] for n in sorted(cfg.nodes,key=cfg.priority_key)],['s2','s3','s1'])

class InstallerRollbackTests(unittest.TestCase):
    def test_failed_upgrade_restores_configuration_and_state(self):
        import shutil
        from aivid_installer.cli import main
        from aivid_installer import __version__
        from aivid_installer.cluster import make_cluster
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);prefix=root/'host';source=root/'source';(source/'packaging/runtime').mkdir(parents=True);(source/'packaging/systemd').mkdir()
            (source/'RELEASE_MANIFEST.json').write_text(json.dumps({'version':__version__,'build_id':'new'}));(source/'packaging/runtime/runtime-manifest.json').write_text(json.dumps({'runtimes':{'linux-x86_64':{'filename':'runtime.tgz'}}}));(source/'packaging/systemd/aivid-health.service').write_text('new unit')
            generated=root/'generated';make_cluster(generated,[{'id':'server1','name':'First','url':'https://127.0.0.1:8443','priority':None}]);conf=prefix/'etc/aivid-health';shutil.copytree(generated/'server1',conf)
            config=conf/'node.json';c=json.loads(config.read_text());oldstate=prefix/'var/lib/aivid-health';oldstate.mkdir(parents=True);c['state_dir']=str(oldstate);config.write_text(json.dumps(c));before=config.read_bytes()
            with sqlite3.connect(oldstate/'monitor.sqlite3') as db:db.execute('CREATE TABLE saved (value TEXT)');db.execute("INSERT INTO saved VALUES ('keep')")
            old=prefix/'opt/aivid-health/releases/old';old.mkdir(parents=True);current=old.parent.parent/'current';current.symlink_to(old)
            unit=prefix/'etc/systemd/system/aivid-health.service';unit.parent.mkdir(parents=True);unit.write_text(f'ExecStart={prefix}/opt/aivid-health/current/venv/bin/aivid-monitor serve --config {config}\n'); old_unit=unit.read_text()
            commands=prefix/'usr/local/bin';commands.mkdir(parents=True);(commands/'aivid-healthctl').symlink_to(old.parent.parent/'current/venv/bin/aivid-healthctl');(commands/'aivid-monitor').symlink_to(old.parent.parent/'current/venv/bin/aivid-monitor')
            def extract(_,dest):(dest/'bin').mkdir(parents=True);(dest/'bin/python3').write_text('runtime')
            def fail_validation(args, **kwargs):
                if 'aivid_health.cli' in args and 'check' in args: raise ValueError('injected validation failure')
            with patch('aivid_installer.cli.extract_runtime',side_effect=extract),patch('aivid_installer.cli.run',side_effect=fail_validation):
                with self.assertRaisesRegex(ValueError,'injected validation failure'):main(['--source',str(source),'--config',str(config),'--prefix',str(prefix),'--no-systemd'])
            self.assertEqual(config.read_bytes(),before);self.assertEqual(current.resolve(),old);self.assertEqual(unit.read_text(),old_unit);self.assertTrue((commands/'aivid-monitor').is_symlink());self.assertFalse((old.parent/'new').exists());self.assertTrue(list((prefix/'opt/aivid-healthmonitor').glob('data.failed-*')))
            with sqlite3.connect(oldstate/'monitor.sqlite3') as db:self.assertEqual(db.execute('SELECT value FROM saved').fetchone()[0],'keep')
