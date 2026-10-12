"""Compatibility risks of the fixed HTTPS port and saved dashboard overrides."""
import copy
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from aivid_health.config import Config, monitor_origin
from aivid_health.membership import current_pairing_code, issue_pairing_code, decode_pair
from aivid_health.store import Store
from aivid_installer.cli import check_network_migration
from aivid_installer.cluster import make_cluster


class SinglePortTests(unittest.TestCase):
    def test_origin_defaults_and_wrong_port_rejection(self):
        self.assertEqual(monitor_origin('203.0.113.4'), 'https://203.0.113.4:8282')
        self.assertEqual(monitor_origin('https://HOST:8282/'), 'https://host:8282')
        self.assertEqual(monitor_origin('https://[::1]'), 'https://[::1]:8282')
        for value in ('https://host:443', 'host:8443', 'http://host', 'https://host/path', 'https://user@host', 'host:0'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                monitor_origin(value)
        with self.assertRaises(ValueError):
            monitor_origin('https://host', explicit=True)

    def test_legacy_urls_change_only_the_port(self):
        for value in ('https://host', 'https://host:443', 'https://host:8443'):
            self.assertEqual(monitor_origin(value, migrate=True), 'https://host:8282')
        self.assertEqual(monitor_origin('https://[2001:db8::1]:443', migrate=True), 'https://[2001:db8::1]:8282')

    def test_saved_overrides_migrate_without_mutating_durable_input(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)/'cluster'
            nodes = [{'id': 'server1', 'name': 'First', 'url': 'https://127.0.0.1', 'priority': None}]
            make_cluster(root, nodes)
            file = root/'server1/node.json'; c = json.loads(file.read_text())
            c.update(fixed_https_port=8282, auth_fingerprint='retained-auth-identity')
            file.write_text(json.dumps(c)); cfg = Config(file)
            overrides = {'nodes': nodes, 'port': 443, 'fixed_https_port': None, 'metrics_seconds': 90}
            before = copy.deepcopy(overrides); cfg.apply(overrides)
            self.assertEqual(overrides, before)
            self.assertEqual(cfg.data['port'], 8282)
            self.assertEqual(cfg.local['url'], 'https://127.0.0.1:8282')
            self.assertEqual(cfg.fingerprint, 'retained-auth-identity')
            self.assertEqual(cfg.data['admin_password_hash'], c['admin_password_hash'])
            self.assertEqual(cfg.data['peer_secret'], c['peer_secret'])
            self.assertEqual(cfg.data['metrics_seconds'], 90)
            cfg.apply(overrides)
            self.assertEqual(cfg.local['url'], 'https://127.0.0.1:8282')

    def test_pending_membership_prevents_port_migration(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with sqlite3.connect(root/'monitor.sqlite3') as db:
                db.execute('CREATE TABLE kv (key TEXT PRIMARY KEY, value TEXT)')
                for state in ({'stage':'prepared'}, {'stage':'committed','propagated':False}):
                    db.execute('INSERT OR REPLACE INTO kv VALUES (?,?)', ('membership', json.dumps(state))); db.commit()
                    with self.assertRaisesRegex(ValueError, 'pending server change'):
                        check_network_migration(root)
                db.execute('UPDATE kv SET value=?', (json.dumps({'stage':'committed','propagated':True}),)); db.commit()
                check_network_migration(root)

    def test_old_pairing_code_hidden_and_replaced_on_new_port(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)/'cluster'
            make_cluster(root, [{'id':'server1','name':'First','url':'https://127.0.0.1','priority':None}])
            file = root/'server1/node.json'; cfg = Config(file)
            db = Store(cfg.state_dir/'monitor.sqlite3', cfg.lease_ttl)
            try:
                old = issue_pairing_code(cfg, db)['code']
                c = json.loads(file.read_text()); c['fixed_https_port'] = 8282; file.write_text(json.dumps(c))
                cfg = Config(file)
                self.assertEqual(current_pairing_code(cfg, db)['code'], '')
                new = issue_pairing_code(cfg, db)['code']
                self.assertNotEqual(new, old)
                self.assertEqual(decode_pair(new)['url'], 'https://127.0.0.1:8282')
                self.assertEqual(current_pairing_code(cfg, db)['code'], new)
            finally:
                db.close()
