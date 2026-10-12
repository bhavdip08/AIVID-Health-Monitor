from __future__ import annotations
import asyncio
import base64
import json
from pathlib import Path
import socket
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

import httpx
from aivid_health.config import Config
from aivid_health.enrollment import decode_code, fetch_node, issue, redeem, unpack_node
from aivid_health.store import Store
from aivid_health.web import create_app
from aivid_installer.wizard import address, check_port, configure_local, create_first


class SetupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.file, self.codes = create_first(self.root / "setup", ["127.0.0.1:18441", "127.0.0.1:18442", "127.0.0.1:18443"])
        self.cfg = Config(self.file)
        self.db = Store(self.root / "monitor.sqlite3")
        self.db.put("enrollment", json.loads(self.cfg.resolve("enrollment.json").read_text()))

    def tearDown(self):
        self.db.close(); self.temp.cleanup()

    def test_join_consumes_only_target_once_and_has_no_ca_private_key(self):
        code = decode_code(self.codes["server2"])
        package = redeem(self.cfg, self.db, code["node"], code["token"])
        file = unpack_node(package, self.root / "joined")
        c = Config(file)
        self.assertEqual(c.node_id, "server2")
        self.assertEqual(c.fingerprint, self.cfg.fingerprint)
        self.assertEqual(set(package), {"node.json", "server.crt", "server.key", "cluster-ca.crt"})
        self.assertIsNone(self.db.get("enrollment")["server3"]["used"])
        with self.assertRaises(ValueError): redeem(self.cfg, self.db, code["node"], code["token"])

    def test_expired_wrong_and_rotated_codes(self):
        code = decode_code(self.codes["server2"])
        with self.assertRaises(ValueError): redeem(self.cfg, self.db, "server3", code["token"])
        entries = self.db.get("enrollment")
        entries["server2"]["expires"] = time.time() - 1
        self.db.put("enrollment", entries)
        with self.assertRaises(ValueError): redeem(self.cfg, self.db, "server2", code["token"])
        fresh = decode_code(issue(self.cfg, entries["server2"], "server2"))
        self.db.put("enrollment", entries)
        with self.assertRaises(ValueError): redeem(self.cfg, self.db, "server2", code["token"])
        self.assertIn("node.json", redeem(self.cfg, self.db, "server2", fresh["token"]))

    def test_tokens_and_payloads_are_not_stored_in_plaintext(self):
        raw = json.dumps(self.db.get("enrollment"))
        self.assertNotIn(decode_code(self.codes["server2"])["token"], raw)
        self.assertNotIn(self.cfg.data["peer_secret"], raw)
        self.assertNotIn("PRIVATE KEY", raw)

    def test_concurrent_redemption_has_one_winner(self):
        code = decode_code(self.codes["server2"])
        def attempt(_):
            try:
                redeem(self.cfg, self.db, "server2", code["token"]); return True
            except ValueError:
                return False
        with ThreadPoolExecutor(max_workers=2) as pool:
            self.assertEqual(sum(pool.map(attempt, range(2))), 1)

    def test_invalid_codes_and_path_traversal(self):
        for code in ("", "AIVID1.bad", "AIVID1." + "x" * 3000):
            with self.assertRaises(ValueError): decode_code(code)
        package = {"../escape": "eA==", "node.json": "e30=", "server.crt": "eA==", "server.key": "eA=="}
        with self.assertRaises(ValueError): unpack_node(package, self.root / "unsafe")
        self.assertFalse((self.root / "escape").exists())

    def test_tls_pin_mismatch_sends_no_http_token(self):
        with patch("aivid_health.enrollment.http.client.HTTPSConnection") as cls:
            conn = cls.return_value
            conn.sock.getpeercert.return_value = b"wrong certificate"
            with self.assertRaisesRegex(ValueError, "No join token"):
                fetch_node(self.codes["server2"])
            conn.request.assert_not_called()

    def test_address_and_busy_port_validation(self):
        self.assertEqual(address("203.0.113.1"), "https://203.0.113.1")
        for value in ("http://example.com", "https://user:pw@example.com", "example.com/path", "example.com:70000"):
            with self.assertRaises(ValueError): address(value)
        with socket.socket() as s:
            s.bind(("0.0.0.0", 0)); s.listen()
            with self.assertRaisesRegex(ValueError, "will not choose another port"):
                check_port(s.getsockname()[1])

    def test_local_setup_selects_password_without_plaintext_file(self):
        inputs = iter(["/", "n"])
        configure_local(self.file, input_fn=lambda *args: next(inputs), password_fn=lambda _: "chosen-test-password")
        c = Config(self.file)
        self.assertTrue(c.data["admin_password_chosen"])
        self.assertNotIn("chosen-test-password", self.file.read_text())
        self.assertFalse((self.file.parent / "credentials.txt").exists())


class SetupAPITests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.root = Path(self.temp.name)
        file, self.codes = create_first(self.root / "setup", ["127.0.0.1:18441", "127.0.0.1:18442", "127.0.0.1:18443"])
        configure_local(file, input_fn=lambda p,d: "/" if "Disks" in p else "n", password_fn=lambda _: "chosen-test-password")
        self.app = create_app(file, start_engine=False)
        self.client = httpx.AsyncClient(transport=httpx.ASGITransport(app=self.app), base_url="https://127.0.0.1:18441")

    async def asyncTearDown(self):
        await self.client.aclose(); await self.app.state.engine.close(); self.app.state.store.close(); self.temp.cleanup()

    async def test_setup_requires_login_and_csrf(self):
        self.assertEqual((await self.client.get("/api/setup")).status_code, 401)
        login = await self.client.post("/api/login", json={"username":"admin", "password":"chosen-test-password"})
        self.assertFalse(login.json()["must_change"])
        self.assertEqual((await self.client.get("/api/setup")).status_code, 200)
        self.assertEqual((await self.client.post("/api/setup/invite/server2")).status_code, 403)
        r = await self.client.post("/api/setup/invite/server2", headers={"x-csrf-token":login.json()["csrf"]})
        self.assertEqual(r.status_code, 200)
        code = decode_code(r.json()["code"])
        redeemed = await self.client.post("/setup/enroll", json={"node":code["node"],"token":code["token"]})
        self.assertEqual(redeemed.status_code, 200)
        self.assertEqual((await self.client.post("/setup/enroll", json={"node":code["node"],"token":code["token"]})).status_code, 401)
        self.assertNotIn("package", (await self.client.get("/api/setup")).text)

    async def test_failed_join_rate_limit(self):
        for _ in range(20):
            self.assertEqual((await self.client.post("/setup/enroll", json={"node":"server2","token":"0"*64})).status_code, 401)
        self.assertEqual((await self.client.post("/setup/enroll", json={"node":"server2","token":"0"*64})).status_code, 429)

    async def test_restart_does_not_reactivate_consumed_seed_token(self):
        code = decode_code(self.codes["server2"])
        payload = {"node":code["node"],"token":code["token"]}
        self.assertEqual((await self.client.post("/setup/enroll",json=payload)).status_code, 200)
        other = create_app(self.root / "setup/server1/node.json", start_engine=False)
        try:
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=other),base_url="https://127.0.0.1:18441") as client:
                self.assertEqual((await client.post("/setup/enroll",json=payload)).status_code, 401)
        finally:
            await other.state.engine.close(); other.state.store.close()


if __name__ == "__main__": unittest.main()
