from __future__ import annotations

import asyncio
import copy
import hashlib
import hmac
import json
import secrets
import re
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request, Query
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from . import __version__
from .config import Config, validate_settings, monitor_origin
from .engine import Engine, authenticate_peer
from .store import Store
from .presentation import DEFAULT_BRANDING, DEFAULT_EMAIL, TOKENS, event_view, server_name, logo_bytes, validate_presentation
from .mail import render_email
from .incidents import incident_rows, incident_summary, delivery_summary, resource_label
from .enrollment import issue, redeem


def validate_username(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_.@-]{1,64}", value):
        raise ValueError("Login ID must be 1 to 64 letters, numbers, or . _ @ -")
    return value


def password_hash(password, salt=None):
    salt = salt or secrets.token_hex(16)
    if not isinstance(password, str) or len(password) > 256:
        raise ValueError("Password must be text of at most 256 characters")
    digest = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=2**14, r=8, p=1).hex()
    return salt + ":" + digest


def password_matches(password, encoded):
    try:
        return hmac.compare_digest(password_hash(password, encoded.split(":")[0]), encoded)
    except (ValueError, TypeError, AttributeError):
        return False


def create_app(config_path=None, *, config=None, store=None, engine=None, start_engine=True):
    cfg = config or Config(config_path)
    db = store or Store(cfg.state_dir / "monitor.sqlite3", cfg.lease_ttl)
    cfg.apply(db.get("config_override", {}))
    eng = engine or Engine(cfg, db)
    if db.get("admin") is None:
        db.put("admin", {"username": validate_username(cfg.data.get("admin_username", "admin")), "password_hash": cfg.data["admin_password_hash"], "must_change": not cfg.data.get("admin_password_chosen", False)})
    if cfg.data.get("enrollment_file") and not db.get("enrollment_initialized"):
        entries = json.loads(cfg.resolve(cfg.data["enrollment_file"]).read_text())
        with db.transaction():
            db._put("enrollment", entries)
            db._put("enrollment_initialized", True)

    @asynccontextmanager
    async def lifespan(app):
        task = asyncio.create_task(eng.run()) if start_engine else None
        yield
        eng.stop.set()
        if task:
            try:
                await asyncio.wait_for(task, timeout=15)
            except (TimeoutError, asyncio.CancelledError):
                task.cancel()
        await eng.close()

    app = FastAPI(title="AIVID Health Monitor", version=__version__, docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    app.state.engine, app.state.store = eng, db
    login_attempts = {}
    enroll_attempts = {}

    @app.post("/setup/enroll")
    async def enroll(request: Request):
        ip = request.client.host if request.client else "unknown"
        now = time.time()
        attempts = [t for t in enroll_attempts.get(ip, []) if now - t < 300]
        if len(attempts) >= 20:
            raise HTTPException(429, "Too many enrollment attempts; wait five minutes")
        if len(enroll_attempts) > 10000:
            enroll_attempts.clear()
        enroll_attempts[ip] = attempts + [now]
        raw = await request.body()
        if len(raw) > 2048:
            raise HTTPException(413, "Enrollment request too large")
        try:
            data = json.loads(raw)
            package = redeem(cfg, db, data.get("node"), data.get("token"))
        except (ValueError, AttributeError) as exc:
            raise HTTPException(401, "Join code not accepted") from exc
        return {"package": package}

    @app.middleware("http")
    async def security(request, call_next):
        try:
            size = int(request.headers.get("content-length", "0") or "0")
        except ValueError:
            return JSONResponse({"detail": "Invalid content length"}, status_code=400)
        if size > 4_000_000:
            return JSONResponse({"detail": "Request too large"}, status_code=413)
        # Browser writes must originate at the current HTTPS dashboard.
        origin = request.headers.get("origin")
        expected_origin = str(request.base_url).rstrip("/")
        if request.method not in ("GET", "HEAD") and origin and origin != expected_origin:
            return JSONResponse({"detail": "Origin rejected"}, status_code=403)
        response = await call_next(request)
        response.headers.update({"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer", "Cache-Control": "no-store",
            "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
            "Strict-Transport-Security": "max-age=31536000"})
        return response

    def session(request, allow_change=False):
        token = request.cookies.get("aivid_session", "")
        key = hashlib.sha256(token.encode()).hexdigest()
        sessions = db.get("sessions", {})
        current = sessions.get(key)
        if not current or current["expiry"] < time.time():
            raise HTTPException(401, "Sign in required")
        if request.method not in ("GET", "HEAD") and not hmac.compare_digest(current["csrf"], request.headers.get("x-csrf-token", "")):
            raise HTTPException(403, "CSRF token missing")
        if db.get("admin")["must_change"] and not allow_change:
            raise HTTPException(403, "Change the initial password first")
        return key, current

    async def peer(request):
        body = await request.body()
        if len(body) > 4_000_000:
            raise HTTPException(413, "Peer request too large")
        try:
            return authenticate_peer(cfg, db, request.method, request.url.path, request.headers, body)
        except ValueError as exc:
            raise HTTPException(401, str(exc)) from exc

    @app.get("/healthz")
    def health():
        return {"status": "ok", "version": __version__}

    @app.get("/readyz")
    def ready():
        healthy = eng.last_tick > time.time() - max(30, cfg.interval * 4) and not eng.last_error
        return JSONResponse({"ready": healthy}, status_code=200 if healthy else 503)

    @app.post("/api/login")
    async def login(request: Request):
        ip = request.client.host if request.client else "unknown"
        now = time.time()
        attempts = [t for t in login_attempts.get(ip, []) if now - t < 300]
        if len(attempts) >= 8:
            raise HTTPException(429, "Too many attempts; wait five minutes")
        body = await request.json()
        if body.get("username") != db.get("admin").get("username", "admin") or not password_matches(body.get("password"), db.get("admin")["password_hash"]):
            login_attempts[ip] = attempts + [now]
            db.audit("login_failed")
            raise HTTPException(401, "Invalid username or password")
        login_attempts.pop(ip, None)
        token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        sessions = {k: v for k, v in db.get("sessions", {}).items() if v["expiry"] > now}
        sessions[hashlib.sha256(token.encode()).hexdigest()] = {"csrf": csrf, "expiry": now + 8 * 3600}
        db.put("sessions", sessions)
        db.audit("login_succeeded")
        response = JSONResponse({"csrf": csrf, "must_change": db.get("admin")["must_change"]})
        response.set_cookie("aivid_session", token, secure=True, httponly=True, samesite="strict", max_age=8 * 3600)
        return response

    @app.get("/api/session")
    def current_session(request: Request):
        _, s = session(request, allow_change=True)
        return {"csrf": s["csrf"], "must_change": db.get("admin")["must_change"]}

    @app.post("/api/password")
    async def change_password(request: Request):
        session(request, allow_change=True)
        body = await request.json()
        if not password_matches(body.get("current"), db.get("admin")["password_hash"]):
            raise HTTPException(400, "Current password is incorrect")
        try:
            hashed = password_hash(body.get("new"))
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        db.put("admin", {**db.get("admin"), "password_hash": hashed, "must_change": False})
        db.put("sessions", {})
        db.audit("password_changed")
        return {"ok": True, "message": "Password changed; sign in again"}

    @app.post("/api/logout")
    def logout(request: Request):
        key, _ = session(request, allow_change=True)
        sessions = db.get("sessions", {})
        sessions.pop(key, None)
        db.put("sessions", sessions)
        r = JSONResponse({"ok": True})
        r.delete_cookie("aivid_session", secure=True, httponly=True, samesite="strict")
        return r

    @app.get("/api/status")
    def status(request: Request):
        session(request)
        record = db.record()
        incidents = incident_rows(record, cfg)
        counts = incident_summary(incidents)
        return {"version": __version__, "local_node": cfg.node_id, "local_name": cfg.local["name"], "nodes": eng.node_views(),
                "leader": eng.leader, "leader_name": server_name(cfg, eng.leader, "Waiting"), "is_leader": eng.is_leader, "quorum": eng.quorum,
                "last_tick": eng.last_tick, "error": eng.last_error,
                "active_incidents": counts["open"], "incident_summary": counts,
                "open_incidents": [{k: v for k, v in row.items() if k != "timeline"} for row in incidents if row["status"] == "open"][:4],
                "delivery_summary": delivery_summary(record["events"]),
                "events": [event_view(cfg, e) for e in sorted(record["events"], key=lambda e: e["created_at"], reverse=True)[:250]],
                "smtp_enabled": eng.settings()["smtp"]["enabled"], "thresholds": eng.settings()["thresholds"], "record_revision": record["revision"],
                "has_logo": bool(cfg.data.get("logo_file")), "majority": cfg.majority, "membership": eng.membership.status()}

    def filtered_rows(rows, node, severity, q):
        query = q.strip().casefold()
        return [r for r in rows if (not node or r["node"] == node)
                and (not severity or r["severity"] == severity)
                and (not query or query in " ".join(str(r.get(k, "")) for k in ("node_name", "metric", "label", "resource", "detail")).casefold())]

    @app.get("/api/incidents")
    def incidents(request: Request, status: str = "open", node: str = "", severity: str = "",
                  q: str = Query("", max_length=200), offset: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=100)):
        session(request)
        if status not in ("open", "closed", "unknown", "all"):
            raise HTTPException(400, "Unknown incident category")
        record = db.record()
        rows = incident_rows(record, cfg)
        summary = incident_summary(rows)
        selected = filtered_rows([r for r in rows if status == "all" or r["status"] == status], node, severity, q)
        if status == "open":
            selected.sort(key=lambda r: (r["severity"] != "critical", r["opened_at"] or 0, r["id"]))
        # Clamp after recoveries/filter changes so a once-full last page cannot
        # appear empty while matching incidents still exist on an earlier page.
        offset = min(offset, max(0, (len(selected) - 1) // limit * limit))
        return {"items": selected[offset:offset + limit], "total": len(selected), "offset": offset,
                "limit": limit, "summary": summary, "record_revision": record["revision"], "retention_days": 90}

    @app.get("/api/deliveries")
    def deliveries(request: Request, node: str = "", severity: str = "", q: str = Query("", max_length=200),
                   offset: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=100)):
        session(request)
        record = db.record()
        rows = [event_view(cfg, e) for e in record["events"]]
        for row in rows:
            row["label"], row["resource"] = resource_label(row["metric"])
        selected = sorted(filtered_rows(rows, node, severity, q), key=lambda e: (e["created_at"], e["id"]), reverse=True)
        offset = min(offset, max(0, (len(selected) - 1) // limit * limit))
        return {"items": selected[offset:offset + limit], "total": len(selected), "offset": offset,
                "limit": limit, "summary": delivery_summary(record["events"]), "record_revision": record["revision"]}

    @app.get("/api/history/{node_id}")
    async def history(node_id: str, request: Request):
        session(request)
        if node_id not in cfg.by_id:
            raise HTTPException(404)
        if node_id != cfg.node_id:
            try:
                return await eng.request(node_id, "/peer/history")
            except Exception:
                return {"items": [], "unavailable": True}
        return {"items": db.history(node_id)}

    @app.get("/api/setup")
    def setup_status(request: Request):
        session(request)
        entries = db.get("enrollment", {})
        events = db.record()["events"]
        tests = sorted([e for e in events if e.get("kind") == "test" or e.get("metric") == "email test"], key=lambda e: e["created_at"], reverse=True)
        return {"nodes": eng.node_views(), "local_node": cfg.node_id, "local_name": cfg.local["name"], "leader": eng.leader, "leader_name": server_name(cfg, eng.leader, "Waiting"),
                "is_leader": eng.is_leader, "smtp_enabled": eng.settings()["smtp"]["enabled"],
                "last_test": event_view(cfg, tests[0]) if tests else None,
                "can_invite": bool(entries),
                "invitations": {n: {"used": v.get("used"), "expires": v["expires"]} for n, v in entries.items()},
                "listen_port": cfg.data["port"], "disk_mode": "auto", "state_dir": str(cfg.state_dir),
                "gpu_required": bool(cfg.data.get("gpu_required")), "metrics_seconds": cfg.data.get("metrics_seconds", cfg.interval),
                "membership": eng.membership.status(), "majority": cfg.majority, "pairable": len(cfg.nodes) == 1,
                "tls_fingerprint": __import__("aivid_health.membership", fromlist=["fingerprint"]).fingerprint(cfg.cert.read_text())}

    @app.post("/api/setup/invite/{node_id}")
    async def create_invite(node_id: str, request: Request):
        session(request)
        if any(n["id"] == node_id and n["status"] == "online" for n in eng.node_views()):
            raise HTTPException(409, "This server is already online. A join code is not needed.")
        with db.transaction():
            entries = db.get("enrollment", {})
            if node_id not in entries:
                raise HTTPException(404, "Create join codes on the first server dashboard")
            code = issue(cfg, entries[node_id], node_id)
            db._put("enrollment", entries)
        db.audit("node_enrollment_issued", node_id)
        return {"code": code, "expires": entries[node_id]["expires"]}

    @app.get("/api/setup/ca")
    def public_ca(request: Request):
        session(request)
        return FileResponse(cfg.ca, filename="AIVID-cluster-ca.crt", media_type="application/x-x509-ca-cert")

    @app.get("/api/settings")
    def settings(request: Request):
        session(request)
        result = copy.deepcopy(eng.settings())
        result["smtp"]["password_set"] = bool(result["smtp"].pop("password_encrypted"))
        return result

    @app.post("/api/settings")
    async def save_settings(request: Request):
        session(request)
        value = await request.json()
        async with eng.lock:
            if not eng.is_leader:
                raise HTTPException(409, "Save settings on the current alert sender dashboard")
            try:
                smtp = value["smtp"]
                password = smtp.pop("password", "")
                smtp.pop("password_set", None)
                smtp["password_encrypted"] = cfg.encrypt(password) if password else eng.settings()["smtp"]["password_encrypted"]
                value = validate_settings(value)
            except (KeyError, ValueError, TypeError, AttributeError) as exc:
                raise HTTPException(400, "Invalid settings: " + str(exc)) from exc
            record = db.record()
            record["settings"] = value
            if not await eng.replicate(record):
                raise HTTPException(503, "No quorum; settings could not be confirmed")
            db.audit("settings_updated")
        return {"ok": True}

    @app.post("/api/test-email")
    async def test_email(request: Request):
        session(request)
        async with eng.lock:
            if not eng.is_leader:
                raise HTTPException(409, "Send the test from the current alert sender dashboard")
            if not eng.settings()["smtp"]["enabled"]:
                raise HTTPException(400, "Enable and save SMTP first")
            record = db.record()
            event = eng.new_event(cfg.local, "email test", "test", "info", "This is the administrator-requested SMTP test")
            record["events"].append(event)
            if not await eng.replicate(record):
                raise HTTPException(503, "No quorum; test could not be queued")
            db.audit("test_email_queued", event["id"])
        return {"queued": True, "event_id": event["id"]}

    @app.post("/api/events/{event_id}/review")
    async def review(event_id: str, request: Request):
        session(request)
        async with eng.lock:
            if not eng.is_leader:
                raise HTTPException(409, "Review this event on the current alert sender dashboard")
            record = db.record()
            event = next((e for e in record["events"] if e["id"] == event_id), None)
            if not event or event["status"] not in ("uncertain", "retry", "pending"):
                raise HTTPException(400, "Event is not awaiting review")
            event.update(status="cancelled", detail_delivery="Notification dismissed by administrator; incident recovery is tracked separately")
            if not await eng.replicate(record):
                raise HTTPException(503, "No quorum")
            db.audit("event_reviewed", event_id)
        return {"ok": True}

    @app.get("/peer/snapshot")
    async def snapshot(request: Request):
        await peer(request)
        return eng.snapshot()

    @app.post("/peer/vote")
    async def vote(request: Request):
        owner = await peer(request)
        body = await request.json()
        term = body.get("term", "")
        epoch = body.get("epoch")
        if not isinstance(term, str) or len(term) != 32 or type(epoch) is not int or epoch < 1:
            raise HTTPException(400, "Invalid term")
        async with eng.lock:
            granted = not eng.membership.blocked and db.grant(owner, term, cfg.lease_ttl, epoch)
        return {"granted": granted, "record": db.record() if granted else None}

    @app.get("/peer/prepare")
    async def prepare(request: Request):
        await peer(request)
        return {"epoch": db.get("vote", {}).get("epoch", 0)}

    @app.post("/peer/record")
    async def record(request: Request):
        owner = await peer(request)
        body = await request.json()
        rec = body.get("record", {})
        if type(rec.get("revision")) is not int or type(rec.get("epoch")) is not int or set(rec) != {"epoch", "revision", "incidents", "events", "settings"}:
            raise HTTPException(400, "Invalid cluster record")
        async with eng.lock:
            return {"accepted": not eng.membership.blocked and db.accept_record(owner, body.get("term"), rec)}

    from .membership import decode_pair, origin, issue_pairing_code, current_pairing_code

    @app.post("/api/setup/local")
    async def local_settings(request: Request):
        session(request)
        b = await request.json()
        try:
            seconds = int(b.get("metrics_seconds", 30))
            if "disk_paths" in b:
                raise ValueError("Disk monitoring is automatic; reload the dashboard")
            if not 10 <= seconds <= 300 or type(b.get("gpu_required")) is not bool:
                raise ValueError("Metrics interval must be 10 to 300 seconds")
            changes = {"disk_mode": "auto", "gpu_required": b["gpu_required"], "metrics_seconds": seconds, "history_seconds": max(60, seconds)}
            async with eng.lock:
                if eng.membership.blocked:
                    raise ValueError("Wait for the server change to finish")
                db.put("config_override", {**db.get("config_override", {}), **changes})
                cfg.apply(changes)
                eng.sample = None
            db.audit("local_settings_updated")
            return {"ok": True}
        except (ValueError, TypeError) as exc:
            raise HTTPException(400, str(exc)) from exc

    @app.get("/api/setup/pair-code")
    async def get_pair_code(request: Request):
        session(request)
        async with eng.lock:
            return current_pairing_code(cfg, db)

    @app.post("/api/setup/pair-code")
    async def pair_code(request: Request):
        session(request)
        try:
            b = await request.json()
            async with eng.lock:
                result = issue_pairing_code(cfg, db, b.get("url", cfg.local["url"]), rotate=True)
            return {**result, "expires_seconds": 3600}
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc

    @app.post("/api/setup/resume-pair")
    async def resume_pair(request: Request):
        session(request)
        try:
            body = await request.json()
            pair = decode_pair(body['pair_code'])
            if cfg.fixed_port:
                pair['url'] = monitor_origin(pair['url'], explicit=True)
            async with eng.lock:
                return eng.membership.renew_pending_pair(pair)
        except (ValueError, KeyError) as exc:
            raise HTTPException(400, str(exc)) from exc

    @app.post("/api/setup/servers")
    async def edit_servers(request: Request):
        session(request)
        b = await request.json()
        try:
            async with eng.lock:
                nodes = copy.deepcopy(cfg.nodes)
                pair = decode_pair(b["pair_code"]) if b.get("pair_code") else None
                if pair and cfg.fixed_port:
                    pair['url'] = monitor_origin(pair['url'], explicit=True)
                name = str(b.get("name", "")).strip()
                if not 1 <= len(name) <= 80:
                    raise ValueError("Server name must be 1 to 80 characters")
                raw_priority = b.get("priority")
                priority = None if raw_priority is None or raw_priority == "" else raw_priority
                if priority is not None and (type(priority) is not int or not 1 <= priority <= 100):
                    raise ValueError("Priority must be blank or an integer from 1 to 100")
                if pair:
                    if pair['id'] in cfg.by_id:
                        raise ValueError("This server is already registered")
                    nodes.append({"id": pair["id"], "name": name, "url": pair["url"], "priority": priority, "certificate": pair["certificate"]})
                else:
                    node = next(n for n in nodes if n["id"] == b["node_id"])
                    url = monitor_origin(b['url']) if cfg.fixed_port else origin(b['url'])
                    node.update(name=name, url=url, priority=priority)
                return await eng.membership.begin(nodes, pair)
        except Exception as exc:
            detail = str(exc)
            for node in sorted(cfg.nodes, key=lambda n: len(n["id"]), reverse=True):
                detail = detail.replace(node["id"], node["name"])
            raise HTTPException(400, detail[:250]) from exc

    @app.post("/setup/pair")
    async def accept_pair(request: Request):
        ip = request.client.host if request.client else "unknown"
        key = "pair:" + ip
        now = time.time()
        attempts = [t for t in enroll_attempts.get(key, []) if now-t < 300]
        if len(attempts) >= 20:
            raise HTTPException(429, "Too many pairing attempts; wait five minutes")
        enroll_attempts[key] = attempts + [now]
        try:
            b = await request.json()
            async with eng.lock:
                if b.get('op') == 'check':
                    pair = db.get('pairing', {})
                    if pair.get('used') or pair.get('expires', 0) < now or not hmac.compare_digest(pair.get('hash', ''), hashlib.sha256(str(b.get('token')).encode()).hexdigest()):
                        raise ValueError('Pairing code expired or used')
                    enroll_attempts.pop(key, None)
                    return {'ok': True, 'node_id': cfg.node_id}
                result = await eng.membership.accept_pair(b.get('token'), b['proposal'])
                enroll_attempts.pop(key, None)
                return result
        except (KeyError, ValueError, TypeError) as exc:
            raise HTTPException(400, str(exc)) from exc

    @app.get("/peer/membership")
    async def membership_state(request: Request):
        await peer(request)
        return {**eng.membership.status(), 'certificate': cfg.cert.read_text(), 'node_id': cfg.node_id}

    @app.get("/peer/history")
    async def peer_history(request: Request):
        await peer(request)
        return {'items': db.history(cfg.node_id)}

    @app.post("/peer/reconfigure")
    async def reconfigure(request: Request):
        await peer(request)
        b = await request.json()
        try:
            async with eng.lock:
                if b['op'] == 'prepare':
                    return eng.membership.prepare(b['proposal'])
                if b['op'] == 'commit':
                    return await eng.membership.commit(b['proposal'], b['acks'], b['record'])
                raise ValueError('Unknown configuration operation')
        except (ValueError, KeyError) as exc:
            raise HTTPException(409, str(exc)) from exc

    @app.get("/api/branding")
    def branding():
        b = eng.settings()["branding"]
        return {"vendor_name": b["vendor_name"], "customer_name": b["customer_name"],
                "vendor_logo": "/brand-logo/vendor", "customer_logo": "/brand-logo/customer" if b["customer_logo"] else None,
                "revision": hashlib.sha256(json.dumps(b, sort_keys=True).encode()).hexdigest()[:16]}

    @app.get("/brand-logo")
    @app.get("/brand-logo/{slot}")
    def logo(slot: str = "vendor"):
        if slot not in ("vendor", "customer"):
            raise HTTPException(404)
        b = eng.settings()["branding"]
        if slot == "vendor" and not b["vendor_logo"]:
            # Keep a previously installed local logo until shared branding is saved.
            legacy = cfg.data.get("logo_file")
            if legacy and "branding" not in (db.record().get("settings") or {}) and cfg.resolve(legacy).is_file():
                return FileResponse(cfg.resolve(legacy))
            return FileResponse(Path(__file__).with_name("static") / "aivid-logo.svg", media_type="image/svg+xml")
        item = logo_bytes(b, slot)
        if not item:
            raise HTTPException(404)
        return Response(item[0], media_type=item[1])

    @app.post("/api/setup/logo")
    async def upload_logo(request: Request):
        session(request)
        import base64
        from .presentation import image_type
        try:
            body = await request.json()
            slot = body.get("slot", "vendor")
            if slot not in ("vendor", "customer"):
                raise ValueError("Choose vendor or customer")
            data = base64.b64decode(body["data"], validate=True)
            mime = image_type(data)
            async with eng.lock:
                if not eng.is_leader:
                    raise HTTPException(409, "Save branding on the current alert sender dashboard")
                value = eng.settings()
                value["branding"][slot + "_logo"] = {"data": body["data"], "mime": mime}
                validate_settings(value)
                record = db.record(); record["settings"] = value
                if not await eng.replicate(record):
                    raise HTTPException(503, "No quorum; branding could not be confirmed")
            return {"ok": True}
        except (KeyError, ValueError, TypeError) as exc:
            raise HTTPException(400, str(exc)) from exc

    @app.get("/api/email-template-defaults")
    def email_defaults(request: Request):
        session(request)
        return {"email": DEFAULT_EMAIL, "branding": DEFAULT_BRANDING, "placeholders": sorted(TOKENS)}

    @app.post("/api/email-preview")
    async def email_preview(request: Request):
        session(request)
        try:
            b = await request.json()
            validate_presentation(b)
            kind = b.get("sample", "offline")
            if kind not in ("offline", "resource", "recovered", "test"):
                raise ValueError("Choose an email preview type")
            event = eng.new_event(cfg.local, "availability" if kind in ("offline", "recovered") else "cpu_percent" if kind == "resource" else "email test",
                                  "open" if kind in ("offline", "resource") else kind,
                                  "critical" if kind in ("offline", "resource") else "info",
                                  "The server is unreachable from two independent monitors." if kind == "offline" else "CPU utilization is 97%; the critical threshold is 95%." if kind == "resource" else "The server is responding to health checks again." if kind == "recovered" else "Your email connection is ready for health alerts.")
            event["dashboard_url"] = cfg.local["url"]
            return render_email(event, b, cfg.local["name"], preview=True)
        except (KeyError, ValueError, TypeError, AttributeError) as exc:
            raise HTTPException(400, str(exc)) from exc

    static = Path(__file__).with_name("static")
    app.mount("/static", StaticFiles(directory=static), name="static")

    @app.get("/")
    def index():
        return FileResponse(static / "index.html")

    return app
