"""Dashboard pairing and conservative, durable all-member configuration barriers.

Changes wait for every old and new member. A prepared member stops voting/sending;
only a proof containing every member's persisted acknowledgement activates the
next configuration. Interrupted changes resume; they never roll back on a timer.
Trusted cluster members share an HMAC key (this is not Byzantine consensus).
"""
from __future__ import annotations
import asyncio
import base64
import copy
import hashlib
import hmac
import http.client
import json
import secrets
import ssl
import time
from urllib.parse import urlsplit
from .config import Config, canonical, monitor_origin

FIELDS = ('cluster_id', 'peer_secret', 'encryption_key', 'auth_fingerprint', 'nodes',
          'generation', 'interval_seconds', 'peer_timeout_seconds', 'lease_seconds', 'offline_samples')


def origin(value):
    value = str(value).strip().rstrip('/')
    if '://' not in value:
        value = 'https://' + value
    u = urlsplit(value)
    if u.scheme != 'https' or not u.hostname or u.username or u.password or u.path or u.query or u.fragment or any(c.isspace() for c in value):
        raise ValueError('Enter an HTTPS server address, without a path or credentials')
    if not 1 <= (u.port or 443) <= 65535:
        raise ValueError('Invalid HTTPS port')
    return value


def fingerprint(pem):
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest()


def pinned_context(pem):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False  # Identity is the exact out-of-band paired leaf certificate.
    ctx.load_verify_locations(cadata=pem)
    ctx.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
    return ctx


def pair_request(info, payload):
    # Verify identity before sending the single-use secret, including during pairing.
    u = urlsplit(origin(info['url']))
    conn = http.client.HTTPSConnection(u.hostname, u.port or 443, timeout=8,
                                     context=pinned_context(info['certificate']))
    try:
        conn.connect()
        actual = hashlib.sha256(conn.sock.getpeercert(binary_form=True)).hexdigest()
        if not hmac.compare_digest(actual, fingerprint(info['certificate'])):
            raise ValueError('TLS certificate mismatch; no pairing token was sent')
        conn.request('POST', '/setup/pair', body=canonical({'token': info['token'], **payload}),
                     headers={'Content-Type': 'application/json'})
        response = conn.getresponse()
        raw = response.read(4_000_001)
        if len(raw) > 4_000_000:
            raise ValueError('Pairing response too large')
        data = json.loads(raw)
        if response.status != 200:
            raise ValueError(data.get('detail', 'Pairing failed'))
        return data
    finally:
        conn.close()


def decode_pair(code):
    try:
        if not isinstance(code, str) or not code.startswith('AIVID2.') or len(code) > 8192:
            raise ValueError()
        d = json.loads(base64.urlsafe_b64decode(code[7:] + '=' * (-len(code[7:]) % 4)))
        d['url'] = origin(d['url'])
        if len(d['token']) != 64 or len(d['id']) > 40:
            raise ValueError()
        fingerprint(d['certificate'])
        return d
    except (ValueError, KeyError, TypeError) as exc:
        raise ValueError('Invalid pairing code. Copy the full code from the new server dashboard.') from exc


def issue_pairing_code(cfg, db, url=None, *, rotate=False):
    """Share one encrypted, expiring code between installer, CLI and dashboard."""
    with db.transaction():
        cfg.apply(db.get('config_override', {}))
        settings = db.record().get('settings') or {}
        if len(cfg.nodes) != 1 or db.get('membership', {}).get('stage') == 'prepared' or settings.get('smtp', {}).get('enabled'):
            raise ValueError('Pair only a standalone server with email disabled')
        url = monitor_origin(url or cfg.local['url']) if cfg.fixed_port else origin(url or cfg.local['url'])
        previous = db.get('pairing', {})
        if not rotate and not previous.get('used') and previous.get('expires', 0) > time.time() and previous.get('url') == url and previous.get('code_encrypted'):
            return {'code': cfg.decrypt(previous['code_encrypted']), 'expires': previous['expires']}
        token = secrets.token_hex(32)
        d = {'id': cfg.node_id, 'url': url, 'certificate': cfg.cert.read_text(), 'token': token}
        code = 'AIVID2.' + base64.urlsafe_b64encode(canonical(d)).decode().rstrip('=')
        expires = time.time() + 3600
        db._put('pairing', {'hash': hashlib.sha256(token.encode()).hexdigest(), 'expires': expires,
                           'used': False, 'url': url, 'code_encrypted': cfg.encrypt(code)})
        return {'code': code, 'expires': expires}


def current_pairing_code(cfg, db):
    with db.transaction():
        pair = db.get('pairing', {})
        if len(cfg.nodes) != 1 or pair.get('used') or pair.get('expires', 0) <= time.time() or not pair.get('code_encrypted'):
            return {'code': '', 'expires': None}
        if cfg.fixed_port:
            try:
                monitor_origin(pair.get('url', ''), explicit=True)
            except ValueError:
                return {'code': '', 'expires': None}
        return {'code': cfg.decrypt(pair['code_encrypted']), 'expires': pair['expires']}


class Membership:
    def __init__(self, engine):
        self.eng = engine
        self.cfg, self.db = engine.config, engine.store
        self.error = ''
        self.running = False

    @property
    def blocked(self):
        return self.db.get('membership', {}).get('stage') == 'prepared'

    def status(self):
        state = self.db.get('membership', {})
        return {'stage': state.get('stage', 'ready'), 'generation': self.cfg.data.get('generation', 0),
                'pending': self.blocked, 'error': self.error, 'can_resume_pair': self.blocked and bool(state.get('pair')),
                'message': 'Waiting for all servers to finish the saved configuration change. Keep every server online.' if self.blocked else ''}

    def pairing_code(self, url, rotate=True):
        return issue_pairing_code(self.cfg, self.db, url, rotate=rotate)['code']

    def sign_ack(self, proposal):
        record = self.db.record()
        ack = {'node': self.cfg.node_id, 'proposal': hashlib.sha256(canonical(proposal)).hexdigest(),
               'tag': [record['epoch'], record['revision']], 'record_hash': hashlib.sha256(canonical(record)).hexdigest(),
               'epoch': self.db.get('vote', {}).get('epoch', 0)}
        ack['signature'] = hmac.new(self.cfg.data['peer_secret'].encode(), canonical(ack), hashlib.sha256).hexdigest()
        return ack

    def prepare(self, proposal):
        self.validate_ports(proposal['target']['nodes'])
        old = self.db.get('membership', {})
        if old.get('proposal', {}).get('id') == proposal['id']:
            return {'ack': old['ack'], 'record': old['record']}
        if old.get('stage') == 'prepared':
            raise ValueError('Another saved configuration change is pending')
        if proposal['base'] != self.cfg.data.get('generation', 0) or proposal['target']['generation'] != proposal['base'] + 1:
            raise ValueError('Configuration generation mismatch; update every monitor first')
        ids = {n['id'] for n in proposal['target']['nodes']}
        if self.cfg.node_id not in ids or set(proposal['required']) != ids or not set(proposal['old']).issubset(ids):
            raise ValueError('Invalid configuration membership')
        test = Config(self.cfg.path)
        test.apply({k: proposal['target'][k] for k in FIELDS if k in proposal['target']})
        if proposal['target']['cluster_id'] != self.cfg.data['cluster_id']:
            raise ValueError('Different cluster')
        ack = self.sign_ack(proposal)
        self.db.put('membership', {'stage': 'prepared', 'proposal': proposal, 'ack': ack, 'record': self.db.record()})
        self.eng.deadline = 0
        self.eng.leader = None
        return {'ack': ack, 'record': self.db.record()}

    async def accept_pair(self, token, proposal):
        self.validate_ports(proposal['target']['nodes'])
        pair = self.db.get('pairing', {})
        digest = hashlib.sha256(str(token).encode()).hexdigest()
        saved = self.db.get('membership', {})
        if not hmac.compare_digest(pair.get('hash', ''), digest):
            raise ValueError('Pairing code not accepted')
        if saved.get('proposal', {}).get('id') == proposal['id']:
            return {'ack': saved['ack'], 'record': saved['record']}
        if pair.get('used') or pair.get('expires', 0) < time.time() or len(self.cfg.nodes) != 1 or self.eng.settings()['smtp']['enabled']:
            raise ValueError('Pairing code expired, used, or this server is already in a cluster')
        target = copy.deepcopy(proposal['target'])
        target['generation'] = proposal['base']
        if self.cfg.node_id not in proposal['required'] or self.cfg.node_id in proposal['old']:
            raise ValueError('This code belongs to a different server')
        test = Config(self.cfg.path); test.apply(target)
        local = next(n for n in target['nodes'] if n['id'] == self.cfg.node_id)
        if local.get('certificate') != self.cfg.cert.read_text():
            raise ValueError('Local certificate does not match invitation')
        # Adoption, frozen state, and token consumption are one durable transaction.
        with self.db.transaction():
            self.db._put('standalone_backup', {'config': self.cfg.data, 'record': self.db.record()})
            overrides = {k: target[k] for k in FIELDS if k in target}
            self.db._put('config_override', {**self.db.get('config_override', {}), **overrides})
            self.cfg.apply(overrides)
            self.db._put('cluster_record', {'epoch': 0, 'revision': 0, 'incidents': {}, 'events': [], 'settings': None})
            ack = self.sign_ack(proposal)
            self.db._put('membership', {'stage': 'prepared', 'proposal': proposal, 'ack': ack, 'record': self.db.record()})
            pair['used'] = True; self.db._put('pairing', pair)
        await self.eng.reconfigure()
        return {'ack': ack, 'record': self.db.record()}

    def validate_proof(self, proposal, acks, record):
        if set(acks) != set(proposal['required']):
            raise ValueError('Every old and new server must acknowledge the change')
        digest = hashlib.sha256(canonical(proposal)).hexdigest()
        for node, value in acks.items():
            ack = dict(value); signature = ack.pop('signature', '')
            expected = hmac.new(self.cfg.data['peer_secret'].encode(), canonical(ack), hashlib.sha256).hexdigest()
            if ack.get('node') != node or ack.get('proposal') != digest or not hmac.compare_digest(expected, signature):
                raise ValueError('Invalid configuration acknowledgement')
        best = max((acks[n] for n in proposal['old']), key=lambda a: a['tag'])
        if any(a['tag'] == best['tag'] and a['record_hash'] != best['record_hash'] for n, a in acks.items() if n in proposal['old']):
            raise ValueError('Conflicting delivery records; change paused')
        if [record['epoch'], record['revision']] != best['tag'] or hashlib.sha256(canonical(record)).hexdigest() != best['record_hash']:
            raise ValueError('Delivery record does not match the acknowledged state')

    async def commit(self, proposal, acks, record):
        state = self.db.get('membership', {})
        if state.get('proposal', {}).get('id') != proposal['id']:
            raise ValueError('Configuration was not prepared on this server')
        self.validate_proof(proposal, acks, record)
        if state['stage'] == 'committed':
            return {'committed': True}
        with self.db.transaction():
            overrides = {**self.db.get('config_override', {}), **proposal['target']}
            self.db._put('config_override', overrides)
            self.db._put('cluster_record', record)
            self.db._put('vote', {'owner': '', 'term': '', 'epoch': max(a['epoch'] for a in acks.values())})
            state.update(stage='committed', proof=acks, committed_record=record, propagated=False)
            state.pop('pair', None)
            self.db._put('membership', state)
        self.db.vote_deadline = 0
        self.cfg.apply(overrides)
        await self.eng.reconfigure()
        self.db.audit('membership_committed', proposal['id'])
        return {'committed': True}

    def renew_pending_pair(self, pair):
        state = self.db.get('membership', {})
        if state.get('stage') != 'prepared' or not state.get('pair'):
            raise ValueError('No pending pairing token can be replaced on this server')
        original = json.loads(self.cfg.decrypt(state['pair']))
        if any(pair.get(k) != original.get(k) for k in ('id', 'url', 'certificate')):
            raise ValueError('The replacement code must identify the same server, address and certificate')
        state['pair'] = self.cfg.encrypt(json.dumps(pair))
        self.db.put('membership', state)
        self.error = ''
        return {'pending': True, 'message': 'Replacement pairing code saved; the original server change will resume'}

    def validate_ports(self, nodes):
        if self.cfg.fixed_port:
            for node in nodes:
                monitor_origin(node['url'], explicit=True)

    async def begin(self, nodes, pair=None):
        self.validate_ports(nodes)
        if not self.eng.is_leader:
            raise ValueError('Make server changes on the current alert sender dashboard')
        if self.blocked or self.db.get('membership', {}).get('propagated') is False:
            raise ValueError('A saved configuration change is still pending')
        # Read-only preflight avoids freezing a cluster with known unavailable peers.
        for n in self.cfg.nodes:
            if n['id'] != self.cfg.node_id:
                candidate = next(item for item in nodes if item['id'] == n['id'])
                answer = await self.eng.request_node({**n, 'url': candidate['url']}, '/peer/membership')
                if answer.get('node_id') != n['id']:
                    raise ValueError('The address belongs to a different server')
                if answer.get('pending'):
                    raise ValueError('A server already has a pending change')
                next(item for item in nodes if item['id'] == n['id'])['certificate'] = answer['certificate']
            else:
                next(item for item in nodes if item['id'] == n['id'])['certificate'] = self.cfg.cert.read_text()
        for node in nodes:
            if node['id'] != self.cfg.node_id and node['id'] in self.cfg.by_id and node['url'] != self.cfg.by_id[node['id']]['url']:
                answer = await self.eng.request_node(node, '/peer/snapshot')
                if answer.get('node_id') != node['id']:
                    raise ValueError('The new address does not identify this server')
        if pair:
            answer = await asyncio.to_thread(pair_request, pair, {'op': 'check'})
            if answer.get('node_id') != pair['id']:
                raise ValueError('Pairing code identity mismatch')
        target = {k: self.cfg.data[k] for k in FIELDS if k in self.cfg.data}
        target.update(nodes=nodes, generation=self.cfg.data.get('generation', 0)+1, auth_fingerprint=self.cfg.fingerprint)
        test = Config(self.cfg.path); test.apply(target)
        proposal = {'id': secrets.token_hex(16), 'base': self.cfg.data.get('generation', 0), 'target': target,
                    'old': [n['id'] for n in self.cfg.nodes], 'required': [n['id'] for n in nodes]}
        self.prepare(proposal)
        if pair:
            state = self.db.get('membership'); state['pair'] = self.cfg.encrypt(json.dumps(pair)); self.db.put('membership', state)
        # Progress happens in the regular loop, outside the dashboard request.
        return {'pending': True, 'message': 'Change saved. Keep all servers online while configuration synchronizes.'}

    async def progress(self):
        state = self.db.get('membership', {})
        if not state or state.get('propagated') or self.running:
            return
        self.running = True
        try:
            p = state['proposal']
            if state['stage'] == 'prepared':
                acks, records = {self.cfg.node_id: state['ack']}, {self.cfg.node_id: state['record']}
                if state.get('pair'):
                    pair = json.loads(self.cfg.decrypt(state['pair']))
                    answer = await asyncio.to_thread(pair_request, pair, {'op': 'prepare', 'proposal': p})
                    acks[pair['id']], records[pair['id']] = answer['ack'], answer['record']
                for n in p['target']['nodes']:
                    if n['id'] in acks:
                        continue
                    answer = await self.eng.request_node(n, '/peer/reconfigure', {'op': 'prepare', 'proposal': p})
                    acks[n['id']], records[n['id']] = answer['ack'], answer['record']
                best = max((records[n] for n in p['old']), key=lambda r: (r['epoch'], r['revision']))
                await self.commit(p, acks, best)
                state = self.db.get('membership')
            complete = True
            for n in p['target']['nodes']:
                if n['id'] == self.cfg.node_id:
                    continue
                try:
                    await self.eng.request_node(n, '/peer/reconfigure', {'op': 'commit', 'proposal': p,
                                                'acks': state['proof'], 'record': state['committed_record']})
                except Exception:
                    complete = False
            if complete:
                state['propagated'] = True; self.db.put('membership', state)
            self.error = '' if complete else 'Waiting for a server to accept the committed configuration'
        except Exception as exc:
            self.error = 'Configuration sync paused: ' + str(exc)[:160]
        finally:
            self.running = False
