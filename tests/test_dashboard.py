from __future__ import annotations
import copy
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch
import httpx
from aivid_health.config import Config
from aivid_health.engine import signed_headers, authenticate_peer
from aivid_health.web import create_app, password_hash
from aivid_installer.cluster import make_cluster
from aivid_installer.cli import ensure_service_account


class AccountRepairTests(unittest.TestCase):
    def test_existing_group_missing_user_reuses_group(self):
        user=types.SimpleNamespace(pw_uid=991,pw_gid=991)
        with patch('aivid_installer.cli.grp.getgrnam',return_value=types.SimpleNamespace(gr_gid=991)), patch('aivid_installer.cli.pwd.getpwnam',side_effect=[KeyError(),user]), patch('aivid_installer.cli.run') as run:
            self.assertIs(ensure_service_account(Path('/var/lib/aivid-health')),user)
            args=run.call_args.args[0]
            self.assertIn('--gid',args);self.assertNotIn('--user-group',args)
            self.assertEqual(run.call_count,1)

    def test_existing_account_is_idempotent(self):
        with patch('aivid_installer.cli.grp.getgrnam'), patch('aivid_installer.cli.pwd.getpwnam'), patch('aivid_installer.cli.run') as run:
            ensure_service_account(Path('/var/lib/aivid-health'));run.assert_not_called()

    def test_missing_group_and_user_created_in_order(self):
        with patch('aivid_installer.cli.grp.getgrnam',side_effect=KeyError()), patch('aivid_installer.cli.pwd.getpwnam',side_effect=[KeyError(),object()]), patch('aivid_installer.cli.run') as run:
            ensure_service_account(Path('/var/lib/aivid-health'))
            self.assertEqual([c.args[0][0] for c in run.call_args_list],['groupadd','useradd'])


class DashboardTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        make_cluster(self.root/'cluster',[{'id':'server1','name':'First','url':'https://127.0.0.1:18443','priority':1}])
        self.file=self.root/'cluster/server1/node.json'
        c=json.loads(self.file.read_text());c.update(admin_password_hash=password_hash('dashboard-test-password'),admin_password_chosen=True)
        self.file.write_text(json.dumps(c));self.app=create_app(self.file,start_engine=False)
        self.eng=self.app.state.engine;self.db=self.app.state.store;self.cfg=self.eng.config
        self.client=httpx.AsyncClient(transport=httpx.ASGITransport(app=self.app),base_url='https://127.0.0.1:18443')
        r=await self.client.post('/api/login',json={'username':'admin','password':'dashboard-test-password'});self.headers={'x-csrf-token':r.json()['csrf']}
    async def asyncTearDown(self):
        await self.client.aclose();await self.eng.close();self.db.close();self.temp.cleanup()
    def proposal(self):
        return {'id':'test-transition','base':0,'old':['server1'],'required':['server1'],
                'target':{'nodes':self.cfg.nodes,'generation':1,'cluster_id':self.cfg.data['cluster_id'],'auth_fingerprint':self.cfg.fingerprint}}

    async def test_local_save_requires_csrf_and_automatic_disks(self):
        body={'gpu_required':False,'metrics_seconds':30}
        self.assertEqual((await self.client.post('/api/setup/local',json=body)).status_code,403)
        self.assertEqual((await self.client.post('/api/setup/local',json=body,headers=self.headers)).status_code,200)
        self.assertEqual(self.db.get('config_override')['metrics_seconds'],30)
        body['disk_paths']=['relative']
        self.assertEqual((await self.client.post('/api/setup/local',json=body,headers=self.headers)).status_code,400)

    async def test_prepared_change_blocks_vote_and_record_even_after_restart(self):
        p=self.proposal();self.eng.membership.prepare(p)
        self.assertTrue(self.eng.membership.blocked)
        from aivid_health.config import canonical
        body={'term':'1'*32,'epoch':1};raw=canonical(body);headers=signed_headers(self.cfg,'POST','/peer/vote',raw)
        r=await self.client.post('/peer/vote',content=raw,headers=headers)
        self.assertFalse(r.json()['granted'])
        other=create_app(self.file,start_engine=False)
        try:self.assertTrue(other.state.engine.membership.blocked)
        finally:await other.state.engine.close();other.state.store.close()

    async def test_commit_requires_complete_untampered_proof_and_preserves_record(self):
        p=self.proposal();a=self.eng.membership.prepare(p)
        with self.assertRaises(ValueError):await self.eng.membership.commit(p,{},a['record'])
        bad=copy.deepcopy(a['ack']);bad['record_hash']='0'*64
        with self.assertRaises(ValueError):await self.eng.membership.commit(p,{'server1':bad},a['record'])
        changed=copy.deepcopy(a['record']);changed['revision']=1
        with self.assertRaises(ValueError):await self.eng.membership.commit(p,{'server1':a['ack']},changed)
        await self.eng.membership.commit(p,{'server1':a['ack']},a['record'])
        self.assertEqual(self.cfg.data['generation'],1);self.assertFalse(self.eng.membership.blocked)
        self.assertEqual(self.db.record(),a['record'])

    async def test_old_generation_requests_are_rejected_after_commit(self):
        headers=signed_headers(self.cfg,'GET','/peer/snapshot')
        p=self.proposal();a=self.eng.membership.prepare(p);await self.eng.membership.commit(p,{'server1':a['ack']},a['record'])
        self.assertEqual((await self.client.get('/peer/snapshot',headers=headers)).status_code,401)

    async def test_pair_code_is_private_expiring_and_rotatable(self):
        from aivid_health.membership import decode_pair
        response=await self.client.post('/api/setup/pair-code',json={'url':self.cfg.local['url']},headers=self.headers)
        d=decode_pair(response.json()['code'])
        self.assertNotIn(d['token'],json.dumps(self.db.get('pairing')))
        old=self.db.get('pairing')['hash']
        self.eng.membership.pairing_code(self.cfg.local['url'])
        self.assertNotEqual(old,self.db.get('pairing')['hash'])
        self.assertEqual((await self.client.post('/setup/pair',json={'op':'check','token':d['token']})).status_code,400)

    async def test_current_pairing_code_matches_cli_and_survives_restart(self):
        import contextlib, io
        from aivid_health.cli import main
        text=io.StringIO()
        with contextlib.redirect_stdout(text):
            self.assertEqual(main(['pair-code','--config',str(self.file)]),0)
        code=text.getvalue().strip()
        self.assertTrue(code.startswith('AIVID2.'))
        self.assertEqual((await self.client.get('/api/setup/pair-code')).json()['code'],code)
        text=io.StringIO()
        with contextlib.redirect_stdout(text):main(['pair-code','--config',str(self.file)])
        self.assertEqual(text.getvalue().strip(),code)
        other=create_app(self.file,start_engine=False)
        try:
            from aivid_health.membership import current_pairing_code
            self.assertEqual(current_pairing_code(other.state.engine.config,other.state.store)['code'],code)
        finally:
            await other.state.engine.close();other.state.store.close()
        pair=self.db.get('pairing');pair['expires']=0;self.db.put('pairing',pair)
        self.assertEqual((await self.client.get('/api/setup/pair-code')).json()['code'],'')

    async def test_chosen_login_survives_password_change(self):
        admin=self.db.get('admin');admin['username']='aivid.ops';self.db.put('admin',admin)
        self.assertEqual((await self.client.post('/api/login',json={'username':'admin','password':'dashboard-test-password'})).status_code,401)
        r=await self.client.post('/api/login',json={'username':'aivid.ops','password':'dashboard-test-password'})
        self.assertFalse(r.json()['must_change'])
        r=await self.client.post('/api/password',json={'current':'dashboard-test-password','new':'new-dashboard-password'},headers={'x-csrf-token':r.json()['csrf']})
        self.assertEqual(r.status_code,200)
        r=await self.client.post('/api/login',json={'username':'aivid.ops','password':'new-dashboard-password'})
        self.assertEqual(r.status_code,200);self.assertFalse(r.json()['must_change'])

    async def test_blank_priority_can_be_saved_and_numbers_are_strict(self):
        await self.eng.elect()
        body={'node_id':'server1','name':'First','url':self.cfg.local['url'],'priority':None}
        r=await self.client.post('/api/setup/servers',json=body,headers=self.headers)
        self.assertEqual(r.status_code,200,r.text)
        await self.eng.membership.progress();self.assertIsNone(self.cfg.local['priority'])
        for value in (0,101,True,1.5,'1'):
            body['priority']=value
            self.assertEqual((await self.client.post('/api/setup/servers',json=body,headers=self.headers)).status_code,400)

    async def test_logo_rejects_active_content(self):
        import base64
        data=base64.b64encode(b'<svg onload="alert(1)"></svg>').decode()
        self.assertEqual((await self.client.post('/api/setup/logo',json={'data':data},headers=self.headers)).status_code,400)

    async def test_public_address_edit_does_not_require_nat_hairpin(self):
        await self.eng.elect()
        nodes=copy.deepcopy(self.cfg.nodes);nodes[0]['url']='https://203.0.113.99'
        with patch.object(self.eng, 'request_node', side_effect=AssertionError('Must not dial own public IP')):
            await self.eng.membership.begin(nodes)
            await self.eng.membership.progress()
        self.assertEqual(self.cfg.local['url'], 'https://203.0.113.99')
        self.assertFalse(self.eng.membership.blocked)

    async def test_expired_pending_pair_can_be_renewed_without_changing_proposal(self):
        p=self.proposal();self.eng.membership.prepare(p)
        pair={'id':'server2','url':'https://10.0.0.2','certificate':'trusted-certificate','token':'a'*64}
        state=self.db.get('membership');state['pair']=self.cfg.encrypt(json.dumps(pair));self.db.put('membership',state)
        replacement={**pair,'token':'b'*64}
        self.eng.membership.renew_pending_pair(replacement)
        self.assertEqual(self.db.get('membership')['proposal'],p)
        self.assertEqual(json.loads(self.cfg.decrypt(self.db.get('membership')['pair']))['token'],'b'*64)
        with self.assertRaises(ValueError):self.eng.membership.renew_pending_pair({**replacement,'url':'https://10.0.0.3'})
        self.assertTrue(self.eng.membership.blocked)

    async def test_capacity_and_unique_priorities(self):
        for n in (1,2,3,5,32):
            c=Config(self.file);c.apply({'nodes':[{'id':f'server{i}','name':f'{i}','url':f'https://10.0.0.{i}','priority':i} for i in range(1,n+1)]})
            self.assertEqual(c.majority,n//2+1)
        with self.assertRaises(ValueError):c.apply({'nodes':c.nodes+[{'id':'server33','url':'https://10.0.0.33','priority':33}]})

if __name__=='__main__':unittest.main()
