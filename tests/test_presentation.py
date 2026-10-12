"""Branding/template upgrade compatibility, injection resistance and account behavior."""
import base64
import copy
import json
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import test_dashboard as fixtures
from aivid_health.config import DEFAULT_SETTINGS, validate_settings
from aivid_health.mail import make_message, render_email
from aivid_health.presentation import DEFAULT_EMAIL, event_view, normalize_settings, validate_presentation
from aivid_health.web import password_hash, password_matches


class PresentationUnitTests(unittest.TestCase):
    def setUp(self):
        self.settings=copy.deepcopy(DEFAULT_SETTINGS)
        self.settings['smtp'].update(sender='monitor@example.com',recipients=['ops@example.com'])
        self.event={'id':'abc123','node':'server-1069dda2','node_name':'Compute West', 'metric':'availability','kind':'open','severity':'critical','created_at':time.time(),'title':'Compute West offline','detail':'<script>alert(1)</script>', 'dashboard_url':'https://10.0.0.1:8282'}

    def test_password_accepts_short_and_empty_without_losing_hashing(self):
        for text in ('x','', '123', ' '):
            hashed=password_hash(text)
            self.assertTrue(password_matches(text,hashed));self.assertFalse(password_matches(text+'wrong',hashed))
        for bad in (None,1,'a'*257):
            with self.assertRaises(ValueError):password_hash(bad)

    def test_existing_settings_gain_defaults_without_mutation(self):
        legacy={k:v for k,v in self.settings.items() if k not in ('branding','email')}
        upgraded=validate_settings(legacy)
        self.assertEqual(upgraded['email'],DEFAULT_EMAIL)
        self.assertNotIn('email',legacy)
        self.assertEqual(upgraded['smtp'],legacy['smtp'])

    def test_templates_reject_headers_expressions_and_unknown_fields(self):
        for text in ('Bad\nBcc: injected@example.com','Bad\rSubject: x','{server_name.__class__}','{unknown}','{server_name!r}','{server_name:>20}'):
            settings=copy.deepcopy(self.settings);settings['email']['subject']=text
            with self.assertRaises(ValueError):validate_settings(settings)
        self.settings['email']['accent_color']='red; background:url(https://evil.example)'
        with self.assertRaises(ValueError):validate_settings(self.settings)

    def test_styled_mail_uses_names_embedded_logos_and_stable_id(self):
        msg=make_message(self.event,{**self.settings['smtp'],**{k:self.settings[k] for k in ('branding','email')}},'Operations East')
        self.assertEqual(msg['Subject'],'[OFFLINE] Compute West | Action required')
        self.assertEqual(msg['Message-ID'],'<abc123@aivid-health.local>')
        body=msg.get_body(preferencelist=('html',)).get_content()
        self.assertIn('Alert sender',body);self.assertIn('Operations East',body)
        self.assertNotIn('server-1069dda2',body);self.assertNotIn('<script>',body)
        self.assertIn('&lt;script&gt;',body);self.assertIn('cid:aivid-vendor',body)
        self.assertTrue(any(p.get('Content-ID')=='<aivid-vendor>' for p in msg.walk()))
        self.assertIn('Alert sender: Operations East',msg.get_body(preferencelist=('plain',)).get_content())

    def test_each_event_selects_custom_subject_and_preview_matches_mail(self):
        for sample,key,metric,kind in [('Offline','offline_subject','availability','open'),('Recovered','recovery_subject','availability','recovered'),('Test','test_subject','email test','test'),('Attention required','subject','cpu_percent','escalated')]:
            self.settings['email'][key]='{customer_name} | {server_name} | {sender_name} | {status}'
            self.settings['branding']['customer_name']='Example Company'
            e={**self.event,'metric':metric,'kind':kind}
            r=render_email(e,self.settings,'Operations East',preview=True)
            self.assertEqual(r['subject'],f'Example Company | Compute West | Operations East | {sample}')
            self.assertNotIn('cid:',r['html']);self.assertIn('data:image/png;base64,',r['html'])
            self.assertEqual(r['subject'],render_email(e,self.settings,'Operations East')['subject'])

    def test_logos_and_brand_names_reject_active_content_oversize_and_controls(self):
        for logo in ({'data':base64.b64encode(b'<svg onload="alert(1)"></svg>').decode(),'mime':'image/svg+xml'}, {'data':'A'*350000,'mime':'image/png'}, {'data':'INVALID$$','mime':'image/png'}):
            self.settings['branding']['customer_logo']=logo
            with self.assertRaises(ValueError):validate_settings(self.settings)
        self.settings['branding']['customer_logo']=None
        for name in ('','x\nBcc: other','a'*81):
            self.settings['branding']['customer_name']=name
            with self.assertRaises(ValueError):validate_settings(self.settings)


# Reuse setup/teardown only; avoid rerunning inherited unrelated tests.
class PresentationAPITests(unittest.IsolatedAsyncioTestCase):
    asyncSetUp=fixtures.DashboardTests.asyncSetUp
    asyncTearDown=fixtures.DashboardTests.asyncTearDown

    async def test_status_setup_and_historical_events_follow_renames(self):
        await self.eng.elect()
        e=self.eng.new_event(self.cfg.local,'availability','open','critical','Offline');e['sender']='server1'
        record=self.db.record();record['events'].append(e);self.db.put('cluster_record',record)
        self.cfg.local['name']='Operations West'
        for path in ('/api/status','/api/setup'):
            r=await self.client.get(path);self.assertEqual(r.json()['leader_name'],'Operations West');self.assertEqual(r.json()['local_name'],'Operations West')
        events=(await self.client.get('/api/status')).json()['events'];self.assertEqual(events[0]['sender_name'],'Operations West');self.assertEqual(events[0]['node_name'],'Operations West')
        v=event_view(self.cfg,e);self.assertEqual(v['node_name'],'Operations West');self.assertEqual(v['sender_name'],'Operations West')
        self.assertIn('Operations West',v['title'])

    async def test_short_then_blank_password_can_sign_in_and_preserves_login(self):
        current='dashboard-test-password'
        for new in ('x',''):
            r=await self.client.post('/api/password',json={'current':current,'new':new},headers=self.headers)
            self.assertEqual(r.status_code,200,r.text)
            r=await self.client.post('/api/login',json={'username':'admin','password':new});self.assertEqual(r.status_code,200,r.text)
            self.headers={'x-csrf-token':r.json()['csrf']};current=new

    async def test_branding_custom_templates_persist_and_preview_is_read_only(self):
        await self.eng.elect()
        v=(await self.client.get('/api/settings')).json()
        logo=Path(__import__('aivid_health').__file__).with_name('static').joinpath('aivid-logo.png').read_bytes()
        v['branding'].update(customer_name='Customer & Co',customer_logo={'data':base64.b64encode(logo).decode(),'mime':'image/png'})
        v['email']['offline_subject']='Custom offline: {server_name} via {sender_name}'
        before=self.db.record()
        body={**{k:v[k] for k in ('email','branding')},'sample':'offline'}
        self.assertEqual((await self.client.post('/api/email-preview',json=body)).status_code,403)
        r=await self.client.post('/api/email-preview',json=body,headers=self.headers);self.assertEqual(r.status_code,200,r.text)
        self.assertEqual(r.json()['subject'],'Custom offline: First via First');self.assertEqual(self.db.record(),before)
        r=await self.client.post('/api/settings',json=v,headers=self.headers);self.assertEqual(r.status_code,200,r.text)
        self.assertEqual((await self.client.get('/brand-logo/customer')).content,logo)
        self.assertEqual((await self.client.get('/api/settings')).json()['email'],v['email'])
        from aivid_health.web import create_app
        other=create_app(self.file,start_engine=False)
        try:self.assertEqual(other.state.engine.settings()['branding'],v['branding'])
        finally:await other.state.engine.close();other.state.store.close()
        v['branding']['customer_logo']=None
        self.assertEqual((await self.client.post('/api/settings',json=v,headers=self.headers)).status_code,200)
        self.assertEqual((await self.client.get('/brand-logo/customer')).status_code,404)

    async def test_legacy_local_logo_migrates_once_and_default_restore_sticks(self):
        logo=Path(__import__('aivid_health').__file__).with_name('static').joinpath('aivid-logo.png')
        self.cfg.data['logo_file']=str(logo)
        self.assertIsNotNone(self.eng.settings()['branding']['vendor_logo'])
        await self.eng.elect()
        v=(await self.client.get('/api/settings')).json()
        v['branding']['vendor_logo']=None
        self.assertEqual((await self.client.post('/api/settings',json=v,headers=self.headers)).status_code,200)
        self.assertIsNone(self.eng.settings()['branding']['vendor_logo'])

    async def test_logo_auth_csrf_sender_and_template_validation(self):
        data=base64.b64encode(Path(__import__('aivid_health').__file__).with_name('static').joinpath('aivid-logo.png').read_bytes()).decode()
        body={'data':data,'slot':'customer'}
        self.assertEqual((await self.client.post('/api/setup/logo',json=body)).status_code,403)
        self.assertEqual((await self.client.post('/api/setup/logo',json=body,headers=self.headers)).status_code,409)
        await self.eng.elect()
        self.assertEqual((await self.client.post('/api/setup/logo',json=body,headers=self.headers)).status_code,200)
        v=(await self.client.get('/api/settings')).json();v['email']['subject']='{invalid}'
        self.assertEqual((await self.client.post('/api/settings',json=v,headers=self.headers)).status_code,400)
