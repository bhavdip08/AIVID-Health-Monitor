"""Regression checks at the actual smtplib DATA byte boundary; no mail is sent."""
import copy
import re
import smtplib
import unittest
from email import policy
from email.parser import BytesParser
from unittest.mock import patch

from aivid_health.mail import deliver, render_email
from aivid_health.presentation import DEFAULT_BRANDING, DEFAULT_EMAIL


class MailTransportTests(unittest.TestCase):
    def check_delivery(self, metric, kind, severity, name='aivid40'):
        event = dict(id='wire-regression', node_name=name, metric=metric,
                     kind=kind, severity=severity, created_at=1791112893,
                     title='Health check', detail='Usage is 76.9% < 95%.\nReview A & B.',
                     dashboard_url='https://192.168.112.251:8282')
        settings = dict(host='smtp.example.test', port=25, security='plain',
                        username='', sender='monitor@example.com',
                        recipients=['ops@example.com'],
                        email=copy.deepcopy(DEFAULT_EMAIL),
                        branding=copy.deepcopy(DEFAULT_BRANDING))
        settings['branding']['customer_name'] = 'Example & Co · પરીક્ષણ'
        wire = []
        client = smtplib.SMTP()
        client.ehlo_or_helo_if_needed = lambda: None
        client.mail = lambda *a: (250, b'OK')
        client.rcpt = lambda *a: (250, b'OK')
        client.putcmd = lambda *a: None
        replies = iter([(354, b'Send data'), (250, b'Accepted')])
        client.getreply = lambda: next(replies)
        client.send = wire.append
        with patch('aivid_health.mail.smtplib.SMTP', return_value=client):
            self.assertEqual(deliver(event, settings, '', 'aivid42')['status'], 'sent')
        raw = b''.join(wire)
        self.assertTrue(raw.endswith(b'\r\n.\r\n'))
        self.assertIsNone(re.search(rb'(?<!\r)\n|\r(?!\n)', raw))
        self.assertTrue(all(b < 128 for b in raw))
        self.assertLessEqual(max(map(len, raw.split(b'\r\n'))), 998)
        parsed = BytesParser(policy=policy.default).parsebytes(raw[:-3])
        expected = render_email(event, settings, 'aivid42')
        self.assertEqual(str(parsed['Subject']), expected['subject'])
        self.assertEqual(parsed['Message-ID'], '<wire-regression@aivid-health.local>')
        for content_type, key in [('plain', 'text'), ('html', 'html')]:
            body = parsed.get_body(preferencelist=(content_type,))
            self.assertEqual(body['Content-Transfer-Encoding'], 'base64')
            self.assertEqual(body.get_content().replace('\r\n', '\n').rstrip('\n'),
                             expected[key].replace('\r\n', '\n').rstrip('\n'))
        for slot, data, mime in expected['attachments']:
            images = [p for p in parsed.walk() if p['Content-ID'] == '<aivid-' + slot + '>']
            self.assertEqual(len(images), 1)
            self.assertEqual(images[0].get_payload(decode=True), data)
            self.assertEqual(images[0].get_content_type(), mime)

    def test_smtp_test_message(self):
        self.check_delivery('email test', 'test', 'info')

    def test_disk_warning(self):
        self.check_delivery('disk_percent', 'open', 'warning')

    def test_offline_message(self):
        self.check_delivery('availability', 'open', 'critical')

    def test_recovery_message(self):
        self.check_delivery('availability', 'recovered', 'healthy')

    def test_unicode_names_and_customer_branding(self):
        self.check_delivery('cpu_percent', 'escalated', 'critical', 'પરીક્ષણ · 检测')


if __name__ == '__main__':
    unittest.main()
