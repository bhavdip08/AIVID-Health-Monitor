"""SMTP delivery with explicit treatment of an unknown DATA outcome."""
from __future__ import annotations

import html
import smtplib
import ssl
from datetime import datetime, timezone
from email.message import EmailMessage
from email.policy import SMTP


class MailError(Exception):
    def __init__(self, message, uncertain=False):
        super().__init__(message)
        self.uncertain = uncertain


def render_email(event, settings, observer, *, preview=False):
    from .presentation import DEFAULT_EMAIL, DEFAULT_BRANDING, expand, logo_bytes
    email = settings.get('email', DEFAULT_EMAIL)
    branding = settings.get('branding', DEFAULT_BRANDING)
    offline = event['metric'] == 'availability' and event['kind'] in ('open', 'escalated')
    recovered = event['kind'] == 'recovered'
    test = event['kind'] == 'test'
    status = 'Offline' if offline else 'Recovered' if recovered else 'Test' if test else 'Attention required'
    name = event.get('node_name') or 'Monitored server'
    url = event.get('dashboard_url', '')
    from urllib.parse import urlsplit
    if urlsplit(url).scheme != 'https' or not urlsplit(url).hostname:
        url = ''
    values = {
        'server_name': name, 'sender_name': observer, 'status': status,
        'severity': event['severity'].upper(), 'metric': event['metric'].replace('_', ' '),
        'details': event['detail'], 'observed_at': datetime.fromtimestamp(event['created_at'], timezone.utc).strftime('%d %b %Y, %H:%M:%S UTC'),
        'title': event['title'], 'dashboard_url': url,
        'customer_name': branding['customer_name'], 'vendor_name': branding['vendor_name'],
        'action': 'Check server power, network connectivity and the aivid-health service.' if offline else 'No further action is needed unless the issue returns.' if recovered else 'This test confirms the alert sender can submit mail to your SMTP relay.' if test else 'Review the workload and available capacity on this server.',
    }
    subject_key = 'offline_subject' if offline else 'recovery_subject' if recovered else 'test_subject' if test else 'subject'
    # Names and imported historical details must never inject mail headers.
    subject = ' '.join(expand(email[subject_key], values).split())[:500]
    heading = expand(email['heading'], values)
    body = expand(email['body'], values)
    footer = expand(email['footer'], values)
    escape = html.escape
    color = '#13845b' if recovered else '#b83045' if offline else email['accent_color']
    attachments = []
    def brand(slot):
        asset = logo_bytes(branding, slot)
        label = branding[slot + '_name']
        if not asset:
            return f'<span style="font-size:16px;font-weight:700;color:#19253e">{escape(label)}</span>'
        data, mime = asset
        if preview:
            import base64
            src = 'data:' + mime + ';base64,' + base64.b64encode(data).decode()
        else:
            src = 'cid:aivid-' + slot
            attachments.append((slot, data, mime))
        return f'<img src="{src}" alt="{escape(label)}" width="145" style="width:100%;max-width:145px;max-height:64px;object-fit:contain;border:0;vertical-align:middle">'
    logos = brand('vendor'), brand('customer')
    rows = ''.join(f'<tr><td style="padding:12px 0;border-bottom:1px solid #e6ebf3;color:#64748b;width:36%;font-size:13px">{label}</td><td style="padding:12px 0;border-bottom:1px solid #e6ebf3;font-size:14px;font-weight:600;color:#19253e">{escape(str(value))}</td></tr>' for label, value in [('Server', name), ('Severity', values['severity']), ('Health check', values['metric']), ('Observed at', values['observed_at']), ('Alert sender', observer)])
    button = f'<p style="margin:28px 0 4px"><a href="{escape(url, quote=True)}" style="display:inline-block;padding:13px 23px;background:{email["accent_color"]};border-radius:6px;color:#ffffff;font-weight:600;text-decoration:none;font-size:14px">Open health dashboard →</a></p>' if url else ''
    rendered = f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{escape(subject)}</title></head>
<body style="margin:0;background:#f1f4f9;font-family:Arial,Helvetica,sans-serif;color:#19253e">
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background:#f1f4f9"><tr><td align="center" style="padding:32px 12px">
<table role="presentation" width="620" cellspacing="0" cellpadding="0" style="width:100%;max-width:620px;background:#ffffff;border:1px solid #e2e8f0;border-radius:12px;overflow:hidden">
<tr><td style="padding:25px 30px;border-bottom:1px solid #e6ebf3"><table role="presentation" width="100%"><tr><td>{logos[0]}</td><td align="right">{logos[1]}</td></tr></table></td></tr>
<tr><td style="padding:32px 30px 14px;border-top:4px solid {color}"><span style="font-size:11px;letter-spacing:1.5px;font-weight:700;color:{color}">HEALTH MONITOR / {escape(status.upper())}</span><h1 style="font-size:27px;line-height:1.3;letter-spacing:-.5px;margin:16px 0;color:#15223c">{escape(heading)}</h1><p style="font-size:15px;line-height:1.75;margin:0;color:#516077">{escape(body).replace(chr(10), '<br>')}</p></td></tr>
<tr><td style="padding:6px 30px 30px"><table role="presentation" width="100%" cellspacing="0" cellpadding="0">{rows}</table>{button}</td></tr>
<tr><td style="padding:20px 30px;background:#f8fafc;border-top:1px solid #e6ebf3;font-size:12px;line-height:1.7;color:#64748b">{escape(footer).replace(chr(10), '<br>')}</td></tr></table>
<p style="font-size:11px;letter-spacing:.8px;color:#7b879e;margin:22px 0 0">{escape(branding['vendor_name'])} · HEALTH MONITOR</p></td></tr></table></body></html>'''
    text = f"{heading}\n\n{body}\n\n" + '\n'.join(f'{label}: {value}' for label, value in [('Server', name), ('Severity', values['severity']), ('Health check', values['metric']), ('Observed at', values['observed_at']), ('Alert sender', observer)]) + (f'\n\nDashboard: {url}' if url else '') + f'\n\n{footer}\n'
    result = {'subject': subject, 'html': rendered, 'text': text}
    if not preview:
        result['attachments'] = attachments
    return result


def make_message(event, smtp, observer):
    rendered = render_email(event, smtp, observer)
    message = EmailMessage(policy=SMTP)
    message['From'] = smtp['sender']
    message['To'] = ', '.join(smtp['recipients'])
    message['Subject'] = rendered['subject']
    message['Message-ID'] = f"<{event['id']}@aivid-health.local>"
    message['Date'] = datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S +0000')
    # Encode both bodies explicitly; relays must not reinterpret UTF-8 or
    # quoted-printable soft line breaks inside HTML attributes and text.
    message.set_content(rendered['text'], charset='utf-8', cte='base64')
    message.add_alternative(rendered['html'], subtype='html', charset='utf-8', cte='base64')
    for slot, data, mime in rendered['attachments']:
        message.get_payload()[1].add_related(data, maintype='image', subtype=mime.split('/')[1], cid=f'<aivid-{slot}>', disposition='inline')
    return message


def deliver(event, smtp, password, observer):
    client = None
    in_data = False
    try:
        context = ssl.create_default_context()
        if smtp["security"] == "tls":
            client = smtplib.SMTP_SSL(smtp["host"], smtp["port"], timeout=8, context=context)
        else:
            client = smtplib.SMTP(smtp["host"], smtp["port"], timeout=8)
        client.ehlo_or_helo_if_needed()
        if smtp["security"] == "starttls":
            client.starttls(context=context)
            client.ehlo()
        if smtp["username"]:
            client.login(smtp["username"], password)
        code, _ = client.mail(smtp["sender"])
        if code != 250:
            raise MailError(f"SMTP rejected sender with code {code}")
        accepted, rejected = [], []
        for address in smtp["recipients"]:
            code, _ = client.rcpt(address)
            (accepted if code in (250, 251) else rejected).append(address)
        if not accepted:
            raise MailError("SMTP rejected all recipients")
        message = make_message(event, smtp, observer)
        in_data = True
        # SMTP.data(bytes) does not normalize line endings. Serialize with CRLF.
        code, _ = client.data(message.as_bytes(policy=SMTP))
        in_data = False
        if code != 250:
            raise MailError(f"SMTP rejected message with code {code}")
        # QUIT may fail after successful DATA. Delivery is already accepted.
        return {"status": "sent", "detail": f"SMTP accepted; {len(rejected)} recipient(s) rejected" if rejected else "SMTP accepted"}
    except MailError:
        raise
    except smtplib.SMTPDataError as exc:
        raise MailError(f"SMTP rejected message with code {exc.smtp_code}") from exc
    except (OSError, smtplib.SMTPException) as exc:
        # Do not put provider responses, credentials or addresses into logs.
        raise MailError(f"SMTP {type(exc).__name__}", uncertain=in_data) from exc
    finally:
        if client:
            client.close()
