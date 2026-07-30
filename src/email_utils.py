import html
import logging
import os

import requests

logger = logging.getLogger(__name__)


def send_waitlist_verification_email(to_email: str, first_name: str,
                                     verification_link: str) -> bool:
    api_key = os.environ.get('RESEND_API_KEY', '').strip()
    if not api_key:
        logger.error('RESEND_API_KEY is not configured')
        return False

    safe_name = html.escape(first_name or 'there')
    safe_link = html.escape(verification_link, quote=True)
    body = f"""
    <div style="font-family:Arial,sans-serif;background:#050505;padding:40px 0">
      <div style="max-width:520px;margin:auto;background:#111;border:1px solid #292929;border-radius:12px;padding:40px 36px">
        <h1 style="color:#f97316;margin:0 0 8px">HOOPSLINE</h1>
        <p style="color:#888;font-size:12px;letter-spacing:.1em;text-transform:uppercase;margin:0 0 28px">Early access verification</p>
        <p style="color:#f0f0f0">Hey {safe_name},</p>
        <p style="color:#aaa;line-height:1.6;margin-bottom:26px">Confirm your email to finish joining the Hoopsline early access list. This link expires in 24 hours.</p>
        <a href="{safe_link}" style="display:inline-block;background:#f97316;color:#090909;font-weight:700;padding:13px 24px;border-radius:8px;text-decoration:none">Verify my email</a>
        <p style="color:#666;font-size:12px;line-height:1.6;margin-top:28px">If you did not request early access, ignore this message.<br><br>Or copy this link:<br><span style="color:#999;word-break:break-all">{safe_link}</span></p>
      </div>
    </div>"""
    try:
        response = requests.post(
            'https://api.resend.com/emails',
            headers={'Authorization': f'Bearer {api_key}', 'Content-Type': 'application/json'},
            json={
                'from': os.environ.get('MAIL_FROM', 'Hoopsline <noreply@hoopsline.com>'),
                'to': [to_email],
                'subject': 'Verify your email for the Hoopsline waitlist',
                'html': body,
            },
            timeout=8,
        )
        response.raise_for_status()
        return True
    except Exception as exc:
        logger.warning('Waitlist verification email failed: %s', exc)
        return False
