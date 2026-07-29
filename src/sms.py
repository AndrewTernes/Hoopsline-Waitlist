"""
Hoopsline SMS — Sent.dm wrapper.
Use cases: phone verification codes and welcome messages only.
"""

import os
import re
import logging

import requests

_logger = logging.getLogger(__name__)

_api_key      = os.getenv('SENTDM_API_KEY')
_base_url     = os.getenv('SENTDM_BASE_URL', 'https://api.sent.dm/v3').rstrip('/')
_template_verification = os.getenv('SENTDM_TEMPLATE_VERIFICATION')
_template_welcome      = os.getenv('SENTDM_TEMPLATE_WELCOME')


def normalize_e164(phone: str) -> str | None:
    """Return E.164 form (+1XXXXXXXXXX) for a US number, or None if invalid/non-US."""
    digits = re.sub(r'\D', '', phone)
    if len(digits) == 10:
        digits = '1' + digits
    if len(digits) == 11 and digits.startswith('1'):
        return '+' + digits
    return None


def _send_template(to_phone: str, template_id: str, variables: dict) -> tuple[bool, str]:
    """Send an SMS via a Sent.dm template. Returns (success, error_message)."""
    if not _api_key:
        return False, 'Sent.dm not configured (missing SENTDM_API_KEY in .env)'
    if not template_id:
        return False, 'Sent.dm template not configured'
    try:
        response = requests.post(
            f'{_base_url}/messages',
            headers={
                'x-api-key': _api_key,
                'Content-Type': 'application/json',
            },
            json={
                'to': [to_phone],
                'template': {
                    'id': template_id,
                    'variables': variables,
                },
                'channel': ['sms'],
            },
            timeout=10,
        )
        response.raise_for_status()
        payload = response.json()
        if not payload.get('success'):
            _logger.error('Sent.dm send failed: %s', payload)
            return False, str(payload)
        _logger.info('Sent.dm SMS queued: request_id=%s to=%s',
                     payload.get('meta', {}).get('request_id'), to_phone)
        return True, ''
    except requests.RequestException as e:
        detail = str(e)
        if e.response is not None:
            try:
                detail = f'{e.response.status_code} {e.response.text}'
            except Exception:
                pass
        _logger.error('Sent.dm send failed: %s', detail)
        return False, detail
    except Exception as e:
        _logger.exception('Unexpected error sending SMS via Sent.dm')
        return False, str(e)


def send_verification_code(phone: str, code: str) -> tuple[bool, str]:
    return _send_template(phone, _template_verification, {'code': code})


def send_welcome_sms(phone: str) -> tuple[bool, str]:
    return _send_template(phone, _template_welcome, {})
