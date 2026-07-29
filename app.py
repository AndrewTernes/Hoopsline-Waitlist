"""
Hoopsline — standalone waitlist signup app.

Minimal Flask app serving ONLY the early-access waitlist: the landing page
and its phone-verification signup flow. No predictions, admin panel, auth,
or Stripe — those live in the main app and are intentionally not reachable
from this deployment.
"""

import os
import sys
import logging
import secrets
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from werkzeug.middleware.proxy_fix import ProxyFix

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

# FLASK_SECRET_KEY must be set in production (Vercel env vars) so sessions
# survive across serverless invocations — a random per-process key would
# invalidate in-flight waitlist signups (they're held in the session for the
# ~10 minute code-entry window) on every cold start.
_secret = os.environ.get('FLASK_SECRET_KEY')
if not _secret:
    if os.environ.get('VERCEL'):
        raise RuntimeError('FLASK_SECRET_KEY must be set in production.')
    logger.warning('[STARTUP] FLASK_SECRET_KEY not set — using an ephemeral key (dev only).')
    _secret = secrets.token_hex(32)
app.secret_key = _secret

app.config['MAX_CONTENT_LENGTH']         = 1 * 1024 * 1024   # 1 MB — plenty for this form
app.config['SESSION_COOKIE_HTTPONLY']    = True
app.config['SESSION_COOKIE_SAMESITE']    = 'Lax'
app.config['SESSION_COOKIE_SECURE']      = not os.environ.get('FLASK_DEBUG', '').lower() in ('1', 'true')
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=['200 per day', '50 per hour'],
    storage_uri='memory://',
)

csrf = CSRFProtect(app)


def _mask_phone(phone: str) -> str:
    """Return a display-safe version like +1 ***-***-7890."""
    if len(phone) >= 10:
        return f'+1 ***-***-{phone[-4:]}'
    return '***'


@app.route('/')
def index():
    return redirect(url_for('waitlist'))


@app.route('/waitlist')
def waitlist():
    return render_template('waitlist.html')


@app.route('/api/waitlist/count')
def waitlist_count():
    try:
        from supabase_client import get_supabase_admin
        sb = get_supabase_admin()
        result = sb.table('waitlist').select('count', count='exact').execute()
        count = result.count or 0
        return jsonify({'count': count})
    except Exception as e:
        logger.error('waitlist_count error: %s', e)
        return jsonify({'count': 0})


@app.route('/api/waitlist/send-code', methods=['POST'])
@csrf.exempt
@limiter.limit('5 per 15 minutes')
def waitlist_send_code():
    """Validate waitlist signup details and text a verification code. Nothing
    is written to the waitlist table until the code is confirmed — the pending
    signup lives only in the session, since there's no account to attach a
    phone_verifications row to at this stage."""
    from datetime import date
    from sms import normalize_e164, send_verification_code
    from input_sanitizer import sanitize_email, sanitize_string

    data       = request.get_json(silent=True) or {}
    first_name = sanitize_string(data.get('first_name') or '', 50)
    last_name  = sanitize_string(data.get('last_name') or '', 50)
    email      = sanitize_email(data.get('email') or '')
    phone_raw  = sanitize_string(data.get('phone') or '', 20)
    birthday   = sanitize_string(data.get('birthday') or '', 10)

    if not first_name or not last_name:
        return jsonify({'success': False, 'error': 'Enter your first and last name.'}), 400
    if not email:
        return jsonify({'success': False, 'error': 'Enter a valid email address.'}), 400
    if not phone_raw:
        return jsonify({'success': False, 'error': 'Enter your phone number.'}), 400
    if not birthday:
        return jsonify({'success': False, 'error': 'Enter your date of birth.'}), 400

    phone = normalize_e164(phone_raw)
    if not phone:
        return jsonify({'success': False, 'error': 'Please enter a valid US phone number (e.g. +1 555 000 0000).'}), 400

    try:
        dob   = date.fromisoformat(birthday)
        today = date.today()
        age   = today.year - dob.year - ((today.month, today.day) < (dob.month, dob.day))
        if age < 18:
            return jsonify({'success': False, 'error': 'You must be 18 years of age or older to join the waitlist.'}), 400
    except ValueError:
        return jsonify({'success': False, 'error': 'Invalid date of birth.'}), 400

    now = datetime.now(timezone.utc)
    pending = session.get('waitlist_pending')
    if pending and pending.get('phone') == phone:
        window_start = datetime.fromisoformat(pending['send_window_start'])
        send_count   = pending['send_count'] if (now - window_start).total_seconds() < 3600 else 0
        if send_count >= 3:
            return jsonify({'success': False, 'error': 'Too many codes requested for this number. Try again in an hour.'}), 429
        new_count        = send_count + 1
        new_window_start = pending['send_window_start'] if (now - window_start).total_seconds() < 3600 else now.isoformat()
    else:
        new_count        = 1
        new_window_start = now.isoformat()

    code = ''.join(secrets.choice('0123456789') for _ in range(6))
    session['waitlist_pending'] = {
        'first_name':        first_name,
        'last_name':         last_name,
        'email':             email,
        'phone':             phone,
        'birthday':          birthday,
        'code':              code,
        'expires_at':        (now + timedelta(minutes=10)).isoformat(),
        'attempts':          0,
        'lockout_until':     None,
        'send_count':        new_count,
        'send_window_start': new_window_start,
    }
    session.modified = True

    ok, err = send_verification_code(phone, code)
    if not ok:
        logger.warning(f'Waitlist verification SMS failed for {phone[:6]}***: {err}')
        return jsonify({'success': False, 'error': 'Oops, that didn\'t work. Please try again in a moment.'}), 500

    return jsonify({'success': True, 'phone_hint': _mask_phone(phone)})


@app.route('/api/waitlist/resend-code', methods=['POST'])
@csrf.exempt
@limiter.limit('5 per 15 minutes')
def waitlist_resend_code():
    from sms import send_verification_code
    pending = session.get('waitlist_pending')
    if not pending:
        return jsonify({'success': False, 'error': 'No pending signup. Start again.'}), 400

    now          = datetime.now(timezone.utc)
    window_start = datetime.fromisoformat(pending['send_window_start'])
    send_count   = pending['send_count'] if (now - window_start).total_seconds() < 3600 else 0
    if send_count >= 3:
        return jsonify({'success': False, 'error': 'Too many code requests. Wait up to an hour before requesting again.'}), 429

    code = ''.join(secrets.choice('0123456789') for _ in range(6))
    pending['code']              = code
    pending['expires_at']        = (now + timedelta(minutes=10)).isoformat()
    pending['attempts']          = 0
    pending['lockout_until']     = None
    pending['send_count']        = send_count + 1
    pending['send_window_start'] = pending['send_window_start'] if (now - window_start).total_seconds() < 3600 else now.isoformat()
    session['waitlist_pending'] = pending
    session.modified = True

    ok, err = send_verification_code(pending['phone'], code)
    if not ok:
        logger.warning(f'Waitlist resend SMS failed for {pending["phone"][:6]}***: {err}')
        return jsonify({'success': False, 'error': 'Oops, that didn\'t work. Please try again in a moment.'}), 500
    return jsonify({'success': True})


@app.route('/api/waitlist/verify-code', methods=['POST'])
@csrf.exempt
@limiter.limit('10 per 15 minutes')
def waitlist_verify_code():
    from input_sanitizer import sanitize_string

    pending = session.get('waitlist_pending')
    if not pending:
        return jsonify({'success': False, 'error': 'No pending signup. Start again.'}), 400

    code = sanitize_string((request.get_json(silent=True) or {}).get('code') or '', 6)
    if not code:
        return jsonify({'success': False, 'error': 'Verification code is required.'}), 400

    now = datetime.now(timezone.utc)

    if pending.get('lockout_until'):
        lockout = datetime.fromisoformat(pending['lockout_until'])
        if now < lockout:
            remaining = int((lockout - now).total_seconds() / 60) + 1
            return jsonify({'success': False, 'error': f'Too many failed attempts. Try again in {remaining} minute(s).'}), 429

    expires = datetime.fromisoformat(pending['expires_at'])
    if now > expires:
        return jsonify({'success': False, 'error': 'Code has expired. Request a new one.'}), 400

    if pending['code'] != code:
        pending['attempts'] += 1
        if pending['attempts'] >= 5:
            pending['lockout_until'] = (now + timedelta(minutes=30)).isoformat()
            session['waitlist_pending'] = pending
            session.modified = True
            return jsonify({'success': False, 'error': 'Too many failed attempts. Try again in 30 minutes.'}), 429
        session['waitlist_pending'] = pending
        session.modified = True
        remaining = max(0, 5 - pending['attempts'])
        return jsonify({'success': False, 'error': f'Incorrect code. {remaining} attempt(s) remaining.'}), 400

    try:
        from supabase_client import get_supabase_admin
        sb = get_supabase_admin()
        already_exists = False
        try:
            sb.table('waitlist').insert({
                'first_name': pending['first_name'],
                'last_name':  pending['last_name'],
                'email':      pending['email'],
                'phone':      pending['phone'],
                'birthday':   pending['birthday'],
            }).execute()
        except Exception as insert_error:
            error_msg = str(insert_error).lower()
            if 'unique constraint' in error_msg or 'duplicate' in error_msg:
                already_exists = True
            else:
                raise

        session.pop('waitlist_pending', None)
        session.modified = True
        return jsonify({'success': True, 'already_exists': already_exists})
    except Exception as e:
        logger.error('waitlist_verify_code insert error: %s', e)
        return jsonify({'success': False, 'error': 'Unable to complete your signup right now. Please try again.'}), 500


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5050))
    app.run(host='0.0.0.0', port=port, debug=os.environ.get('FLASK_DEBUG', '').lower() in ('1', 'true'))
