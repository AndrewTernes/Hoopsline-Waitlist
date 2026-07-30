"""
Hoopsline — standalone waitlist signup app.

Minimal Flask app serving ONLY the early-access waitlist: the landing page
and its email-verification signup flow. No predictions, admin panel, auth,
or Stripe — those live in the main app and are intentionally not reachable
from this deployment.
"""

import os
import sys
import logging
import secrets
import re
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from flask import Flask, render_template, request, jsonify, redirect, url_for, g
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from flask_wtf.csrf import CSRFError
from werkzeug.middleware.proxy_fix import ProxyFix

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

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
elif os.environ.get('VERCEL') and len(_secret) < 32:
    raise RuntimeError('FLASK_SECRET_KEY must be at least 32 characters.')
app.secret_key = _secret

app.config['MAX_CONTENT_LENGTH']         = 32 * 1024
app.config['SESSION_COOKIE_HTTPONLY']    = True
app.config['SESSION_COOKIE_SAMESITE']    = 'Lax'
app.config['SESSION_COOKIE_SECURE']      = not os.environ.get('FLASK_DEBUG', '').lower() in ('1', 'true')
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
app.config['WTF_CSRF_SSL_STRICT']        = False

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=['200 per day', '50 per hour'],
    storage_uri='memory://',
)

csrf = CSRFProtect(app)


@app.errorhandler(CSRFError)
def handle_csrf_error(_error):
    return jsonify({
        'success': False,
        'error': 'Your form session expired. Refresh the page and try again.',
    }), 400

@app.before_request
def enforce_request_security():
    g.csp_nonce = secrets.token_urlsafe(24)
    if request.method in ('POST', 'PUT', 'PATCH') and not request.is_json:
        return jsonify({'success': False, 'error': 'JSON request required.'}), 415
    if request.method in ('POST', 'PUT', 'PATCH'):
        origin = request.headers.get('Origin')
        if origin and origin != 'https://waitlist.hoopsline.com':
            return jsonify({'success': False, 'error': 'Invalid request origin.'}), 403


@app.context_processor
def inject_csp_nonce():
    return {'csp_nonce': g.get('csp_nonce', '')}


@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        f"script-src 'self' 'nonce-{g.get('csp_nonce', '')}'; "
        "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
        "font-src 'self'; connect-src 'self'; object-src 'none'; "
        "base-uri 'none'; frame-ancestors 'none'; form-action 'self'; "
        "upgrade-insecure-requests"
    )
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Permissions-Policy'] = (
        'camera=(), microphone=(), geolocation=(), payment=(), usb=()'
    )
    response.headers['Cross-Origin-Opener-Policy'] = 'same-origin'
    response.headers['Cache-Control'] = 'no-store'
    if request.is_secure:
        response.headers['Strict-Transport-Security'] = (
            'max-age=31536000; includeSubDomains'
        )
    return response


def _email_rate_key():
    payload = request.get_json(silent=True) or {}
    email = str(payload.get('email') or '').strip().lower()
    return f'email:{email}' if email else f'ip:{get_remote_address()}'


def _insert_waitlist_row(first_name, last_name, email, phone, birthday):
    """Insert a waitlist signup. Returns (ok, already_exists, error_message)."""
    from supabase_client import get_supabase_admin
    sb = get_supabase_admin()
    try:
        sb.table('waitlist').insert({
            'first_name': first_name,
            'last_name':  last_name,
            'email':      email,
            'phone':      phone,
            'birthday':   birthday,
            'verified_at': None,
        }).execute()
        return True, False, ''
    except Exception as insert_error:
        error_msg = str(insert_error).lower()
        if 'unique constraint' in error_msg or 'duplicate' in error_msg:
            return True, True, ''
        logger.error('waitlist insert failed: %s', type(insert_error).__name__)
        return False, False, str(insert_error)


def _send_waitlist_verification(email: str, first_name: str) -> bool:
    from itsdangerous import URLSafeTimedSerializer
    from email_utils import send_waitlist_verification_email

    serializer = URLSafeTimedSerializer(
        app.config['SECRET_KEY'], salt='waitlist-email-verification'
    )
    token = serializer.dumps(email)
    base_url = os.environ.get(
        'WAITLIST_BASE_URL', 'https://waitlist.hoopsline.com'
    ).rstrip('/')
    if base_url != 'https://waitlist.hoopsline.com':
        logger.error('WAITLIST_BASE_URL must be https://waitlist.hoopsline.com')
        return False
    try:
        from supabase_client import get_supabase_admin
        reservation = get_supabase_admin().rpc(
            'reserve_waitlist_verification_email',
            {'target_email': email},
        ).execute()
        decision = reservation.data
        if decision in ('verified', 'limited'):
            # Keep the public response indistinguishable to prevent account
            # enumeration and suppress repeat-email abuse.
            return True
        if decision != 'send':
            logger.error('Verification email reservation returned %r', decision)
            return False
    except Exception as exc:
        logger.error(
            'Verification email reservation failed: %s', type(exc).__name__
        )
        return False
    link = f'{base_url}/waitlist/verify?token={token}'
    return send_waitlist_verification_email(email, first_name, link)


@lru_cache(maxsize=2)
def _load_legal_document(document: str) -> dict:
    """Load the user-provided legal copy without changing its wording."""
    source = Path(__file__).with_name('legal') / 'hoopsline-legal.txt'
    lines = [line.strip() for line in source.read_text(encoding='utf-8').splitlines()
             if line.strip()]
    terms_index = lines.index('HOOPSLINE TERMS OF SERVICE')
    selected = lines[:terms_index] if document == 'privacy' else lines[terms_index:]

    sections = []
    current = {'heading': None, 'id': 'introduction', 'paragraphs': []}
    for line in selected[3:]:
        heading_match = re.match(r'^(\d+)\.\s+(.+)$', line)
        if heading_match:
            if current['paragraphs']:
                sections.append(current)
            current = {
                'heading': line,
                'id': f'section-{heading_match.group(1)}',
                'paragraphs': [],
            }
        else:
            current['paragraphs'].append(line)
    if current['paragraphs']:
        sections.append(current)

    return {
        'title': (
            'Hoopsline Privacy Policy'
            if document == 'privacy'
            else 'Hoopsline Terms of Service'
        ),
        'effective_date': selected[1],
        'last_updated': selected[2],
        'sections': sections,
    }


@app.route('/')
def index():
    return redirect(url_for('waitlist'))


@app.route('/waitlist')
def waitlist():
    return render_template('waitlist.html')


@app.route('/privacy')
def privacy():
    return render_template(
        'legal.html',
        document=_load_legal_document('privacy'),
        active_document='privacy',
    )


@app.route('/terms')
def terms():
    return render_template(
        'legal.html',
        document=_load_legal_document('terms'),
        active_document='terms',
    )


@app.route('/api/waitlist/count')
def waitlist_count():
    try:
        from supabase_client import get_supabase_admin
        sb = get_supabase_admin()
        result = (sb.table('waitlist').select('count', count='exact')
                  .not_.is_('verified_at', 'null').execute())
        count = result.count or 0
        return jsonify({'count': count})
    except Exception as e:
        logger.error('waitlist_count error: %s', e)
        return jsonify({'count': 0})


@app.route('/api/waitlist/send-code', methods=['POST'])
@limiter.limit('3 per 15 minutes')
@limiter.limit('3 per hour', key_func=_email_rate_key)
def waitlist_send_code():
    """Create a pending signup and send the email ownership challenge."""
    from datetime import date
    from sms import normalize_e164
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

    ok, already_exists, _err = _insert_waitlist_row(
        first_name, last_name, email, phone, birthday
    )
    if not ok:
        return jsonify({'success': False, 'error': 'Unable to complete your signup right now. Please try again.'}), 500
    if not _send_waitlist_verification(email, first_name):
        return jsonify({'success': False, 'error': 'We could not send the verification email. Please try again.'}), 503

    return jsonify({'success': True, 'already_exists': already_exists,
                    'skip_verification': True,
                    'verification_required': True})


@app.route('/waitlist/verify')
def waitlist_verify():
    from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

    serializer = URLSafeTimedSerializer(
        app.config['SECRET_KEY'], salt='waitlist-email-verification'
    )
    try:
        email = serializer.loads(
            (request.args.get('token') or '').strip(), max_age=86400
        )
    except SignatureExpired:
        return render_template(
            'waitlist_verify.html', verified=False,
            message='This verification link has expired. Complete the waitlist form again for a new one.'
        ), 400
    except BadSignature:
        return render_template(
            'waitlist_verify.html', verified=False,
            message='This verification link is invalid. Complete the waitlist form again.'
        ), 400

    try:
        from supabase_client import get_supabase_admin
        result = (get_supabase_admin().table('waitlist')
                  .update({'verified_at': datetime.now(timezone.utc).isoformat()})
                  .eq('email', email).execute())
        if not result.data:
            raise ValueError('No matching waitlist request')
        return render_template(
            'waitlist_verify.html', verified=True,
            message='Your email is verified. You are officially on the Hoopsline early access list.'
        )
    except Exception as exc:
        logger.error('waitlist_verify error: %s', exc)
        return render_template(
            'waitlist_verify.html', verified=False,
            message='We could not verify your email right now. Please try the link again shortly.'
        ), 500


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5050))
    app.run(host='127.0.0.1', port=port,
            debug=os.environ.get('FLASK_DEBUG', '').lower() in ('1', 'true'))
