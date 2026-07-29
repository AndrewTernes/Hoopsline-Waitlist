"""
Central input sanitizer for Hoopsline.
All user-supplied strings pass through these helpers before reaching business
logic or the database.
"""

import re
import html
from functools import wraps
from flask import request, jsonify

MAX_STRING_LENGTH  = 500
MAX_EMAIL_LENGTH   = 254
MAX_PASSWORD_LENGTH = 128
MAX_SEARCH_LENGTH  = 100
MAX_JSON_SIZE      = 50_000   # 50 KB

_VALID_NBA_ABBRS = {
    'ATL', 'BOS', 'BRK', 'CHA', 'CHI', 'CLE', 'DAL', 'DEN', 'DET', 'GSW',
    'HOU', 'IND', 'LAC', 'LAL', 'MEM', 'MIA', 'MIL', 'MIN', 'NOP', 'NYK',
    'OKC', 'ORL', 'PHI', 'PHX', 'POR', 'SAC', 'SAS', 'TOR', 'UTA', 'WAS',
    # legacy / alt abbreviations seen in ESPN data
    'NJN', 'NOH', 'SEA', 'VAN',
}

_VALID_STAT_TYPES = {
    'points', 'rebounds', 'assists', 'steals', 'blocks',
    'threes', 'free_throws', 'pra', 'pr', 'pa', 'ra',
    'double_double', 'triple_double',
}


def sanitize_string(value: str, max_length: int = MAX_STRING_LENGTH) -> str:
    """Strip HTML tags, control characters, and trim whitespace."""
    if not isinstance(value, str):
        return ''
    value = html.escape(value)
    # Remove C0 control chars except \t (0x09) and \n (0x0a)
    value = re.sub(r'[\x00-\x08\x0b-\x0c\x0e-\x1f\x7f]', '', value)
    return value.strip()[:max_length]


def sanitize_email(value: str) -> str:
    """Validate and lowercase an email address; return '' if invalid."""
    value = sanitize_string(value, MAX_EMAIL_LENGTH).lower()
    if not re.match(r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$', value):
        return ''
    return value


def sanitize_team_abbr(value: str) -> str:
    """Accept only known NBA team abbreviations."""
    value = sanitize_string(value, 4).upper().strip()
    return value if value in _VALID_NBA_ABBRS else ''


def sanitize_player_name(value: str) -> str:
    """Allow letters, spaces, hyphens, apostrophes, and dots only."""
    value = sanitize_string(value, 60)
    if not re.match(r"^[a-zA-Z\s\-'\.]+$", value):
        return ''
    return value


def sanitize_stat_type(value: str) -> str:
    """Accept only known stat type identifiers."""
    value = sanitize_string(value, 20).lower()
    return value if value in _VALID_STAT_TYPES else ''


def sanitize_username(value: str) -> str:
    """Allow alphanumeric, underscore, and hyphen only; max 30 chars."""
    value = re.sub(r'[^a-zA-Z0-9_\-]', '', str(value or ''))
    return value[:30]


def reject_oversized_request(max_size: int = MAX_JSON_SIZE):
    """Decorator: return 413 if Content-Length exceeds max_size."""
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            cl = request.content_length
            if cl and cl > max_size:
                return jsonify({'error': 'Request too large'}), 413
            return f(*args, **kwargs)
        return wrapped
    return decorator
