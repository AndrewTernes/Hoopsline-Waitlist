"""
Supabase client — wraps supabase-py for the Hoopsline app.

Two clients:
  get_supabase()        → anon key  — user-facing sign-up / sign-in / reset
  get_supabase_admin()  → service role — server-side user management (admin panel)

Both are module-level singletons (lru_cache) so the TCP connection is reused.

NOTE: This file is named supabase_client.py (not supabase_auth.py) to avoid
shadowing the installed `supabase_auth` package that supabase-py depends on.
"""

import os
import logging
from functools import lru_cache

logger = logging.getLogger(__name__)

SUPABASE_URL         = os.environ.get('SUPABASE_URL', '').rstrip('/')
SUPABASE_ANON_KEY    = os.environ.get('SUPABASE_ANON_KEY', '')
SUPABASE_SERVICE_KEY = os.environ.get('SUPABASE_SERVICE_ROLE_KEY', '')


def is_configured() -> bool:
    """True when the minimum env vars needed for user auth are present."""
    return bool(SUPABASE_URL and SUPABASE_ANON_KEY)


@lru_cache(maxsize=1)
def get_supabase():
    """Anon/public client — safe to call from user-facing routes."""
    from supabase import create_client
    if not is_configured():
        raise RuntimeError(
            'SUPABASE_URL and SUPABASE_ANON_KEY must be set in .env before using Supabase auth.'
        )
    return create_client(SUPABASE_URL, SUPABASE_ANON_KEY)


@lru_cache(maxsize=1)
def get_supabase_admin():
    """Service-role client — NEVER expose the service key to the browser."""
    from supabase import create_client
    if not SUPABASE_URL or not SUPABASE_SERVICE_KEY:
        raise RuntimeError(
            'SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY must be set in .env for admin operations.'
        )
    return create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)
