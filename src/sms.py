"""Phone-number normalization for waitlist contact details."""

import re


def normalize_e164(phone: str) -> str | None:
    """Return E.164 form (+1XXXXXXXXXX) for a valid US number."""
    if not isinstance(phone, str):
        return None
    digits = re.sub(r'\D', '', phone)
    if len(digits) == 10:
        digits = '1' + digits
    if len(digits) == 11 and digits.startswith('1'):
        return '+' + digits
    return None
