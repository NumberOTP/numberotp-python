"""Webhook signature check.

NumberOTP signs each webhook body with HMAC-SHA256 using your webhook secret
and sends ``x-numberotp-signature: sha256=<hex>``. Verify the raw body bytes
before parsing JSON::

    from numberotp import verify_webhook
    if not verify_webhook(request.body, request.headers.get("x-numberotp-signature"), secret):
        return 401
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Optional, Union


def verify_webhook(raw_body: Union[bytes, str], signature_header: Optional[str], secret: str) -> bool:
    if not signature_header or not secret:
        return False
    given = signature_header.strip()
    if given.lower().startswith("sha256="):
        given = given[7:]
    body = raw_body.encode() if isinstance(raw_body, str) else raw_body
    expected = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, given.lower())
