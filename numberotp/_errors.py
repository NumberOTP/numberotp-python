"""Errors. Every failed API call raises NumberOTPError (or a subclass) with the
HTTP ``status`` and the API's stable ``code`` — branch on ``code``, not on the
message, which is written for people and may change."""

from __future__ import annotations

import re
from typing import Any, Optional


class NumberOTPError(Exception):
    def __init__(self, message: str, status: int = 0, code: Optional[str] = None, body: Any = None) -> None:
        super().__init__(message)
        self.message = message
        self.status = status
        self.code = code
        self.body = body

    def __repr__(self) -> str:
        return f"{type(self).__name__}(status={self.status}, code={self.code!r}, message={self.message!r})"


class APIConnectionError(NumberOTPError):
    """The request never reached the API, or timed out."""


class AuthenticationError(NumberOTPError):
    """401 — missing, invalid or expired credentials."""


class InsufficientBalanceError(NumberOTPError):
    """402 — not enough balance."""


class PermissionDeniedError(NumberOTPError):
    """403 — the credential lacks a scope, or the account is on hold."""


class NotFoundError(NumberOTPError):
    """404 — no such thing, or nothing in stock (code NO_NUMBERS_AVAILABLE)."""


class ConflictError(NumberOTPError):
    """409 — the number isn't in a state that allows this, or the price went above max_price."""


class RateLimitError(NumberOTPError):
    """429 — slow down (retried automatically first)."""


class ServerError(NumberOTPError):
    """5xx (retried automatically first where safe)."""


class ActivationClosedError(NumberOTPError):
    """wait_for_code: the number expired or was canceled before an SMS arrived. It was refunded."""

    def __init__(self, activation_status: str, body: Any = None) -> None:
        super().__init__(
            f"The number is {activation_status} and won't receive a code. It has been refunded.",
            400,
            "ACTIVATION_CLOSED",
            body,
        )
        self.activation_status = activation_status


class WaitTimeoutError(NumberOTPError):
    """wait_for_code: your own timeout passed first. The number may still receive a code."""

    def __init__(self) -> None:
        super().__init__(
            "Timed out waiting for the code. The number is still open — wait again, or cancel it for a refund.",
            0,
            "WAIT_TIMEOUT",
        )


_OAUTH_CODE = re.compile(r"^[a-z_]+$")


def error_from_response(status: int, body: Any) -> NumberOTPError:
    body_dict = body if isinstance(body, dict) else {}
    err = body_dict.get("error")
    code = body_dict.get("code") if isinstance(body_dict.get("code"), str) else None
    if code is None and isinstance(err, str) and _OAUTH_CODE.match(err):
        code = err  # OAuth (RFC 6749) errors
    message = body_dict.get("error_description") or (err if isinstance(err, str) else None) or f"HTTP {status}"
    cls = {
        401: AuthenticationError,
        402: InsufficientBalanceError,
        403: PermissionDeniedError,
        404: NotFoundError,
        409: ConflictError,
        429: RateLimitError,
    }.get(status, ServerError if status >= 500 else NumberOTPError)
    return cls(message, status, code, body)
