"""Official Python client for the NumberOTP API — virtual numbers for SMS / OTP verification.

::

    from numberotp import NumberOTP

    client = NumberOTP()  # reads NOTP_API_KEY
    act = client.activations.create_and_wait(service="wa", country="16")
    print(act["phone_number"], act["otp"])
"""

from ._client import AsyncNumberOTP, NumberOTP
from ._core import DEFAULT_BASE_URL, VERSION
from ._errors import (
    ActivationClosedError,
    APIConnectionError,
    AuthenticationError,
    ConflictError,
    InsufficientBalanceError,
    NotFoundError,
    NumberOTPError,
    PermissionDeniedError,
    RateLimitError,
    ServerError,
    WaitTimeoutError,
)
from .webhooks import verify_webhook

__version__ = VERSION

__all__ = [
    "NumberOTP",
    "AsyncNumberOTP",
    "verify_webhook",
    "NumberOTPError",
    "APIConnectionError",
    "AuthenticationError",
    "InsufficientBalanceError",
    "PermissionDeniedError",
    "NotFoundError",
    "ConflictError",
    "RateLimitError",
    "ServerError",
    "ActivationClosedError",
    "WaitTimeoutError",
    "DEFAULT_BASE_URL",
    "VERSION",
]
