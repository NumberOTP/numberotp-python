# numberotp (Python)

The official Python client for the [NumberOTP API](https://www.numberotp.com/docs/api): real phone numbers for SMS / OTP verification. It has sync and async clients, is fully typed, and supports Python 3.9+.

```bash
pip install numberotp
```

Get an API key at [numberotp.com/dashboard/developer](https://www.numberotp.com/dashboard/developer) and set it as `NOTP_API_KEY`. Guides: [numberotp.com/docs/sdks](https://www.numberotp.com/docs/sdks).

```python
from numberotp import NumberOTP

client = NumberOTP()  # reads NOTP_API_KEY

act = client.activations.create_and_wait(
    service="wa", country="16",
    on_number=lambda n: print("Use this number:", n["phoneNumber"]),
)
print("Code:", act["otp"])
```

### Async
```python
from numberotp import AsyncNumberOTP

async with AsyncNumberOTP() as client:
    n = await client.activations.create(service="tg", country="187")
    act = await client.activations.wait_for_code(n["data"]["id"], timeout=600)
```

### More
```python
client.services.search(q="discord.com")
client.prices.get(service="wa")
client.activations.resend(id) / finish(id) / cancel(id)   # cancel → full refund
for event in client.events.stream():                      # live events, reconnects by itself
    ...
from numberotp import verify_webhook                      # check x-numberotp-signature
client.auth.device_login(lambda c: print(c["user_code"]))  # sign a user in (CLI-style)
```

### Errors and reliability
- Errors carry `.status` and a stable `.code`: `InsufficientBalanceError`, `NotFoundError`, `ConflictError`, `ActivationClosedError`, `WaitTimeoutError` and others.
- Purchases send an `Idempotency-Key`, so retries never buy twice.
- Expired access tokens refresh automatically.
