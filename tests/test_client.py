import hashlib
import hmac
import json

import httpx
import pytest

import numberotp._core as core
from numberotp import (
    ActivationClosedError,
    AsyncNumberOTP,
    InsufficientBalanceError,
    NumberOTP,
    ServerError,
    verify_webhook,
)

ACTIVATION = {
    "id": "123", "phone_number": "447700900123", "service": "wa", "service_name": "WhatsApp", "country": "16",
    "status": "received", "otp": "482913", "full_sms": "Your code is 482913", "sms": [], "cost": 0.42,
    "pool": "pool1", "expires_at": "x", "created_at": "x",
}


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    monkeypatch.setattr(core.time, "sleep", lambda s: None)
    monkeypatch.setattr("numberotp._client.time.sleep", lambda s: None)


def mock(*handlers):
    """httpx client answering from handlers in order; records requests."""
    calls = []

    def handle(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        h = handlers[min(len(calls) - 1, len(handlers) - 1)]
        return h(request)

    return calls, httpx.MockTransport(handle)


def js(body, status=200):
    return lambda req: httpx.Response(status, json=body)


def body_of(req):
    return json.loads(req.content) if req.content else None


def test_api_key_base_url_and_query():
    calls, transport = mock(js({"success": True, "data": []}))
    client = NumberOTP("notp_test", http_client=httpx.Client(transport=transport))
    client.activations.list(status="waiting", limit=5)
    assert str(calls[0].url) == "https://api.numberotp.com/v1/user/activations?status=waiting&limit=5"
    assert calls[0].headers["authorization"] == "Bearer notp_test"


def test_public_endpoints_send_no_credentials():
    calls, transport = mock(js({"success": True, "data": []}))
    client = NumberOTP("notp_test", http_client=httpx.Client(transport=transport))
    client.services.search(q="discord.com")
    assert "authorization" not in calls[0].headers


def test_purchase_retry_reuses_idempotency_key():
    calls, transport = mock(js({"error": "busy"}, 503), js({"success": True, "data": {"id": "1"}, "balance": 1}))
    client = NumberOTP("notp_test", http_client=httpx.Client(transport=transport))
    client.activations.create(service="wa", country="16")
    assert len(calls) == 2
    key = calls[0].headers["idempotency-key"]
    assert key and calls[1].headers["idempotency-key"] == key
    assert body_of(calls[0]) == {"service": "wa", "country": "16"}


def test_non_idempotent_post_not_retried():
    calls, transport = mock(js({"error": "boom"}, 500))
    client = NumberOTP("notp_test", http_client=httpx.Client(transport=transport))
    with pytest.raises(ServerError):
        client.activations.finish("123")
    assert len(calls) == 1


def test_typed_error_with_code():
    calls, transport = mock(js({"error": "Insufficient balance. Please add funds.", "code": "INSUFFICIENT_BALANCE"}, 402))
    client = NumberOTP("notp_test", http_client=httpx.Client(transport=transport))
    with pytest.raises(InsufficientBalanceError) as exc:
        client.activations.create(service="wa", country="16")
    assert exc.value.code == "INSUFFICIENT_BALANCE" and exc.value.status == 402


def test_refreshes_expired_access_token():
    saved = []

    def refresh(req):
        assert req.url.path == "/v1/oauth/token"
        assert body_of(req) == {"grant_type": "refresh_token", "refresh_token": "notp_rt_old"}
        assert "authorization" not in req.headers
        return httpx.Response(200, json={"access_token": "new", "refresh_token": "notp_rt_new"})

    def after(req):
        assert req.headers["authorization"] == "Bearer new"
        return httpx.Response(200, json={"success": True, "data": {"balance": 3}})

    calls, transport = mock(js({"error": "Unauthorized"}, 401), refresh, after)
    client = NumberOTP(access_token="old", refresh_token="notp_rt_old", on_tokens=saved.append,
                       http_client=httpx.Client(transport=transport))
    assert client.account.get()["data"]["balance"] == 3
    assert saved[0]["refresh_token"] == "notp_rt_new"


def test_wait_for_code_polls_again_then_returns_activation():
    calls, transport = mock(
        js({"success": False, "error": "Timeout", "status": "waiting"}, 408),
        js({"success": True, "data": {"otp": "482913", "status": "received"}}),
        js({"success": True, "data": ACTIVATION}),
    )
    client = NumberOTP("notp_test", http_client=httpx.Client(transport=transport))
    act = client.activations.wait_for_code("123")
    assert act["otp"] == "482913"
    assert [c.url.path for c in calls] == ["/v1/activations/123/wait", "/v1/activations/123/wait", "/v1/activations/123"]


def test_wait_for_code_raises_when_expired():
    calls, transport = mock(js({"success": False, "error": "Activation is expired", "status": "expired"}, 400))
    client = NumberOTP("notp_test", http_client=httpx.Client(transport=transport))
    with pytest.raises(ActivationClosedError) as exc:
        client.activations.wait_for_code("123")
    assert exc.value.activation_status == "expired"


def test_events_stream_parses_sse():
    event = {"id": "evt_1", "type": "activation.code_received", "created_at": "x", "data": ACTIVATION}
    text = f"retry: 2000\n: connected\n\nid: 1-0\nevent: activation.code_received\ndata: {json.dumps(event)}\n\n"
    calls, transport = mock(lambda req: httpx.Response(200, content=text.encode(), headers={"content-type": "text/event-stream"}))
    client = NumberOTP("notp_test", http_client=httpx.Client(transport=transport))
    got = next(client.events.stream())
    assert got["type"] == "activation.code_received" and got["stream_id"] == "1-0"


def test_device_login():
    code = {"device_code": "dc", "user_code": "BCDF-GHJK", "verification_uri": "u", "verification_uri_complete": "u?c",
            "expires_in": 600, "interval": 5}
    calls, transport = mock(
        js(code),
        js({"error": "authorization_pending", "error_description": "Waiting"}, 400),
        js({"error": "slow_down", "error_description": "Slow"}, 400),
        js({"access_token": "at", "refresh_token": "notp_rt_1"}),
    )
    shown = []
    client = NumberOTP(http_client=httpx.Client(transport=transport))
    tokens = client.auth.device_login(shown.append, device_name="test")
    assert shown[0]["user_code"] == "BCDF-GHJK"
    assert tokens["access_token"] == "at"
    assert body_of(calls[3])["grant_type"] == "urn:ietf:params:oauth:grant-type:device_code"
    assert body_of(calls[3])["device_code"] == "dc"


def test_verify_webhook():
    secret, body = "whsec_test", json.dumps({"id": "123", "otp": "482913"})
    sig = "sha256=" + hmac.new(secret.encode(), body.encode(), hashlib.sha256).hexdigest()
    assert verify_webhook(body, sig, secret)
    assert not verify_webhook(body + " ", sig, secret)
    assert not verify_webhook(body, sig, "other")
    assert not verify_webhook(body, None, secret)


async def test_async_client_and_wait():
    calls, transport = mock(
        js({"success": True, "data": {"id": "123", "phoneNumber": "447700900123"}, "balance": 1}),
        js({"success": True, "data": {"otp": "482913", "status": "received"}}),
        js({"success": True, "data": ACTIVATION}),
    )
    async with AsyncNumberOTP("notp_test", http_client=httpx.AsyncClient(transport=transport)) as client:
        numbers = []
        act = await client.activations.create_and_wait(service="wa", country="16", on_number=numbers.append)
    assert numbers[0]["phoneNumber"] == "447700900123"
    assert act["otp"] == "482913"
    assert calls[0].headers["idempotency-key"]
