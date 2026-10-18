"""The NumberOTP clients (sync and async) and their hand-written helpers."""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any, AsyncIterator, Awaitable, Callable, Dict, Iterator, Mapping, Optional, Union

import httpx

from ._core import AsyncTransport, SyncTransport, TokenCallback
from ._errors import ActivationClosedError, NumberOTPError, WaitTimeoutError, error_from_response
from ._generated import (
    ActivationsResource,
    AsyncActivationsResource,
    AsyncAuthResource,
    AsyncEventsResource,
    AsyncResources,
    AuthResource,
    EventsResource,
    Resources,
)

_CLOSED = {"expired", "canceled", "finished"}


def _wait_outcome(err: NumberOTPError) -> str:
    """'again' (window still open), 'closed', or 'raise'."""
    status = err.body.get("status") if isinstance(err.body, dict) else None
    if err.status == 408 or status == "waiting" or err.code == "TIMEOUT":
        return "again"
    if err.status == 400 and status in _CLOSED:
        return "closed"
    return "raise"


# ── SSE ──────────────────────────────────────────────────────────────────────

class _SseParser:
    def __init__(self) -> None:
        self.id: Optional[str] = None
        self.event: Optional[str] = None
        self.data: list = []

    def feed(self, line: str) -> Optional[Dict[str, Any]]:
        if line == "":
            if not self.data:
                return None
            msg = {"id": self.id, "event": self.event, "data": "\n".join(self.data)}
            self.id, self.event, self.data = None, None, []
            return msg
        if line.startswith(":"):
            return None
        field, _, value = line.partition(":")
        value = value[1:] if value.startswith(" ") else value
        if field == "data":
            self.data.append(value)
        elif field == "id":
            self.id = value
        elif field == "event":
            self.event = value
        return None


def _event_from(msg: Dict[str, Any]) -> Dict[str, Any]:
    event = json.loads(msg["data"])
    event["stream_id"] = msg["id"]
    return event


# ── Sync ─────────────────────────────────────────────────────────────────────

class Activations(ActivationsResource):
    def wait_once(self, id: str, request_options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:  # type: ignore[override]
        """One long-poll round (up to ~55 s). Prefer wait_for_code()."""
        return super().wait_once(id, request_options={"timeout": 70.0, "max_retries": 0, **(request_options or {})})

    def wait_for_code(self, id: str, *, timeout: float = 1200.0) -> Dict[str, Any]:
        """Waits until the code arrives and returns the whole activation (code, full SMS, all
        messages). Raises ActivationClosedError if it expired or was canceled first (refunded),
        WaitTimeoutError if ``timeout`` seconds pass."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                self.wait_once(id, request_options={"timeout": min(70.0, deadline - time.monotonic() + 5)})
                return self.get(id)["data"]
            except NumberOTPError as e:
                outcome = _wait_outcome(e)
                if outcome == "again":
                    continue
                if outcome == "closed":
                    raise ActivationClosedError(e.body["status"], e.body) from e
                raise
        raise WaitTimeoutError()

    def create_and_wait(self, *, service: str, country: str, timeout: float = 1200.0,
                        on_number: Optional[Callable[[Dict[str, Any]], None]] = None, **params: Any) -> Dict[str, Any]:
        """Buys a number, then waits for its code — the common case in one call."""
        created = self.create(service=service, country=country, **params)
        if on_number:
            on_number(created["data"])
        return self.wait_for_code(created["data"]["id"], timeout=timeout)


class Events(EventsResource):
    def stream(self, *, since: Optional[str] = None) -> Iterator[Dict[str, Any]]:
        """Live events, forever (reconnects by itself, never skips one)::

            for event in client.events.stream():
                if event["type"] == "activation.code_received": ...
        """
        cursor = since
        failures = 0
        while True:
            try:
                resp = self._t.send("GET", "/events", query={"since": cursor} if cursor else None, stream=True,
                                    options={"timeout": httpx.Timeout(75.0, connect=10.0), "max_retries": 0,
                                             "headers": {"Accept": "text/event-stream"}})
            except NumberOTPError:
                failures += 1
                if failures > 5:
                    raise
                time.sleep(min(30, 2**failures))
                continue
            try:
                if resp.is_error:
                    resp.read()
                    raise error_from_response(resp.status_code, resp.json() if resp.content else None)
                failures = 0
                parser = _SseParser()
                for line in resp.iter_lines():
                    msg = parser.feed(line)
                    if msg:
                        if msg["id"]:
                            cursor = msg["id"]
                        yield _event_from(msg)
            except httpx.HTTPError:
                pass  # dropped connection — reconnect from the cursor
            finally:
                resp.close()


class Auth(AuthResource):
    def _sign_in(self, **fields: Any) -> Dict[str, Any]:
        tokens = self.token(**fields)
        self._t.set_tokens(tokens)
        if self._t.on_tokens:
            self._t.on_tokens(tokens)
        return tokens

    def device_login(self, on_code: Callable[[Dict[str, Any]], None], *, client: str = "cli",
                     device_name: Optional[str] = None) -> Dict[str, Any]:
        """Device sign-in (RFC 8628): ``on_code`` shows the person a code; they approve it on
        numberotp.com/device; this returns the tokens (and signs the client in)."""
        code = self.start_device_sign_in(client=client, device_name=device_name)
        on_code(code)
        interval = max(1, int(code["interval"]))
        deadline = time.monotonic() + int(code["expires_in"])
        while time.monotonic() < deadline:
            time.sleep(interval)
            try:
                return self._sign_in(grant_type="urn:ietf:params:oauth:grant-type:device_code",
                                     device_code=code["device_code"], platform=client, device_name=device_name)
            except NumberOTPError as e:
                if e.code == "authorization_pending":
                    continue
                if e.code == "slow_down":
                    interval += 5
                    continue
                raise
        raise NumberOTPError("The sign-in code expired before it was approved", 400, "expired_token")

    def sign_in_with_email_code(self, email: str, code: str, *, name: Optional[str] = None,
                                platform: Optional[str] = None, device_name: Optional[str] = None) -> Dict[str, Any]:
        """Signs in with the 6-digit code from send_email_code() — creates the account if it's new."""
        return self._sign_in(grant_type="urn:numberotp:params:grant-type:email_code", email=email, code=code,
                             name=name, platform=platform, device_name=device_name)

    def sign_in_with_password(self, email: str, password: str, *, platform: Optional[str] = None,
                              device_name: Optional[str] = None) -> Dict[str, Any]:
        return self._sign_in(grant_type="password", email=email, password=password, platform=platform, device_name=device_name)

    def sign_out(self) -> None:
        """Revokes the refresh token server-side and forgets the tokens."""
        if self._t.refresh_token:
            try:
                self.revoke(token=self._t.refresh_token)
            except NumberOTPError:
                pass
        self._t.clear_tokens()


class NumberOTP(Resources):
    """The NumberOTP API client.

    ::

        client = NumberOTP()            # reads NOTP_API_KEY
        n = client.activations.create(service="wa", country="16")
        act = client.activations.wait_for_code(n["data"]["id"])
        print(act["otp"])
    """

    activations: Activations  # type: ignore[assignment]
    events: Events  # type: ignore[assignment]
    auth: Auth  # type: ignore[assignment]

    def __init__(self, api_key: Optional[str] = None, *, access_token: Optional[str] = None,
                 refresh_token: Optional[str] = None, on_tokens: Optional[TokenCallback] = None,
                 base_url: Optional[str] = None, timeout: float = 30.0, max_retries: int = 2,
                 http_client: Optional[httpx.Client] = None, default_headers: Optional[Mapping[str, str]] = None) -> None:
        self._transport = SyncTransport(api_key=api_key, access_token=access_token, refresh_token=refresh_token,
                                        on_tokens=on_tokens, base_url=base_url, timeout=timeout,
                                        max_retries=max_retries, http_client=http_client, default_headers=default_headers)
        self._init_resources(self._transport)
        self.activations = Activations(self._transport)
        self.events = Events(self._transport)
        self.auth = Auth(self._transport)

    def set_tokens(self, tokens: Mapping[str, Any]) -> None:
        self._transport.set_tokens(tokens)

    def close(self) -> None:
        self._transport.close()

    def __enter__(self) -> "NumberOTP":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()


# ── Async ────────────────────────────────────────────────────────────────────

class AsyncActivations(AsyncActivationsResource):
    async def wait_once(self, id: str, request_options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:  # type: ignore[override]
        return await super().wait_once(id, request_options={"timeout": 70.0, "max_retries": 0, **(request_options or {})})

    async def wait_for_code(self, id: str, *, timeout: float = 1200.0) -> Dict[str, Any]:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        while loop.time() < deadline:
            try:
                await self.wait_once(id, request_options={"timeout": min(70.0, deadline - loop.time() + 5)})
                return (await self.get(id))["data"]
            except NumberOTPError as e:
                outcome = _wait_outcome(e)
                if outcome == "again":
                    continue
                if outcome == "closed":
                    raise ActivationClosedError(e.body["status"], e.body) from e
                raise
        raise WaitTimeoutError()

    async def create_and_wait(self, *, service: str, country: str, timeout: float = 1200.0,
                              on_number: Optional[Callable[[Dict[str, Any]], Union[None, Awaitable[None]]]] = None,
                              **params: Any) -> Dict[str, Any]:
        created = await self.create(service=service, country=country, **params)
        if on_number:
            result = on_number(created["data"])
            if asyncio.iscoroutine(result):
                await result
        return await self.wait_for_code(created["data"]["id"], timeout=timeout)


class AsyncEvents(AsyncEventsResource):
    async def stream(self, *, since: Optional[str] = None) -> AsyncIterator[Dict[str, Any]]:
        cursor = since
        failures = 0
        while True:
            try:
                resp = await self._t.send("GET", "/events", query={"since": cursor} if cursor else None, stream=True,
                                          options={"timeout": httpx.Timeout(75.0, connect=10.0), "max_retries": 0,
                                                   "headers": {"Accept": "text/event-stream"}})
            except NumberOTPError:
                failures += 1
                if failures > 5:
                    raise
                await asyncio.sleep(min(30, 2**failures))
                continue
            try:
                if resp.is_error:
                    await resp.aread()
                    raise error_from_response(resp.status_code, resp.json() if resp.content else None)
                failures = 0
                parser = _SseParser()
                async for line in resp.aiter_lines():
                    msg = parser.feed(line)
                    if msg:
                        if msg["id"]:
                            cursor = msg["id"]
                        yield _event_from(msg)
            except httpx.HTTPError:
                pass
            finally:
                await resp.aclose()


class AsyncAuth(AsyncAuthResource):
    async def _sign_in(self, **fields: Any) -> Dict[str, Any]:
        tokens = await self.token(**fields)
        self._t.set_tokens(tokens)
        if self._t.on_tokens:
            result = self._t.on_tokens(tokens)
            if asyncio.iscoroutine(result):
                await result
        return tokens

    async def device_login(self, on_code: Callable[[Dict[str, Any]], Union[None, Awaitable[None]]], *,
                           client: str = "cli", device_name: Optional[str] = None) -> Dict[str, Any]:
        code = await self.start_device_sign_in(client=client, device_name=device_name)
        result = on_code(code)
        if asyncio.iscoroutine(result):
            await result
        interval = max(1, int(code["interval"]))
        loop = asyncio.get_running_loop()
        deadline = loop.time() + int(code["expires_in"])
        while loop.time() < deadline:
            await asyncio.sleep(interval)
            try:
                return await self._sign_in(grant_type="urn:ietf:params:oauth:grant-type:device_code",
                                           device_code=code["device_code"], platform=client, device_name=device_name)
            except NumberOTPError as e:
                if e.code == "authorization_pending":
                    continue
                if e.code == "slow_down":
                    interval += 5
                    continue
                raise
        raise NumberOTPError("The sign-in code expired before it was approved", 400, "expired_token")

    async def sign_in_with_email_code(self, email: str, code: str, *, name: Optional[str] = None,
                                      platform: Optional[str] = None, device_name: Optional[str] = None) -> Dict[str, Any]:
        return await self._sign_in(grant_type="urn:numberotp:params:grant-type:email_code", email=email, code=code,
                                   name=name, platform=platform, device_name=device_name)

    async def sign_in_with_password(self, email: str, password: str, *, platform: Optional[str] = None,
                                    device_name: Optional[str] = None) -> Dict[str, Any]:
        return await self._sign_in(grant_type="password", email=email, password=password, platform=platform, device_name=device_name)

    async def sign_out(self) -> None:
        if self._t.refresh_token:
            try:
                await self.revoke(token=self._t.refresh_token)
            except NumberOTPError:
                pass
        self._t.clear_tokens()


class AsyncNumberOTP(AsyncResources):
    """Async NumberOTP client — same API as NumberOTP, with ``await``."""

    activations: AsyncActivations  # type: ignore[assignment]
    events: AsyncEvents  # type: ignore[assignment]
    auth: AsyncAuth  # type: ignore[assignment]

    def __init__(self, api_key: Optional[str] = None, *, access_token: Optional[str] = None,
                 refresh_token: Optional[str] = None, on_tokens: Optional[TokenCallback] = None,
                 base_url: Optional[str] = None, timeout: float = 30.0, max_retries: int = 2,
                 http_client: Optional[httpx.AsyncClient] = None, default_headers: Optional[Mapping[str, str]] = None) -> None:
        self._transport = AsyncTransport(api_key=api_key, access_token=access_token, refresh_token=refresh_token,
                                         on_tokens=on_tokens, base_url=base_url, timeout=timeout,
                                         max_retries=max_retries, http_client=http_client, default_headers=default_headers)
        self._init_resources(self._transport)
        self.activations = AsyncActivations(self._transport)
        self.events = AsyncEvents(self._transport)
        self.auth = AsyncAuth(self._transport)

    def set_tokens(self, tokens: Mapping[str, Any]) -> None:
        self._transport.set_tokens(tokens)

    async def close(self) -> None:
        await self._transport.close()

    async def __aenter__(self) -> "AsyncNumberOTP":
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.close()
