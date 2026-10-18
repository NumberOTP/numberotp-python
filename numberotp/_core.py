"""HTTP transport: auth, retries (with a stable Idempotency-Key), token refresh."""

from __future__ import annotations

import asyncio
import json
import os
import random
import threading
import time
import uuid
from email.utils import parsedate_to_datetime
from typing import Any, Awaitable, Callable, Dict, Mapping, Optional, Union

import httpx

from ._errors import APIConnectionError, AuthenticationError, NumberOTPError, error_from_response

VERSION = "0.1.1"
DEFAULT_BASE_URL = "https://api.numberotp.com/v1"
RETRY_STATUSES = {408, 429, 500, 502, 503, 504}

TokenCallback = Callable[[Dict[str, Any]], Union[None, Awaitable[None]]]


def compact(d: Mapping[str, Any]) -> Dict[str, Any]:
    """Drops arguments left as None, so only what you passed is sent."""
    return {k: v for k, v in d.items() if v is not None}


def _backoff(attempt: int) -> float:
    base = min(8.0, 0.5 * (2**attempt))
    return base / 2 + random.random() * (base / 2)


def _retry_after(resp: httpx.Response) -> Optional[float]:
    value = resp.headers.get("retry-after")
    if not value:
        return None
    try:
        return min(60.0, max(0.0, float(value)))
    except ValueError:
        try:
            return min(60.0, max(0.0, parsedate_to_datetime(value).timestamp() - time.time()))
        except (TypeError, ValueError):
            return None


def _parse(resp: httpx.Response) -> Any:
    if not resp.content:
        return None
    try:
        return resp.json()
    except json.JSONDecodeError:
        return resp.text


class _Base:
    def __init__(
        self,
        *,
        api_key: Optional[str] = None,
        access_token: Optional[str] = None,
        refresh_token: Optional[str] = None,
        on_tokens: Optional[TokenCallback] = None,
        base_url: Optional[str] = None,
        timeout: float = 30.0,
        max_retries: int = 2,
        default_headers: Optional[Mapping[str, str]] = None,
    ) -> None:
        self.base_url = (base_url or os.environ.get("NOTP_BASE_URL") or DEFAULT_BASE_URL).rstrip("/")
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.api_key = api_key if api_key is not None else (None if access_token else os.environ.get("NOTP_API_KEY"))
        self.on_tokens = on_tokens
        self.timeout = timeout
        self.max_retries = max_retries
        self.default_headers = dict(default_headers or {})

    def set_tokens(self, tokens: Mapping[str, Any]) -> None:
        """Switch to a signed-in user's tokens (e.g. after sign-in)."""
        self.access_token = tokens["access_token"]
        if tokens.get("refresh_token"):
            self.refresh_token = tokens["refresh_token"]
        self.api_key = None

    def clear_tokens(self) -> None:
        self.access_token = None
        self.refresh_token = None

    def _headers(self, auth: bool, has_body: bool, options: Optional[Mapping[str, Any]]) -> Dict[str, str]:
        h = {
            "Accept": "application/json",
            "User-Agent": f"numberotp-python/{VERSION}",
            "X-NumberOTP-Client": f"sdk-python/{VERSION}",
            **self.default_headers,
            **dict((options or {}).get("headers") or {}),
        }
        cred = self.access_token or self.api_key
        if auth and cred:
            h["Authorization"] = f"Bearer {cred}"
        if has_body:
            h["Content-Type"] = "application/json"
        return h

    def _plan(self, method: str, path: str, query: Optional[Mapping[str, Any]], fixed_query: Optional[Mapping[str, str]],
              body: Any, idempotent: bool, options: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
        opts = dict(options or {})
        params = {k: (str(v).lower() if isinstance(v, bool) else v) for k, v in {**(query or {}), **(fixed_query or {})}.items() if v is not None}
        idem = (opts.get("idempotency_key") or str(uuid.uuid4())) if idempotent else None
        return {
            "url": self.base_url + path,
            "params": params,
            "content": json.dumps(body) if body is not None else None,
            "idem": idem,
            "can_retry": method in ("GET", "DELETE") or idem is not None,
            "timeout": opts.get("timeout", self.timeout),
            "max_retries": opts.get("max_retries", self.max_retries),
        }


class SyncTransport(_Base):
    def __init__(self, *, http_client: Optional[httpx.Client] = None, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._http = http_client or httpx.Client()
        self._refresh_lock = threading.Lock()

    def close(self) -> None:
        self._http.close()

    def send(self, method: str, path: str, *, query: Optional[Mapping[str, Any]] = None, fixed_query: Optional[Mapping[str, str]] = None,
             body: Any = None, idempotent: bool = False, auth: bool = True, options: Optional[Mapping[str, Any]] = None,
             stream: bool = False) -> httpx.Response:
        plan = self._plan(method, path, query, fixed_query, body, idempotent, options)
        refreshed = False
        attempt = 0
        while True:
            headers = self._headers(auth, body is not None, options)
            if plan["idem"]:
                headers["Idempotency-Key"] = plan["idem"]
            try:
                req = self._http.build_request(method, plan["url"], params=plan["params"], content=plan["content"], headers=headers, timeout=plan["timeout"])
                resp = self._http.send(req, stream=stream)
            except httpx.TimeoutException as e:
                if plan["can_retry"] and attempt < plan["max_retries"]:
                    time.sleep(_backoff(attempt)); attempt += 1; continue
                raise APIConnectionError("Request timed out", 0, "TIMEOUT") from e
            except httpx.HTTPError as e:
                if plan["can_retry"] and attempt < plan["max_retries"]:
                    time.sleep(_backoff(attempt)); attempt += 1; continue
                raise APIConnectionError(f"Could not reach NumberOTP: {e}", 0, "CONNECTION_ERROR") from e

            if resp.status_code == 401 and not refreshed and auth and self.refresh_token and self.access_token:
                refreshed = True
                resp.close()
                self.refresh_access_token()
                continue
            if resp.status_code in RETRY_STATUSES and (plan["can_retry"] or resp.status_code == 429) and attempt < plan["max_retries"]:
                delay = _retry_after(resp) or _backoff(attempt)
                resp.close()
                time.sleep(delay); attempt += 1; continue
            return resp

    def request(self, method: str, path: str, **kwargs: Any) -> Any:
        resp = self.send(method, path, **kwargs)
        data = _parse(resp)
        if resp.is_error:
            raise error_from_response(resp.status_code, data)
        return data

    def refresh_access_token(self) -> None:
        if not self.refresh_token:
            raise AuthenticationError("No refresh token to renew the session with", 401, "NO_REFRESH_TOKEN")
        with self._refresh_lock:
            try:
                tokens = self.request("POST", "/oauth/token", auth=False,
                                      body={"grant_type": "refresh_token", "refresh_token": self.refresh_token},
                                      options={"max_retries": 1})
            except NumberOTPError as e:
                raise _session_ended(e) from e
            self.set_tokens(tokens)
            if self.on_tokens:
                self.on_tokens(tokens)


def _session_ended(e: NumberOTPError) -> NumberOTPError:
    """A refused refresh token (revoked, expired, rotated away) means the session is over: report it as a 401."""
    if isinstance(e, AuthenticationError) or not (400 <= e.status < 500) or e.status == 429:
        return e
    return AuthenticationError(e.message or "Your session has ended. Sign in again.", 401, e.code or "invalid_grant", e.body)


class AsyncTransport(_Base):
    def __init__(self, *, http_client: Optional[httpx.AsyncClient] = None, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._http = http_client or httpx.AsyncClient()
        self._refresh_lock = asyncio.Lock()

    async def close(self) -> None:
        await self._http.aclose()

    async def send(self, method: str, path: str, *, query: Optional[Mapping[str, Any]] = None, fixed_query: Optional[Mapping[str, str]] = None,
                   body: Any = None, idempotent: bool = False, auth: bool = True, options: Optional[Mapping[str, Any]] = None,
                   stream: bool = False) -> httpx.Response:
        plan = self._plan(method, path, query, fixed_query, body, idempotent, options)
        refreshed = False
        attempt = 0
        while True:
            headers = self._headers(auth, body is not None, options)
            if plan["idem"]:
                headers["Idempotency-Key"] = plan["idem"]
            try:
                req = self._http.build_request(method, plan["url"], params=plan["params"], content=plan["content"], headers=headers, timeout=plan["timeout"])
                resp = await self._http.send(req, stream=stream)
            except httpx.TimeoutException as e:
                if plan["can_retry"] and attempt < plan["max_retries"]:
                    await asyncio.sleep(_backoff(attempt)); attempt += 1; continue
                raise APIConnectionError("Request timed out", 0, "TIMEOUT") from e
            except httpx.HTTPError as e:
                if plan["can_retry"] and attempt < plan["max_retries"]:
                    await asyncio.sleep(_backoff(attempt)); attempt += 1; continue
                raise APIConnectionError(f"Could not reach NumberOTP: {e}", 0, "CONNECTION_ERROR") from e

            if resp.status_code == 401 and not refreshed and auth and self.refresh_token and self.access_token:
                refreshed = True
                await resp.aclose()
                await self.refresh_access_token()
                continue
            if resp.status_code in RETRY_STATUSES and (plan["can_retry"] or resp.status_code == 429) and attempt < plan["max_retries"]:
                delay = _retry_after(resp) or _backoff(attempt)
                await resp.aclose()
                await asyncio.sleep(delay); attempt += 1; continue
            return resp

    async def request(self, method: str, path: str, **kwargs: Any) -> Any:
        resp = await self.send(method, path, **kwargs)
        data = _parse(resp)
        if resp.is_error:
            raise error_from_response(resp.status_code, data)
        return data

    async def refresh_access_token(self) -> None:
        if not self.refresh_token:
            raise AuthenticationError("No refresh token to renew the session with", 401, "NO_REFRESH_TOKEN")
        async with self._refresh_lock:
            try:
                tokens = await self.request("POST", "/oauth/token", auth=False,
                                            body={"grant_type": "refresh_token", "refresh_token": self.refresh_token},
                                            options={"max_retries": 1})
            except NumberOTPError as e:
                raise _session_ended(e) from e
            self.set_tokens(tokens)
            if self.on_tokens:
                result = self.on_tokens(tokens)
                if asyncio.iscoroutine(result):
                    await result
