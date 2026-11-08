"""WebUI protection: optional login, Host-header and CSRF checks, rate limiting, security headers."""

from __future__ import annotations

import asyncio
import base64
import binascii
import contextlib
import hashlib
import hmac
import ipaddress
import json
import math
import os
import time
from collections import deque
from collections.abc import Callable
from pathlib import Path
from urllib.parse import quote, urlsplit

from starlette.datastructures import MutableHeaders
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse, RedirectResponse, Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from .config import DEFAULT_WEBUI_USERNAME, AppConfig
from .settings import SettingsStore

SESSION_COOKIE = "wgproxy_session"
SESSION_MAX_AGE = 30 * 24 * 3600
CSRF_HEADER = "x-requested-with"
CSRF_VALUE = "wgproxy"
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
PUBLIC_PATHS = frozenset({"/healthz", "/login", "/api/auth/login", "/favicon.ico"})
PUBLIC_PREFIXES = ("/static/",)
SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
}
LOGIN_FAILURE_LIMIT = 5
LOGIN_FAILURE_WINDOW = 60.0
_SCRYPT_N, _SCRYPT_R, _SCRYPT_P = 2**14, 8, 1


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = os.urandom(16) if salt is None else salt
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=32)
    return f"scrypt${_SCRYPT_N}${_SCRYPT_R}${_SCRYPT_P}${_b64e(salt)}${_b64e(digest)}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, n, r, p, salt, digest = encoded.split("$")
        if algorithm != "scrypt":
            return False
        expected = _b64d(digest)
        actual = hashlib.scrypt(
            password.encode("utf-8"), salt=_b64d(salt), n=int(n), r=int(r), p=int(p), dklen=len(expected)
        )
    except (ValueError, binascii.Error):
        return False
    return hmac.compare_digest(actual, expected)


def load_or_create_secret(path: Path) -> bytes:
    """Per-install key used to sign session cookies."""
    try:
        secret = bytes.fromhex(path.read_text(encoding="ascii").strip())
        if len(secret) >= 32:
            return secret
    except (OSError, ValueError):
        pass
    secret = os.urandom(32)
    path.write_text(secret.hex(), encoding="ascii")
    os.chmod(path, 0o600)
    return secret


def host_name(value: str) -> str:
    """Host name part of a Host header / netloc, without port or IPv6 brackets."""
    value = value.strip().lower()
    if value.startswith("["):
        end = value.find("]")
        return value[1:end] if end != -1 else value
    return value.rsplit(":", 1)[0] if value.count(":") == 1 else value


def client_key(host: str | None) -> str:
    """Rate-limit bucket of a client address: the IP itself, or its /64 for IPv6 (one host
    usually controls a whole /64, so per-address limits would be trivial to dodge)."""
    if not host:
        return "unknown"
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return host
    if isinstance(address, ipaddress.IPv6Address):
        if address.ipv4_mapped is not None:
            return str(address.ipv4_mapped)
        return str(ipaddress.IPv6Network((address, 64), strict=False))
    return str(address)


class LoginThrottled(Exception):
    def __init__(self, retry_after: int):
        self.retry_after = retry_after
        self.detail = f"Too many failed login attempts; try again in {retry_after} s"
        super().__init__(self.detail)


class LoginRateLimiter:
    """Sliding-window limit on failed logins per client.

    An attempt takes its slot *before* the slow password check and returns it on success, so
    a burst of concurrent guesses cannot overshoot the limit.
    """

    def __init__(
        self,
        limit: int = LOGIN_FAILURE_LIMIT,
        window: float = LOGIN_FAILURE_WINDOW,
        clock: Callable[[], float] = time.monotonic,
        max_clients: int = 4096,
    ):
        self.limit = limit
        self.window = window
        self._clock = clock
        self._max_clients = max_clients
        self._attempts: dict[str, deque[float]] = {}

    def _recent(self, key: str, now: float) -> deque[float]:
        attempts = self._attempts.get(key, deque())
        while attempts and attempts[0] <= now - self.window:
            attempts.popleft()
        return attempts

    def acquire(self, key: str) -> float | None:
        """Count one attempt by ``key``. Returns its token, or None while ``key`` is blocked."""
        now = self._clock()
        attempts = self._recent(key, now)
        if len(attempts) >= self.limit:
            return None
        if key not in self._attempts:
            if len(self._attempts) >= self._max_clients:
                self._prune(now)
            self._attempts[key] = attempts
        attempts.append(now)
        return now

    def release(self, key: str, token: float) -> None:
        """Forget a successful attempt: only failures count toward the limit."""
        attempts = self._attempts.get(key)
        if attempts is None:
            return
        with contextlib.suppress(ValueError):
            attempts.remove(token)
        if not attempts:
            del self._attempts[key]

    def retry_after(self, key: str) -> int:
        """Seconds until ``key`` may try again; 0 when it is not blocked."""
        now = self._clock()
        attempts = self._recent(key, now)
        if len(attempts) < self.limit:
            return 0
        return max(1, math.ceil(attempts[0] + self.window - now))

    def _prune(self, now: float) -> None:
        for key in [key for key in self._attempts if not self._recent(key, now)]:
            del self._attempts[key]
        while len(self._attempts) >= self._max_clients:
            del self._attempts[next(iter(self._attempts))]


class Auth:
    """WebUI login.

    With WGPROXY_WEBUI_PASSWORD set, the login is that user name and password. Otherwise the
    optional password from the Settings page applies (no user name), or nothing at all.
    """

    def __init__(
        self,
        store: SettingsStore,
        secret: bytes,
        *,
        username: str = DEFAULT_WEBUI_USERNAME,
        env_password: str = "",
        limiter: LoginRateLimiter | None = None,
    ):
        self.store = store
        self.secret = secret
        self.username = username
        # Salt derived from the install secret: the hash, and with it every session, stays valid
        # across restarts for as long as the password does not change.
        salt = hmac.new(secret, b"wgproxy env password salt", hashlib.sha256).digest()[:16]
        self._env_hash = hash_password(env_password, salt) if env_password else ""
        self.limiter = limiter or LoginRateLimiter()
        self._verified: dict[str, str] = {}  # sha256(password) -> hash it matched
        self._failures: deque[float] = deque(maxlen=100)

    @property
    def managed_by_env(self) -> bool:
        return bool(self._env_hash)

    def _password_hash(self) -> str:
        return self._env_hash or self.store.ui_password_hash()

    def enabled(self) -> bool:
        return bool(self._password_hash())

    def set_password(self, password: str) -> None:
        self._verified.clear()
        self.store.set_ui_password_hash(hash_password(password) if password else "")

    def check_password(self, password: str) -> bool:
        encoded = self._password_hash()
        if not encoded:
            return True
        key = hashlib.sha256(password.encode("utf-8")).hexdigest()
        if self._verified.get(key) == encoded:
            return True
        if verify_password(password, encoded):
            self._verified = {key: encoded}
            return True
        return False

    def check_credentials(self, username: str, password: str) -> bool:
        password_ok = self.check_password(password)  # always runs: no timing hint about the user name
        if not self.managed_by_env:
            return password_ok  # the Settings-page password has no user name
        username_ok = hmac.compare_digest(username.encode("utf-8"), self.username.encode("utf-8"))
        return password_ok and username_ok

    async def login(self, client: str | None, username: str, password: str) -> bool:
        """Rate-limited credential check shared by the login form and HTTP Basic auth.

        Raises LoginThrottled while ``client`` has too many recent failures.
        """
        key = client_key(client)
        token = self.limiter.acquire(key)
        if token is None:
            raise LoginThrottled(self.limiter.retry_after(key))
        if await asyncio.to_thread(self.check_credentials, username, password):
            self.limiter.release(key, token)
            return True
        delay = self.failure_delay()
        self.record_failure()
        if delay:
            # Only failures wait, so failures from others (e.g. bots on a public port) never
            # slow down a correct login or an authenticated script.
            await asyncio.sleep(delay)
        return False

    def record_failure(self) -> None:
        self._failures.append(time.monotonic())

    def failure_delay(self) -> float:
        """Extra wait for a failed attempt: grows with recent failures from anywhere, capped at 10 s."""
        cutoff = time.monotonic() - 300
        recent = sum(1 for moment in self._failures if moment > cutoff)
        return 0.0 if recent < 3 else min(10.0, 0.5 * (recent - 2))

    def _fingerprint(self) -> str:
        material = self._password_hash()
        if self.managed_by_env:
            material = f"{self.username}\0{material}"  # renaming the user also signs sessions out
        return hmac.new(self.secret, material.encode("utf-8"), hashlib.sha256).hexdigest()[:16]

    def _sign(self, payload: str) -> str:
        return hmac.new(self.secret, payload.encode("utf-8"), hashlib.sha256).hexdigest()

    def issue_session(self) -> str:
        payload = _b64e(json.dumps({"iat": int(time.time()), "fp": self._fingerprint()}).encode("utf-8"))
        return f"{payload}.{self._sign(payload)}"

    def session_valid(self, token: str | None) -> bool:
        if not token or "." not in token:
            return False
        payload, signature = token.rsplit(".", 1)
        if not hmac.compare_digest(self._sign(payload), signature):
            return False
        try:
            data = json.loads(_b64d(payload))
        except (ValueError, binascii.Error):
            return False
        if not isinstance(data, dict) or time.time() - float(data.get("iat", 0)) > SESSION_MAX_AGE:
            return False
        # Changing or removing the password invalidates every existing session.
        return hmac.compare_digest(str(data.get("fp", "")), self._fingerprint())

    async def basic_valid(self, header: str | None, client: str | None = None) -> bool:
        """HTTP Basic auth for scripts. The user name is only checked for the environment login."""
        if not header or not header.lower().startswith("basic "):
            return False
        try:
            decoded = base64.b64decode(header[6:].strip()).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError):
            return False
        username, _, password = decoded.partition(":")
        return await self.login(client, username, password)

    def set_cookie(self, response: Response) -> None:
        response.set_cookie(
            SESSION_COOKIE,
            self.issue_session(),
            max_age=SESSION_MAX_AGE,
            httponly=True,
            samesite="strict",
            path="/",
        )


def _is_public(path: str) -> bool:
    return path in PUBLIC_PATHS or path.startswith(PUBLIC_PREFIXES)


def throttled_response(exc: LoginThrottled) -> JSONResponse:
    return JSONResponse({"detail": exc.detail}, status_code=429, headers={"Retry-After": str(exc.retry_after)})


class SecurityMiddleware:
    """Pure ASGI middleware (keeps streaming responses such as the log feed intact)."""

    def __init__(self, app: ASGIApp, cfg: AppConfig, auth: Auth):
        self.app = app
        self.cfg = cfg
        self.auth = auth

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        request = Request(scope)
        rejection = await self._reject(request)
        if rejection is not None:
            await rejection(scope, receive, send)
            return
        is_api = scope["path"].startswith("/api/")

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                for name, value in SECURITY_HEADERS.items():
                    headers.setdefault(name, value)
                if is_api:
                    headers.setdefault("Cache-Control", "no-store")
            await send(message)

        await self.app(scope, receive, send_with_headers)

    async def _reject(self, request: Request) -> Response | None:
        # DNS-rebinding protection: only allowlisted names (loopback by default) may address the WebUI.
        if host_name(request.headers.get("host", "")) not in self.cfg.allowed_hosts:
            return PlainTextResponse("Invalid Host header", status_code=400)
        method = request.method.upper()
        if method not in SAFE_METHODS:
            origin = request.headers.get("origin")
            if origin and origin != "null" and host_name(urlsplit(origin).netloc) not in self.cfg.allowed_hosts:
                return JSONResponse({"detail": "Cross-origin request blocked"}, status_code=403)
            # A custom header cannot be sent cross-site without a CORS preflight, which is never granted.
            if request.headers.get(CSRF_HEADER, "").lower() != CSRF_VALUE:
                return JSONResponse({"detail": "Missing X-Requested-With: wgproxy header"}, status_code=403)
        path = request.url.path
        if _is_public(path) or not self.auth.enabled():
            return None
        if self.auth.session_valid(request.cookies.get(SESSION_COOKIE)):
            return None
        client = request.client.host if request.client else None
        try:
            if await self.auth.basic_valid(request.headers.get("authorization"), client):
                return None
        except LoginThrottled as exc:
            return throttled_response(exc)
        if path.startswith("/api/") or method not in SAFE_METHODS:
            return JSONResponse({"detail": "Authentication required"}, status_code=401)
        return RedirectResponse(f"/login?next={quote(path)}", status_code=303)
