"""WebUI protection: optional password login, Host-header and CSRF checks, security headers."""

from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import hmac
import json
import os
import time
from collections import deque
from pathlib import Path
from urllib.parse import quote, urlsplit

from starlette.datastructures import MutableHeaders
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse, RedirectResponse, Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from .config import AppConfig
from .settings import SettingsStore

SESSION_COOKIE = "wgproxy_session"
SESSION_MAX_AGE = 30 * 24 * 3600
CSRF_HEADER = "x-requested-with"
CSRF_VALUE = "wgproxy"
MIN_PASSWORD_LENGTH = 8
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
_SCRYPT_N, _SCRYPT_R, _SCRYPT_P = 2**14, 8, 1


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def hash_password(password: str) -> str:
    salt = os.urandom(16)
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


class Auth:
    def __init__(self, store: SettingsStore, secret: bytes):
        self.store = store
        self.secret = secret
        self._verified: dict[str, str] = {}  # sha256(password) -> hash it matched
        self._failures: deque[float] = deque(maxlen=100)

    def enabled(self) -> bool:
        return bool(self.store.ui_password_hash())

    def set_password(self, password: str) -> None:
        self._verified.clear()
        self.store.set_ui_password_hash(hash_password(password) if password else "")

    def check_password(self, password: str) -> bool:
        encoded = self.store.ui_password_hash()
        if not encoded:
            return True
        key = hashlib.sha256(password.encode("utf-8")).hexdigest()
        if self._verified.get(key) == encoded:
            return True
        if verify_password(password, encoded):
            self._verified = {key: encoded}
            return True
        return False

    def record_failure(self) -> None:
        self._failures.append(time.monotonic())

    def failure_delay(self) -> float:
        """Slow down password guessing: grows with recent failures, capped at 10 s."""
        cutoff = time.monotonic() - 300
        recent = sum(1 for moment in self._failures if moment > cutoff)
        return 0.0 if recent < 3 else min(10.0, 0.5 * (recent - 2))

    def _fingerprint(self) -> str:
        encoded = self.store.ui_password_hash()
        return hmac.new(self.secret, encoded.encode("utf-8"), hashlib.sha256).hexdigest()[:16]

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

    async def basic_valid(self, header: str | None) -> bool:
        """HTTP Basic auth for scripts (any username, the UI password)."""
        if not header or not header.lower().startswith("basic "):
            return False
        try:
            decoded = base64.b64decode(header[6:].strip()).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError):
            return False
        _, _, password = decoded.partition(":")
        return await asyncio.to_thread(self.check_password, password)

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
        # DNS-rebinding protection: only loopback names may address the WebUI.
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
        if await self.auth.basic_valid(request.headers.get("authorization")):
            return None
        if path.startswith("/api/") or method not in SAFE_METHODS:
            return JSONResponse({"detail": "Authentication required"}, status_code=401)
        return RedirectResponse(f"/login?next={quote(path)}", status_code=303)
