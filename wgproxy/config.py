"""Process-level configuration read from environment variables."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

from .hosts import connect_host, is_wildcard, parse_listen_host, parse_public_host

# Every listener (WebUI and every proxy inbound) binds here unless WGPROXY_LISTEN_HOST says
# otherwise. Loopback keeps everything private to the host; exposing it is an explicit choice.
DEFAULT_LISTEN_HOST = "127.0.0.1"
DEFAULT_WEBUI_USERNAME = "admin"
MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_LENGTH = 256

_DEFAULT_ALLOWED_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})


class ConfigError(ValueError):
    """An environment variable holds an invalid value."""


@dataclass(frozen=True)
class AppConfig:
    data_dir: Path
    sing_box: str
    webui_port: int
    log_level: str
    allowed_hosts: frozenset[str]
    listen_host: str = DEFAULT_LISTEN_HOST
    public_host: str = ""
    webui_username: str = DEFAULT_WEBUI_USERNAME
    # Only hashed by Auth at start-up; never compared in plain text. Kept out of repr() and logs.
    webui_password: str = field(default="", repr=False)

    @property
    def db_path(self) -> Path:
        return self.data_dir / "wgproxy.db"

    @property
    def engine_dir(self) -> Path:
        return self.data_dir / "engine"

    @property
    def secret_path(self) -> Path:
        return self.data_dir / "secret.key"

    @property
    def connect_host(self) -> str:
        """Where local clients reach the listeners (loopback for a wildcard bind)."""
        return connect_host(self.listen_host)

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> AppConfig:
        env = os.environ if env is None else env
        raw_port = env.get("WGPROXY_WEBUI_PORT", "8080")
        try:
            port = int(raw_port)
        except ValueError as exc:
            raise ConfigError(f"WGPROXY_WEBUI_PORT must be a number, got {raw_port!r}") from exc
        if not 1 <= port <= 65535:
            raise ConfigError(f"WGPROXY_WEBUI_PORT out of range: {port}")

        raw_listen = env.get("WGPROXY_LISTEN_HOST", "").strip() or DEFAULT_LISTEN_HOST
        try:
            listen_host = parse_listen_host(raw_listen)
        except ValueError as exc:
            raise ConfigError(f"WGPROXY_LISTEN_HOST {exc}, got {raw_listen!r}") from None

        raw_public = env.get("WGPROXY_PUBLIC_HOST", "")
        try:
            public_host = parse_public_host(raw_public)
        except ValueError as exc:
            raise ConfigError(f"WGPROXY_PUBLIC_HOST {exc}, got {raw_public!r}") from None

        username = env.get("WGPROXY_WEBUI_USERNAME", "").strip() or DEFAULT_WEBUI_USERNAME
        # ':' would break HTTP Basic auth, which splits "user:password" at the first colon.
        if len(username) > 64 or ":" in username or any(ch.isspace() or not ch.isprintable() for ch in username):
            raise ConfigError("WGPROXY_WEBUI_USERNAME must be at most 64 characters, without ':' or spaces")

        password = env.get("WGPROXY_WEBUI_PASSWORD", "")
        if password and not MIN_PASSWORD_LENGTH <= len(password) <= MAX_PASSWORD_LENGTH:
            raise ConfigError(
                f"WGPROXY_WEBUI_PASSWORD must be {MIN_PASSWORD_LENGTH} to {MAX_PASSWORD_LENGTH} characters long"
            )

        extra_hosts = {
            host.strip().lower()
            for host in env.get("WGPROXY_ALLOWED_HOSTS", "").split(",")
            if host.strip()
        }
        # A client addressing the WebUI by its own bind IP (e.g. the healthcheck) is no
        # DNS-rebinding risk, so a specific listen address is always accepted.
        if not is_wildcard(listen_host):
            extra_hosts.add(listen_host)
        return cls(
            data_dir=Path(env.get("WGPROXY_DATA_DIR", "./data")).expanduser().resolve(),
            sing_box=env.get("WGPROXY_SING_BOX", "sing-box"),
            webui_port=port,
            log_level=env.get("WGPROXY_LOG_LEVEL", "info").upper(),
            allowed_hosts=_DEFAULT_ALLOWED_HOSTS | extra_hosts,
            listen_host=listen_host,
            public_host=public_host,
            webui_username=username,
            webui_password=password,
        )
