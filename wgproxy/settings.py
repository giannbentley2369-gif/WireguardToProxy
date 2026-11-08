"""User-editable settings, persisted in the SQLite ``settings`` table."""

from __future__ import annotations

import ipaddress
import logging
import re
import secrets
import string
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from .db import Database
from .hosts import parse_public_host
from .wgconf import is_hostname, is_ip

log = logging.getLogger("wgproxy.settings")

UI_PASSWORD_KEY = "ui_password_hash"
_GOMEMLIMIT_RE = re.compile(r"^\d+(B|KiB|MiB|GiB|TiB)?$")
_PASSWORD_ALPHABET = string.ascii_letters + string.digits


def generate_password(length: int = 20) -> str:
    return "".join(secrets.choice(_PASSWORD_ALPHABET) for _ in range(length))


def _no_whitespace(value: str, what: str) -> str:
    if any(ch.isspace() or not ch.isprintable() for ch in value):
        raise ValueError(f"{what} must not contain spaces or control characters")
    return value


class Settings(BaseModel):
    model_config = ConfigDict(extra="ignore")

    # Upstream SOCKS5 proxy (e.g. the outer VPN client). Empty host = direct mode.
    upstream_host: str = "127.0.0.1"
    upstream_port: int = Field(2080, ge=1, le=65535)
    upstream_username: str = Field("", max_length=255)
    upstream_password: str = Field("", max_length=255)

    # Credentials required by every local proxy listener.
    proxy_username: str = Field("wgproxy", min_length=1, max_length=64)
    proxy_password: str = Field("", max_length=128)

    # Host written into exported proxy URLs (WGPROXY_PUBLIC_HOST overrides it). Empty = automatic.
    public_host: str = Field("", max_length=253)

    port_range_start: int = Field(20000, ge=1024, le=65535)
    port_range_end: int = Field(20999, ge=1024, le=65535)

    bootstrap_dns: str = "1.1.1.1"
    bootstrap_dns_protocol: Literal["udp", "tcp"] = "udp"
    tunnel_dns_fallback: str = "1.1.1.1"

    default_mtu: int = Field(1280, ge=1000, le=9000)
    default_keepalive: int = Field(25, ge=0, le=3600)

    log_level: Literal["trace", "debug", "info", "warn", "error"] = "warn"
    shard_size: int = Field(10, ge=1, le=1000)
    shard_start_delay: float = Field(3.0, ge=0, le=120)
    gomemlimit: str = "384MiB"

    test_url: str = "https://api.ipify.org"
    test_timeout: float = Field(15.0, ge=2, le=120)
    test_concurrency: int = Field(25, ge=1, le=200)
    auto_test_interval: int = Field(0, ge=0, le=10080)
    geo_via_upstream: bool = True

    @field_validator("upstream_host")
    @classmethod
    def _check_upstream_host(cls, value: str) -> str:
        value = value.strip()
        if value and not (is_ip(value) or is_hostname(value)):
            raise ValueError("must be an IP address or host name (no scheme, no port)")
        return value

    @field_validator("bootstrap_dns", "tunnel_dns_fallback")
    @classmethod
    def _check_ip(cls, value: str) -> str:
        value = value.strip()
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            raise ValueError("must be an IP address") from None

    @field_validator("public_host")
    @classmethod
    def _check_public_host(cls, value: str) -> str:
        return parse_public_host(value)

    @field_validator("proxy_username")
    @classmethod
    def _check_username(cls, value: str) -> str:
        _no_whitespace(value, "username")
        if ":" in value:
            raise ValueError("username must not contain ':'")
        return value

    @field_validator("proxy_password")
    @classmethod
    def _check_password(cls, value: str) -> str:
        return _no_whitespace(value, "password")

    @field_validator("gomemlimit")
    @classmethod
    def _check_gomemlimit(cls, value: str) -> str:
        value = value.strip()
        if value and not _GOMEMLIMIT_RE.match(value):
            raise ValueError("use a Go memory size such as 384MiB, or leave empty to disable")
        return value

    @field_validator("test_url")
    @classmethod
    def _check_test_url(cls, value: str) -> str:
        value = value.strip()
        if not re.match(r"^https?://[^\s/]+", value):
            raise ValueError("must be an http:// or https:// URL")
        return value

    @model_validator(mode="after")
    def _check_ranges(self) -> Settings:
        if self.port_range_start > self.port_range_end:
            raise ValueError("port_range_start must not be greater than port_range_end")
        return self

    @property
    def upstream_enabled(self) -> bool:
        return bool(self.upstream_host)


# Changing any of these regenerates engine configs (shard_size also re-packs the shards).
ENGINE_KEYS = frozenset(
    {
        "upstream_host",
        "upstream_port",
        "upstream_username",
        "upstream_password",
        "proxy_username",
        "proxy_password",
        "bootstrap_dns",
        "bootstrap_dns_protocol",
        "tunnel_dns_fallback",
        "default_mtu",
        "default_keepalive",
        "log_level",
        "shard_size",
        "gomemlimit",
    }
)
_FIELDS = frozenset(Settings.model_fields)


class SettingsStore:
    """Loads and validates settings. Reads always hit the database (no stale caches)."""

    def __init__(self, db: Database):
        self.db = db

    def load(self) -> Settings:
        stored = {key: value for key, value in self.db.get_settings().items() if key in _FIELDS}
        try:
            return Settings.model_validate(stored)
        except ValidationError as exc:
            # Drop individually invalid values (e.g. after a manual DB edit) instead of failing.
            bad = {str(error["loc"][0]) for error in exc.errors() if error.get("loc")}
            log.warning("ignoring invalid stored settings: %s", ", ".join(sorted(bad)) or "?")
            cleaned = {key: value for key, value in stored.items() if key not in bad}
            try:
                return Settings.model_validate(cleaned)
            except ValidationError:
                return Settings()

    def ensure_initialized(self) -> Settings:
        """Generate the per-install proxy password on first start."""
        settings = self.load()
        if not settings.proxy_password:
            self.db.set_settings({"proxy_password": generate_password()})
            settings = self.load()
            log.info("generated proxy credentials for user %r", settings.proxy_username)
        return settings

    def update(self, changes: dict[str, Any]) -> tuple[Settings, set[str]]:
        """Validate and persist ``changes``. Returns the new settings and the changed keys."""
        unknown = set(changes) - _FIELDS
        if unknown:
            raise ValueError(f"unknown settings: {', '.join(sorted(unknown))}")
        current = self.load()
        merged = current.model_dump() | changes
        updated = Settings.model_validate(merged)
        if not updated.proxy_password:
            raise ValueError("proxy_password must not be empty")
        new_values = updated.model_dump()
        old_values = current.model_dump()
        changed = {key for key in changes if new_values[key] != old_values[key]}
        if changed:
            self.db.set_settings({key: new_values[key] for key in changed})
        return updated, changed

    def ui_password_hash(self) -> str:
        value = self.db.get_settings().get(UI_PASSWORD_KEY, "")
        return value if isinstance(value, str) else ""

    def set_ui_password_hash(self, value: str) -> None:
        if value:
            self.db.set_settings({UI_PASSWORD_KEY: value})
        else:
            self.db.delete_setting(UI_PASSWORD_KEY)
