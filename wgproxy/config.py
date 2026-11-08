"""Process-level configuration read from environment variables."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

# Every listener (WebUI and every proxy inbound) binds here. This is a hard design rule:
# nothing is ever exposed beyond the host's loopback interface.
LISTEN_HOST = "127.0.0.1"

_DEFAULT_ALLOWED_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})


@dataclass(frozen=True)
class AppConfig:
    data_dir: Path
    sing_box: str
    webui_port: int
    log_level: str
    allowed_hosts: frozenset[str]

    @property
    def db_path(self) -> Path:
        return self.data_dir / "wgproxy.db"

    @property
    def engine_dir(self) -> Path:
        return self.data_dir / "engine"

    @property
    def secret_path(self) -> Path:
        return self.data_dir / "secret.key"

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> AppConfig:
        env = os.environ if env is None else env
        raw_port = env.get("WGPROXY_WEBUI_PORT", "8080")
        try:
            port = int(raw_port)
        except ValueError as exc:
            raise ValueError(f"WGPROXY_WEBUI_PORT must be a number, got {raw_port!r}") from exc
        if not 1 <= port <= 65535:
            raise ValueError(f"WGPROXY_WEBUI_PORT out of range: {port}")
        extra_hosts = {
            host.strip().lower()
            for host in env.get("WGPROXY_ALLOWED_HOSTS", "").split(",")
            if host.strip()
        }
        return cls(
            data_dir=Path(env.get("WGPROXY_DATA_DIR", "./data")).expanduser().resolve(),
            sing_box=env.get("WGPROXY_SING_BOX", "sing-box"),
            webui_port=port,
            log_level=env.get("WGPROXY_LOG_LEVEL", "info").upper(),
            allowed_hosts=_DEFAULT_ALLOWED_HOSTS | extra_hosts,
        )
