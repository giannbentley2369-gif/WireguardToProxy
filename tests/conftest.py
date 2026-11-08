from __future__ import annotations

import base64
import contextlib
import os
import random
import shlex
import socket
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from wgproxy.app import create_app
from wgproxy.config import AppConfig

FAKE_SING_BOX = Path(__file__).parent / "fake_sing_box.py"
HEADERS = {"X-Requested-With": "wgproxy"}
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})


def make_key() -> str:
    return base64.b64encode(os.urandom(32)).decode("ascii")


def make_conf(
    *,
    private_key: str | None = None,
    peer_key: str | None = None,
    address: str = "10.64.0.2/32",
    dns: str | None = "10.64.0.1",
    endpoint: str = "198.51.100.10:51820",
    allowed_ips: str = "0.0.0.0/0",
    mtu: int | None = None,
    keepalive: str | None = None,
    preshared_key: str | None = None,
) -> str:
    lines = ["[Interface]", f"PrivateKey = {private_key or make_key()}", f"Address = {address}"]
    if dns:
        lines.append(f"DNS = {dns}")
    if mtu:
        lines.append(f"MTU = {mtu}")
    lines += ["", "[Peer]", f"PublicKey = {peer_key or make_key()}"]
    if preshared_key:
        lines.append(f"PresharedKey = {preshared_key}")
    lines += [f"Endpoint = {endpoint}", f"AllowedIPs = {allowed_ips}"]
    if keepalive is not None:
        lines.append(f"PersistentKeepalive = {keepalive}")
    return "\n".join(lines) + "\n"


def free_port_range(size: int = 200) -> int:
    """Start of a port range whose first ports are currently free on 127.0.0.1."""
    for _ in range(50):
        base = random.randint(30000, 45000)
        free = True
        for port in range(base, base + 10):
            with socket.socket() as sock:
                try:
                    sock.bind(("127.0.0.1", port))
                except OSError:
                    free = False
                    break
        if free:
            return base
    raise RuntimeError("no free port range found")


@pytest.fixture
def fake_sing_box(tmp_path: Path) -> Path:
    wrapper = tmp_path / "bin" / "sing-box"
    wrapper.parent.mkdir()
    wrapper.write_text(
        f"#!/bin/sh\nexec {shlex.quote(sys.executable)} {shlex.quote(str(FAKE_SING_BOX))} \"$@\"\n",
        encoding="utf-8",
    )
    wrapper.chmod(0o755)
    return wrapper


@pytest.fixture
def make_client(tmp_path: Path, monkeypatch):
    """Factory for API test clients (engine not started). Keyword arguments override AppConfig
    fields; every client shares one data directory, like restarts of the same install."""
    with contextlib.ExitStack() as stack:

        def factory(*, client: tuple[str, int] = ("testclient", 50000), **overrides) -> TestClient:
            values = {
                "data_dir": tmp_path / "data",
                "sing_box": str(tmp_path / "missing-sing-box"),  # validation is skipped without a binary
                "webui_port": 18080,
                "log_level": "INFO",
                "allowed_hosts": LOOPBACK_HOSTS,
            }
            cfg = AppConfig(**(values | overrides))
            monkeypatch.setenv("WGPROXY_DATA_DIR", str(cfg.data_dir))
            app = create_app(cfg, background=False)
            return stack.enter_context(
                TestClient(app, base_url="http://127.0.0.1:18080", headers=HEADERS, client=client)
            )

        yield factory
