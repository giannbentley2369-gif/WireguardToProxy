"""Checks against the real sing-box binary (skipped when it is not installed).

Point WGPROXY_SING_BOX at the binary, or put ``sing-box`` on PATH.
"""

from __future__ import annotations

import json
import os
import shutil
import signal
import socket
import subprocess
import time
from pathlib import Path

import pytest

from wgproxy import SUPPORTED_SING_BOX_SERIES
from wgproxy.singbox import EngineSettings, Tunnel, UpstreamProxy, build_config, render
from wgproxy.wgconf import parse_wireguard_conf

from .conftest import free_port_range, make_conf

SING_BOX = os.environ.get("WGPROXY_SING_BOX") or shutil.which("sing-box")
pytestmark = pytest.mark.skipif(not SING_BOX or not shutil.which(SING_BOX), reason="sing-box binary not available")


def _tunnels(base: int) -> list[Tunnel]:
    return [
        Tunnel("ip-peer", base, parse_wireguard_conf(make_conf(endpoint="127.0.0.1:9"))),
        Tunnel("domain-peer", base + 1, parse_wireguard_conf(make_conf(endpoint="vpn.example.invalid:51820", mtu=1420))),
        Tunnel(
            "dual-stack",
            base + 2,
            parse_wireguard_conf(make_conf(address="10.1.0.2/32, fd00::2/128", allowed_ips="0.0.0.0/0, ::/0", keepalive="0")),
        ),
    ]


def _settings(upstream: UpstreamProxy | None) -> EngineSettings:
    return EngineSettings(upstream=upstream, proxy_username="user", proxy_password="secret")


def test_binary_is_the_supported_series():
    output = subprocess.run([SING_BOX, "version"], capture_output=True, text=True, check=True).stdout
    assert f"version {SUPPORTED_SING_BOX_SERIES}" in output


@pytest.mark.parametrize("upstream", [UpstreamProxy("127.0.0.1", 2080, "u", "p"), None], ids=["upstream", "direct"])
def test_generated_config_passes_sing_box_check(tmp_path: Path, upstream: UpstreamProxy | None):
    path = tmp_path / "config.json"
    path.write_text(render(build_config(_tunnels(20000), _settings(upstream))))
    result = subprocess.run([SING_BOX, "check", "-c", str(path)], capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr


def _accepts(port: int) -> bool:
    with socket.socket() as sock:
        sock.settimeout(0.3)
        return sock.connect_ex(("127.0.0.1", port)) == 0


@pytest.mark.parametrize("with_upstream", [False, True], ids=["direct", "upstream-down"])
def test_generated_config_runs_and_stops_on_sigterm(tmp_path: Path, with_upstream: bool):
    """`sing-box check` does not catch everything (e.g. a missing default_domain_resolver is
    fatal only at run time), so the generated config must actually start."""
    base = free_port_range()
    upstream = UpstreamProxy("127.0.0.1", free_port_range()) if with_upstream else None
    path = tmp_path / "config.json"
    config = build_config(_tunnels(base), _settings(upstream))
    path.write_text(json.dumps(config))
    process = subprocess.Popen(
        [SING_BOX, "run", "--disable-color", "-c", str(path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        env={**os.environ, "GOMEMLIMIT": "384MiB"},
    )
    try:
        deadline = time.monotonic() + 10
        ports = [base, base + 1, base + 2]
        while time.monotonic() < deadline and not all(_accepts(port) for port in ports):
            assert process.poll() is None, process.communicate()[0]
            time.sleep(0.1)
        assert all(_accepts(port) for port in ports)
        time.sleep(1.5)  # unreachable peers and DNS failures must not stop the process
        assert process.poll() is None, process.communicate()[0]
    finally:
        process.send_signal(signal.SIGTERM)
        output, _ = process.communicate(timeout=15)
    assert process.returncode == 0, output
    assert "FATAL" not in output
