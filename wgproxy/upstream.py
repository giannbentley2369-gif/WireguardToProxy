"""Upstream SOCKS5 proxy: reachability monitoring and step-by-step diagnostics."""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import os
import socket
import struct
import time
from collections.abc import Callable
from typing import Any
from urllib.parse import quote

import httpx

from .db import utcnow_iso
from .settings import Settings, SettingsStore
from .wgconf import is_ip


class Socks5Error(RuntimeError):
    pass


async def resolve_host(host: str) -> str:
    """Resolve a host name with the system resolver (``/etc/hosts`` first). IPs pass through."""
    if is_ip(host):
        return host
    loop = asyncio.get_running_loop()
    for family in (socket.AF_INET, socket.AF_UNSPEC):
        try:
            infos = await loop.getaddrinfo(host, None, family=family, type=socket.SOCK_STREAM)
        except socket.gaierror:
            continue
        if infos:
            return str(infos[0][4][0])
    raise OSError(f"cannot resolve {host!r}")


def upstream_proxy_url(settings: Settings) -> str | None:
    if not settings.upstream_host:
        return None
    auth = ""
    if settings.upstream_username:
        auth = f"{quote(settings.upstream_username, safe='')}:{quote(settings.upstream_password, safe='')}@"
    host = settings.upstream_host
    if ":" in host:
        host = f"[{host}]"
    return f"socks5://{auth}{host}:{settings.upstream_port}"


async def socks5_negotiate(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter, username: str, password: str
) -> str:
    """Greeting plus optional RFC 1929 authentication. Returns the method used."""
    methods = [0x00, 0x02] if username else [0x00]
    writer.write(bytes([0x05, len(methods), *methods]))
    await writer.drain()
    version, method = await reader.readexactly(2)
    if version != 0x05:
        raise Socks5Error("the server did not answer as a SOCKS5 proxy")
    if method == 0xFF:
        raise Socks5Error("no acceptable authentication method (does the proxy require credentials?)")
    if method == 0x02:
        if not username:
            raise Socks5Error("the proxy requires a username and password")
        user, pwd = username.encode(), password.encode()
        writer.write(bytes([0x01, len(user)]) + user + bytes([len(pwd)]) + pwd)
        await writer.drain()
        _, status = await reader.readexactly(2)
        if status != 0x00:
            raise Socks5Error("username/password rejected by the proxy")
        return "username/password"
    if method != 0x00:
        raise Socks5Error(f"the proxy selected unsupported method {method:#x}")
    return "no authentication"


async def _read_socks_address(reader: asyncio.StreamReader, atyp: int) -> str:
    if atyp == 0x01:
        return socket.inet_ntop(socket.AF_INET, await reader.readexactly(4))
    if atyp == 0x04:
        return socket.inet_ntop(socket.AF_INET6, await reader.readexactly(16))
    if atyp == 0x03:
        length = (await reader.readexactly(1))[0]
        return (await reader.readexactly(length)).decode("ascii", "replace")
    raise Socks5Error(f"unknown address type {atyp}")


async def socks5_udp_associate(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> tuple[str, int]:
    writer.write(bytes([0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0]))
    await writer.drain()
    _, reply, _, atyp = await reader.readexactly(4)
    if reply != 0x00:
        raise Socks5Error(f"UDP ASSOCIATE refused (reply code {reply})")
    host = await _read_socks_address(reader, atyp)
    (port,) = struct.unpack("!H", await reader.readexactly(2))
    return host, port


def build_dns_query(name: str, query_id: int) -> bytes:
    header = struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0)
    qname = b"".join(bytes([len(label)]) + label.encode("ascii") for label in name.split(".") if label) + b"\0"
    return header + qname + struct.pack("!HH", 1, 1)


def _socks_udp_header(ip: str, port: int) -> bytes:
    address = ipaddress.ip_address(ip)
    atyp = b"\x01" if address.version == 4 else b"\x04"
    return b"\x00\x00\x00" + atyp + address.packed + struct.pack("!H", port)


def _strip_socks_udp_header(data: bytes) -> bytes:
    if len(data) < 4:
        raise Socks5Error("truncated UDP relay packet")
    atyp = data[3]
    if atyp == 0x01:
        offset = 4 + 4
    elif atyp == 0x04:
        offset = 4 + 16
    elif atyp == 0x03:
        offset = 4 + 1 + data[4]
    else:
        raise Socks5Error(f"unknown address type {atyp} in UDP relay packet")
    return data[offset + 2 :]


def _udp_exchange(relay: tuple[str, int], dns_server: str, payload: bytes, timeout: float) -> bytes:
    family = socket.AF_INET6 if ":" in relay[0] else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(_socks_udp_header(dns_server, 53) + payload, relay)
        data, _ = sock.recvfrom(4096)
    return _strip_socks_udp_header(data)


async def fetch_exit_ip(proxy_url: str | None, timeout: float = 10.0) -> str:
    """Return the public IP seen by Cloudflare when connecting through ``proxy_url``."""
    async with httpx.AsyncClient(proxy=proxy_url, timeout=timeout, trust_env=False) as client:
        response = await client.get("https://1.1.1.1/cdn-cgi/trace")
        response.raise_for_status()
    for line in response.text.splitlines():
        if line.startswith("ip="):
            return line[3:].strip()
    raise ValueError("unexpected response from 1.1.1.1/cdn-cgi/trace")


class UpstreamMonitor:
    """Periodically checks that the upstream SOCKS5 port accepts TCP connections."""

    def __init__(self, store: SettingsStore, interval_ok: float = 60.0, interval_bad: float = 5.0):
        self.store = store
        self.interval_ok = interval_ok
        self.interval_bad = interval_bad
        self.state = "unknown"  # unknown | disabled | reachable | unreachable
        self.address: str | None = None
        self.error: str | None = None
        self.checked_at: str | None = None
        self.on_reachable: Callable[[], None] | None = None
        self._wake = asyncio.Event()

    def snapshot(self) -> dict[str, Any]:
        return {"state": self.state, "address": self.address, "error": self.error, "checked_at": self.checked_at}

    def poke(self) -> None:
        self._wake.set()

    async def probe(self) -> bool:
        settings = self.store.load()
        previous = self.state
        self.checked_at = utcnow_iso()
        if not settings.upstream_host:
            self.state, self.address, self.error = "disabled", None, None
            return True
        self.address = f"{settings.upstream_host}:{settings.upstream_port}"
        try:
            host = await resolve_host(settings.upstream_host)
            _, writer = await asyncio.wait_for(asyncio.open_connection(host, settings.upstream_port), 3)
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
        except (OSError, asyncio.TimeoutError) as exc:
            self.state, self.error = "unreachable", str(exc) or exc.__class__.__name__
            return False
        self.state, self.error = "reachable", None
        if previous != "reachable" and self.on_reachable is not None:
            self.on_reachable()
        return True

    async def run(self) -> None:
        while True:
            ok = await self.probe()
            interval = self.interval_ok if ok else self.interval_bad
            self._wake.clear()
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(self._wake.wait(), interval)

    async def diagnose(self) -> dict[str, Any]:
        """Step-by-step check of everything WireGuard needs from the upstream proxy."""
        settings = self.store.load()
        steps: list[dict[str, Any]] = []

        def add(name: str, ok: bool, detail: str) -> bool:
            steps.append({"name": name, "ok": ok, "detail": detail})
            return ok

        if not settings.upstream_host:
            add("Upstream", True, "No upstream configured: tunnels use direct userspace UDP (host routing table)")
            return {"ok": True, "steps": steps}
        try:
            host = await resolve_host(settings.upstream_host)
        except OSError as exc:
            add("Resolve host", False, str(exc))
            return {"ok": False, "steps": steps}
        if host != settings.upstream_host:
            add("Resolve host", True, f"{settings.upstream_host} -> {host}")
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, settings.upstream_port), 5)
        except (OSError, asyncio.TimeoutError) as exc:
            add("TCP connect", False, f"{host}:{settings.upstream_port}: {exc or 'timed out'}")
            return {"ok": False, "steps": steps}
        add("TCP connect", True, f"{host}:{settings.upstream_port} accepts connections")
        try:
            try:
                method = await asyncio.wait_for(
                    socks5_negotiate(reader, writer, settings.upstream_username, settings.upstream_password), 5
                )
            except (Socks5Error, OSError, asyncio.TimeoutError, asyncio.IncompleteReadError) as exc:
                add("SOCKS5 handshake", False, str(exc) or "no valid SOCKS5 reply")
                return {"ok": False, "steps": steps}
            add("SOCKS5 handshake", True, f"accepted ({method})")
            try:
                exit_ip = await fetch_exit_ip(upstream_proxy_url(settings))
                add("TCP through upstream", True, f"works; outer exit IP is {exit_ip}")
            except Exception as exc:  # report any failure as a step result
                add("TCP through upstream", False, f"{exc.__class__.__name__}: {exc}")
            try:
                relay_host, relay_port = await asyncio.wait_for(socks5_udp_associate(reader, writer), 5)
                if relay_host in {"0.0.0.0", "::"}:
                    relay_host = host
                query_id = int.from_bytes(os.urandom(2), "big")
                started = time.perf_counter()
                answer = await asyncio.to_thread(
                    _udp_exchange,
                    (relay_host, relay_port),
                    settings.bootstrap_dns,
                    build_dns_query("example.com", query_id),
                    5.0,
                )
                elapsed = (time.perf_counter() - started) * 1000
                if len(answer) < 2 or struct.unpack("!H", answer[:2])[0] != query_id:
                    raise Socks5Error("unexpected DNS answer through the UDP relay")
                add(
                    "UDP through upstream",
                    True,
                    f"DNS reply from {settings.bootstrap_dns} in {elapsed:.0f} ms (WireGuard needs UDP)",
                )
            except Exception as exc:
                add(
                    "UDP through upstream",
                    False,
                    f"{exc.__class__.__name__}: {exc or 'no reply'}. WireGuard cannot work without UDP support.",
                )
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
        return {"ok": all(step["ok"] for step in steps), "steps": steps}
