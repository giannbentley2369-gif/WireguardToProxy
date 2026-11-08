"""Generation of sing-box 1.14.x configuration files.

Rules enforced here (see the README, "Architecture"):

* every inbound listens on the configured listen host only (127.0.0.1 unless
  WGPROXY_LISTEN_HOST says otherwise) and requires the proxy credentials;
* every WireGuard endpoint is userspace (``"system": false``) and dials through a detour:
  the SOCKS5 ``upstream`` outbound when one is configured, otherwise an explicit ``direct``
  outbound;
* every inbound is bound to exactly one endpoint by a route rule and a final catch-all rule
  rejects anything else, so traffic can never fall through to a default route;
* destination names are resolved by a per-tunnel DNS server reached *through* that tunnel,
  and IP families the tunnel cannot carry are rejected;
* endpoint host names are resolved by the bootstrap DNS server through the same detour.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from .config import DEFAULT_LISTEN_HOST
from .wgconf import Peer, WireGuardConfig

UPSTREAM_TAG = "upstream"
DIRECT_TAG = "direct"
BOOTSTRAP_DNS_TAG = "bootstrap-dns"
ENDPOINT_PREFIX = "wg-"
INBOUND_PREFIX = "in-"
DNS_PREFIX = "dns-"


@dataclass(frozen=True)
class UpstreamProxy:
    host: str  # IP literal; host names are resolved by the caller
    port: int
    username: str = ""
    password: str = ""


@dataclass(frozen=True)
class EngineSettings:
    upstream: UpstreamProxy | None
    proxy_username: str
    proxy_password: str
    bootstrap_dns: str = "1.1.1.1"
    bootstrap_dns_protocol: str = "udp"
    tunnel_dns_fallback: str = "1.1.1.1"
    default_mtu: int = 1280
    default_keepalive: int = 25
    log_level: str = "warn"
    listen_host: str = DEFAULT_LISTEN_HOST


@dataclass(frozen=True)
class Tunnel:
    name: str
    port: int
    conf: WireGuardConfig


def endpoint_tag(name: str) -> str:
    return ENDPOINT_PREFIX + name


def inbound_tag(name: str) -> str:
    return INBOUND_PREFIX + name


def dns_tag(name: str) -> str:
    return DNS_PREFIX + name


def tag_to_name(tag: str) -> str | None:
    """Map a generated tag back to the tunnel name (None for shared components)."""
    for prefix in (ENDPOINT_PREFIX, INBOUND_PREFIX, DNS_PREFIX):
        if tag.startswith(prefix):
            return tag[len(prefix) :]
    return None


def resolve_strategy(conf: WireGuardConfig) -> str:
    versions = conf.ip_versions
    if versions == {4, 6}:
        return "prefer_ipv4"
    if versions == {6}:
        return "ipv6_only"
    return "ipv4_only"


def tunnel_dns_server(conf: WireGuardConfig, fallback: str) -> str:
    """First DNS server from the .conf the tunnel can reach, else the fallback."""
    for server in conf.dns:
        if ipaddress.ip_address(server).version in conf.ip_versions:
            return server
    return fallback


def effective_mtu(conf: WireGuardConfig, default_mtu: int) -> int:
    # The default acts as a ceiling: tunnels run inside the outer VPN, so a .conf written for
    # a direct link (typically MTU 1420) is capped, while a smaller explicit MTU is kept.
    return min(conf.mtu, default_mtu) if conf.mtu else default_mtu


def effective_keepalive(peer: Peer, default_keepalive: int) -> int:
    return default_keepalive if peer.persistent_keepalive is None else peer.persistent_keepalive


def _peer_options(peer: Peer, settings: EngineSettings) -> dict[str, Any]:
    options: dict[str, Any] = {
        "address": peer.endpoint_host,
        "port": peer.endpoint_port,
        "public_key": peer.public_key,
        "allowed_ips": list(peer.allowed_ips),
    }
    if peer.preshared_key:
        options["pre_shared_key"] = peer.preshared_key
    keepalive = effective_keepalive(peer, settings.default_keepalive)
    if keepalive:
        options["persistent_keepalive_interval"] = keepalive
    return options


def _outbounds(settings: EngineSettings) -> list[dict[str, Any]]:
    if settings.upstream is not None:
        upstream: dict[str, Any] = {
            "type": "socks",
            "tag": UPSTREAM_TAG,
            "server": settings.upstream.host,
            "server_port": settings.upstream.port,
            "version": "5",
        }
        if settings.upstream.username:
            upstream["username"] = settings.upstream.username
            upstream["password"] = settings.upstream.password
        return [upstream]
    # Endpoints always dial through a detour, even in direct mode: without one sing-box uses a
    # 128-packet batched UDP bind costing ~8 MiB per tunnel, versus ~0.4 MiB with a detour.
    # sing-box rejects detours to an "empty" direct outbound, so one dial field is set.
    return [{"type": "direct", "tag": DIRECT_TAG, "connect_timeout": "10s"}]


def build_config(tunnels: Sequence[Tunnel], settings: EngineSettings) -> dict[str, Any]:
    """Build one complete sing-box configuration hosting ``tunnels``."""
    names = [tunnel.name for tunnel in tunnels]
    if len(set(names)) != len(names):
        raise ValueError("tunnel names must be unique")
    ports = [tunnel.port for tunnel in tunnels]
    if len(set(ports)) != len(ports):
        raise ValueError("tunnel ports must be unique")

    detour = UPSTREAM_TAG if settings.upstream is not None else DIRECT_TAG
    bootstrap: dict[str, Any] = {
        "type": settings.bootstrap_dns_protocol,
        "tag": BOOTSTRAP_DNS_TAG,
        "server": settings.bootstrap_dns,
        "server_port": 53,
    }
    if settings.upstream is not None:
        bootstrap["detour"] = UPSTREAM_TAG
    dns_servers: list[dict[str, Any]] = [bootstrap]
    endpoints: list[dict[str, Any]] = []
    inbounds: list[dict[str, Any]] = []
    resolve_rules: list[dict[str, Any]] = []
    route_rules: list[dict[str, Any]] = []
    reject_v6: list[str] = []
    reject_v4: list[str] = []

    for tunnel in tunnels:
        conf = tunnel.conf
        ep_tag, in_tag, tunnel_dns_tag = endpoint_tag(tunnel.name), inbound_tag(tunnel.name), dns_tag(tunnel.name)
        endpoints.append(
            {
                "type": "wireguard",
                "tag": ep_tag,
                "system": False,
                "mtu": effective_mtu(conf, settings.default_mtu),
                "address": list(conf.addresses),
                "private_key": conf.private_key,
                "peers": [_peer_options(peer, settings) for peer in conf.peers],
                "workers": 1,
                "detour": detour,
                "domain_resolver": {"server": BOOTSTRAP_DNS_TAG, "strategy": "ipv4_only"},
            }
        )
        inbounds.append(
            {
                "type": "mixed",
                "tag": in_tag,
                "listen": settings.listen_host,
                "listen_port": tunnel.port,
                "users": [{"username": settings.proxy_username, "password": settings.proxy_password}],
            }
        )
        dns_servers.append(
            {
                "type": "udp",
                "tag": tunnel_dns_tag,
                "server": tunnel_dns_server(conf, settings.tunnel_dns_fallback),
                "server_port": 53,
                "detour": ep_tag,
            }
        )
        resolve_rules.append(
            {"inbound": [in_tag], "action": "resolve", "server": tunnel_dns_tag, "strategy": resolve_strategy(conf)}
        )
        route_rules.append({"inbound": [in_tag], "action": "route", "outbound": ep_tag})
        if not conf.has_ipv6:
            reject_v6.append(in_tag)
        if not conf.has_ipv4:
            reject_v4.append(in_tag)

    rules: list[dict[str, Any]] = list(resolve_rules)
    if reject_v6:
        rules.append({"inbound": reject_v6, "ip_version": 6, "action": "reject"})
    if reject_v4:
        rules.append({"inbound": reject_v4, "ip_version": 4, "action": "reject"})
    rules.extend(route_rules)
    # Catch-all: anything not bound to a tunnel above is rejected, never routed by default.
    rules.append({"action": "reject"})

    return {
        "log": {"level": settings.log_level, "timestamp": True},
        "dns": {"servers": dns_servers, "final": BOOTSTRAP_DNS_TAG, "strategy": "ipv4_only"},
        "endpoints": endpoints,
        "inbounds": inbounds,
        "outbounds": _outbounds(settings),
        "route": {
            "rules": rules,
            # Required by sing-box >= 1.14 at run time (`check` does not flag its absence).
            "default_domain_resolver": {"server": BOOTSTRAP_DNS_TAG, "strategy": "ipv4_only"},
        },
    }


def render(config: dict[str, Any]) -> str:
    return json.dumps(config, indent=2) + "\n"


def config_hash(config: dict[str, Any]) -> str:
    canonical = json.dumps(config, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
