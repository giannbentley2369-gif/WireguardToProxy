"""Addresses: where listeners bind, how local clients reach them, and what exports show."""

from __future__ import annotations

import ipaddress

from .wgconf import is_hostname

LOOPBACK_V4 = "127.0.0.1"
LOOPBACK_V6 = "::1"


def is_wildcard(host: str) -> bool:
    """True for the "every interface" bind addresses 0.0.0.0 and ::."""
    try:
        return ipaddress.ip_address(host).is_unspecified
    except ValueError:
        return False


def is_loopback(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host == "localhost"


def _reject_zone_index(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> None:
    if isinstance(address, ipaddress.IPv6Address) and address.scope_id:
        raise ValueError("must not include an IPv6 zone index such as %eth0")


def parse_listen_host(value: str) -> str:
    """Normalize a bind address. Only IP literals are accepted."""
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError:
        raise ValueError("must be an IP address such as 127.0.0.1 or 0.0.0.0") from None
    _reject_zone_index(address)
    return str(address)


def parse_public_host(value: str) -> str:
    """Normalize a host for exported URLs: empty, an IP literal or a host name, never a wildcard."""
    value = value.strip()
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
    if not value:
        return ""
    # A numeric last label is a mistyped IP address (e.g. 256.1.1.1), not a usable host name.
    if is_hostname(value) and not value.rsplit(".", 1)[-1].isdigit():
        return value.lower()
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        raise ValueError("must be an IP address or host name (no scheme, no port)") from None
    if address.is_unspecified:
        raise ValueError(f"must be a reachable address, not the wildcard {address}")
    _reject_zone_index(address)
    return str(address)


def connect_host(listen_host: str) -> str:
    """Address local clients (healthcheck, proxy tests) use to reach a listener on ``listen_host``.

    A wildcard bind also accepts connections on loopback; a specific address is used as is.
    """
    if not is_wildcard(listen_host):
        return listen_host
    return LOOPBACK_V6 if ipaddress.ip_address(listen_host).version == 6 else LOOPBACK_V4


def url_host(host: str) -> str:
    """``host`` as written in a URL authority: IPv6 literals go in brackets."""
    return f"[{host}]" if ":" in host else host


def export_host(public_host: str, listen_host: str, request_host: str = "") -> str:
    """Host written into exported proxy URLs. Never a wildcard address.

    Resolution order: the configured public host; else the listen address when it is a
    specific one; else the host the WebUI was reached at (the request's Host header, which
    the Host allowlist has already vetted); else loopback.
    """
    if public_host and not is_wildcard(public_host):
        return public_host
    if not is_wildcard(listen_host):
        return listen_host
    try:
        reached_at = parse_public_host(request_host)
    except ValueError:
        reached_at = ""
    return reached_at or connect_host(listen_host)
