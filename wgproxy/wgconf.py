"""Parser for standard WireGuard (wg-quick style) ``.conf`` files.

Only the keys that matter for a userspace client tunnel are interpreted:

* ``[Interface]``: PrivateKey, Address, DNS, MTU
* ``[Peer]``: PublicKey, PresharedKey, Endpoint, AllowedIPs, PersistentKeepalive

wg-quick host settings (PostUp, Table, FwMark, ...) are ignored with a warning: this
application never touches the host's interfaces, routing tables or firewall.
"""

from __future__ import annotations

import base64
import binascii
import ipaddress
import re
from dataclasses import dataclass
from typing import Any

MAX_CONF_SIZE = 64 * 1024

# Labels may contain underscores: not RFC-valid, but some providers use them.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?"
    r"(?:\.[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?)*$"
)
_IGNORED_INTERFACE_KEYS = {
    "listenport",
    "fwmark",
    "table",
    "preup",
    "postup",
    "predown",
    "postdown",
    "saveconfig",
}


class ConfParseError(ValueError):
    """The text is not a usable WireGuard client configuration."""


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def is_hostname(value: str) -> bool:
    return bool(_HOSTNAME_RE.match(value)) and not is_ip(value)


@dataclass(frozen=True)
class Peer:
    public_key: str
    endpoint_host: str
    endpoint_port: int
    allowed_ips: tuple[str, ...]
    preshared_key: str | None = None
    # None = not specified in the file, 0 = explicitly disabled.
    persistent_keepalive: int | None = None

    @property
    def endpoint(self) -> str:
        host = f"[{self.endpoint_host}]" if ":" in self.endpoint_host else self.endpoint_host
        return f"{host}:{self.endpoint_port}"

    @property
    def endpoint_is_domain(self) -> bool:
        return not is_ip(self.endpoint_host)


@dataclass(frozen=True)
class WireGuardConfig:
    private_key: str
    addresses: tuple[str, ...]
    peers: tuple[Peer, ...]
    dns: tuple[str, ...] = ()
    mtu: int | None = None
    warnings: tuple[str, ...] = ()

    @property
    def ip_versions(self) -> frozenset[int]:
        """IP versions the tunnel can actually carry: needs a local address *and* a route."""
        local = {ipaddress.ip_interface(addr).version for addr in self.addresses}
        routed = {
            ipaddress.ip_network(prefix, strict=False).version
            for peer in self.peers
            for prefix in peer.allowed_ips
        }
        return frozenset(local & routed)

    @property
    def has_ipv4(self) -> bool:
        return 4 in self.ip_versions

    @property
    def has_ipv6(self) -> bool:
        return 6 in self.ip_versions

    @property
    def peer_public_keys(self) -> tuple[str, ...]:
        return tuple(peer.public_key for peer in self.peers)

    @property
    def primary_endpoint(self) -> str:
        return self.peers[0].endpoint

    def summary(self) -> dict[str, Any]:
        """Non-secret description for the UI (no private or preshared keys)."""
        return {
            "addresses": list(self.addresses),
            "dns": list(self.dns),
            "mtu": self.mtu,
            "ip_versions": sorted(self.ip_versions),
            "peers": [
                {
                    "public_key": peer.public_key,
                    "endpoint": peer.endpoint,
                    "endpoint_is_domain": peer.endpoint_is_domain,
                    "allowed_ips": list(peer.allowed_ips),
                    "persistent_keepalive": peer.persistent_keepalive,
                    "has_preshared_key": peer.preshared_key is not None,
                }
                for peer in self.peers
            ],
            "warnings": list(self.warnings),
        }


def _split_list(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def _parse_key(value: str, key: str, lineno: int) -> str:
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise ConfParseError(f"line {lineno}: {key} is not valid base64") from None
    if len(raw) != 32:
        raise ConfParseError(f"line {lineno}: {key} must decode to 32 bytes, got {len(raw)}")
    return base64.b64encode(raw).decode("ascii")


def _parse_address(item: str, lineno: int) -> str:
    try:
        return str(ipaddress.ip_interface(item))
    except ValueError:
        raise ConfParseError(f"line {lineno}: invalid Address {item!r}") from None


def _parse_endpoint(value: str, lineno: int) -> tuple[str, int]:
    value = value.strip()
    if value.startswith("["):
        end = value.find("]")
        if end == -1 or not value[end + 1 :].startswith(":"):
            raise ConfParseError(f"line {lineno}: invalid Endpoint {value!r}")
        host, port_text = value[1:end], value[end + 2 :]
        try:
            host = str(ipaddress.IPv6Address(host))
        except ValueError:
            raise ConfParseError(f"line {lineno}: invalid IPv6 address in Endpoint {value!r}") from None
    else:
        if value.count(":") != 1:
            raise ConfParseError(
                f"line {lineno}: Endpoint must be host:port (write IPv6 as [address]:port), got {value!r}"
            )
        host, port_text = value.split(":", 1)
        host = host.strip()
        if is_ip(host):
            host = str(ipaddress.ip_address(host))
        elif is_hostname(host.rstrip(".")):
            host = host.rstrip(".").lower()
        else:
            raise ConfParseError(f"line {lineno}: invalid Endpoint host {host!r}")
    try:
        port = int(port_text)
    except ValueError:
        raise ConfParseError(f"line {lineno}: invalid Endpoint port {port_text!r}") from None
    if not 1 <= port <= 65535:
        raise ConfParseError(f"line {lineno}: Endpoint port out of range: {port}")
    return host, port


def _parse_int(value: str, key: str, lineno: int, low: int, high: int) -> int:
    try:
        number = int(value)
    except ValueError:
        raise ConfParseError(f"line {lineno}: {key} must be a number, got {value!r}") from None
    if not low <= number <= high:
        raise ConfParseError(f"line {lineno}: {key} must be between {low} and {high}, got {number}")
    return number


def _set_once(target: dict[str, Any], field: str, value: Any, key: str, lineno: int) -> None:
    if field in target:
        raise ConfParseError(f"line {lineno}: {key} is specified more than once")
    target[field] = value


def _apply_interface(iface: dict[str, Any], key: str, lkey: str, value: str, lineno: int, warnings: list[str]) -> None:
    if lkey == "privatekey":
        _set_once(iface, "private_key", _parse_key(value, key, lineno), key, lineno)
    elif lkey == "address":
        iface["addresses"].extend(_parse_address(item, lineno) for item in _split_list(value))
    elif lkey == "dns":
        for item in _split_list(value):
            if is_ip(item):
                iface["dns"].append(str(ipaddress.ip_address(item)))
            else:
                warnings.append(f"line {lineno}: DNS search domain {item!r} ignored")
    elif lkey == "mtu":
        _set_once(iface, "mtu", _parse_int(value, key, lineno, 576, 65535), key, lineno)
    elif lkey in _IGNORED_INTERFACE_KEYS:
        warnings.append(f"line {lineno}: {key} is a wg-quick host setting and is ignored")
    else:
        warnings.append(f"line {lineno}: unknown [Interface] key {key!r} ignored")


def _apply_peer(peer: dict[str, Any], key: str, lkey: str, value: str, lineno: int, warnings: list[str]) -> None:
    if lkey == "publickey":
        _set_once(peer, "public_key", _parse_key(value, key, lineno), key, lineno)
    elif lkey == "presharedkey":
        _set_once(peer, "preshared_key", _parse_key(value, key, lineno), key, lineno)
    elif lkey == "endpoint":
        _set_once(peer, "endpoint", _parse_endpoint(value, lineno), key, lineno)
    elif lkey == "allowedips":
        for item in _split_list(value):
            try:
                peer["allowed_ips"].append(str(ipaddress.ip_network(item, strict=False)))
            except ValueError:
                raise ConfParseError(f"line {lineno}: invalid AllowedIPs entry {item!r}") from None
    elif lkey == "persistentkeepalive":
        keepalive = 0 if value.strip().lower() == "off" else _parse_int(value, key, lineno, 0, 65535)
        _set_once(peer, "keepalive", keepalive, key, lineno)
    else:
        warnings.append(f"line {lineno}: unknown [Peer] key {key!r} ignored")


def _dedupe(items: list[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(items))


def parse_wireguard_conf(text: str) -> WireGuardConfig:
    """Parse a wg-quick style configuration. Raises :class:`ConfParseError` when unusable."""
    if len(text) > MAX_CONF_SIZE:
        raise ConfParseError(f"file is larger than {MAX_CONF_SIZE // 1024} KiB")
    text = text.lstrip("\ufeff")
    iface: dict[str, Any] | None = None
    peers: list[dict[str, Any]] = []
    warnings: list[str] = []
    section: str | None = None

    for lineno, raw_line in enumerate(text.splitlines(), start=1):
        # wg-quick semantics: '#' starts a comment anywhere (base64 never contains '#').
        line = raw_line.split("#", 1)[0].strip()
        if not line or line.startswith(";"):
            continue
        if line.startswith("[") and line.endswith("]"):
            name = line[1:-1].strip().lower()
            if name == "interface":
                if iface is not None:
                    raise ConfParseError(f"line {lineno}: duplicate [Interface] section")
                iface = {"addresses": [], "dns": []}
                section = "interface"
            elif name == "peer":
                peers.append({"allowed_ips": [], "line": lineno})
                section = "peer"
            else:
                warnings.append(f"line {lineno}: unknown section {line} ignored")
                section = "unknown"
            continue
        if "=" not in line:
            raise ConfParseError(f"line {lineno}: expected 'Key = Value', got {line!r}")
        key, value = (part.strip() for part in line.split("=", 1))
        if section is None:
            raise ConfParseError(f"line {lineno}: {key!r} appears before any section")
        if not value:
            raise ConfParseError(f"line {lineno}: {key} has an empty value")
        lkey = key.lower()
        if section == "interface":
            assert iface is not None
            _apply_interface(iface, key, lkey, value, lineno, warnings)
        elif section == "peer":
            _apply_peer(peers[-1], key, lkey, value, lineno, warnings)

    if iface is None:
        raise ConfParseError("missing [Interface] section")
    if "private_key" not in iface:
        raise ConfParseError("[Interface] has no PrivateKey")
    if not iface["addresses"]:
        raise ConfParseError("[Interface] has no Address")
    if not peers:
        raise ConfParseError("missing [Peer] section")

    parsed_peers: list[Peer] = []
    for peer in peers:
        where = f"[Peer] at line {peer['line']}"
        if "public_key" not in peer:
            raise ConfParseError(f"{where} has no PublicKey")
        if "endpoint" not in peer:
            raise ConfParseError(f"{where} has no Endpoint (a client tunnel needs a server address)")
        if not peer["allowed_ips"]:
            raise ConfParseError(f"{where} has no AllowedIPs")
        host, port = peer["endpoint"]
        parsed_peers.append(
            Peer(
                public_key=peer["public_key"],
                endpoint_host=host,
                endpoint_port=port,
                allowed_ips=_dedupe(peer["allowed_ips"]),
                preshared_key=peer.get("preshared_key"),
                persistent_keepalive=peer.get("keepalive"),
            )
        )
    keys = [peer.public_key for peer in parsed_peers]
    if len(set(keys)) != len(keys):
        raise ConfParseError("the same peer PublicKey appears more than once")

    config = WireGuardConfig(
        private_key=iface["private_key"],
        addresses=_dedupe(iface["addresses"]),
        peers=tuple(parsed_peers),
        dns=_dedupe(iface["dns"]),
        mtu=iface.get("mtu"),
        warnings=tuple(warnings),
    )
    if not config.ip_versions:
        raise ConfParseError(
            "no usable IP family: the Address family must also be covered by the peer's AllowedIPs"
        )
    return config
