"""Port allocation for proxy listeners and assignment of tunnels to engine shards."""

from __future__ import annotations

import functools
import socket
from collections.abc import Callable, Iterable, Mapping, Sequence

from .config import DEFAULT_LISTEN_HOST

MIN_PORT = 1024
MAX_PORT = 65535

PortProbe = Callable[[int], bool]


class NoFreePortError(RuntimeError):
    pass


class PortValidationError(ValueError):
    pass


def is_port_free(port: int, host: str = DEFAULT_LISTEN_HOST) -> bool:
    """True when a TCP listener could bind ``host:port`` right now.

    SO_REUSEADDR mirrors Go's ``net.Listen`` (used by sing-box), so sockets lingering in
    TIME_WAIT are not mistaken for a port that is in use.
    """
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((host, port))
    except OSError:
        return False
    return True


def port_probe(host: str) -> PortProbe:
    """Probe checking ports on the address the proxy listeners bind."""
    return functools.partial(is_port_free, host=host)


class PortAllocator:
    """Hands out the lowest free port of a range, skipping reserved and taken ports."""

    def __init__(self, start: int, end: int, reserved: Iterable[int] = (), probe: PortProbe = is_port_free):
        if not MIN_PORT <= start <= end <= MAX_PORT:
            raise ValueError(f"invalid port range {start}-{end}")
        self.start = start
        self.end = end
        self.reserved = frozenset(reserved)
        self.probe = probe

    def allocate(self, taken: Iterable[int]) -> int:
        blocked = set(taken) | self.reserved
        for port in range(self.start, self.end + 1):
            if port not in blocked and self.probe(port):
                return port
        raise NoFreePortError(f"no free port left in the range {self.start}-{self.end}")

    def validate_override(self, port: int, taken: Iterable[int], *, current: int | None = None) -> None:
        """Check a user-chosen port. ``taken`` must not include the proxy's own port."""
        if not MIN_PORT <= port <= MAX_PORT:
            raise PortValidationError(f"port must be between {MIN_PORT} and {MAX_PORT}")
        if port in self.reserved:
            raise PortValidationError(f"port {port} is reserved (WebUI or upstream proxy)")
        if port in set(taken):
            raise PortValidationError(f"port {port} is already assigned to another proxy")
        if port != current and not self.probe(port):
            raise PortValidationError(f"port {port} is in use by another program")


def repair_ports(assigned: Mapping[int, int], allocator: PortAllocator, taken: Iterable[int] = ()) -> dict[int, int]:
    """Return ``{proxy_id: new_port}`` for every proxy whose port cannot be bound.

    Only unavailable ports move; every other proxy keeps its assignment.
    """
    blocked = set(taken) | set(assigned.values())
    moves: dict[int, int] = {}
    for proxy_id, port in sorted(assigned.items()):
        if port not in allocator.reserved and allocator.probe(port):
            continue
        new_port = allocator.allocate(blocked)
        blocked.add(new_port)
        moves[proxy_id] = new_port
    return moves


def assign_shards(members: Sequence[tuple[int, int | None]], shard_size: int) -> dict[int, int]:
    """Assign active proxies to shards of at most ``shard_size`` members.

    ``members`` holds ``(proxy_id, current_shard)`` for every active proxy. Existing
    assignments are kept while their shard has room, so enabling or disabling a proxy only
    restarts the one shard it belongs to.
    """
    if shard_size < 1:
        raise ValueError("shard_size must be at least 1")
    result: dict[int, int] = {}
    counts: dict[int, int] = {}
    pending: list[int] = []
    for proxy_id, shard in sorted(members, key=lambda item: item[0]):
        if shard is not None and shard >= 0 and counts.get(shard, 0) < shard_size:
            result[proxy_id] = shard
            counts[shard] = counts.get(shard, 0) + 1
        else:
            pending.append(proxy_id)
    for proxy_id in pending:
        shard = 0
        while counts.get(shard, 0) >= shard_size:
            shard += 1
        result[proxy_id] = shard
        counts[shard] = counts.get(shard, 0) + 1
    return result


def reserved_ports(webui_port: int, upstream_host: str, upstream_port: int) -> frozenset[int]:
    """Ports that must never be handed to a proxy listener."""
    ports = {webui_port}
    if upstream_host in {"127.0.0.1", "localhost", "::1"} or upstream_host.startswith("127."):
        ports.add(upstream_port)
    return frozenset(ports)
