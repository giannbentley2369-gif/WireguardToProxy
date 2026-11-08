from __future__ import annotations

import socket

import pytest

from wgproxy.ports import (
    NoFreePortError,
    PortAllocator,
    PortValidationError,
    assign_shards,
    is_port_free,
    port_probe,
    repair_ports,
    reserved_ports,
)


def probe_except(*busy: int):
    blocked = set(busy)
    return lambda port: port not in blocked


def test_allocates_lowest_free_port_skipping_taken_reserved_and_busy():
    allocator = PortAllocator(20000, 20010, reserved={20001}, probe=probe_except(20002))
    assert allocator.allocate(taken=set()) == 20000
    assert allocator.allocate(taken={20000}) == 20003
    assert allocator.allocate(taken={20000, 20003}) == 20004


def test_exhausted_range_raises():
    allocator = PortAllocator(20000, 20002, probe=probe_except(20001))
    with pytest.raises(NoFreePortError):
        allocator.allocate(taken={20000, 20002})


def test_invalid_range_is_rejected():
    with pytest.raises(ValueError):
        PortAllocator(30000, 20000)
    with pytest.raises(ValueError):
        PortAllocator(80, 2000)


def test_validate_override():
    allocator = PortAllocator(20000, 20999, reserved={8080}, probe=probe_except(21000))
    allocator.validate_override(25000, taken={20000})
    with pytest.raises(PortValidationError, match="between"):
        allocator.validate_override(80, taken=set())
    with pytest.raises(PortValidationError, match="reserved"):
        allocator.validate_override(8080, taken=set())
    with pytest.raises(PortValidationError, match="another proxy"):
        allocator.validate_override(20000, taken={20000})
    with pytest.raises(PortValidationError, match="another program"):
        allocator.validate_override(21000, taken=set())
    # A proxy's own (running) port is never reported as busy.
    allocator.validate_override(21000, taken=set(), current=21000)


def test_repair_moves_only_unavailable_ports():
    assigned = {1: 20000, 2: 20001, 3: 20002}
    allocator = PortAllocator(20000, 20010, probe=probe_except(20001))
    moves = repair_ports(assigned, allocator, taken={20003})
    assert moves == {2: 20004}


def test_repair_keeps_ports_stable_when_everything_is_free():
    allocator = PortAllocator(20000, 20010, probe=lambda port: True)
    assert repair_ports({1: 20005, 2: 20000}, allocator) == {}


def test_repair_gives_each_moved_proxy_a_distinct_port():
    allocator = PortAllocator(20000, 20010, probe=probe_except(20000, 20001))
    moves = repair_ports({1: 20000, 2: 20001, 3: 20002}, allocator)
    assert set(moves) == {1, 2}
    assert len(set(moves.values())) == 2
    assert not set(moves.values()) & {20000, 20001, 20002}


def test_repair_moves_proxies_sitting_on_reserved_ports():
    allocator = PortAllocator(20000, 20010, reserved={20000}, probe=lambda port: True)
    assert repair_ports({7: 20000}, allocator) == {7: 20001}


def test_repair_raises_when_no_port_is_left():
    allocator = PortAllocator(20000, 20001, probe=probe_except(20000))
    with pytest.raises(NoFreePortError):
        repair_ports({1: 20000, 2: 20001}, allocator)


def test_is_port_free_detects_listeners():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        sock.listen()
        port = sock.getsockname()[1]
        assert is_port_free(port) is False
        # A wildcard bind would collide with the loopback listener as well.
        assert is_port_free(port, "0.0.0.0") is False
        assert port_probe("0.0.0.0")(port) is False
    assert is_port_free(port) is True
    assert port_probe("0.0.0.0")(port) is True


def test_is_port_free_supports_ipv6_hosts():
    try:
        sock = socket.socket(socket.AF_INET6)
        sock.bind(("::1", 0))
    except OSError:
        pytest.skip("IPv6 loopback is not available")
    with sock:
        sock.listen()
        port = sock.getsockname()[1]
        assert is_port_free(port, "::1") is False
    assert is_port_free(port, "::1") is True


def test_reserved_ports_include_loopback_upstream_only():
    assert reserved_ports(8080, "127.0.0.1", 2080) == {8080, 2080}
    assert reserved_ports(8080, "localhost", 2080) == {8080, 2080}
    assert reserved_ports(8080, "", 2080) == {8080}
    assert reserved_ports(8080, "192.168.1.5", 2080) == {8080}


def test_assign_shards_packs_new_proxies():
    assert assign_shards([(1, None), (2, None), (3, None)], 2) == {1: 0, 2: 0, 3: 1}


def test_assign_shards_keeps_existing_assignments():
    # Proxy 2 was disabled: the others stay where they are, so only shard 0 restarts.
    assert assign_shards([(1, 0), (3, 1), (4, 1)], 2) == {1: 0, 3: 1, 4: 1}
    # A new proxy fills the free slot instead of shifting everybody.
    assert assign_shards([(1, 0), (3, 1), (4, 1), (5, None)], 2) == {1: 0, 3: 1, 4: 1, 5: 0}


def test_assign_shards_moves_only_overflow():
    result = assign_shards([(1, 0), (2, 0), (3, 0)], 2)
    assert result == {1: 0, 2: 0, 3: 1}


def test_assign_shards_validates_size():
    with pytest.raises(ValueError):
        assign_shards([(1, None)], 0)
