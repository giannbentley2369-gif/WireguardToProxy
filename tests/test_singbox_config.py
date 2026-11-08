from __future__ import annotations

from typing import Any

import pytest

from wgproxy.singbox import (
    BOOTSTRAP_DNS_TAG,
    DIRECT_TAG,
    UPSTREAM_TAG,
    EngineSettings,
    Tunnel,
    UpstreamProxy,
    build_config,
    config_hash,
    dns_tag,
    endpoint_tag,
    inbound_tag,
    tag_to_name,
)
from wgproxy.wgconf import parse_wireguard_conf

from .conftest import make_conf

UPSTREAM = UpstreamProxy("127.0.0.1", 2080)


def settings(upstream: UpstreamProxy | None = UPSTREAM, **overrides: Any) -> EngineSettings:
    values: dict[str, Any] = {"upstream": upstream, "proxy_username": "user", "proxy_password": "secret"}
    values.update(overrides)
    return EngineSettings(**values)


def tunnel(name: str, port: int, **conf_kwargs: Any) -> Tunnel:
    return Tunnel(name, port, parse_wireguard_conf(make_conf(**conf_kwargs)))


@pytest.fixture
def tunnels() -> list[Tunnel]:
    return [
        tunnel("US-miami-1", 20000, endpoint="miami-1.sgw.guardianapp.com:51820"),
        tunnel("DE-berlin", 20001, endpoint="198.51.100.20:51820", dns=None),
        tunnel(
            "dual",
            20002,
            address="10.9.0.2/32, fd00::2/128",
            allowed_ips="0.0.0.0/0, ::/0",
            dns="fd00::1, 10.9.0.1",
        ),
    ]


def _by_tag(items: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {item["tag"]: item for item in items}


def _walk(value: Any):
    if isinstance(value, dict):
        for key, item in value.items():
            yield key, item
            yield from _walk(item)
    elif isinstance(value, list):
        for item in value:
            yield from _walk(item)


def test_upstream_detour_on_every_endpoint_and_bootstrap_dns(tunnels):
    config = build_config(tunnels, settings(UpstreamProxy("127.0.0.1", 2080, "u", "p")))
    assert config["outbounds"] == [
        {
            "type": "socks",
            "tag": UPSTREAM_TAG,
            "server": "127.0.0.1",
            "server_port": 2080,
            "version": "5",
            "username": "u",
            "password": "p",
        }
    ]
    for endpoint in config["endpoints"]:
        assert endpoint["detour"] == UPSTREAM_TAG
        assert endpoint["domain_resolver"] == {"server": BOOTSTRAP_DNS_TAG, "strategy": "ipv4_only"}
        assert endpoint["system"] is False
        assert endpoint["workers"] == 1
        assert "listen_port" not in endpoint  # would conflict with detour and open a UDP listener
    bootstrap = config["dns"]["servers"][0]
    assert bootstrap["tag"] == BOOTSTRAP_DNS_TAG
    assert bootstrap["detour"] == UPSTREAM_TAG
    assert bootstrap["server"] == "1.1.1.1"
    assert config["dns"]["final"] == BOOTSTRAP_DNS_TAG
    assert config["route"]["default_domain_resolver"]["server"] == BOOTSTRAP_DNS_TAG


def test_direct_mode_uses_explicit_direct_detour(tunnels):
    config = build_config(tunnels, settings(upstream=None))
    assert [outbound["type"] for outbound in config["outbounds"]] == ["direct"]
    direct = config["outbounds"][0]
    assert direct["tag"] == DIRECT_TAG
    # sing-box refuses detours to an "empty" direct outbound; one dial field must be set.
    assert set(direct) - {"type", "tag"}
    assert all(endpoint["detour"] == DIRECT_TAG for endpoint in config["endpoints"])
    assert "detour" not in config["dns"]["servers"][0]
    assert not any(value == UPSTREAM_TAG for _, value in _walk(config))


def test_upstream_without_credentials_omits_auth(tunnels):
    outbound = build_config(tunnels, settings())["outbounds"][0]
    assert "username" not in outbound and "password" not in outbound


def test_each_inbound_is_bound_to_its_own_endpoint(tunnels):
    config = build_config(tunnels, settings())
    rules = config["route"]["rules"]
    route_rules = [rule for rule in rules if rule.get("action") == "route"]
    assert len(route_rules) == len(tunnels)
    for item in tunnels:
        matching = [rule for rule in route_rules if rule["inbound"] == [inbound_tag(item.name)]]
        assert len(matching) == 1
        assert matching[0]["outbound"] == endpoint_tag(item.name)
    # Nothing is ever routed to the upstream/direct outbound or left to a default route.
    assert all(rule["outbound"].startswith("wg-") for rule in route_rules)
    assert rules[-1] == {"action": "reject"}
    last_route = max(index for index, rule in enumerate(rules) if rule.get("action") == "route")
    assert last_route == len(rules) - 2


def test_destination_dns_goes_through_the_tunnel(tunnels):
    config = build_config(tunnels, settings())
    servers = _by_tag(config["dns"]["servers"])
    resolve_rules = [rule for rule in config["route"]["rules"] if rule.get("action") == "resolve"]
    assert len(resolve_rules) == len(tunnels)
    first_route = next(i for i, rule in enumerate(config["route"]["rules"]) if rule.get("action") == "route")
    for item in tunnels:
        rule = next(rule for rule in resolve_rules if rule["inbound"] == [inbound_tag(item.name)])
        assert config["route"]["rules"].index(rule) < first_route
        server = servers[rule["server"]]
        assert server["tag"] == dns_tag(item.name)
        assert server["detour"] == endpoint_tag(item.name)
    assert servers[dns_tag("US-miami-1")]["server"] == "10.64.0.1"  # DNS from the .conf
    assert servers[dns_tag("DE-berlin")]["server"] == "1.1.1.1"  # fallback when the .conf has none
    assert servers[dns_tag("dual")]["server"] == "fd00::1"


def test_ipv6_rejected_unless_the_tunnel_provides_it(tunnels):
    config = build_config(tunnels, settings())
    rules = config["route"]["rules"]
    v6_reject = [rule for rule in rules if rule.get("ip_version") == 6]
    assert len(v6_reject) == 1
    assert v6_reject[0]["action"] == "reject"
    assert set(v6_reject[0]["inbound"]) == {inbound_tag("US-miami-1"), inbound_tag("DE-berlin")}
    assert not [rule for rule in rules if rule.get("ip_version") == 4]
    strategies = {rule["inbound"][0]: rule["strategy"] for rule in rules if rule.get("action") == "resolve"}
    assert strategies[inbound_tag("US-miami-1")] == "ipv4_only"
    assert strategies[inbound_tag("dual")] == "prefer_ipv4"
    first_route = next(i for i, rule in enumerate(rules) if rule.get("action") == "route")
    assert rules.index(v6_reject[0]) < first_route


def test_ipv6_only_tunnel_rejects_ipv4():
    item = tunnel("v6", 20010, address="fd00::2/128", allowed_ips="::/0", dns="fd00::1")
    rules = build_config([item], settings())["route"]["rules"]
    assert {"inbound": [inbound_tag("v6")], "ip_version": 4, "action": "reject"} in rules
    assert next(rule for rule in rules if rule.get("action") == "resolve")["strategy"] == "ipv6_only"


def test_inbounds_are_authenticated_loopback_mixed_listeners(tunnels):
    config = build_config(tunnels, settings())
    inbounds = _by_tag(config["inbounds"])
    for item in tunnels:
        inbound = inbounds[inbound_tag(item.name)]
        assert inbound["type"] == "mixed"
        assert inbound["listen"] == "127.0.0.1"
        assert inbound["listen_port"] == item.port
        assert inbound["users"] == [{"username": "user", "password": "secret"}]
    listen_values = [value for key, value in _walk(config) if key == "listen"]
    assert listen_values and set(listen_values) == {"127.0.0.1"}


def test_mtu_and_keepalive_defaults():
    items = [
        tunnel("plain", 1),
        tunnel("big-mtu", 2, mtu=1420, keepalive="15"),
        tunnel("small-mtu", 3, mtu=1200, keepalive="0"),
    ]
    endpoints = _by_tag(build_config(items, settings())["endpoints"])
    assert endpoints["wg-plain"]["mtu"] == 1280
    assert endpoints["wg-plain"]["peers"][0]["persistent_keepalive_interval"] == 25
    assert endpoints["wg-big-mtu"]["mtu"] == 1280  # the default is a ceiling
    assert endpoints["wg-big-mtu"]["peers"][0]["persistent_keepalive_interval"] == 15
    assert endpoints["wg-small-mtu"]["mtu"] == 1200
    assert "persistent_keepalive_interval" not in endpoints["wg-small-mtu"]["peers"][0]


def test_peer_fields_are_mapped():
    conf_tunnel = tunnel("psk", 4, endpoint="vpn.example.com:443", preshared_key="A" * 43 + "=")
    peer = build_config([conf_tunnel], settings())["endpoints"][0]["peers"][0]
    source = conf_tunnel.conf.peers[0]
    assert peer == {
        "address": "vpn.example.com",
        "port": 443,
        "public_key": source.public_key,
        "pre_shared_key": source.preshared_key,
        "allowed_ips": ["0.0.0.0/0"],
        "persistent_keepalive_interval": 25,
    }


def test_settings_are_applied(tunnels):
    config = build_config(
        tunnels,
        settings(bootstrap_dns="9.9.9.9", bootstrap_dns_protocol="tcp", tunnel_dns_fallback="8.8.8.8", log_level="info"),
    )
    assert config["log"] == {"level": "info", "timestamp": True}
    bootstrap = config["dns"]["servers"][0]
    assert (bootstrap["type"], bootstrap["server"]) == ("tcp", "9.9.9.9")
    assert _by_tag(config["dns"]["servers"])[dns_tag("DE-berlin")]["server"] == "8.8.8.8"


def test_tags_are_unique_and_reversible(tunnels):
    config = build_config(tunnels, settings())
    tags = [item["tag"] for section in ("endpoints", "inbounds", "outbounds") for item in config[section]]
    tags += [server["tag"] for server in config["dns"]["servers"]]
    assert len(tags) == len(set(tags))
    for item in tunnels:
        for tag in (endpoint_tag(item.name), inbound_tag(item.name), dns_tag(item.name)):
            assert tag_to_name(tag) == item.name
    assert tag_to_name(UPSTREAM_TAG) is None
    assert tag_to_name(BOOTSTRAP_DNS_TAG) is None


def test_rejects_duplicate_names_or_ports():
    with pytest.raises(ValueError, match="names"):
        build_config([tunnel("a", 1), tunnel("a", 2)], settings())
    with pytest.raises(ValueError, match="ports"):
        build_config([tunnel("a", 1), tunnel("b", 1)], settings())


def test_config_hash_is_stable_and_content_sensitive(tunnels):
    first = build_config(tunnels, settings())
    assert config_hash(first) == config_hash(build_config(tunnels, settings()))
    assert config_hash(first) != config_hash(build_config(tunnels, settings(upstream=None)))
