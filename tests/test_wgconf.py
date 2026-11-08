from __future__ import annotations

import pytest

from wgproxy.wgconf import ConfParseError, parse_wireguard_conf

from .conftest import make_conf, make_key

PRIV = make_key()
PUB = make_key()
PSK = make_key()


def test_parses_a_standard_config():
    text = f"""
[Interface]
PrivateKey = {PRIV}
Address = 10.64.12.34/32, fd00:abcd::2/128
DNS = 10.64.0.1, fd00:abcd::1
MTU = 1420

[Peer]
PublicKey = {PUB}
PresharedKey = {PSK}
Endpoint = 203.0.113.7:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 15
"""
    conf = parse_wireguard_conf(text)
    assert conf.private_key == PRIV
    assert conf.addresses == ("10.64.12.34/32", "fd00:abcd::2/128")
    assert conf.dns == ("10.64.0.1", "fd00:abcd::1")
    assert conf.mtu == 1420
    assert len(conf.peers) == 1
    peer = conf.peers[0]
    assert (peer.public_key, peer.preshared_key) == (PUB, PSK)
    assert (peer.endpoint_host, peer.endpoint_port) == ("203.0.113.7", 51820)
    assert peer.allowed_ips == ("0.0.0.0/0", "::/0")
    assert peer.persistent_keepalive == 15
    assert not peer.endpoint_is_domain
    assert conf.ip_versions == {4, 6}
    assert conf.warnings == ()


def test_domain_endpoint_is_normalised():
    conf = parse_wireguard_conf(make_conf(endpoint="Miami-1.SGW.guardianapp.com.:51820"))
    peer = conf.peers[0]
    assert peer.endpoint_host == "miami-1.sgw.guardianapp.com"
    assert peer.endpoint_is_domain
    assert peer.endpoint == "miami-1.sgw.guardianapp.com:51820"


def test_ipv6_endpoint_needs_brackets():
    conf = parse_wireguard_conf(make_conf(endpoint="[2001:db8::1]:51820"))
    assert conf.peers[0].endpoint_host == "2001:db8::1"
    assert conf.peers[0].endpoint == "[2001:db8::1]:51820"
    with pytest.raises(ConfParseError, match=r"\[address\]:port"):
        parse_wireguard_conf(make_conf(endpoint="2001:db8::1:51820"))


def test_comments_case_bom_and_crlf():
    text = (
        "\ufeff# provider: Example VPN\r\n"
        "[interface]\r\n"
        f"privatekey={PRIV}   # inline comment\r\n"
        "; full-line comment\r\n"
        "ADDRESS = 10.0.0.2\r\n"
        "address = 10.0.0.3/32\r\n"
        "\r\n"
        "[PEER]\r\n"
        f"publickey = {PUB}\r\n"
        "endpoint = 198.51.100.1:443\r\n"
        "allowedips = 0.0.0.0/1\r\n"
        "AllowedIPs = 128.0.0.0/1\r\n"
    )
    conf = parse_wireguard_conf(text)
    assert conf.addresses == ("10.0.0.2/32", "10.0.0.3/32")
    assert conf.peers[0].allowed_ips == ("0.0.0.0/1", "128.0.0.0/1")
    assert conf.peers[0].persistent_keepalive is None
    assert conf.mtu is None


def test_keepalive_off_and_search_domains_and_host_keys():
    text = make_conf(keepalive="off", dns="10.0.0.1, corp.example") + "\n"
    text = text.replace("[Peer]", "PostUp = iptables -A FORWARD\nTable = off\nListenPort = 51820\n\n[Peer]")
    conf = parse_wireguard_conf(text)
    assert conf.peers[0].persistent_keepalive == 0
    assert conf.dns == ("10.0.0.1",)
    joined = " ".join(conf.warnings)
    assert "search domain 'corp.example'" in joined
    assert "PostUp is a wg-quick host setting" in joined
    assert "Table is a wg-quick host setting" in joined


def test_multiple_peers():
    second = make_key()
    text = make_conf() + f"\n[Peer]\nPublicKey = {second}\nEndpoint = 198.51.100.2:51820\nAllowedIPs = 10.0.0.0/8\n"
    conf = parse_wireguard_conf(text)
    assert len(conf.peers) == 2
    assert conf.peers[1].public_key == second


def test_ipv4_only_and_ipv6_only_families():
    assert parse_wireguard_conf(make_conf()).ip_versions == {4}
    # An IPv6 address without an IPv6 route is not usable.
    assert parse_wireguard_conf(make_conf(address="10.0.0.2/32, fd00::2/128")).ip_versions == {4}
    v6 = parse_wireguard_conf(make_conf(address="fd00::2/128", dns="fd00::1", allowed_ips="::/0"))
    assert v6.ip_versions == {6}


def test_summary_does_not_leak_keys():
    conf = parse_wireguard_conf(make_conf(private_key=PRIV, preshared_key=PSK))
    summary = repr(conf.summary())
    assert PRIV not in summary
    assert PSK not in summary
    assert conf.summary()["peers"][0]["has_preshared_key"] is True


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("", "missing \\[Interface\\]"),
        (f"[Peer]\nPublicKey = {PUB}\n", "missing \\[Interface\\]"),
        (f"[Interface]\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = {PUB}\n", "no PrivateKey"),
        (f"[Interface]\nPrivateKey = {PRIV}\n[Peer]\nPublicKey = {PUB}\n", "no Address"),
        (f"[Interface]\nPrivateKey = {PRIV}\nAddress = 10.0.0.2/32\n", "missing \\[Peer\\]"),
        ("[Interface]\nPrivateKey = not-base64!\n", "not valid base64"),
        ("[Interface]\nPrivateKey = AAAA\n", "32 bytes"),
        (f"PrivateKey = {PRIV}\n", "before any section"),
        (f"[Interface]\nPrivateKey = {PRIV}\n[Interface]\n", "duplicate \\[Interface\\]"),
        (f"[Interface]\nPrivateKey = {PRIV}\nPrivateKey = {PRIV}\n", "more than once"),
        ("[Interface]\nMTU = 70000\n", "MTU must be between"),
        ("[Interface]\nAddress = 10.0.0.300/32\n", "invalid Address"),
        ("[Interface]\njust some text\n", "expected 'Key = Value'"),
    ],
)
def test_rejects_broken_interface(text, message):
    with pytest.raises(ConfParseError, match=message):
        parse_wireguard_conf(text)


@pytest.mark.parametrize(
    ("replacement", "message"),
    [
        ("Endpoint = 198.51.100.10:51820\n", "no Endpoint"),
        ("AllowedIPs = 0.0.0.0/0\n", "no AllowedIPs"),
    ],
)
def test_rejects_incomplete_peer(replacement, message):
    with pytest.raises(ConfParseError, match=message):
        parse_wireguard_conf(make_conf().replace(replacement, ""))


@pytest.mark.parametrize(
    ("endpoint", "message"),
    [
        ("198.51.100.10:0", "out of range"),
        ("198.51.100.10:http", "invalid Endpoint port"),
        ("bad host!:51820", "invalid Endpoint host"),
        ("198.51.100.10", "host:port"),
    ],
)
def test_rejects_bad_endpoints(endpoint, message):
    with pytest.raises(ConfParseError, match=message):
        parse_wireguard_conf(make_conf(endpoint=endpoint))


def test_rejects_duplicate_peers_and_unusable_family():
    text = make_conf(peer_key=PUB) + f"\n[Peer]\nPublicKey = {PUB}\nEndpoint = 198.51.100.2:1\nAllowedIPs = 10.0.0.0/8\n"
    with pytest.raises(ConfParseError, match="more than once"):
        parse_wireguard_conf(text)
    with pytest.raises(ConfParseError, match="no usable IP family"):
        parse_wireguard_conf(make_conf(allowed_ips="::/0"))
