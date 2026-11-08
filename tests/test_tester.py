from __future__ import annotations

import httpx
import pytest

from wgproxy.tester import _explain_failure, extract_ip, proxy_url


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        ("203.0.113.7\n", "203.0.113.7"),
        ('{"ip": "2001:db8::1"}', "2001:db8::1"),
        ('{"origin": "198.51.100.4"}', "198.51.100.4"),
        ("fl=123\nip=192.0.2.55\nts=1\n", "192.0.2.55"),
        ("<html>no address here</html>", None),
    ],
)
def test_extract_ip(body, expected):
    assert extract_ip(body) == expected


def test_proxy_url_escapes_credentials():
    assert proxy_url("socks5", "user", "p@ss:w/rd", "127.0.0.1", 20000) == "socks5://user:p%40ss%3Aw%2Frd@127.0.0.1:20000"
    assert proxy_url("http", "u", "p", "127.0.0.1", 1) == "http://u:p@127.0.0.1:1"


def test_proxy_url_uses_the_given_host():
    assert proxy_url("socks5", "u", "p", "203.0.113.10", 2) == "socks5://u:p@203.0.113.10:2"
    assert proxy_url("socks5", "u", "p", "vps.example.com", 3) == "socks5://u:p@vps.example.com:3"
    assert proxy_url("http", "u", "p", "2001:db8::1", 4) == "http://u:p@[2001:db8::1]:4"


def test_failures_are_explained():
    tunnel = _explain_failure(httpx.ProxyError("Proxy Server could not connect: General SOCKS server failure."))
    assert tunnel.startswith("no answer through the tunnel")
    local = _explain_failure(httpx.ConnectError("All connection attempts failed"))
    assert "local proxy port" in local
    other = _explain_failure(httpx.ProxyError("Proxy Server could not connect: Connection refused."))
    assert other.startswith("ProxyError")
