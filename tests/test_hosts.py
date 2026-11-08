"""Host resolution for exported proxy URLs and local clients."""

from __future__ import annotations

import pytest

from wgproxy.hosts import connect_host, export_host, is_wildcard, url_host


def test_public_host_comes_first():
    assert export_host("203.0.113.10", "0.0.0.0", "194.36.188.178") == "203.0.113.10"
    assert export_host("vps.example.com", "192.0.2.10", "localhost") == "vps.example.com"


def test_specific_listen_address_comes_next():
    assert export_host("", "192.0.2.10", "194.36.188.178") == "192.0.2.10"
    assert export_host("", "127.0.0.1", "localhost") == "127.0.0.1"


@pytest.mark.parametrize("listen", ["0.0.0.0", "::"])
def test_wildcard_bind_uses_the_host_the_webui_was_opened_with(listen):
    assert export_host("", listen, "194.36.188.178") == "194.36.188.178"
    assert export_host("", listen, "vps.example.com") == "vps.example.com"
    assert export_host("", listen, "2001:db8::5") == "2001:db8::5"


def test_loopback_is_the_last_resort():
    assert export_host("", "0.0.0.0", "") == "127.0.0.1"
    assert export_host("", "::", "") == "::1"
    assert export_host("", "0.0.0.0", "0.0.0.0") == "127.0.0.1"  # a wildcard Host header is ignored
    assert export_host("", "::", "::") == "::1"


@pytest.mark.parametrize("public", ["", "203.0.113.10", "0.0.0.0", "::"])
@pytest.mark.parametrize("listen", ["127.0.0.1", "0.0.0.0", "::", "192.0.2.10"])
@pytest.mark.parametrize("request_host", ["", "0.0.0.0", "::", "194.36.188.178", "localhost", "not a host!"])
def test_exports_never_use_a_wildcard_address(public, listen, request_host):
    host = export_host(public, listen, request_host)
    assert host and not is_wildcard(host)
    assert host not in {"0.0.0.0", "::"}


def test_url_and_connect_hosts():
    assert url_host("203.0.113.10") == "203.0.113.10"
    assert url_host("vps.example.com") == "vps.example.com"
    assert url_host("::1") == "[::1]"
    assert connect_host("0.0.0.0") == "127.0.0.1"
    assert connect_host("::") == "::1"
    assert connect_host("192.0.2.10") == "192.0.2.10"
