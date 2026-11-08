"""Environment configuration: parsing and validation of the WGPROXY_* variables."""

from __future__ import annotations

import pytest

from wgproxy.__main__ import healthcheck_url
from wgproxy.__main__ import main as cli_main
from wgproxy.config import AppConfig, ConfigError


def config(**env: str) -> AppConfig:
    return AppConfig.from_env({"WGPROXY_DATA_DIR": "/tmp/wgproxy-config-test", **env})


def test_defaults_keep_everything_on_loopback():
    cfg = config()
    assert cfg.listen_host == cfg.connect_host == "127.0.0.1"
    assert cfg.public_host == ""
    assert cfg.webui_username == "admin"
    assert cfg.webui_password == ""
    assert cfg.allowed_hosts == {"127.0.0.1", "localhost", "::1"}


@pytest.mark.parametrize(
    ("raw", "listen", "connect"),
    [
        ("0.0.0.0", "0.0.0.0", "127.0.0.1"),
        ("::", "::", "::1"),
        (" 192.0.2.10 ", "192.0.2.10", "192.0.2.10"),
        ("0:0:0:0:0:0:0:1", "::1", "::1"),
        ("", "127.0.0.1", "127.0.0.1"),
    ],
)
def test_listen_host_is_parsed_and_normalized(raw, listen, connect):
    cfg = config(WGPROXY_LISTEN_HOST=raw)
    assert cfg.listen_host == listen
    assert cfg.connect_host == connect


@pytest.mark.parametrize(
    "raw", ["localhost", "vps.example.com", "1.2.3", "256.1.1.1", "0.0.0.0:8080", "[::1]", "fe80::1%eth0"]
)
def test_listen_host_must_be_an_ip_address(raw):
    with pytest.raises(ConfigError, match="WGPROXY_LISTEN_HOST must"):
        config(WGPROXY_LISTEN_HOST=raw)


def test_specific_listen_address_is_an_allowed_host():
    assert "192.0.2.10" in config(WGPROXY_LISTEN_HOST="192.0.2.10").allowed_hosts
    assert config(WGPROXY_LISTEN_HOST="0.0.0.0").allowed_hosts == {"127.0.0.1", "localhost", "::1"}


def test_allowed_hosts_extend_the_defaults():
    cfg = config(WGPROXY_ALLOWED_HOSTS="194.36.188.178, VPS.Example.com ,,localhost,127.0.0.1")
    assert cfg.allowed_hosts == {"127.0.0.1", "localhost", "::1", "194.36.188.178", "vps.example.com"}


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("", ""),
        ("  ", ""),
        ("203.0.113.10", "203.0.113.10"),
        (" VPS.Example.com ", "vps.example.com"),
        ("[2001:db8::1]", "2001:db8::1"),
        ("2001:DB8::1", "2001:db8::1"),
    ],
)
def test_public_host_is_parsed(raw, expected):
    assert config(WGPROXY_PUBLIC_HOST=raw).public_host == expected


@pytest.mark.parametrize(
    "raw",
    [
        "0.0.0.0",
        "::",
        "[::]",
        "http://203.0.113.10",
        "203.0.113.10:8080",
        "bad host",
        "a/b",
        "fe80::1%eth0",
        "256.1.1.1",
        "194.36.188.1788",
        "1.2.3",
    ],
)
def test_public_host_rejects_wildcards_urls_ports_and_mistyped_ips(raw):
    with pytest.raises(ConfigError, match="WGPROXY_PUBLIC_HOST must"):
        config(WGPROXY_PUBLIC_HOST=raw)


def test_webui_login_variables():
    cfg = config(WGPROXY_WEBUI_USERNAME=" alice ", WGPROXY_WEBUI_PASSWORD="correct horse")
    assert (cfg.webui_username, cfg.webui_password) == ("alice", "correct horse")
    assert "correct horse" not in repr(cfg)
    assert config(WGPROXY_WEBUI_USERNAME="").webui_username == "admin"


@pytest.mark.parametrize("raw", ["a:b", "two words", "x" * 65])
def test_webui_username_is_validated(raw):
    with pytest.raises(ConfigError, match="WGPROXY_WEBUI_USERNAME"):
        config(WGPROXY_WEBUI_USERNAME=raw)


@pytest.mark.parametrize("raw", ["short", "x" * 257])
def test_webui_password_length_is_validated(raw):
    with pytest.raises(ConfigError, match="WGPROXY_WEBUI_PASSWORD"):
        config(WGPROXY_WEBUI_PASSWORD=raw)


@pytest.mark.parametrize(
    ("listen", "url"),
    [
        ("127.0.0.1", "http://127.0.0.1:8080/healthz"),
        ("0.0.0.0", "http://127.0.0.1:8080/healthz"),
        ("::", "http://[::1]:8080/healthz"),
        ("192.0.2.10", "http://192.0.2.10:8080/healthz"),
    ],
)
def test_healthcheck_targets_the_configured_host(listen, url):
    assert healthcheck_url(config(WGPROXY_LISTEN_HOST=listen)) == url


def test_healthcheck_command_reads_the_listen_host(monkeypatch):
    seen: list[str] = []

    class Answer:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return None

    def fake_urlopen(url, timeout):
        seen.append(url)
        return Answer()

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    monkeypatch.setenv("WGPROXY_LISTEN_HOST", "192.0.2.10")
    monkeypatch.setenv("WGPROXY_WEBUI_PORT", "18081")
    assert cli_main(["healthcheck"]) == 0
    assert seen == ["http://192.0.2.10:18081/healthz"]


def test_invalid_configuration_is_reported_without_a_traceback(monkeypatch, capsys):
    monkeypatch.setenv("WGPROXY_LISTEN_HOST", "localhost")
    assert cli_main(["healthcheck"]) == 2
    assert "configuration error: WGPROXY_LISTEN_HOST must be an IP address" in capsys.readouterr().err
