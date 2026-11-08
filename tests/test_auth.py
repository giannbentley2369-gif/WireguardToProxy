"""WebUI login: environment credentials, sessions, CSRF checks and rate limiting."""

from __future__ import annotations

import asyncio
import base64
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from wgproxy.db import Database
from wgproxy.security import Auth, LoginRateLimiter, LoginThrottled, client_key
from wgproxy.settings import SettingsStore

from .conftest import HEADERS

USER, PASSWORD = "admin", "correct horse battery"


def basic(username: str, password: str) -> dict[str, str]:
    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    return {"Authorization": f"Basic {token}"}


def login(client: TestClient, username: str = USER, password: str = PASSWORD, **kwargs):
    return client.post("/api/auth/login", json={"username": username, "password": password}, **kwargs)


def no_global_slowdown(client: TestClient) -> TestClient:
    # The install-wide slow-down after repeated failures would only make these tests slow.
    client.app.state.services.auth.failure_delay = lambda: 0.0
    return client


@pytest.fixture
def env_client(make_client) -> TestClient:
    return no_global_slowdown(make_client(webui_username=USER, webui_password=PASSWORD))


# -- enabled / disabled ----------------------------------------------------------------------


def test_without_a_password_nothing_asks_for_a_login(make_client):
    client = make_client()
    assert client.get("/api/status").json()["auth_enabled"] is False
    assert client.get("/", follow_redirects=False).status_code == 200
    assert client.get("/login", follow_redirects=False).headers["location"] == "/"
    assert client.post("/api/engine/restart").status_code == 200


def test_every_page_and_api_endpoint_requires_the_login(env_client):
    for path in ("/", "/add", "/logs", "/settings"):
        page = env_client.get(path, follow_redirects=False)
        assert page.status_code == 303 and page.headers["location"].startswith("/login?next="), path
    for path in ("/api/status", "/api/proxies", "/api/export", "/api/settings", "/api/logs", "/api/backup.zip"):
        assert env_client.get(path).status_code == 401, path
    assert env_client.post("/api/engine/restart").status_code == 401
    assert env_client.put("/api/settings", json={"test_concurrency": 5}).status_code == 401
    # Public: the login page, static assets and the container healthcheck.
    page = env_client.get("/login")
    assert page.status_code == 200 and 'id="login-username"' in page.text
    assert env_client.get("/static/app.css").status_code == 200
    assert env_client.get("/static/login.js").status_code == 200
    assert env_client.get("/healthz").status_code == 200


def test_login_with_the_environment_credentials(env_client):
    assert login(env_client, username="root").status_code == 401
    assert login(env_client, password="wrong password").status_code == 401
    assert env_client.post("/api/auth/login", json={"password": PASSWORD}).status_code == 401  # user name needed
    response = login(env_client)
    assert response.status_code == 200
    cookie = response.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie
    assert env_client.get("/api/status").json()["auth_enabled"] is True
    settings = env_client.get("/api/settings").json()
    assert settings["ui_password_env"] is True and settings["webui_username"] == USER
    # The Settings-page password cannot replace the environment login.
    assert env_client.post("/api/settings/ui-password", json={"password": "another password"}).status_code == 409
    assert env_client.post("/api/auth/logout").status_code == 200
    assert env_client.get("/api/status").status_code == 401


def test_http_basic_auth_needs_the_user_name_too(env_client):
    assert env_client.get("/api/export", headers=basic(USER, PASSWORD)).status_code == 200
    assert env_client.get("/api/export", headers=basic("someone", PASSWORD)).status_code == 401
    assert env_client.get("/api/export", headers=basic(USER, "nope")).status_code == 401


def test_environment_login_overrides_the_settings_page_password(make_client):
    local = make_client()
    assert local.post("/api/settings/ui-password", json={"password": "settings page pw"}).status_code == 200
    client = no_global_slowdown(make_client(webui_username=USER, webui_password=PASSWORD))
    assert login(client, password="settings page pw").status_code == 401
    assert login(client).status_code == 200


def test_settings_page_password_still_works_without_a_user_name(make_client):
    client = make_client()
    assert client.post("/api/settings/ui-password", json={"password": PASSWORD}).status_code == 200
    client.cookies.clear()
    assert 'id="login-username"' not in client.get("/login").text
    assert client.post("/api/auth/login", json={"password": PASSWORD}).status_code == 200
    client.cookies.clear()
    assert client.get("/api/status", headers=basic("any-name", PASSWORD)).status_code == 200


# -- sessions -------------------------------------------------------------------------------


def session_header(client: TestClient) -> dict[str, str]:
    return {"Cookie": f"wgproxy_session={client.cookies['wgproxy_session']}"}


def test_tampered_session_cookie_is_rejected(env_client):
    assert login(env_client).status_code == 200
    payload, signature = env_client.cookies["wgproxy_session"].rsplit(".", 1)
    env_client.cookies.clear()
    forged = {"Cookie": f"wgproxy_session={payload}.{'0' * len(signature)}"}
    assert env_client.get("/api/status", headers=forged).status_code == 401


def test_sessions_survive_restarts_until_the_login_changes(make_client):
    first = make_client(webui_username=USER, webui_password=PASSWORD)
    assert login(first).status_code == 200
    cookie = session_header(first)
    restarted = make_client(webui_username=USER, webui_password=PASSWORD)  # same data directory
    assert restarted.get("/api/status", headers=cookie).status_code == 200
    new_password = make_client(webui_username=USER, webui_password="a different password")
    assert new_password.get("/api/status", headers=cookie).status_code == 401
    renamed = make_client(webui_username="alice", webui_password=PASSWORD)
    assert renamed.get("/api/status", headers=cookie).status_code == 401


# -- CSRF -----------------------------------------------------------------------------------


def test_csrf_checks_apply_to_logged_in_sessions(env_client):
    assert login(env_client).status_code == 200
    # Cross-site pages cannot add the custom header (no CORS preflight is ever granted) ...
    assert env_client.post("/api/engine/restart", headers={"X-Requested-With": ""}).status_code == 403
    assert env_client.put("/api/settings", json={"test_concurrency": 5}, headers={"X-Requested-With": ""}).status_code == 403
    assert env_client.post("/api/auth/logout", headers={"X-Requested-With": ""}).status_code == 403
    # ... and a foreign Origin is refused even with it.
    assert env_client.post("/api/engine/restart", headers={"Origin": "http://evil.example"}).status_code == 403
    assert env_client.post("/api/engine/restart", headers={"Origin": "http://127.0.0.1:18080"}).status_code == 200


def test_login_form_has_csrf_protection_too(env_client):
    assert login(env_client, headers={"X-Requested-With": ""}).status_code == 403
    assert login(env_client, headers={"Origin": "http://evil.example"}).status_code == 403
    assert "wgproxy_session" not in env_client.cookies


# -- rate limiting --------------------------------------------------------------------------


def test_failed_logins_are_limited_per_client(env_client):
    for _ in range(5):
        assert login(env_client, password="wrong").status_code == 401
    blocked = login(env_client)  # even the right password waits
    assert blocked.status_code == 429
    assert 1 <= int(blocked.headers["retry-after"]) <= 60
    assert "Too many failed login attempts" in blocked.json()["detail"]
    # HTTP Basic auth shares the limit, so it cannot be used to keep guessing.
    assert env_client.get("/api/status", headers=basic(USER, PASSWORD)).status_code == 429
    # Other client addresses are not affected.
    other = TestClient(env_client.app, base_url="http://127.0.0.1:18080", headers=HEADERS, client=("198.51.100.7", 40000))
    assert login(other).status_code == 200


def test_basic_auth_failures_count_toward_the_limit(env_client):
    for _ in range(5):
        assert env_client.get("/api/status", headers=basic(USER, "wrong")).status_code == 401
    assert login(env_client).status_code == 429


def test_successful_logins_do_not_count(env_client):
    for _ in range(8):
        assert login(env_client).status_code == 200


async def test_concurrent_guesses_cannot_overshoot_the_limit(tmp_path: Path):
    db = Database(tmp_path / "wgproxy.db")
    try:
        auth = Auth(SettingsStore(db), b"k" * 32, username=USER, env_password=PASSWORD)
        auth.failure_delay = lambda: 0.0
        results = await asyncio.gather(
            *(auth.login("203.0.113.5", USER, f"guess {index}") for index in range(20)), return_exceptions=True
        )
    finally:
        db.close()
    assert sum(result is False for result in results) == 5
    assert sum(isinstance(result, LoginThrottled) for result in results) == 15


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def test_rate_limiter_uses_a_sliding_window_per_client():
    clock = FakeClock()
    limiter = LoginRateLimiter(limit=5, window=60, clock=clock)
    for _ in range(5):
        assert limiter.acquire("203.0.113.1") is not None
        clock.now += 1
    assert limiter.acquire("203.0.113.1") is None
    assert limiter.retry_after("203.0.113.1") == 55  # the first failure (t=1000) expires at t=1060
    assert limiter.acquire("203.0.113.2") is not None
    clock.now = 1060.5
    assert limiter.retry_after("203.0.113.1") == 0
    assert limiter.acquire("203.0.113.1") is not None  # exactly one slot came free
    assert limiter.acquire("203.0.113.1") is None


def test_rate_limiter_forgets_successes_and_bounds_memory():
    limiter = LoginRateLimiter(limit=2, window=60, clock=FakeClock(), max_clients=3)
    for _ in range(5):
        token = limiter.acquire("good")
        assert token is not None
        limiter.release("good", token)
    assert limiter.retry_after("good") == 0
    for index in range(10):
        limiter.acquire(f"client-{index}")
    assert len(limiter._attempts) <= 3


def test_client_key_groups_ipv6_clients_by_64():
    assert client_key("203.0.113.9") == "203.0.113.9"
    assert client_key("::ffff:203.0.113.9") == "203.0.113.9"
    assert client_key("2001:db8:1:2::1") == client_key("2001:db8:1:2:ffff::9") == "2001:db8:1:2::/64"
    assert client_key(None) == "unknown"
