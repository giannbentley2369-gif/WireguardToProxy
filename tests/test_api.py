from __future__ import annotations

import base64
import io
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from wgproxy.__main__ import main as cli_main

from .conftest import LOOPBACK_HOSTS, free_port_range, make_conf, make_key


def use_free_ports(client: TestClient) -> int:
    base = free_port_range()
    response = client.put("/api/settings", json={"port_range_start": base, "port_range_end": base + 50})
    assert response.status_code == 200, response.text
    return base


@pytest.fixture
def client(make_client):
    test_client = make_client()
    test_client.base_port = use_free_ports(test_client)  # type: ignore[attr-defined]
    return test_client


def paste(client: TestClient, name: str, text: str | None = None, enable: bool = True) -> dict:
    response = client.post("/api/proxies/paste", json={"name": name, "text": text or make_conf(), "enable": enable})
    assert response.status_code == 200, response.text
    return response.json()["results"][0]


def test_healthz_and_pages(client: TestClient):
    assert client.get("/healthz").json()["status"] == "ok"
    for path, marker in [("/", "proxy-rows"), ("/add", "drop-zone"), ("/logs", "log-view"), ("/settings", "settings-form")]:
        response = client.get(path)
        assert response.status_code == 200
        assert marker in response.text
        assert "default-src 'self'" in response.headers["content-security-policy"]
    assert client.get("/static/dashboard.js").status_code == 200


def test_host_header_and_csrf_protection(client: TestClient):
    assert client.get("/api/status", headers={"Host": "evil.example:8080"}).status_code == 400
    assert client.get("/api/status", headers={"Host": "localhost:8080"}).status_code == 200
    response = client.post("/api/engine/restart", headers={"X-Requested-With": ""})
    assert response.status_code == 403
    response = client.post("/api/engine/restart", headers={"Origin": "http://evil.example"})
    assert response.status_code == 403
    assert client.post("/api/engine/restart").status_code == 200


def test_paste_list_patch_export_delete(client: TestClient):
    base = client.base_port  # type: ignore[attr-defined]
    first = paste(client, "US-miami-1", make_conf(endpoint="miami-1.sgw.guardianapp.com:51820"))
    second = paste(client, "DE berlin")
    assert first["status"] == "added" and first["port"] == base
    assert second["name"] == "DE-berlin" and second["port"] == base + 1

    proxies = client.get("/api/proxies").json()
    assert [proxy["name"] for proxy in proxies] == ["DE-berlin", "US-miami-1"]
    assert all(proxy["status"] == "pending" for proxy in proxies)  # engine not running in this test
    detail = client.get(f"/api/proxies/{first['proxy_id']}").json()
    assert detail["config"]["peers"][0]["endpoint"] == "miami-1.sgw.guardianapp.com:51820"
    assert "PrivateKey" not in str(detail)

    status = client.get("/api/status").json()
    username, password = status["credentials"]["username"], status["credentials"]["password"]
    assert username == "wgproxy" and len(password) == 20

    export = client.get("/api/export")
    assert export.headers["content-disposition"] == 'attachment; filename="proxies.txt"'
    assert export.text.splitlines() == [
        f"socks5://{username}:{password}@127.0.0.1:{base + 1}",
        f"socks5://{username}:{password}@127.0.0.1:{base}",
    ]
    assert client.get("/api/export", params={"scheme": "http", "download": False}).text.startswith("http://")

    # Country filter uses the stored test results.
    services = client.app.state.services
    services.db.update_proxy(first["proxy_id"], country="United States", country_code="US", status="ok")
    assert client.get("/api/export", params={"country": "us"}).text.strip().endswith(f":{base}")
    assert client.get("/api/export", params={"status": "ok"}).text.count("\n") == 1

    response = client.patch(f"/api/proxies/{second['proxy_id']}", json={"enabled": False})
    assert response.json()["status"] == "disabled"
    assert client.get("/api/export").text.count("\n") == 1
    assert client.get("/api/export", params={"enabled_only": False}).text.count("\n") == 2

    assert client.delete(f"/api/proxies/{first['proxy_id']}").status_code == 200
    assert client.delete(f"/api/proxies/{first['proxy_id']}").status_code == 404
    # The freed port is handed out again.
    assert paste(client, "new")["port"] == base


def test_port_overrides(client: TestClient):
    base = client.base_port  # type: ignore[attr-defined]
    first = paste(client, "a")
    second = paste(client, "b")
    url = f"/api/proxies/{second['proxy_id']}"
    assert client.patch(url, json={"port": first["port"]}).status_code == 409
    assert client.patch(url, json={"port": 18080}).status_code == 409  # WebUI port is reserved
    assert client.patch(url, json={"port": 80}).status_code == 409
    response = client.patch(url, json={"port": base + 40, "name": "renamed b"})
    assert response.status_code == 200, response.text
    assert response.json()["port"] == base + 40
    assert response.json()["name"] == "renamed-b"
    assert client.patch(url, json={"name": "a"}).status_code == 409


def test_duplicates_and_bulk_actions(client: TestClient):
    private, peer = make_key(), make_key()
    text = make_conf(private_key=private, peer_key=peer)
    assert paste(client, "one", text)["status"] == "added"
    duplicate = paste(client, "two", text)
    assert duplicate["status"] == "error" and "duplicate" in duplicate["error"]
    shared = paste(client, "three", make_conf(private_key=private))
    assert shared["status"] == "added" and shared["warnings"]

    ids = [proxy["id"] for proxy in client.get("/api/proxies").json()]
    response = client.post("/api/proxies/bulk", json={"action": "disable", "ids": ids})
    assert response.json()["affected"] == 2
    assert all(not proxy["enabled"] for proxy in client.get("/api/proxies").json())
    client.post("/api/proxies/bulk", json={"action": "delete", "ids": ids})
    assert client.get("/api/proxies").json() == []


def test_upload_conf_files_and_zip(client: TestClient):
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("bundle/NL-amsterdam.conf", make_conf())
        handle.writestr("notes.txt", "ignored")
    files = [
        ("files", ("US-miami-1.conf", make_conf().encode(), "application/octet-stream")),
        ("files", ("bundle.zip", archive.getvalue(), "application/zip")),
        ("files", ("broken.conf", b"[Interface]\n", "application/octet-stream")),
    ]
    response = client.post("/api/proxies/import", files=files, data={"enable": "false"})
    assert response.status_code == 200, response.text
    results = {item["source"]: item for item in response.json()["results"]}
    assert results["US-miami-1.conf"]["name"] == "US-miami-1"
    assert results["bundle.zip/bundle/NL-amsterdam.conf"]["name"] == "NL-amsterdam"
    assert results["broken.conf"]["status"] == "error"
    assert all(not proxy["enabled"] for proxy in client.get("/api/proxies").json())
    backup = zipfile.ZipFile(io.BytesIO(client.get("/api/backup.zip").content))
    assert sorted(backup.namelist()) == ["NL-amsterdam.conf", "US-miami-1.conf"]


def test_settings_validation(client: TestClient):
    assert client.put("/api/settings", json={"port_range_start": 30000, "port_range_end": 20000}).status_code == 422
    assert client.put("/api/settings", json={"upstream_host": "socks5://127.0.0.1"}).status_code == 422
    assert client.put("/api/settings", json={"bootstrap_dns": "dns.google"}).status_code == 422
    assert client.put("/api/settings", json={"proxy_username": "a:b"}).status_code == 422
    assert client.put("/api/settings", json={"no_such_setting": 1}).status_code == 422
    for bad_host in ("0.0.0.0", "::", "http://203.0.113.10", "203.0.113.10:8080", "256.1.1.1"):
        assert client.put("/api/settings", json={"public_host": bad_host}).status_code == 422, bad_host
    response = client.put("/api/settings", json={"upstream_host": "", "test_concurrency": 10})
    assert response.status_code == 200
    assert response.json()["changed"] == ["test_concurrency", "upstream_host"]
    settings = client.get("/api/settings").json()
    assert settings["upstream_host"] == "" and settings["ui_password_set"] is False


def test_password_protection(client: TestClient, tmp_path: Path):
    response = client.post("/api/settings/ui-password", json={"password": "short"})
    assert response.status_code == 422
    assert client.post("/api/settings/ui-password", json={"password": "correct horse"}).status_code == 200
    assert client.get("/api/status").status_code == 200  # this browser got a fresh session cookie

    client.cookies.clear()
    assert client.get("/api/status").status_code == 401
    page = client.get("/settings", follow_redirects=False)
    assert page.status_code == 303 and page.headers["location"] == "/login?next=/settings"
    assert client.get("/healthz").status_code == 200
    assert client.get("/login").status_code == 200
    assert client.post("/api/auth/login", json={"password": "wrong"}).status_code == 401
    assert client.post("/api/auth/login", json={"password": "correct horse"}).status_code == 200
    assert client.get("/api/status").status_code == 200

    client.cookies.clear()
    token = base64.b64encode(b"script:correct horse").decode()
    assert client.get("/api/export", headers={"Authorization": f"Basic {token}"}).status_code == 200

    # The CLI reset removes the password (e.g. when it was forgotten).
    assert cli_main(["reset-ui-password"]) == 0
    assert client.get("/api/status").status_code == 200


def exported_hosts(client: TestClient, **headers: str) -> set[str]:
    text = client.get("/api/export", headers=headers).text
    return {line.rsplit("@", 1)[1].rsplit(":", 1)[0] for line in text.splitlines()}


def test_export_on_a_wildcard_bind_never_uses_the_bind_address(make_client):
    client = make_client(listen_host="0.0.0.0", allowed_hosts=LOOPBACK_HOSTS | {"194.36.188.178"})
    base = use_free_ports(client)
    paste(client, "US-miami-1")
    status = client.get("/api/status").json()
    username, password = status["credentials"]["username"], status["credentials"]["password"]
    assert status["listen_host"] == "0.0.0.0"

    # No public host: the address the WebUI was opened with (the request's Host header).
    export = client.get("/api/export", headers={"Host": "194.36.188.178:18080"})
    assert export.text == f"socks5://{username}:{password}@194.36.188.178:{base}\n"
    assert exported_hosts(client) == {"127.0.0.1"}  # opened as http://127.0.0.1:18080
    assert client.get("/api/status", headers={"Host": "194.36.188.178:18080"}).json()["export_host"] == "194.36.188.178"

    # The Settings value comes next; the dashboard and the Settings page show it too.
    assert client.put("/api/settings", json={"public_host": " VPS.Example.com "}).status_code == 200
    assert exported_hosts(client, Host="194.36.188.178:18080") == {"vps.example.com"}
    assert client.get("/api/export", params={"scheme": "http", "download": False}).text.startswith("http://")
    assert client.get("/api/settings").json()["export_host"] == "vps.example.com"
    assert "@vps.example.com:PORT" in client.get("/").text
    settings_page = client.get("/settings").text
    assert 'name="public_host"' in settings_page and "Public host/IP for export" in settings_page
    assert "every listener is bound to 0.0.0.0" in settings_page


def test_public_host_from_the_environment_overrides_the_setting(make_client):
    client = make_client(listen_host="0.0.0.0", public_host="203.0.113.10")
    use_free_ports(client)
    paste(client, "a")
    assert client.put("/api/settings", json={"public_host": "vps.example.com"}).status_code == 200
    assert exported_hosts(client) == {"203.0.113.10"}
    settings = client.get("/api/settings").json()
    assert settings["public_host"] == "vps.example.com"
    assert settings["public_host_env"] == settings["export_host"] == "203.0.113.10"


def test_export_uses_a_specific_listen_address(make_client):
    client = make_client(listen_host="127.0.0.1", allowed_hosts=LOOPBACK_HOSTS)
    use_free_ports(client)
    paste(client, "a")
    assert exported_hosts(client, Host="localhost:18080") == {"127.0.0.1"}
