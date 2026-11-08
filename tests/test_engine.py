"""Supervisor tests against real subprocesses (a fake sing-box binary, see fake_sing_box.py)."""

from __future__ import annotations

import asyncio
import json
import socket
import time
from collections.abc import Callable
from pathlib import Path

import pytest

from wgproxy.config import AppConfig
from wgproxy.db import Database
from wgproxy.engine import Engine, EngineTimings
from wgproxy.importer import Candidate, Importer
from wgproxy.logs import LogHub
from wgproxy.ports import is_port_free
from wgproxy.settings import SettingsStore
from wgproxy.upstream import UpstreamMonitor

from .conftest import free_port_range, make_conf

TIMINGS = EngineTimings(
    debounce=0.05, start_timeout=5, settle=0.1, stop_timeout=5, upstream_poll=0.2, backoff_initial=0.2, backoff_max=1
)


class Env:
    def __init__(self, tmp_path: Path, sing_box: Path, listen_host: str = "127.0.0.1"):
        self.cfg = AppConfig(
            data_dir=tmp_path / "data",
            sing_box=str(sing_box),
            webui_port=free_port_range(),
            log_level="INFO",
            allowed_hosts=frozenset({"127.0.0.1"}),
            listen_host=listen_host,
        )
        self.cfg.engine_dir.mkdir(parents=True)
        self.db = Database(self.cfg.db_path)
        self.store = SettingsStore(self.db)
        self.store.ensure_initialized()
        base = free_port_range()
        self.store.update(
            {"upstream_host": "", "port_range_start": base, "port_range_end": base + 200, "shard_size": 1, "shard_start_delay": 0.4}
        )
        self.hub = LogHub()
        self.monitor = UpstreamMonitor(self.store)
        self.engine = Engine(self.cfg, self.db, self.store, self.hub, upstream_probe=self.monitor.probe, timings=TIMINGS)

    async def add(self, count: int) -> list[int]:
        importer = Importer(self.db, self.store, self.cfg.webui_port, listen_host=self.cfg.listen_host)
        outcomes = await importer.import_candidates(
            [Candidate(f"p{i}.conf", f"p{i}", make_conf()) for i in range(count)]
        )
        return [outcome.proxy_id for outcome in outcomes if outcome.proxy_id is not None]

    def state(self, shard: int) -> dict:
        return json.loads((self.cfg.engine_dir / f"shard-{shard:02d}.json.state.json").read_text())


async def wait_for(predicate: Callable[[], bool], timeout: float = 15.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        await asyncio.sleep(0.05)
    raise AssertionError("condition not met in time")


@pytest.fixture
async def env(tmp_path: Path, fake_sing_box: Path):
    environment = Env(tmp_path, fake_sing_box)
    yield environment
    await environment.engine.shutdown()
    environment.db.close()


def running(env: Env, shards: int) -> Callable[[], bool]:
    def check() -> bool:
        snapshot = env.engine.snapshot()
        return env.engine.state == "running" and snapshot["running_shards"] == shards == snapshot["total_shards"]

    return check


async def test_staggered_start_and_graceful_shutdown(env: Env):
    await env.add(3)
    await env.engine.start()
    await wait_for(running(env, 3))
    states = [env.state(index) for index in range(3)]
    starts = sorted(state["started"] for state in states)
    assert starts[1] - starts[0] >= 0.35 and starts[2] - starts[1] >= 0.35  # staggered batches
    assert all(state["gomemlimit"] == "384MiB" for state in states)
    assert all(state["detours"] == ["direct"] for state in states)
    rows = env.db.list_proxies()
    assert all(not is_port_free(row.port) for row in rows)
    assert {row.shard for row in rows} == {0, 1, 2}

    await env.engine.shutdown()
    assert all(env.state(index)["stopped"] is not None for index in range(3))  # exited via SIGTERM
    assert all(is_port_free(row.port) for row in rows)
    assert env.engine.state == "stopped"


async def test_listeners_bind_the_configured_listen_host(tmp_path: Path, fake_sing_box: Path):
    env = Env(tmp_path, fake_sing_box, listen_host="0.0.0.0")
    try:
        await env.add(2)
        await env.engine.start()
        await wait_for(running(env, 2))  # readiness is probed on loopback, which a wildcard bind serves
        assert env.state(0)["listen"] == env.state(1)["listen"] == ["0.0.0.0"]
        assert all(not is_port_free(row.port, "0.0.0.0") for row in env.db.list_proxies())
    finally:
        await env.engine.shutdown()
        env.db.close()


async def test_disabling_a_proxy_restarts_only_its_shard(env: Env):
    ids = await env.add(3)
    await env.engine.start()
    await wait_for(running(env, 3))
    pids = {index: env.state(index)["pid"] for index in range(3)}
    victim = env.db.get_proxy(ids[1])
    assert victim is not None and victim.shard == 1

    env.db.update_proxy(victim.id, enabled=False)
    env.engine.request_apply()
    await wait_for(running(env, 2))
    assert env.state(0)["pid"] == pids[0]
    assert env.state(2)["pid"] == pids[2]
    assert is_port_free(victim.port)
    assert env.engine.proxy_states().get(victim.id) is None

    env.db.update_proxy(victim.id, enabled=True)
    env.engine.request_apply()
    await wait_for(running(env, 3))
    assert env.db.get_proxy(victim.id).port == victim.port  # stable port
    assert env.state(0)["pid"] == pids[0]


async def test_busy_port_at_startup_moves_only_that_proxy(env: Env):
    ids = await env.add(3)
    before = {row.id: row.port for row in env.db.list_proxies()}
    blocker = socket.socket()
    blocker.bind(("127.0.0.1", before[ids[1]]))
    blocker.listen()
    try:
        await env.engine.start()
        await wait_for(running(env, 3))
        after = {row.id: row for row in env.db.list_proxies()}
        assert after[ids[0]].port == before[ids[0]]
        assert after[ids[2]].port == before[ids[2]]
        assert after[ids[1]].port not in before.values()
        assert "was unavailable" in (after[ids[1]].notice or "")
        assert not is_port_free(after[ids[1]].port)
    finally:
        blocker.close()


async def test_bind_failure_reported_by_sing_box_reassigns_the_port(env: Env, monkeypatch):
    ids = await env.add(2)
    victim = env.db.get_proxy(ids[0])
    monkeypatch.setenv("FAKE_SINGBOX_BUSY_PORTS", str(victim.port))
    await env.engine.start()
    await wait_for(running(env, 2))
    moved = env.db.get_proxy(victim.id)
    assert moved.port != victim.port
    assert "could not bind" in (moved.notice or "")


async def test_fatal_tunnel_is_quarantined_and_the_shard_keeps_running(env: Env, monkeypatch):
    env.store.update({"shard_size": 10})
    ids = await env.add(3)
    bad = env.db.get_proxy(ids[1])
    monkeypatch.setenv("FAKE_SINGBOX_FATAL_TAGS", f"wg-{bad.name}")
    await env.engine.start()
    await wait_for(running(env, 1))
    assert "simulated failure" in (env.db.get_proxy(bad.id).engine_error or "")
    assert env.state(0)["tags"] == [f"wg-{env.db.get_proxy(i).name}" for i in (ids[0], ids[2])]
    assert is_port_free(bad.port)


async def test_config_rejected_by_check_quarantines_the_culprit(env: Env, monkeypatch):
    env.store.update({"shard_size": 10})
    ids = await env.add(2)
    bad = env.db.get_proxy(ids[0])
    monkeypatch.setenv("FAKE_SINGBOX_REJECT_TAGS", f"wg-{bad.name}")
    await env.engine.start()
    await wait_for(running(env, 1))
    assert "rejected by sing-box check" in (env.db.get_proxy(bad.id).engine_error or "")
    assert env.state(0)["tags"] == [f"wg-{env.db.get_proxy(ids[1]).name}"]


async def test_waits_for_the_upstream_before_starting(env: Env):
    upstream_port = free_port_range()
    env.store.update({"upstream_host": "127.0.0.1", "upstream_port": upstream_port})
    await env.add(1)
    await env.engine.start()
    await wait_for(lambda: env.engine.state == "waiting_upstream")
    await asyncio.sleep(0.5)
    assert env.engine.snapshot()["running_shards"] == 0
    assert not (env.cfg.engine_dir / "shard-00.json.state.json").exists()

    upstream = socket.socket()
    upstream.bind(("127.0.0.1", upstream_port))
    upstream.listen()
    try:
        await wait_for(running(env, 1))
        assert env.state(0)["detours"] == ["upstream"]
    finally:
        upstream.close()


async def test_changing_the_shard_size_repacks_tunnels(env: Env):
    await env.add(3)
    await env.engine.start()
    await wait_for(running(env, 3))
    env.store.update({"shard_size": 5})
    env.engine.request_apply()
    await wait_for(running(env, 1))
    assert sorted(env.state(0)["ports"]) == sorted(row.port for row in env.db.list_proxies())
    assert {row.shard for row in env.db.list_proxies()} == {0}


async def test_unexpected_exit_is_restarted(env: Env):
    await env.add(1)
    await env.engine.start()
    await wait_for(running(env, 1))
    first_pid = env.state(0)["pid"]
    import os
    import signal

    os.kill(first_pid, signal.SIGKILL)
    await wait_for(lambda: env.state(0)["pid"] != first_pid and env.engine.state == "running", timeout=10)
