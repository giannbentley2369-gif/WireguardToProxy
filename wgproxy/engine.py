"""Engine supervisor: runs the sing-box processes ("shards") hosting the WireGuard tunnels.

Why shards: sing-box brings every endpoint of a process up at once (and a reload restarts all
of them), so a single process cannot stagger WireGuard handshakes. Tunnels are therefore
packed into shards of ``shard_size`` tunnels, each its own sing-box process, started
``shard_start_delay`` seconds apart. Changing one proxy restarts only its shard. A
``shard_size`` at least as large as the number of tunnels gives a single process.

Safety rules:
* every generated config passes ``sing-box check`` before it replaces a running one;
* a port that cannot be bound moves only the affected proxy to a new free port;
* a tunnel that sing-box rejects is quarantined (excluded) instead of blocking its shard.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import re
import signal
import time
import uuid
from collections import deque
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import SUPPORTED_SING_BOX_SERIES
from .config import LISTEN_HOST, AppConfig
from .db import Database, ProxyRow, utcnow_iso
from .logs import LogHub
from .ports import NoFreePortError, PortAllocator, assign_shards, repair_ports, reserved_ports
from .settings import Settings, SettingsStore
from .singbox import EngineSettings, Tunnel, UpstreamProxy, build_config, config_hash, render, tag_to_name
from .upstream import resolve_host
from .wgconf import ConfParseError, WireGuardConfig, is_ip, parse_wireguard_conf

log = logging.getLogger("wgproxy.engine")

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
_PORT_IN_USE_RE = re.compile(
    r"inbound/[a-z0-9_-]+\[(?P<tag>[^\]]+)\]: listen tcp \S*?:(?P<port>\d+): bind: address already in use"
)
_TAG_RE = re.compile(r"(?:endpoint|inbound|outbound|dns)/[a-z0-9_-]+\[(?P<tag>[^\]]+)\]")
_MAX_APPLY_ATTEMPTS = 8


class EngineBinaryError(RuntimeError):
    """sing-box itself could not be executed (missing binary, timeout, ...)."""


@dataclass
class EngineTimings:
    debounce: float = 0.3
    start_timeout: float = 15.0
    settle: float = 0.75
    stop_timeout: float = 10.0
    upstream_poll: float = 5.0
    backoff_initial: float = 5.0
    backoff_max: float = 300.0


@dataclass
class ShardPlan:
    index: int
    rows: list[ProxyRow]
    tunnels: list[Tunnel]
    config: dict[str, Any]
    hash: str

    @property
    def ports(self) -> frozenset[int]:
        return frozenset(tunnel.port for tunnel in self.tunnels)

    @property
    def proxy_ids(self) -> tuple[int, ...]:
        return tuple(row.id for row in self.rows)


@dataclass
class Shard:
    index: int
    state: str = "stopped"  # stopped | starting | running | backoff | failed
    proc: asyncio.subprocess.Process | None = None
    pid: int | None = None
    plan: ShardPlan | None = None
    running_hash: str | None = None
    attempted_hash: str | None = None
    started_at: float | None = None
    last_error: str | None = None
    failures: int = 0
    retry_at: float | None = None
    tail: deque[str] = field(default_factory=lambda: deque(maxlen=80))
    reader: asyncio.Task[None] | None = None
    watcher: asyncio.Task[None] | None = None


def _fatal_line(output: str) -> str | None:
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    for line in reversed(lines):
        if "FATAL" in line or "panic:" in line:
            return line
    return lines[-1] if lines else None


async def _accepts_connections(port: int) -> bool:
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(LISTEN_HOST, port), 0.5)
    except (OSError, asyncio.TimeoutError):
        return False
    writer.close()
    with contextlib.suppress(Exception):
        await writer.wait_closed()
    return True


class Engine:
    def __init__(
        self,
        cfg: AppConfig,
        db: Database,
        store: SettingsStore,
        hub: LogHub,
        upstream_probe: Callable[[], Awaitable[bool]] | None = None,
        timings: EngineTimings | None = None,
    ):
        self.cfg = cfg
        self.db = db
        self.store = store
        self.hub = hub
        self.upstream_probe = upstream_probe
        self.timings = timings or EngineTimings()
        self.state = "stopped"
        self.message = ""
        self.binary_version: str | None = None
        self._shards: dict[int, Shard] = {}
        self._wake = asyncio.Event()
        self._task: asyncio.Task[None] | None = None
        self._closing = False
        self._restart_all = False
        self._applied_shard_size: int | None = None
        self._next_poll: float | None = None
        self._gomemlimit = ""

    # -- public API -----------------------------------------------------------------------

    async def start(self) -> None:
        self.cfg.engine_dir.mkdir(parents=True, exist_ok=True)
        await asyncio.to_thread(self._cleanup_stale)
        self.binary_version = await self.detect_version()
        # Quarantined tunnels get a fresh chance on every engine start.
        self.db.clear_engine_errors()
        self._closing = False
        self.state, self.message = "starting", "Starting"
        self._task = asyncio.create_task(self._run(), name="wgproxy-engine")

    async def shutdown(self) -> None:
        self._closing = True
        self.state, self.message = "stopping", "Stopping"
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._task
            self._task = None
        await self._stop_all()
        self.state, self.message = "stopped", "Stopped"
        log.info("engine stopped")

    def request_apply(self, *, restart_all: bool = False) -> None:
        """Schedule a reconcile pass (debounced). ``restart_all`` restarts every shard."""
        if restart_all:
            self._restart_all = True
        self._wake.set()

    def running_ports(self) -> set[int]:
        return {
            port
            for shard in self._shards.values()
            if shard.proc is not None and shard.plan is not None
            for port in shard.plan.ports
        }

    def proxy_states(self) -> dict[int, str]:
        """Runtime state per proxy id; proxies absent from the map are not scheduled yet."""
        states: dict[int, str] = {}
        for shard in self._shards.values():
            if shard.plan is None:
                continue
            for proxy_id in shard.plan.proxy_ids:
                states[proxy_id] = shard.state
        return states

    def snapshot(self) -> dict[str, Any]:
        now = time.monotonic()
        shards = []
        for shard in sorted(self._shards.values(), key=lambda item: item.index):
            ports = sorted(shard.plan.ports) if shard.plan else []
            shards.append(
                {
                    "index": shard.index,
                    "state": shard.state,
                    "pid": shard.pid,
                    "tunnels": len(shard.plan.rows) if shard.plan else 0,
                    "names": [row.name for row in shard.plan.rows] if shard.plan else [],
                    "ports": ports,
                    "started_at": shard.started_at,
                    "last_error": shard.last_error,
                    "failures": shard.failures,
                    "retry_in": max(0.0, shard.retry_at - now) if shard.retry_at else None,
                }
            )
        return {
            "state": self.state,
            "message": self.message,
            "binary": self.cfg.sing_box,
            "version": self.binary_version,
            "shards": shards,
            "running_shards": sum(1 for shard in shards if shard["state"] == "running"),
            "total_shards": len(shards),
            "running_tunnels": sum(shard["tunnels"] for shard in shards if shard["state"] == "running"),
        }

    async def detect_version(self) -> str | None:
        try:
            proc = await asyncio.create_subprocess_exec(
                self.cfg.sing_box,
                "version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            output, _ = await asyncio.wait_for(proc.communicate(), 30)
        except (OSError, asyncio.TimeoutError) as exc:
            log.error("cannot run sing-box (%s): %s", self.cfg.sing_box, exc)
            return None
        match = re.search(r"version\s+(\S+)", output.decode("utf-8", "replace"))
        version = match.group(1) if match else None
        if version and not version.startswith(SUPPORTED_SING_BOX_SERIES):
            log.warning(
                "sing-box %s detected; this application targets %sx", version, SUPPORTED_SING_BOX_SERIES
            )
        elif version:
            log.info("using sing-box %s", version)
        return version

    async def validate_tunnel(self, conf: WireGuardConfig) -> str | None:
        """Run ``sing-box check`` on a single-tunnel config. None means accepted (or unchecked)."""
        settings = self.store.load()
        try:
            engine_settings = await self.engine_settings(settings)
        except OSError:
            engine_settings = await self.engine_settings(settings, resolve_upstream=False)
        config = build_config([Tunnel("validate", 10000, conf)], engine_settings)
        try:
            return await self._check(config, self._temp_path())
        except EngineBinaryError as exc:
            log.warning("skipping sing-box validation: %s", exc)
            return None

    async def engine_settings(self, settings: Settings, *, resolve_upstream: bool = True) -> EngineSettings:
        upstream = None
        if settings.upstream_host:
            host = settings.upstream_host
            if resolve_upstream:
                host = await resolve_host(host)
            elif not is_ip(host):
                host = "127.0.0.1"  # placeholder: only used for `sing-box check`
            upstream = UpstreamProxy(host, settings.upstream_port, settings.upstream_username, settings.upstream_password)
        return EngineSettings(
            upstream=upstream,
            proxy_username=settings.proxy_username,
            proxy_password=settings.proxy_password,
            bootstrap_dns=settings.bootstrap_dns,
            bootstrap_dns_protocol=settings.bootstrap_dns_protocol,
            tunnel_dns_fallback=settings.tunnel_dns_fallback,
            default_mtu=settings.default_mtu,
            default_keepalive=settings.default_keepalive,
            log_level=settings.log_level,
        )

    # -- main loop ------------------------------------------------------------------------

    async def _run(self) -> None:
        while not self._closing:
            self._wake.clear()
            self._next_poll = None
            try:
                await self._reconcile()
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # keep supervising whatever happens
                log.exception("engine reconcile failed")
                self.state, self.message = "error", f"Internal error: {exc}"
                self._next_poll = 10.0
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(self._wake.wait(), self._next_delay())
            if self.timings.debounce and not self._closing:
                await asyncio.sleep(self.timings.debounce)

    def _next_delay(self) -> float | None:
        now = time.monotonic()
        delays = [max(0.05, shard.retry_at - now) for shard in self._shards.values() if shard.retry_at]
        if self._next_poll is not None:
            delays.append(self._next_poll)
        return min(delays) if delays else None

    async def _reconcile(self) -> None:
        settings = self.store.load()
        self._gomemlimit = settings.gomemlimit
        if self._restart_all:
            self._restart_all = False
            log.info("restarting all engine processes")
            await self._stop_all()
            for shard in self._shards.values():
                shard.attempted_hash = None
                shard.retry_at = None
        if self._applied_shard_size is not None and settings.shard_size != self._applied_shard_size:
            log.info("shard size changed %d -> %d: re-packing tunnels", self._applied_shard_size, settings.shard_size)
            await self._stop_all()
            self.db.clear_shards()
        self._applied_shard_size = settings.shard_size

        desired = self._assign(settings)
        for index in sorted(set(self._shards) - desired):
            await self._stop_shard(self._shards[index])
            del self._shards[index]
            self._remove_files(index)
        if not desired:
            self.state, self.message = "idle", "No enabled proxies"
            return

        try:
            engine_settings = await self.engine_settings(settings)
        except OSError as exc:
            self.state = "error"
            self.message = f"Cannot resolve the upstream host {settings.upstream_host!r}: {exc}"
            self._next_poll = self.timings.upstream_poll
            return

        cold = all(shard.proc is None for shard in self._shards.values())
        if cold and settings.upstream_enabled and self.upstream_probe is not None:
            if not await self.upstream_probe():
                self.state = "waiting_upstream"
                self.message = (
                    f"Waiting for the upstream proxy {settings.upstream_host}:{settings.upstream_port} "
                    "before starting tunnels"
                )
                self._next_poll = self.timings.upstream_poll
                return

        started = 0
        for index in sorted(desired):
            if self._closing:
                return
            shard = self._shards.setdefault(index, Shard(index))
            plan = self._plan(index, engine_settings)
            if plan is None:
                await self._stop_shard(shard)
                continue
            if not self._needs_apply(shard, plan):
                continue
            if started and settings.shard_start_delay > 0:
                self.state = "starting"
                self.message = f"Staggered start: next shard in {settings.shard_start_delay:g}s"
                await asyncio.sleep(settings.shard_start_delay)
                plan = self._plan(index, engine_settings)
                if plan is None:
                    await self._stop_shard(shard)
                    continue
            self.state, self.message = "starting", f"Starting shard {index}"
            await self._apply_shard(shard, plan, engine_settings)
            started += 1
        self._refresh_state()

    def _assign(self, settings: Settings) -> set[int]:
        rows = [row for row in self.db.list_proxies() if row.active]
        mapping = assign_shards([(row.id, row.shard) for row in rows], settings.shard_size)
        for row in rows:
            if mapping[row.id] != row.shard:
                self.db.update_proxy(row.id, shard=mapping[row.id])
        return set(mapping.values())

    def _plan(self, index: int, engine_settings: EngineSettings) -> ShardPlan | None:
        rows: list[ProxyRow] = []
        tunnels: list[Tunnel] = []
        for row in self.db.list_proxies():
            if not row.active or row.shard != index:
                continue
            try:
                conf = parse_wireguard_conf(row.conf_text)
            except ConfParseError as exc:
                self._quarantine(row, f"invalid configuration: {exc}")
                continue
            rows.append(row)
            tunnels.append(Tunnel(row.name, row.port, conf))
        if not tunnels:
            return None
        config = build_config(tunnels, engine_settings)
        return ShardPlan(index, rows, tunnels, config, config_hash(config))

    def _needs_apply(self, shard: Shard, plan: ShardPlan) -> bool:
        if shard.proc is not None and shard.running_hash == plan.hash:
            return False
        if shard.attempted_hash == plan.hash:
            if shard.state == "failed":
                return False  # waits for a change or a manual restart
            if shard.state == "backoff" and shard.retry_at and time.monotonic() < shard.retry_at:
                return False
        return True

    def _refresh_state(self) -> None:
        shards = list(self._shards.values())
        tunnels = sum(len(shard.plan.rows) for shard in shards if shard.plan and shard.state == "running")
        if not shards:
            self.state, self.message = "idle", "No enabled proxies"
        elif all(shard.state == "running" for shard in shards):
            self.state, self.message = "running", f"{tunnels} tunnel(s) in {len(shards)} process(es)"
        elif any(shard.state in {"backoff", "failed"} for shard in shards):
            bad = sum(1 for shard in shards if shard.state in {"backoff", "failed"})
            self.state = "degraded"
            self.message = f"{bad} of {len(shards)} engine process(es) not running"
        else:
            self.state, self.message = "starting", "Starting"

    # -- applying one shard ---------------------------------------------------------------

    async def _apply_shard(self, shard: Shard, plan: ShardPlan | None, engine_settings: EngineSettings) -> None:
        for _ in range(_MAX_APPLY_ATTEMPTS):
            if plan is None:
                await self._stop_shard(shard)
                return
            shard.plan = plan if shard.proc is None else shard.plan
            check_path = self._path(shard.index, ".check.json")
            try:
                check_error = await self._check(plan.config, check_path)
                if check_error is not None:
                    rejected = await self._find_rejected(plan, engine_settings)
                    if rejected:
                        for row, error in rejected:
                            self._quarantine(row, f"rejected by sing-box check: {error}")
                        plan = self._plan(shard.index, engine_settings)
                        continue
            except EngineBinaryError as exc:
                self._fail(shard, plan, str(exc), backoff=True)
                return
            if check_error is not None:
                # Not attributable to one tunnel: keep whatever is running and report.
                self._fail(shard, plan, f"generated configuration rejected by sing-box check: {check_error}")
                return

            await self._stop_shard(shard)
            if self._repair_ports(plan):
                plan = self._plan(shard.index, engine_settings)
                continue
            os.replace(check_path, self._path(shard.index))
            failure = await self._launch(shard, plan)
            if failure is None:
                return
            if self._fix_failure(failure, plan):
                plan = self._plan(shard.index, engine_settings)
                continue
            self._fail(shard, plan, f"sing-box exited during startup: {_fatal_line(failure)}", backoff=True)
            return
        self._fail(shard, plan, "giving up after repeated startup failures", backoff=True)

    def _fail(self, shard: Shard, plan: ShardPlan | None, message: str, *, backoff: bool = False) -> None:
        shard.attempted_hash = plan.hash if plan else None
        shard.last_error = message
        if backoff:
            shard.failures += 1
            delay = min(self.timings.backoff_max, self.timings.backoff_initial * 2 ** (shard.failures - 1))
            shard.retry_at = time.monotonic() + delay
            if shard.proc is None:
                shard.state = "backoff"
            log.error("shard %d: %s (retrying in %.0fs)", shard.index, message, delay)
        else:
            shard.retry_at = None
            if shard.proc is None:
                shard.state = "failed"
            log.error("shard %d: %s", shard.index, message)

    async def _launch(self, shard: Shard, plan: ShardPlan) -> str | None:
        """Start sing-box for ``plan``. Returns None when running, else the process output."""
        env = dict(os.environ)
        if self._gomemlimit:
            env["GOMEMLIMIT"] = self._gomemlimit
        else:
            env.pop("GOMEMLIMIT", None)
        try:
            proc = await asyncio.create_subprocess_exec(
                self.cfg.sing_box,
                "run",
                "--disable-color",
                "-c",
                str(self._path(shard.index)),
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                env=env,
                start_new_session=True,  # terminal signals must not reach the engine directly
                limit=1 << 20,
            )
        except OSError as exc:
            return f"FATAL cannot execute {self.cfg.sing_box}: {exc}"
        shard.proc, shard.pid, shard.plan = proc, proc.pid, plan
        shard.state, shard.started_at = "starting", time.time()
        shard.tail.clear()
        self._write_pid(shard.index, proc.pid)
        shard.reader = asyncio.create_task(self._pump(shard, proc))
        waiter = asyncio.create_task(proc.wait())
        ready = await self._wait_ready(plan.ports, waiter)
        if waiter.done():
            if shard.reader is not None:
                with contextlib.suppress(Exception):
                    await asyncio.wait_for(shard.reader, 2)
            if shard.proc is proc:
                self._detach(shard)
            return "\n".join(shard.tail) or f"sing-box exited with code {proc.returncode}"
        if not ready:
            log.warning("shard %d: listeners not ready after %.0fs; continuing", shard.index, self.timings.start_timeout)
        shard.state = "running"
        shard.running_hash = shard.attempted_hash = plan.hash
        shard.last_error, shard.failures, shard.retry_at = None, 0, None
        shard.watcher = asyncio.create_task(self._watch(shard, proc, waiter))
        log.info(
            "shard %d running (pid %d): %d tunnel(s) on ports %s",
            shard.index,
            proc.pid,
            len(plan.rows),
            ", ".join(str(port) for port in sorted(plan.ports)),
        )
        return None

    async def _wait_ready(self, ports: frozenset[int], waiter: asyncio.Task[int]) -> bool:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + self.timings.start_timeout
        pending = set(ports)
        while pending and loop.time() < deadline and not waiter.done():
            for port in sorted(pending):
                if await _accepts_connections(port):
                    pending.discard(port)
            if pending:
                await asyncio.wait({waiter}, timeout=0.1)
        # Listeners open before the post-start stage, which can still fail fatally.
        if not waiter.done():
            await asyncio.wait({waiter}, timeout=self.timings.settle)
        return not pending and not waiter.done()

    async def _pump(self, shard: Shard, proc: asyncio.subprocess.Process) -> None:
        source = f"shard-{shard.index:02d}"
        assert proc.stdout is not None
        while True:
            try:
                line = await proc.stdout.readline()
            except ValueError:  # over-long line; the reader already discarded it
                continue
            except Exception:
                return
            if not line:
                return
            text = _ANSI_RE.sub("", line.decode("utf-8", "replace")).rstrip()
            if text:
                shard.tail.append(text)
                self.hub.publish(source, text)

    async def _watch(self, shard: Shard, proc: asyncio.subprocess.Process, waiter: asyncio.Task[int]) -> None:
        code = await waiter
        if shard.reader is not None:
            with contextlib.suppress(Exception):
                await asyncio.wait_for(shard.reader, 2)
        if shard.proc is not proc or self._closing:
            return  # stopped on purpose
        plan = shard.plan
        self._detach(shard)
        output = "\n".join(shard.tail)
        summary = _fatal_line(output) or f"exit code {code}"
        log.error("shard %d: sing-box exited unexpectedly: %s", shard.index, summary)
        if plan is not None and self._fix_failure(output, plan):
            shard.state, shard.attempted_hash = "stopped", None
        else:
            self._fail(shard, plan, f"sing-box exited unexpectedly: {summary}", backoff=True)
        self._refresh_state()
        self._wake.set()

    def _detach(self, shard: Shard) -> None:
        shard.proc = None
        shard.pid = None
        shard.running_hash = None
        self._remove_pid(shard.index)

    async def _stop_shard(self, shard: Shard) -> None:
        proc = shard.proc
        if proc is None:
            return
        shard.proc = None  # detach first so the watcher treats the exit as intentional
        if proc.returncode is None:
            with contextlib.suppress(ProcessLookupError):
                proc.send_signal(signal.SIGTERM)
            try:
                await asyncio.wait_for(proc.wait(), self.timings.stop_timeout)
            except asyncio.TimeoutError:
                log.warning("shard %d: sing-box ignored SIGTERM for %.0fs; killing it", shard.index, self.timings.stop_timeout)
                with contextlib.suppress(ProcessLookupError):
                    proc.kill()
                await proc.wait()
        for task in (shard.reader, shard.watcher):
            if task is not None and not task.done():
                with contextlib.suppress(Exception):
                    await asyncio.wait_for(task, 2)
        shard.reader = shard.watcher = None
        shard.pid = None
        shard.running_hash = None
        shard.state = "stopped"
        self._remove_pid(shard.index)

    async def _stop_all(self) -> None:
        await asyncio.gather(*(self._stop_shard(shard) for shard in self._shards.values()), return_exceptions=True)

    # -- validation and repairs -----------------------------------------------------------

    async def _check(self, config: dict[str, Any], path: Path) -> str | None:
        """Write ``config`` to ``path`` and run ``sing-box check``. None means valid."""
        path.write_text(render(config), encoding="utf-8")
        os.chmod(path, 0o600)
        try:
            proc = await asyncio.create_subprocess_exec(
                self.cfg.sing_box,
                "check",
                "--disable-color",
                "-c",
                str(path),
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
        except OSError as exc:
            raise EngineBinaryError(f"cannot execute {self.cfg.sing_box}: {exc}") from exc
        try:
            output, _ = await asyncio.wait_for(proc.communicate(), 60)
        except asyncio.TimeoutError:
            with contextlib.suppress(ProcessLookupError):
                proc.kill()
            await proc.wait()
            raise EngineBinaryError("sing-box check timed out") from None
        if proc.returncode == 0:
            return None
        text = _ANSI_RE.sub("", output.decode("utf-8", "replace")).strip()
        return text[-2000:] or f"sing-box check exited with code {proc.returncode}"

    async def _find_rejected(self, plan: ShardPlan, engine_settings: EngineSettings) -> list[tuple[ProxyRow, str]]:
        """Identify tunnels that sing-box rejects on their own."""
        baseline = self._temp_path()
        try:
            if await self._check(build_config([], engine_settings), baseline) is not None:
                return []  # the shared settings are the problem, not a tunnel
        finally:
            baseline.unlink(missing_ok=True)
        limiter = asyncio.Semaphore(4)

        async def check_one(row: ProxyRow, tunnel: Tunnel) -> tuple[ProxyRow, str | None]:
            path = self._temp_path()
            async with limiter:
                try:
                    return row, await self._check(build_config([tunnel], engine_settings), path)
                finally:
                    path.unlink(missing_ok=True)

        results = await asyncio.gather(*(check_one(row, tunnel) for row, tunnel in zip(plan.rows, plan.tunnels)))
        return [(row, error) for row, error in results if error]

    def _allocator(self) -> PortAllocator:
        settings = self.store.load()
        reserved = reserved_ports(self.cfg.webui_port, settings.upstream_host, settings.upstream_port)
        return PortAllocator(settings.port_range_start, settings.port_range_end, reserved)

    def _repair_ports(self, plan: ShardPlan) -> bool:
        """Move proxies of ``plan`` whose port cannot be bound. True when anything changed."""
        allocator = self._allocator()
        assigned = {row.id: row.port for row in plan.rows}
        taken = (self.db.used_ports() | self.running_ports()) - set(assigned.values())
        try:
            moves = repair_ports(assigned, allocator, taken)
        except NoFreePortError as exc:
            for row in plan.rows:
                if not allocator.probe(row.port):
                    self._quarantine(row, f"port {row.port} is unavailable and {exc}")
            return True
        for row in plan.rows:
            if row.id in moves:
                self._record_port_move(row, moves[row.id], "it was in use")
        return bool(moves)

    def _fix_failure(self, output: str, plan: ShardPlan) -> bool:
        """Handle startup failures attributable to one proxy. True when something changed."""
        match = _PORT_IN_USE_RE.search(output)
        if match:
            row = self._row_for_tag(match.group("tag"), plan)
            if row is not None:
                try:
                    new_port = self._allocator().allocate(self.db.used_ports() | self.running_ports())
                except NoFreePortError as exc:
                    self._quarantine(row, f"port {row.port} is unavailable and {exc}")
                    return True
                self._record_port_move(row, new_port, "sing-box could not bind it")
                return True
        fatal = _fatal_line(output) or ""
        match = _TAG_RE.search(fatal)
        if match:
            row = self._row_for_tag(match.group("tag"), plan)
            if row is not None:
                self._quarantine(row, f"sing-box failed to start this tunnel: {fatal}")
                return True
        return False

    @staticmethod
    def _row_for_tag(tag: str, plan: ShardPlan) -> ProxyRow | None:
        name = tag_to_name(tag)
        return next((row for row in plan.rows if row.name == name), None) if name else None

    def _record_port_move(self, row: ProxyRow, new_port: int, reason: str) -> None:
        notice = f"Port {row.port} was unavailable ({reason}); moved to {new_port} at {utcnow_iso()}"
        self.db.update_proxy(row.id, port=new_port, notice=notice)
        log.warning("proxy %s: port %d unavailable (%s); now using port %d", row.name, row.port, reason, new_port)

    def _quarantine(self, row: ProxyRow, reason: str) -> None:
        self.db.update_proxy(row.id, engine_error=reason[:2000])
        log.error("proxy %s excluded from the engine: %s", row.name, reason)

    # -- files ----------------------------------------------------------------------------

    def _path(self, index: int, suffix: str = ".json") -> Path:
        return self.cfg.engine_dir / f"shard-{index:02d}{suffix}"

    def _temp_path(self) -> Path:
        return self.cfg.engine_dir / f"validate-{uuid.uuid4().hex}.json"

    def _write_pid(self, index: int, pid: int) -> None:
        self._path(index, ".pid").write_text(str(pid), encoding="utf-8")

    def _remove_pid(self, index: int) -> None:
        self._path(index, ".pid").unlink(missing_ok=True)

    def _remove_files(self, index: int) -> None:
        for suffix in (".json", ".check.json", ".pid"):
            self._path(index, suffix).unlink(missing_ok=True)

    def _cleanup_stale(self) -> None:
        """Stop sing-box processes left behind by a previous crash and delete old files."""
        engine_dir = str(self.cfg.engine_dir)
        for pid_file in self.cfg.engine_dir.glob("shard-*.pid"):
            try:
                pid = int(pid_file.read_text(encoding="utf-8").strip())
                cmdline = Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ").decode("utf-8", "replace")
            except (OSError, ValueError):
                pid_file.unlink(missing_ok=True)
                continue
            if pid != os.getpid() and "run" in cmdline and engine_dir in cmdline:
                log.warning("stopping stale sing-box process %d", pid)
                with contextlib.suppress(ProcessLookupError):
                    os.kill(pid, signal.SIGTERM)
                    for _ in range(50):
                        time.sleep(0.1)
                        os.kill(pid, 0)
                    os.kill(pid, signal.SIGKILL)
            pid_file.unlink(missing_ok=True)
        for pattern in ("shard-*.json", "validate-*.json"):
            for path in self.cfg.engine_dir.glob(pattern):
                path.unlink(missing_ok=True)
