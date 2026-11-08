"""Proxy tests: exit IP and latency through each local proxy, country via ip-api.com."""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import json
import logging
import re
import time
from collections.abc import Iterable, Sequence
from dataclasses import asdict, dataclass
from typing import Any
from urllib.parse import quote

import httpx

from . import __version__
from .config import LISTEN_HOST
from .db import Database, ProxyRow, utcnow_iso
from .settings import Settings, SettingsStore
from .upstream import upstream_proxy_url

log = logging.getLogger("wgproxy.tester")

USER_AGENT = f"wgproxy/{__version__}"
# The free ip-api.com tier is HTTP only; batches hold at most 100 addresses.
IP_API_BATCH_URL = "http://ip-api.com/batch"
IP_API_FIELDS = "status,message,country,countryCode,city,query"
IP_API_BATCH_SIZE = 100
_IP_RE = re.compile(r"[0-9a-fA-F:.]{3,45}")


def proxy_url(scheme: str, username: str, password: str, port: int) -> str:
    return f"{scheme}://{quote(username, safe='')}:{quote(password, safe='')}@{LISTEN_HOST}:{port}"


def extract_ip(text: str) -> str | None:
    """Find the IP address in a "what is my IP" response (plain text or JSON)."""
    text = text.strip()
    candidates: list[str] = []
    with contextlib.suppress(ValueError, AttributeError):
        data = json.loads(text)
        if isinstance(data, dict):
            candidates.extend(str(data.get(key, "")) for key in ("ip", "query", "origin", "address"))
    candidates.append(text)
    candidates.extend(_IP_RE.findall(text))
    for candidate in candidates:
        candidate = candidate.strip()
        try:
            return str(ipaddress.ip_address(candidate))
        except ValueError:
            continue
    return None


@dataclass
class CheckResult:
    ok: bool
    exit_ip: str | None = None
    latency_ms: int | None = None
    error: str | None = None


def _describe(exc: Exception) -> str:
    text = str(exc).strip()
    return f"{exc.__class__.__name__}: {text}" if text else exc.__class__.__name__


def _explain_failure(exc: Exception) -> str:
    """Translate client errors into what they mean for a local tunnel proxy."""
    text = str(exc)
    if isinstance(exc, httpx.ProxyError) and any(
        marker in text for marker in ("General SOCKS server failure", "unreachable", "TTL expired")
    ):
        # sing-box answers SOCKS "general failure" when nothing comes back through the tunnel.
        return f"no answer through the tunnel: WireGuard handshake or DNS inside the tunnel failed ({text})"
    if isinstance(exc, httpx.ConnectError):
        return f"the local proxy port does not accept connections; is its engine process running? ({text})"
    return _describe(exc)


async def check_proxy(port: int, username: str, password: str, url: str, timeout: float) -> CheckResult:
    """Fetch ``url`` through the local SOCKS5 listener on ``port``."""
    started = time.perf_counter()
    try:
        async with httpx.AsyncClient(
            proxy=proxy_url("socks5", username, password, port),
            timeout=timeout,
            trust_env=False,
            follow_redirects=True,
            headers={"User-Agent": USER_AGENT},
        ) as client:
            response = await client.get(url)
    except httpx.TimeoutException:
        return CheckResult(False, error=f"timed out after {timeout:g}s")
    except (httpx.HTTPError, OSError) as exc:
        return CheckResult(False, error=_explain_failure(exc))
    latency = int((time.perf_counter() - started) * 1000)
    if response.status_code >= 400:
        return CheckResult(False, latency_ms=latency, error=f"HTTP {response.status_code} from the test URL")
    ip = extract_ip(response.text[:2000])
    if ip is None:
        return CheckResult(False, latency_ms=latency, error="no IP address found in the test URL response")
    return CheckResult(True, exit_ip=ip, latency_ms=latency)


async def lookup_geo(ips: Iterable[str], proxy: str | None, timeout: float = 15.0) -> dict[str, dict[str, Any]]:
    """Country/city per IP via the ip-api.com batch endpoint."""
    unique = sorted(set(ips))
    results: dict[str, dict[str, Any]] = {}
    if not unique:
        return results
    async with httpx.AsyncClient(
        proxy=proxy, timeout=timeout, trust_env=False, headers={"User-Agent": USER_AGENT}
    ) as client:
        for start in range(0, len(unique), IP_API_BATCH_SIZE):
            chunk = unique[start : start + IP_API_BATCH_SIZE]
            for attempt in range(2):
                response = await client.post(
                    IP_API_BATCH_URL, params={"fields": IP_API_FIELDS}, json=[{"query": ip} for ip in chunk]
                )
                if response.status_code == 429 and attempt == 0:
                    wait = min(60, int(response.headers.get("X-Ttl", "60") or 60))
                    log.warning("ip-api.com rate limit reached; waiting %ds", wait)
                    await asyncio.sleep(wait)
                    continue
                response.raise_for_status()
                break
            for item in response.json():
                if isinstance(item, dict) and item.get("status") == "success" and item.get("query"):
                    results[str(item["query"])] = item
            if response.headers.get("X-Rl") == "0" and start + IP_API_BATCH_SIZE < len(unique):
                await asyncio.sleep(min(60, int(response.headers.get("X-Ttl", "60") or 60)))
    return results


@dataclass
class TestJob:
    id: int
    total: int
    started_at: str
    done: int = 0
    ok: int = 0
    failed: int = 0
    phase: str = "testing"  # testing | geo | finished
    running: bool = True
    finished_at: str | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class Tester:
    def __init__(self, db: Database, store: SettingsStore):
        self.db = db
        self.store = store
        self.job: TestJob | None = None
        self._task: asyncio.Task[None] | None = None
        self._seq = 0

    def snapshot(self) -> dict[str, Any] | None:
        return self.job.to_dict() if self.job else None

    @property
    def running(self) -> bool:
        return self.job is not None and self.job.running

    def start(self, ids: Sequence[int] | None = None) -> TestJob:
        if self.running:
            raise RuntimeError("a test run is already in progress")
        wanted = set(ids) if ids is not None else None
        rows = [row for row in self.db.list_proxies() if row.active and (wanted is None or row.id in wanted)]
        self._seq += 1
        job = TestJob(id=self._seq, total=len(rows), started_at=utcnow_iso())
        self.job = job
        self._task = asyncio.create_task(self._run(job, rows), name="wgproxy-test")
        return job

    async def test_one(self, proxy_id: int) -> ProxyRow | None:
        row = self.db.get_proxy(proxy_id)
        if row is None:
            return None
        settings = self.store.load()
        results = await self._test_rows([row], settings)
        await self._apply_geo(results, settings)
        return self.db.get_proxy(proxy_id)

    async def shutdown(self) -> None:
        if self._task is not None and not self._task.done():
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._task

    async def auto_loop(self) -> None:
        while True:
            interval = self.store.load().auto_test_interval
            if interval <= 0:
                await asyncio.sleep(60)
                continue
            await asyncio.sleep(interval * 60)
            if self.store.load().auto_test_interval > 0 and not self.running:
                log.info("starting scheduled test of all proxies")
                self.start()
                if self._task is not None:
                    with contextlib.suppress(Exception):
                        await self._task

    async def _run(self, job: TestJob, rows: list[ProxyRow]) -> None:
        settings = self.store.load()
        try:
            results = await self._test_rows(rows, settings, job)
            job.phase = "geo"
            await self._apply_geo(results, settings)
        except asyncio.CancelledError:
            job.error = "cancelled"
            raise
        except Exception as exc:
            log.exception("test run failed")
            job.error = _describe(exc)
        finally:
            job.running = False
            job.phase = "finished"
            job.finished_at = utcnow_iso()
            log.info("test run finished: %d ok, %d failed of %d", job.ok, job.failed, job.total)

    async def _test_rows(
        self, rows: list[ProxyRow], settings: Settings, job: TestJob | None = None
    ) -> dict[int, CheckResult]:
        limiter = asyncio.Semaphore(settings.test_concurrency)
        results: dict[int, CheckResult] = {}

        async def run_one(row: ProxyRow) -> None:
            async with limiter:
                result = await check_proxy(
                    row.port, settings.proxy_username, settings.proxy_password, settings.test_url, settings.test_timeout
                )
            results[row.id] = result
            self._store_result(row, result)
            if job is not None:
                job.done += 1
                if result.ok:
                    job.ok += 1
                else:
                    job.failed += 1

        await asyncio.gather(*(run_one(row) for row in rows))
        return results

    def _store_result(self, row: ProxyRow, result: CheckResult) -> None:
        values: dict[str, Any] = {
            "status": "ok" if result.ok else "dead",
            "latency_ms": result.latency_ms,
            "check_error": result.error,
            "checked_at": utcnow_iso(),
        }
        if result.ok:
            values["exit_ip"] = result.exit_ip
            if result.exit_ip != row.exit_ip:
                values.update(country=None, country_code=None, city=None)
        self.db.update_proxy(row.id, **values)

    async def _apply_geo(self, results: dict[int, CheckResult], settings: Settings) -> None:
        ips = {result.exit_ip for result in results.values() if result.ok and result.exit_ip}
        if not ips:
            return
        proxy = upstream_proxy_url(settings) if settings.geo_via_upstream else None
        try:
            geo = await lookup_geo(ips, proxy)
        except Exception as exc:
            log.warning("country lookup via ip-api.com failed: %s", _describe(exc))
            return
        for proxy_id, result in results.items():
            info = geo.get(result.exit_ip or "")
            if result.ok and info:
                self.db.update_proxy(
                    proxy_id,
                    country=info.get("country"),
                    country_code=info.get("countryCode"),
                    city=info.get("city"),
                )
