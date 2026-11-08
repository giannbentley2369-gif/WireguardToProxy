"""In-memory log hub: ring buffer + live fan-out for the WebUI log viewer.

Engine output is rate limited per source. With the upstream proxy down, every tunnel logs a
reconnect error each second, which would otherwise flood the buffer and the browser.
"""

from __future__ import annotations

import asyncio
import logging
import re
import threading
import time
from collections import deque
from dataclasses import dataclass

_LEVEL_RE = re.compile(r"\b(TRACE|DEBUG|INFO|WARN|WARNING|ERROR|FATAL|PANIC)\b")


def detect_level(text: str) -> str:
    match = _LEVEL_RE.search(text[:80])
    if not match:
        return "INFO"
    level = match.group(1)
    return "WARN" if level == "WARNING" else level


@dataclass(frozen=True)
class LogEntry:
    seq: int
    ts: float
    source: str
    level: str
    text: str

    def to_dict(self) -> dict[str, object]:
        return {"seq": self.seq, "ts": self.ts, "source": self.source, "level": self.level, "text": self.text}


class _Bucket:
    __slots__ = ("tokens", "updated", "suppressed")

    def __init__(self, burst: float):
        self.tokens = burst
        self.updated = time.monotonic()
        self.suppressed = 0


def _offer(queue: asyncio.Queue[LogEntry], entry: LogEntry) -> None:
    try:
        queue.put_nowait(entry)
    except asyncio.QueueFull:
        # Slow consumer: drop its oldest entry rather than blocking producers.
        try:
            queue.get_nowait()
            queue.put_nowait(entry)
        except (asyncio.QueueEmpty, asyncio.QueueFull):
            pass


class LogHub:
    def __init__(self, capacity: int = 3000, rate_per_sec: float = 30.0, burst: float = 300.0):
        self._entries: deque[LogEntry] = deque(maxlen=capacity)
        self._lock = threading.Lock()
        self._seq = 0
        self._rate = rate_per_sec
        self._burst = burst
        self._buckets: dict[str, _Bucket] = {}
        self._subscribers: set[asyncio.Queue[LogEntry]] = set()
        self._loop: asyncio.AbstractEventLoop | None = None

    def bind_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop

    def _take_token(self, source: str) -> bool:
        bucket = self._buckets.get(source)
        if bucket is None:
            bucket = self._buckets[source] = _Bucket(self._burst)
        now = time.monotonic()
        bucket.tokens = min(self._burst, bucket.tokens + (now - bucket.updated) * self._rate)
        bucket.updated = now
        if bucket.tokens >= 1:
            bucket.tokens -= 1
            return True
        bucket.suppressed += 1
        return False

    def publish(self, source: str, text: str, level: str | None = None, *, throttle: bool = True) -> None:
        text = text.rstrip("\r\n")
        if not text:
            return
        with self._lock:
            if throttle and not self._take_token(source):
                return
            self._seq += 1
            entry = LogEntry(self._seq, time.time(), source, level or detect_level(text), text)
            self._entries.append(entry)
            subscribers = list(self._subscribers)
        self._dispatch(entry, subscribers)

    def _dispatch(self, entry: LogEntry, subscribers: list[asyncio.Queue[LogEntry]]) -> None:
        loop = self._loop
        if loop is None or not subscribers or loop.is_closed():
            return
        try:
            running = asyncio.get_running_loop()
        except RuntimeError:
            running = None
        if running is loop:
            for queue in subscribers:
                _offer(queue, entry)
        else:
            for queue in subscribers:
                loop.call_soon_threadsafe(_offer, queue, entry)

    def recent(self, limit: int = 500, source: str | None = None) -> list[LogEntry]:
        with self._lock:
            entries = list(self._entries)
        if source:
            entries = [entry for entry in entries if entry.source == source]
        return entries[-limit:] if limit > 0 else entries

    def sources(self) -> list[str]:
        with self._lock:
            return sorted({entry.source for entry in self._entries})

    def subscribe(self, maxsize: int = 2000) -> asyncio.Queue[LogEntry]:
        queue: asyncio.Queue[LogEntry] = asyncio.Queue(maxsize=maxsize)
        with self._lock:
            self._subscribers.add(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue[LogEntry]) -> None:
        with self._lock:
            self._subscribers.discard(queue)

    def flush_suppressed(self) -> None:
        with self._lock:
            pending = [(source, bucket.suppressed) for source, bucket in self._buckets.items() if bucket.suppressed]
            for source, _ in pending:
                self._buckets[source].suppressed = 0
        for source, count in pending:
            self.publish(
                source,
                f"[wgproxy] {count} log line(s) from {source} suppressed (rate limit {self._rate:g}/s)",
                level="WARN",
                throttle=False,
            )

    async def run_flusher(self, interval: float = 5.0) -> None:
        while True:
            await asyncio.sleep(interval)
            self.flush_suppressed()


class HubLogHandler(logging.Handler):
    """Mirrors application log records into the hub (source "app")."""

    def __init__(self, hub: LogHub):
        super().__init__()
        self.hub = hub

    def emit(self, record: logging.LogRecord) -> None:
        try:
            message = self.format(record)
            level = "WARN" if record.levelname == "WARNING" else record.levelname
            self.hub.publish("app", message, level=level, throttle=False)
        except Exception:  # pragma: no cover - logging must never raise
            self.handleError(record)
