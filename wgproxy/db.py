"""SQLite persistence: proxies (including the port manifest), settings and test results."""

from __future__ import annotations

import json
import sqlite3
import threading
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, fields
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS proxies (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    name         TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    conf_text    TEXT    NOT NULL,
    private_key  TEXT    NOT NULL,
    peer_keys    TEXT    NOT NULL,
    endpoint     TEXT    NOT NULL,
    port         INTEGER NOT NULL UNIQUE,
    enabled      INTEGER NOT NULL DEFAULT 1,
    shard        INTEGER,
    engine_error TEXT,
    notice       TEXT,
    status       TEXT    NOT NULL DEFAULT 'unknown',
    exit_ip      TEXT,
    country      TEXT,
    country_code TEXT,
    city         TEXT,
    latency_ms   INTEGER,
    check_error  TEXT,
    checked_at   TEXT,
    created_at   TEXT    NOT NULL,
    updated_at   TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS proxies_private_key ON proxies (private_key);
"""


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


@dataclass
class ProxyRow:
    id: int
    name: str
    conf_text: str
    private_key: str
    peer_keys: str
    endpoint: str
    port: int
    enabled: bool
    shard: int | None
    engine_error: str | None
    notice: str | None
    status: str
    exit_ip: str | None
    country: str | None
    country_code: str | None
    city: str | None
    latency_ms: int | None
    check_error: str | None
    checked_at: str | None
    created_at: str
    updated_at: str

    @property
    def peer_key_set(self) -> set[str]:
        return set(self.peer_keys.split())

    @property
    def active(self) -> bool:
        """Enabled and not quarantined by the engine."""
        return self.enabled and not self.engine_error

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> ProxyRow:
        data = {f.name: row[f.name] for f in fields(cls)}
        data["enabled"] = bool(data["enabled"])
        return cls(**data)


_UPDATABLE = {
    f.name for f in fields(ProxyRow) if f.name not in {"id", "created_at", "updated_at"}
}


class Database:
    """Thread-safe wrapper around a single SQLite connection (WAL mode)."""

    def __init__(self, path: Path | str):
        self.path = Path(path)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False, isolation_level=None, timeout=10)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.executescript(_SCHEMA)
            self._conn.execute(
                "INSERT OR IGNORE INTO meta (key, value) VALUES ('schema_version', ?)", (str(SCHEMA_VERSION),)
            )

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                yield self._conn
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
            self._conn.execute("COMMIT")

    # -- settings -------------------------------------------------------------------------

    def get_settings(self) -> dict[str, Any]:
        with self._lock:
            rows = self._conn.execute("SELECT key, value FROM settings").fetchall()
        result: dict[str, Any] = {}
        for row in rows:
            try:
                result[row["key"]] = json.loads(row["value"])
            except json.JSONDecodeError:
                continue
        return result

    def set_settings(self, values: dict[str, Any]) -> None:
        with self.transaction() as conn:
            conn.executemany(
                "INSERT INTO settings (key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                [(key, json.dumps(value)) for key, value in values.items()],
            )

    def delete_setting(self, key: str) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM settings WHERE key = ?", (key,))

    # -- proxies --------------------------------------------------------------------------

    def list_proxies(self) -> list[ProxyRow]:
        with self._lock:
            rows = self._conn.execute("SELECT * FROM proxies ORDER BY name COLLATE NOCASE").fetchall()
        return [ProxyRow.from_row(row) for row in rows]

    def get_proxy(self, proxy_id: int) -> ProxyRow | None:
        with self._lock:
            row = self._conn.execute("SELECT * FROM proxies WHERE id = ?", (proxy_id,)).fetchone()
        return ProxyRow.from_row(row) if row else None

    def get_proxies(self, ids: Iterable[int]) -> list[ProxyRow]:
        wanted = set(ids)
        return [row for row in self.list_proxies() if row.id in wanted]

    def find_by_name(self, name: str) -> ProxyRow | None:
        with self._lock:
            row = self._conn.execute("SELECT * FROM proxies WHERE name = ? COLLATE NOCASE", (name,)).fetchone()
        return ProxyRow.from_row(row) if row else None

    def insert_proxy(
        self,
        *,
        name: str,
        conf_text: str,
        private_key: str,
        peer_keys: str,
        endpoint: str,
        port: int,
        enabled: bool,
    ) -> int:
        now = utcnow_iso()
        with self._lock:
            cursor = self._conn.execute(
                "INSERT INTO proxies (name, conf_text, private_key, peer_keys, endpoint, port, enabled, "
                "created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (name, conf_text, private_key, peer_keys, endpoint, port, int(enabled), now, now),
            )
        return int(cursor.lastrowid)

    def update_proxy(self, proxy_id: int, **values: Any) -> None:
        self.update_proxies([proxy_id], **values)

    def update_proxies(self, ids: Iterable[int], **values: Any) -> int:
        unknown = set(values) - _UPDATABLE
        if unknown:
            raise ValueError(f"unknown proxy fields: {sorted(unknown)}")
        id_list = list(ids)
        if not id_list or not values:
            return 0
        values = {key: int(value) if isinstance(value, bool) else value for key, value in values.items()}
        assignments = ", ".join(f"{key} = ?" for key in values)
        params = [*values.values(), utcnow_iso()]
        placeholders = ", ".join("?" for _ in id_list)
        with self._lock:
            cursor = self._conn.execute(
                f"UPDATE proxies SET {assignments}, updated_at = ? WHERE id IN ({placeholders})",
                [*params, *id_list],
            )
        return cursor.rowcount

    def delete_proxies(self, ids: Iterable[int]) -> int:
        id_list = list(ids)
        if not id_list:
            return 0
        placeholders = ", ".join("?" for _ in id_list)
        with self._lock:
            cursor = self._conn.execute(f"DELETE FROM proxies WHERE id IN ({placeholders})", id_list)
        return cursor.rowcount

    def used_ports(self) -> set[int]:
        with self._lock:
            rows = self._conn.execute("SELECT port FROM proxies").fetchall()
        return {int(row["port"]) for row in rows}

    def clear_engine_errors(self) -> None:
        with self._lock:
            self._conn.execute("UPDATE proxies SET engine_error = NULL WHERE engine_error IS NOT NULL")

    def clear_shards(self) -> None:
        with self._lock:
            self._conn.execute("UPDATE proxies SET shard = NULL")
