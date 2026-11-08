"""Construction and wiring of the application's long-lived services."""

from __future__ import annotations

import logging
from dataclasses import dataclass

from .config import AppConfig
from .db import Database
from .engine import Engine, EngineTimings
from .hosts import export_host
from .importer import Importer
from .logs import HubLogHandler, LogHub
from .security import Auth, host_name, load_or_create_secret
from .settings import SettingsStore
from .tester import Tester
from .upstream import UpstreamMonitor


@dataclass
class Services:
    cfg: AppConfig
    db: Database
    store: SettingsStore
    hub: LogHub
    upstream: UpstreamMonitor
    engine: Engine
    tester: Tester
    importer: Importer
    auth: Auth

    def export_host(self, host_header: str = "") -> str:
        """Host for exported proxy URLs: WGPROXY_PUBLIC_HOST, then the Settings value, then
        a specific listen address, then the host this request reached the WebUI at."""
        public = self.cfg.public_host or self.store.load().public_host
        return export_host(public, self.cfg.listen_host, host_name(host_header))

    def close(self) -> None:
        self.db.close()


def _attach_log_handler(hub: LogHub) -> None:
    logger = logging.getLogger("wgproxy")
    for handler in list(logger.handlers):
        if isinstance(handler, HubLogHandler):
            logger.removeHandler(handler)
    handler = HubLogHandler(hub)
    handler.setFormatter(logging.Formatter("%(name)s: %(message)s"))
    logger.addHandler(handler)
    if logger.level == logging.NOTSET:
        logger.setLevel(logging.INFO)


def build_services(cfg: AppConfig, timings: EngineTimings | None = None) -> Services:
    cfg.data_dir.mkdir(parents=True, exist_ok=True)
    cfg.engine_dir.mkdir(parents=True, exist_ok=True)
    db = Database(cfg.db_path)
    store = SettingsStore(db)
    store.ensure_initialized()
    hub = LogHub()
    _attach_log_handler(hub)
    upstream = UpstreamMonitor(store)
    engine = Engine(cfg, db, store, hub, upstream_probe=upstream.probe, timings=timings)
    upstream.on_reachable = engine.request_apply
    tester = Tester(db, store, host=cfg.connect_host)
    importer = Importer(
        db,
        store,
        cfg.webui_port,
        running_ports=engine.running_ports,
        validator=engine.validate_tunnel,
        listen_host=cfg.listen_host,
    )
    auth = Auth(
        store,
        load_or_create_secret(cfg.secret_path),
        username=cfg.webui_username,
        env_password=cfg.webui_password,
    )
    return Services(cfg, db, store, hub, upstream, engine, tester, importer, auth)
