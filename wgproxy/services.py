"""Construction and wiring of the application's long-lived services."""

from __future__ import annotations

import logging
from dataclasses import dataclass

from .config import AppConfig
from .db import Database
from .engine import Engine, EngineTimings
from .importer import Importer
from .logs import HubLogHandler, LogHub
from .security import Auth, load_or_create_secret
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
    tester = Tester(db, store)
    importer = Importer(
        db, store, cfg.webui_port, running_ports=engine.running_ports, validator=engine.validate_tunnel
    )
    auth = Auth(store, load_or_create_secret(cfg.secret_path))
    return Services(cfg, db, store, hub, upstream, engine, tester, importer, auth)
