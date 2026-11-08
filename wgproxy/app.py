"""FastAPI application factory."""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import AsyncIterator
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from . import __version__
from .api import router as api_router
from .config import AppConfig
from .engine import EngineTimings
from .pages import router as pages_router
from .security import SecurityMiddleware
from .services import build_services

log = logging.getLogger("wgproxy.app")
STATIC_DIR = Path(__file__).parent / "static"


def create_app(
    cfg: AppConfig | None = None,
    *,
    background: bool = True,
    timings: EngineTimings | None = None,
) -> FastAPI:
    """Build the app. ``background=False`` skips the engine and monitors (used by API tests)."""
    cfg = cfg or AppConfig.from_env()
    services = build_services(cfg, timings=timings)

    @contextlib.asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        services.hub.bind_loop(asyncio.get_running_loop())
        tasks: list[asyncio.Task[None]] = []
        if background:
            log.info("starting (data directory %s)", cfg.data_dir)
            await services.engine.start()
            tasks = [
                asyncio.create_task(services.upstream.run(), name="upstream-monitor"),
                asyncio.create_task(services.tester.auto_loop(), name="auto-test"),
                asyncio.create_task(services.hub.run_flusher(), name="log-flusher"),
            ]
        try:
            yield
        finally:
            log.info("shutting down")
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            await services.tester.shutdown()
            if background:
                await services.engine.shutdown()
            services.close()

    app = FastAPI(
        title="WireGuard to Proxy",
        version=__version__,
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.services = services
    app.add_middleware(SecurityMiddleware, cfg=cfg, auth=services.auth)
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
    app.include_router(api_router)
    app.include_router(pages_router)

    @app.get("/healthz", include_in_schema=False)
    async def healthz() -> dict[str, str]:
        return {"status": "ok", "engine": services.engine.state}

    return app
