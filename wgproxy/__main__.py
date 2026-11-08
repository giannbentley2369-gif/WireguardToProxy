"""Command line entry point: ``python -m wgproxy [serve|healthcheck|reset-ui-password]``."""

from __future__ import annotations

import argparse
import logging
import os
import sys
import urllib.request

from . import __version__
from .config import AppConfig, ConfigError
from .hosts import url_host


def _setup_logging(level: str) -> None:
    logging.basicConfig(
        level=level if level in logging.getLevelNamesMapping() else "INFO",
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        stream=sys.stdout,
    )
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)


def serve() -> int:
    import uvicorn

    from .app import create_app

    os.umask(0o077)  # database, keys and generated configs are private
    cfg = AppConfig.from_env()
    # sing-box and every other child process inherit os.environ; the WebUI password stays here.
    os.environ.pop("WGPROXY_WEBUI_PASSWORD", None)
    _setup_logging(cfg.log_level)
    config = uvicorn.Config(
        create_app(cfg),
        host=cfg.listen_host,
        port=cfg.webui_port,
        log_config=None,
        access_log=False,
        server_header=False,
        proxy_headers=False,
        timeout_graceful_shutdown=5,
        lifespan="on",
    )
    uvicorn.Server(config).run()
    return 0


def healthcheck_url(cfg: AppConfig) -> str:
    # connect_host: a wildcard bind (0.0.0.0 / ::) is checked on loopback, a specific address as is.
    return f"http://{url_host(cfg.connect_host)}:{cfg.webui_port}/healthz"


def healthcheck() -> int:
    url = healthcheck_url(AppConfig.from_env())
    try:
        with urllib.request.urlopen(url, timeout=4) as response:  # noqa: S310 - URL built from validated config
            return 0 if response.status == 200 else 1
    except Exception as exc:
        print(f"healthcheck failed: {exc}", file=sys.stderr)
        return 1


def reset_ui_password() -> int:
    from .db import Database
    from .settings import SettingsStore

    cfg = AppConfig.from_env()
    db = Database(cfg.db_path)
    try:
        SettingsStore(db).set_ui_password_hash("")
    finally:
        db.close()
    if cfg.webui_password:
        print("Settings-page password removed. WGPROXY_WEBUI_PASSWORD is set, so the WebUI still asks for that login.")
    else:
        print("WebUI password removed; the WebUI no longer asks for a password.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="wgproxy", description="WireGuard configs as local SOCKS5/HTTP proxies")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(dest="command")
    commands.add_parser("serve", help="run the WebUI and the engine (default)")
    commands.add_parser("healthcheck", help="exit 0 when the WebUI answers on its listen address")
    commands.add_parser("reset-ui-password", help="remove the WebUI password set on the Settings page")
    args = parser.parse_args(argv)
    handlers = {"serve": serve, "healthcheck": healthcheck, "reset-ui-password": reset_ui_password}
    try:
        return handlers[args.command or "serve"]()
    except ConfigError as exc:
        print(f"wgproxy: configuration error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
