"""Server-rendered page shells; data is loaded by the page scripts from the JSON API."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates

from . import __version__

TEMPLATES_DIR = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
router = APIRouter()


def _render(request: Request, template: str, page: str, title: str, **context: Any) -> HTMLResponse:
    services = request.app.state.services
    return templates.TemplateResponse(
        request,
        template,
        {"page": page, "title": title, "version": __version__, "auth_enabled": services.auth.enabled(), **context},
    )


@router.get("/", response_class=HTMLResponse)
async def dashboard(request: Request) -> HTMLResponse:
    return _render(request, "dashboard.html", "dashboard", "Dashboard")


@router.get("/add", response_class=HTMLResponse)
async def add_configs(request: Request) -> HTMLResponse:
    return _render(request, "add.html", "add", "Add configs")


@router.get("/logs", response_class=HTMLResponse)
async def logs(request: Request) -> HTMLResponse:
    return _render(request, "logs.html", "logs", "Engine & logs")


@router.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request) -> HTMLResponse:
    return _render(request, "settings.html", "settings", "Settings")


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, next: str = "/") -> Response:
    if not request.app.state.services.auth.enabled():
        return RedirectResponse("/", status_code=303)
    safe_next = next if next.startswith("/") and not next.startswith("//") else "/"
    return _render(request, "login.html", "login", "Log in", next_url=safe_next)
