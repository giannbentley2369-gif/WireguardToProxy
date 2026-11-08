"""JSON API used by the WebUI (and usable from scripts with HTTP Basic auth)."""

from __future__ import annotations

import asyncio
import io
import json
import zipfile
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Body, Depends, File, Form, HTTPException, Query, Request, Response, UploadFile
from fastapi.responses import PlainTextResponse, StreamingResponse
from pydantic import BaseModel, Field, ValidationError

from . import __version__
from .config import MIN_PASSWORD_LENGTH
from .db import ProxyRow
from .importer import MAX_UPLOAD_BYTES, Candidate, Outcome, UploadError, candidates_from_upload, sanitize_name
from .ports import PortAllocator, PortValidationError, port_probe, reserved_ports
from .security import SESSION_COOKIE, LoginThrottled
from .services import Services
from .settings import ENGINE_KEYS, generate_password
from .tester import proxy_url
from .wgconf import MAX_CONF_SIZE, ConfParseError, parse_wireguard_conf

router = APIRouter(prefix="/api")


def get_services(request: Request) -> Services:
    return request.app.state.services


Svc = Annotated[Services, Depends(get_services)]


def proxy_view(row: ProxyRow, runtime: str | None) -> dict[str, Any]:
    """Proxy as shown in the dashboard, with one combined ``status``."""
    if not row.enabled:
        status = "disabled"
    elif row.engine_error:
        status = "error"
    elif runtime is None:
        status = "pending"
    elif runtime != "running":
        status = runtime  # starting | backoff | failed | stopped
    else:
        status = row.status  # ok | dead | unknown (result of the last test)
    return {
        "id": row.id,
        "name": row.name,
        "port": row.port,
        "enabled": row.enabled,
        "status": status,
        "runtime": runtime,
        "check_status": row.status,
        "endpoint": row.endpoint,
        "exit_ip": row.exit_ip,
        "country": row.country,
        "country_code": row.country_code,
        "city": row.city,
        "latency_ms": row.latency_ms,
        "check_error": row.check_error,
        "checked_at": row.checked_at,
        "engine_error": row.engine_error,
        "notice": row.notice,
        "shard": row.shard,
        "created_at": row.created_at,
        "updated_at": row.updated_at,
    }


def _require_proxy(svc: Services, proxy_id: int) -> ProxyRow:
    row = svc.db.get_proxy(proxy_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Proxy not found")
    return row


def _validation_message(exc: ValidationError) -> str:
    parts = []
    for error in exc.errors():
        location = ".".join(str(item) for item in error.get("loc", ()))
        message = str(error.get("msg", "invalid value")).removeprefix("Value error, ")
        parts.append(f"{location}: {message}" if location else message)
    return "; ".join(parts)


# -- status -------------------------------------------------------------------------------


@router.get("/status")
async def get_status(svc: Svc, request: Request) -> dict[str, Any]:
    settings = svc.store.load()
    rows = svc.db.list_proxies()
    states = svc.engine.proxy_states()
    views = [proxy_view(row, states.get(row.id)) for row in rows]
    return {
        "version": __version__,
        "listen_host": svc.cfg.listen_host,
        "export_host": svc.export_host(request.headers.get("host", "")),
        "auth_enabled": svc.auth.enabled(),
        "engine": svc.engine.snapshot(),
        "upstream": svc.upstream.snapshot() | {"configured": settings.upstream_enabled},
        "test": svc.tester.snapshot(),
        "credentials": {"username": settings.proxy_username, "password": settings.proxy_password},
        "counts": {
            "total": len(views),
            "enabled": sum(1 for view in views if view["enabled"]),
            "ok": sum(1 for view in views if view["status"] == "ok"),
            "dead": sum(1 for view in views if view["status"] == "dead"),
            "errors": sum(1 for view in views if view["status"] in {"error", "failed", "backoff"}),
        },
    }


# -- proxies ------------------------------------------------------------------------------


@router.get("/proxies")
async def list_proxies(svc: Svc) -> list[dict[str, Any]]:
    states = svc.engine.proxy_states()
    return [proxy_view(row, states.get(row.id)) for row in svc.db.list_proxies()]


@router.get("/proxies/{proxy_id}")
async def get_proxy(proxy_id: int, svc: Svc) -> dict[str, Any]:
    row = _require_proxy(svc, proxy_id)
    view = proxy_view(row, svc.engine.proxy_states().get(row.id))
    try:
        view["config"] = parse_wireguard_conf(row.conf_text).summary()
    except ConfParseError as exc:
        view["config"] = {"error": str(exc)}
    return view


@router.post("/proxies/import")
async def import_files(
    svc: Svc,
    files: Annotated[list[UploadFile], File(description=".conf files and/or .zip archives")],
    enable: Annotated[bool, Form()] = True,
) -> dict[str, Any]:
    candidates: list[Candidate] = []
    failures: list[Outcome] = []
    for upload in files:
        name = upload.filename or "upload.conf"
        data = await upload.read(MAX_UPLOAD_BYTES + 1)
        if len(data) > MAX_UPLOAD_BYTES:
            failures.append(Outcome(name, "error", error=f"larger than {MAX_UPLOAD_BYTES // 2**20} MiB"))
            continue
        try:
            candidates.extend(candidates_from_upload(name, data))
        except UploadError as exc:
            failures.append(Outcome(name, "error", error=str(exc)))
    outcomes = failures + await svc.importer.import_candidates(candidates, enable=enable)
    if any(outcome.status == "added" for outcome in outcomes):
        svc.engine.request_apply()
    return {"results": [outcome.to_dict() for outcome in outcomes]}


class PasteRequest(BaseModel):
    name: str = Field("", max_length=200)
    text: str = Field(..., min_length=1, max_length=MAX_CONF_SIZE)
    enable: bool = True


@router.post("/proxies/paste")
async def paste_config(body: PasteRequest, svc: Svc) -> dict[str, Any]:
    hint = sanitize_name(body.name) if body.name.strip() else "pasted"
    outcomes = await svc.importer.import_candidates([Candidate("pasted text", hint, body.text)], enable=body.enable)
    if any(outcome.status == "added" for outcome in outcomes):
        svc.engine.request_apply()
    return {"results": [outcome.to_dict() for outcome in outcomes]}


class ProxyPatch(BaseModel):
    enabled: bool | None = None
    name: str | None = Field(None, min_length=1, max_length=200)
    port: int | None = None


@router.patch("/proxies/{proxy_id}")
async def update_proxy(proxy_id: int, body: ProxyPatch, svc: Svc) -> dict[str, Any]:
    row = _require_proxy(svc, proxy_id)
    changes: dict[str, Any] = {}
    if body.name is not None:
        name = sanitize_name(body.name)
        other = svc.db.find_by_name(name)
        if other is not None and other.id != row.id:
            raise HTTPException(status_code=409, detail=f"The name {name!r} is already used")
        if name != row.name:
            changes["name"] = name
    if body.port is not None and body.port != row.port:
        settings = svc.store.load()
        allocator = PortAllocator(
            settings.port_range_start,
            settings.port_range_end,
            reserved_ports(svc.cfg.webui_port, settings.upstream_host, settings.upstream_port),
            probe=port_probe(svc.cfg.listen_host),
        )
        taken = (svc.db.used_ports() | svc.engine.running_ports()) - {row.port}
        try:
            allocator.validate_override(body.port, taken, current=row.port)
        except PortValidationError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from None
        changes.update(port=body.port, notice=None)
    if body.enabled is not None:
        if body.enabled != row.enabled:
            changes["enabled"] = body.enabled
        if body.enabled and row.engine_error:
            changes["engine_error"] = None  # re-enabling retries a quarantined tunnel
    if changes:
        svc.db.update_proxy(row.id, **changes)
        svc.engine.request_apply()
    updated = _require_proxy(svc, proxy_id)
    return proxy_view(updated, svc.engine.proxy_states().get(updated.id))


@router.delete("/proxies/{proxy_id}")
async def delete_proxy(proxy_id: int, svc: Svc) -> dict[str, Any]:
    if not svc.db.delete_proxies([proxy_id]):
        raise HTTPException(status_code=404, detail="Proxy not found")
    svc.engine.request_apply()
    return {"deleted": 1}


class BulkRequest(BaseModel):
    action: Literal["enable", "disable", "delete", "test", "retry"]
    ids: list[int] = Field(..., min_length=1, max_length=10000)


@router.post("/proxies/bulk")
async def bulk_action(body: BulkRequest, svc: Svc) -> dict[str, Any]:
    ids = [row.id for row in svc.db.get_proxies(body.ids)]
    if body.action == "test":
        try:
            job = svc.tester.start(ids)
        except RuntimeError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from None
        return {"affected": job.total, "job": job.to_dict()}
    if body.action == "enable":
        affected = svc.db.update_proxies(ids, enabled=True, engine_error=None)
    elif body.action == "disable":
        affected = svc.db.update_proxies(ids, enabled=False)
    elif body.action == "retry":
        affected = svc.db.update_proxies(ids, engine_error=None)
    else:
        affected = svc.db.delete_proxies(ids)
    svc.engine.request_apply()
    return {"affected": affected}


@router.post("/proxies/{proxy_id}/test")
async def test_proxy(proxy_id: int, svc: Svc) -> dict[str, Any]:
    _require_proxy(svc, proxy_id)
    row = await svc.tester.test_one(proxy_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Proxy not found")
    return proxy_view(row, svc.engine.proxy_states().get(row.id))


@router.get("/proxies/{proxy_id}/conf")
async def download_conf(proxy_id: int, svc: Svc) -> PlainTextResponse:
    row = _require_proxy(svc, proxy_id)
    return PlainTextResponse(
        row.conf_text, headers={"Content-Disposition": f'attachment; filename="{row.name}.conf"'}
    )


@router.get("/backup.zip")
async def backup_zip(svc: Svc) -> Response:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for row in svc.db.list_proxies():
            archive.writestr(f"{row.name}.conf", row.conf_text)
    return Response(
        buffer.getvalue(),
        media_type="application/zip",
        headers={"Content-Disposition": 'attachment; filename="wireguard-configs.zip"'},
    )


# -- tests and export ---------------------------------------------------------------------


class TestRequest(BaseModel):
    ids: list[int] | None = None


@router.post("/tests")
async def start_tests(svc: Svc, body: TestRequest | None = None) -> dict[str, Any]:
    try:
        job = svc.tester.start(body.ids if body else None)
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from None
    return job.to_dict()


@router.get("/tests/current")
async def current_test(svc: Svc) -> dict[str, Any] | None:
    return svc.tester.snapshot()


@router.get("/export")
async def export_proxies(
    svc: Svc,
    request: Request,
    scheme: Literal["socks5", "http"] = "socks5",
    enabled_only: bool = True,
    status: Literal["any", "ok"] = "any",
    country: str = "",
    ids: str = "",
    download: bool = True,
) -> PlainTextResponse:
    """proxies.txt: one ``scheme://USER:PASS@HOST:PORT`` line per proxy (HOST: see Services.export_host)."""
    settings = svc.store.load()
    host = svc.export_host(request.headers.get("host", ""))
    rows = svc.db.list_proxies()
    if enabled_only:
        rows = [row for row in rows if row.enabled]
    if status == "ok":
        rows = [row for row in rows if row.active and row.status == "ok"]
    wanted_countries = {item.strip().upper() for item in country.split(",") if item.strip()}
    if wanted_countries:
        rows = [
            row
            for row in rows
            if (row.country_code or "").upper() in wanted_countries or (row.country or "").upper() in wanted_countries
        ]
    wanted_ids = {int(item) for item in ids.split(",") if item.strip().isdigit()}
    if wanted_ids:
        rows = [row for row in rows if row.id in wanted_ids]
    lines = [proxy_url(scheme, settings.proxy_username, settings.proxy_password, host, row.port) for row in rows]
    headers = {"Content-Disposition": 'attachment; filename="proxies.txt"'} if download else {}
    return PlainTextResponse("\n".join(lines) + ("\n" if lines else ""), headers=headers)


# -- engine and logs ----------------------------------------------------------------------


@router.get("/engine")
async def engine_status(svc: Svc) -> dict[str, Any]:
    return svc.engine.snapshot()


@router.post("/engine/restart")
async def restart_engine(svc: Svc) -> dict[str, Any]:
    svc.db.clear_engine_errors()
    svc.engine.request_apply(restart_all=True)
    return {"ok": True}


@router.get("/logs")
async def recent_logs(
    svc: Svc, limit: Annotated[int, Query(ge=1, le=5000)] = 500, source: str = ""
) -> dict[str, Any]:
    entries = svc.hub.recent(limit, source or None)
    return {"entries": [entry.to_dict() for entry in entries], "sources": svc.hub.sources()}


@router.get("/logs/stream")
async def stream_logs(request: Request, svc: Svc) -> StreamingResponse:
    """Server-sent events: recent backlog, then live entries."""
    hub = svc.hub
    try:
        after = int(request.headers.get("last-event-id") or request.query_params.get("after") or 0)
    except ValueError:
        after = 0
    queue = hub.subscribe()

    async def events():
        last = after
        try:
            for entry in hub.recent(1000):
                if entry.seq > last:
                    last = entry.seq
                    yield f"id: {entry.seq}\ndata: {json.dumps(entry.to_dict())}\n\n"
            while True:
                try:
                    entry = await asyncio.wait_for(queue.get(), timeout=15)
                except asyncio.TimeoutError:
                    yield ": keep-alive\n\n"
                    continue
                if entry.seq <= last:
                    continue
                last = entry.seq
                yield f"id: {entry.seq}\ndata: {json.dumps(entry.to_dict())}\n\n"
        finally:
            hub.unsubscribe(queue)

    return StreamingResponse(
        events(), media_type="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"}
    )


# -- settings -----------------------------------------------------------------------------


@router.get("/settings")
async def get_settings(svc: Svc, request: Request) -> dict[str, Any]:
    return svc.store.load().model_dump() | {
        "ui_password_set": svc.auth.enabled(),
        "ui_password_env": svc.auth.managed_by_env,
        "webui_username": svc.auth.username if svc.auth.managed_by_env else "",
        "webui_port": svc.cfg.webui_port,
        "listen_host": svc.cfg.listen_host,
        "public_host_env": svc.cfg.public_host,
        "export_host": svc.export_host(request.headers.get("host", "")),
    }


@router.put("/settings")
async def put_settings(svc: Svc, body: Annotated[dict[str, Any], Body()]) -> dict[str, Any]:
    try:
        settings, changed = svc.store.update(body)
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail=_validation_message(exc)) from None
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    if changed & ENGINE_KEYS:
        svc.engine.request_apply()
    if changed & {"upstream_host", "upstream_port"}:
        svc.upstream.poke()
    return {"settings": settings.model_dump(), "changed": sorted(changed)}


class UiPasswordRequest(BaseModel):
    password: str = Field("", max_length=256)


@router.post("/settings/ui-password")
async def set_ui_password(body: UiPasswordRequest, svc: Svc, response: Response) -> dict[str, Any]:
    if svc.auth.managed_by_env:
        raise HTTPException(
            status_code=409, detail="The WebUI login is set by WGPROXY_WEBUI_PASSWORD; change it there and restart"
        )
    if body.password and len(body.password) < MIN_PASSWORD_LENGTH:
        raise HTTPException(status_code=422, detail=f"Use at least {MIN_PASSWORD_LENGTH} characters")
    await asyncio.to_thread(svc.auth.set_password, body.password)
    if body.password:
        svc.auth.set_cookie(response)  # keep the current browser logged in
    else:
        response.delete_cookie(SESSION_COOKIE, path="/")
    return {"ui_password_set": bool(body.password)}


@router.post("/settings/proxy-password/regenerate")
async def regenerate_proxy_password(svc: Svc) -> dict[str, Any]:
    settings, _ = svc.store.update({"proxy_password": generate_password()})
    svc.engine.request_apply()
    return {"username": settings.proxy_username, "password": settings.proxy_password}


@router.post("/upstream/test")
async def test_upstream(svc: Svc) -> dict[str, Any]:
    result = await svc.upstream.diagnose()
    svc.upstream.poke()
    return result


# -- authentication -----------------------------------------------------------------------


class LoginRequest(BaseModel):
    username: str = Field("", max_length=256)  # only checked for the WGPROXY_WEBUI_* login
    password: str = Field(..., max_length=256)


@router.post("/auth/login")
async def login(body: LoginRequest, request: Request, svc: Svc, response: Response) -> dict[str, Any]:
    if not svc.auth.enabled():
        return {"ok": True}
    client = request.client.host if request.client else None
    try:
        ok = await svc.auth.login(client, body.username, body.password)
    except LoginThrottled as exc:
        raise HTTPException(
            status_code=429, detail=exc.detail, headers={"Retry-After": str(exc.retry_after)}
        ) from None
    if not ok:
        detail = "Wrong user name or password" if svc.auth.managed_by_env else "Wrong password"
        raise HTTPException(status_code=401, detail=detail)
    svc.auth.set_cookie(response)
    return {"ok": True}


@router.post("/auth/logout")
async def logout(response: Response) -> dict[str, Any]:
    response.delete_cookie(SESSION_COOKIE, path="/")
    return {"ok": True}
