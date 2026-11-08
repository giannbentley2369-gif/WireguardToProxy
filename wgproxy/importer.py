"""Importing WireGuard configs from uploads (.conf / .zip) and pasted text."""

from __future__ import annotations

import asyncio
import io
import re
import zipfile
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import asdict, dataclass, field
from pathlib import PurePosixPath
from typing import Any

from .config import DEFAULT_LISTEN_HOST
from .db import Database
from .ports import NoFreePortError, PortAllocator, port_probe, reserved_ports
from .settings import SettingsStore
from .wgconf import MAX_CONF_SIZE, ConfParseError, WireGuardConfig, parse_wireguard_conf

MAX_UPLOAD_BYTES = 20 * 1024 * 1024
MAX_ZIP_ENTRIES = 2000
MAX_ZIP_UNCOMPRESSED = 50 * 1024 * 1024
MAX_NAME_LENGTH = 64

Validator = Callable[[WireGuardConfig], Awaitable[str | None]]


class UploadError(ValueError):
    pass


@dataclass
class Candidate:
    source: str
    name_hint: str
    text: str = ""
    error: str | None = None


@dataclass
class Outcome:
    source: str
    status: str  # added | error
    name: str | None = None
    proxy_id: int | None = None
    port: int | None = None
    warnings: list[str] = field(default_factory=list)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def sanitize_name(raw: str) -> str:
    """Turn a file name or user input into a tag-safe proxy name ([A-Za-z0-9._-])."""
    name = re.sub(r"[^A-Za-z0-9._-]+", "-", raw.strip())
    name = re.sub(r"-{2,}", "-", name).strip("-.")
    return name[:MAX_NAME_LENGTH].rstrip("-.") or "wg"


def unique_name(base: str, existing_lower: Iterable[str]) -> str:
    taken = set(existing_lower)
    if base.lower() not in taken:
        return base
    counter = 2
    while True:
        suffix = f"-{counter}"
        candidate = base[: MAX_NAME_LENGTH - len(suffix)] + suffix
        if candidate.lower() not in taken:
            return candidate
        counter += 1


def name_from_filename(filename: str) -> str:
    base = PurePosixPath(filename.replace("\\", "/")).name
    if base.lower().endswith(".conf"):
        base = base[:-5]
    return sanitize_name(base)


def _decode(data: bytes) -> str:
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise UploadError("not a UTF-8 text file") from None


def candidates_from_upload(filename: str, data: bytes) -> list[Candidate]:
    """Expand one uploaded file (.conf or .zip) into import candidates."""
    if filename.lower().endswith(".zip") or data[:4] == b"PK\x03\x04":
        return _candidates_from_zip(filename, data)
    if len(data) > MAX_CONF_SIZE:
        return [Candidate(filename, name_from_filename(filename), error="file is larger than 64 KiB")]
    try:
        text = _decode(data)
    except UploadError as exc:
        return [Candidate(filename, name_from_filename(filename), error=str(exc))]
    return [Candidate(filename, name_from_filename(filename), text)]


def _candidates_from_zip(filename: str, data: bytes) -> list[Candidate]:
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        raise UploadError(f"{filename}: not a valid zip archive") from None
    with archive:
        entries = [info for info in archive.infolist() if not info.is_dir()]
        if len(entries) > MAX_ZIP_ENTRIES:
            raise UploadError(f"{filename}: too many files in the archive (limit {MAX_ZIP_ENTRIES})")
        candidates: list[Candidate] = []
        total = 0
        for info in entries:
            path = PurePosixPath(info.filename.replace("\\", "/"))
            if not path.name.lower().endswith(".conf") or path.name.startswith(".") or "__MACOSX" in path.parts:
                continue
            source = f"{filename}/{info.filename}"
            if info.file_size > MAX_CONF_SIZE:
                candidates.append(Candidate(source, name_from_filename(path.name), error="file is larger than 64 KiB"))
                continue
            total += info.file_size
            if total > MAX_ZIP_UNCOMPRESSED:
                raise UploadError(f"{filename}: archive expands to more than {MAX_ZIP_UNCOMPRESSED // 2**20} MiB")
            try:
                with archive.open(info) as handle:
                    raw = handle.read(MAX_CONF_SIZE + 1)
            except (zipfile.BadZipFile, RuntimeError, OSError, NotImplementedError) as exc:
                candidates.append(Candidate(source, name_from_filename(path.name), error=f"cannot extract: {exc}"))
                continue
            if len(raw) > MAX_CONF_SIZE:
                candidates.append(Candidate(source, name_from_filename(path.name), error="file is larger than 64 KiB"))
                continue
            try:
                candidates.append(Candidate(source, name_from_filename(path.name), _decode(raw)))
            except UploadError as exc:
                candidates.append(Candidate(source, name_from_filename(path.name), error=str(exc)))
    if not candidates:
        raise UploadError(f"{filename}: the archive contains no .conf files")
    return candidates


class Importer:
    def __init__(
        self,
        db: Database,
        store: SettingsStore,
        webui_port: int,
        running_ports: Callable[[], set[int]] = set,
        validator: Validator | None = None,
        listen_host: str = DEFAULT_LISTEN_HOST,
    ):
        self.db = db
        self.store = store
        self.webui_port = webui_port
        self.listen_host = listen_host
        self.running_ports = running_ports
        self.validator = validator

    async def import_candidates(self, candidates: list[Candidate], *, enable: bool = True) -> list[Outcome]:
        outcomes: list[Outcome | None] = [None] * len(candidates)
        parsed: list[tuple[int, Candidate, WireGuardConfig]] = []
        for index, candidate in enumerate(candidates):
            if candidate.error:
                outcomes[index] = Outcome(candidate.source, "error", error=candidate.error)
                continue
            try:
                parsed.append((index, candidate, parse_wireguard_conf(candidate.text)))
            except ConfParseError as exc:
                outcomes[index] = Outcome(candidate.source, "error", error=str(exc))

        errors = await self._validate_all([conf for _, _, conf in parsed])
        settings = self.store.load()
        allocator = PortAllocator(
            settings.port_range_start,
            settings.port_range_end,
            reserved_ports(self.webui_port, settings.upstream_host, settings.upstream_port),
            probe=port_probe(self.listen_host),
        )
        for (index, candidate, conf), validation_error in zip(parsed, errors):
            if validation_error:
                outcomes[index] = Outcome(
                    candidate.source, "error", error=f"sing-box rejected this configuration: {validation_error}"
                )
                continue
            outcomes[index] = self._insert(candidate, conf, allocator, enable)
        return [outcome for outcome in outcomes if outcome is not None]

    async def _validate_all(self, confs: list[WireGuardConfig]) -> list[str | None]:
        if self.validator is None or not confs:
            return [None] * len(confs)
        validator = self.validator
        limiter = asyncio.Semaphore(8)

        async def run(conf: WireGuardConfig) -> str | None:
            async with limiter:
                return await validator(conf)

        return list(await asyncio.gather(*(run(conf) for conf in confs)))

    def _insert(self, candidate: Candidate, conf: WireGuardConfig, allocator: PortAllocator, enable: bool) -> Outcome:
        rows = self.db.list_proxies()
        peer_keys = set(conf.peer_public_keys)
        same_key = [row for row in rows if row.private_key == conf.private_key]
        exact = next((row for row in same_key if row.peer_key_set & peer_keys), None)
        if exact is not None:
            return Outcome(
                candidate.source,
                "error",
                error=f"duplicate of '{exact.name}' (same private key and server): two sessions would conflict",
            )
        warnings = list(conf.warnings)
        if same_key:
            others = ", ".join(row.name for row in same_key[:3]) + ("..." if len(same_key) > 3 else "")
            warnings.append(
                f"shares its private key with {others}; fine for providers that issue one key per device"
            )
        name = unique_name(sanitize_name(candidate.name_hint), (row.name.lower() for row in rows))
        try:
            port = allocator.allocate(self.db.used_ports() | self.running_ports())
        except NoFreePortError as exc:
            return Outcome(candidate.source, "error", error=str(exc))
        proxy_id = self.db.insert_proxy(
            name=name,
            conf_text=candidate.text.lstrip("\ufeff"),
            private_key=conf.private_key,
            peer_keys=" ".join(sorted(peer_keys)),
            endpoint=conf.primary_endpoint,
            port=port,
            enabled=enable,
        )
        return Outcome(candidate.source, "added", name=name, proxy_id=proxy_id, port=port, warnings=warnings)
