from __future__ import annotations

import io
import zipfile
from pathlib import Path

import pytest

from wgproxy.db import Database
from wgproxy.importer import (
    Candidate,
    Importer,
    UploadError,
    candidates_from_upload,
    name_from_filename,
    sanitize_name,
    unique_name,
)
from wgproxy.settings import SettingsStore

from .conftest import free_port_range, make_conf, make_key


@pytest.fixture
def importer(tmp_path: Path):
    db = Database(tmp_path / "test.db")
    store = SettingsStore(db)
    store.ensure_initialized()
    base = free_port_range()
    store.update({"port_range_start": base, "port_range_end": base + 100})
    yield Importer(db, store, webui_port=8080), db, base
    db.close()


def test_names():
    assert name_from_filename("US-miami-1.conf") == "US-miami-1"
    assert name_from_filename("configs/Proton VPN #12.CONF") == "Proton-VPN-12"
    assert name_from_filename("C:\\Users\\me\\de_frankfurt.conf") == "de_frankfurt"
    assert sanitize_name("  ../../etc/passwd ") == "etc-passwd"
    assert sanitize_name("***") == "wg"
    assert len(sanitize_name("x" * 200)) == 64
    assert unique_name("US-1", {"us-1", "us-1-2"}) == "US-1-3"
    assert unique_name("free", {"other"}) == "free"


def _zip(files: dict[str, str]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, text in files.items():
            archive.writestr(name, text)
    return buffer.getvalue()


def test_zip_expansion_skips_noise():
    data = _zip(
        {
            "US-miami-1.conf": make_conf(),
            "nested/DE-berlin.conf": make_conf(),
            "__MACOSX/._US-miami-1.conf": "junk",
            ".hidden.conf": "junk",
            "readme.txt": "hello",
        }
    )
    candidates = candidates_from_upload("bundle.zip", data)
    assert [candidate.name_hint for candidate in candidates] == ["US-miami-1", "DE-berlin"]
    assert all(candidate.error is None for candidate in candidates)


def test_bad_uploads():
    with pytest.raises(UploadError, match="no .conf"):
        candidates_from_upload("empty.zip", _zip({"a.txt": "x"}))
    with pytest.raises(UploadError, match="not a valid zip"):
        candidates_from_upload("broken.zip", b"PK\x03\x04garbage")
    (big,) = candidates_from_upload("big.conf", b"#" * 70_000)
    assert big.error and "64 KiB" in big.error
    (binary,) = candidates_from_upload("bin.conf", b"\xff\xfe\x00bad")
    assert binary.error and "UTF-8" in binary.error


async def test_import_assigns_names_and_sequential_ports(importer):
    imp, db, base = importer
    outcomes = await imp.import_candidates(
        [Candidate("US-miami-1.conf", "US-miami-1", make_conf()), Candidate("US-miami-1 (2).conf", "US-miami-1", make_conf())]
    )
    assert [outcome.status for outcome in outcomes] == ["added", "added"]
    assert [outcome.name for outcome in outcomes] == ["US-miami-1", "US-miami-1-2"]
    assert [outcome.port for outcome in outcomes] == [base, base + 1]
    rows = db.list_proxies()
    assert {row.port for row in rows} == {base, base + 1}
    assert all(row.enabled for row in rows)


async def test_duplicates_are_rejected_but_shared_keys_only_warn(importer):
    imp, db, _ = importer
    private, peer = make_key(), make_key()
    first = make_conf(private_key=private, peer_key=peer)
    same_server = make_conf(private_key=private, peer_key=peer, endpoint="203.0.113.1:51820")
    other_server = make_conf(private_key=private)
    outcomes = await imp.import_candidates(
        [Candidate("a", "a", first), Candidate("b", "b", same_server), Candidate("c", "c", other_server)]
    )
    assert outcomes[0].status == "added"
    assert outcomes[1].status == "error" and "duplicate of 'a'" in (outcomes[1].error or "")
    assert outcomes[2].status == "added"
    assert any("shares its private key" in warning for warning in outcomes[2].warnings)
    assert len(db.list_proxies()) == 2


async def test_parse_and_validation_errors_are_reported_in_order(importer):
    imp, db, _ = importer

    async def validator(conf):
        return "simulated rejection" if conf.peers[0].endpoint_port == 666 else None

    imp.validator = validator
    outcomes = await imp.import_candidates(
        [
            Candidate("broken.conf", "broken", "[Interface]\n"),
            Candidate("evil.conf", "evil", make_conf(endpoint="198.51.100.1:666")),
            Candidate("ok.conf", "ok", make_conf()),
            Candidate("too-big.conf", "too-big", error="file is larger than 64 KiB"),
        ],
        enable=False,
    )
    assert [outcome.source for outcome in outcomes] == ["broken.conf", "evil.conf", "ok.conf", "too-big.conf"]
    assert [outcome.status for outcome in outcomes] == ["error", "error", "added", "error"]
    assert "simulated rejection" in (outcomes[1].error or "")
    (row,) = db.list_proxies()
    assert row.name == "ok" and row.enabled is False
