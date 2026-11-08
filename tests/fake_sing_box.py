"""Stand-in for the sing-box binary, used by the engine tests.

Supports ``version``, ``check -c FILE`` and ``run -c FILE``:

* ``check`` fails when an endpoint tag listed in FAKE_SINGBOX_REJECT_TAGS is present;
* ``run`` binds every inbound port on its ``listen`` address, records its state in ``FILE.state.json`` and
  exits cleanly on SIGTERM. FAKE_SINGBOX_BUSY_PORTS simulates "address already in use" and
  FAKE_SINGBOX_FATAL_TAGS a fatal start error of an endpoint (both comma-separated).
"""

from __future__ import annotations

import json
import os
import select
import signal
import socket
import sys
import time


def _env_set(name: str) -> set[str]:
    return {item.strip() for item in os.environ.get(name, "").split(",") if item.strip()}


def _load(path: str) -> dict:
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def _write_state(path: str, state: dict) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as handle:
        json.dump(state, handle)
    os.replace(tmp, path)


def check(path: str) -> int:
    config = _load(path)
    rejected = {endpoint["tag"] for endpoint in config.get("endpoints", [])} & _env_set("FAKE_SINGBOX_REJECT_TAGS")
    if rejected:
        print(f"FATAL[0000] initialize endpoint[0]: simulated rejection of {sorted(rejected)[0]}")
        return 1
    return 0


def run(path: str) -> int:
    config = _load(path)
    for endpoint in config.get("endpoints", []):
        if endpoint["tag"] in _env_set("FAKE_SINGBOX_FATAL_TAGS"):
            print(f"FATAL[0000] start service: start endpoint/wireguard[{endpoint['tag']}]: simulated failure", flush=True)
            return 1
    busy = {int(port) for port in _env_set("FAKE_SINGBOX_BUSY_PORTS")}
    listeners = []
    for inbound in config.get("inbounds", []):
        port, tag, host = inbound["listen_port"], inbound["tag"], inbound["listen"]
        shown_host = f"[{host}]" if ":" in host else host
        message = (
            f"FATAL[0000] start service: start inbound: start inbound/mixed[{tag}]: "
            f"listen tcp {shown_host}:{port}: bind: address already in use"
        )
        sock = socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            if port in busy:
                raise OSError("simulated")
            sock.bind((host, port))
            sock.listen(16)
        except OSError:
            print(message, flush=True)
            return 1
        listeners.append(sock)

    state_path = path + ".state.json"
    state = {
        "pid": os.getpid(),
        "started": time.time(),
        "ports": [inbound["listen_port"] for inbound in config.get("inbounds", [])],
        "listen": [inbound["listen"] for inbound in config.get("inbounds", [])],
        "tags": [endpoint["tag"] for endpoint in config.get("endpoints", [])],
        "detours": [endpoint.get("detour") for endpoint in config.get("endpoints", [])],
        "gomemlimit": os.environ.get("GOMEMLIMIT"),
        "stopped": None,
    }
    _write_state(state_path, state)
    stopping = False

    def on_term(signum, frame):  # noqa: ARG001
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, on_term)
    print("+0000 2026-01-01 00:00:00 WARN fake sing-box running", flush=True)
    while not stopping:
        readable, _, _ = select.select(listeners, [], [], 0.1) if listeners else ([], [], time.sleep(0.1))
        for sock in readable:
            with __import__("contextlib").suppress(OSError):
                connection, _ = sock.accept()
                connection.close()
    for sock in listeners:
        sock.close()
    state["stopped"] = time.time()
    _write_state(state_path, state)
    return 0


def main(argv: list[str]) -> int:
    args = [arg for arg in argv if arg != "--disable-color"]
    if not args:
        return 2
    if args[0] == "version":
        print("sing-box version 1.14.4\n\nEnvironment: fake")
        return 0
    if args[0] in {"check", "run"} and len(args) >= 3 and args[1] == "-c":
        return check(args[2]) if args[0] == "check" else run(args[2])
    print(f"unsupported arguments: {argv}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
