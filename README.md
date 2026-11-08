# WireGuard to Proxy

A self-hosted WebUI that turns WireGuard `.conf` files into local proxies. Every config becomes one
**userspace** WireGuard tunnel (sing-box with its gVisor network stack) plus one authenticated
**SOCKS5 + HTTP** listener on `127.0.0.1`, so any application on the machine can use it.

Built for a Linux laptop that also runs an outer VPN client (Throne / sing-box / Clash core) and for up
to ~150 configs:

- **Userspace only**: no kernel WireGuard, no TUN device, no routing-table or firewall changes, no
  `NET_ADMIN`.
- **Loopback only**: the WebUI and every proxy bind `127.0.0.1`.
- **Upstream-proxy aware**: tunnels dial through the outer VPN client's SOCKS5 port, so their traffic
  never meets the outer VPN's TUN.

## Contents

- [Features](#features)
- [Quick start](#quick-start)
- [Architecture](#architecture)
- [Usage](#usage)
- [Configuration reference](#configuration-reference)
- [Data directory and backups](#data-directory-and-backups)
- [Security notes](#security-notes)
- [Troubleshooting](#troubleshooting)
- [Development](#development)
- [Design choices](#design-choices)

## Features

- **Dashboard**: name (from the file name, e.g. `US-miami-1`), local port, enable toggle, status
  (OK / dead / unknown, plus engine states), exit IP, country, latency and last check. Search, filters,
  sorting and bulk actions (enable, disable, test, delete).
- **Import**: one or many `.conf` files, `.zip` archives or pasted text. Configs that repeat the private
  key *and* server of an existing config are rejected as duplicates.
- **Test all**: fetches the exit IP through every enabled proxy (25 in parallel) and looks up countries
  with the ip-api.com batch API. Results are stored with timestamps.
- **Export** `proxies.txt` as `socks5://USER:PASS@127.0.0.1:PORT` (or `http://…`), filtered by enabled
  state, last test result, country or selection.
- **Engine & logs**: live sing-box log (server-sent events) and an overview of the engine processes.
- **Settings**: upstream proxy (with a step-by-step test), proxy credentials, WebUI password, port range
  and per-proxy port overrides, DNS, MTU and keepalive, engine batching, testing.
- **Stable ports** that survive restarts and reboots, with automatic per-proxy repair when a port is
  taken.
- **Staggered start**: tunnels come up in small batches, not as one handshake burst.

## Quick start

Requirements: Linux with **Docker Engine** and the Compose plugin, on x86-64 or arm64. On Lubuntu or
Ubuntu, `sudo apt install docker.io docker-compose-v2` works. Docker Desktop is not supported: it runs
containers in a VM, where `network_mode: host` does not give access to the host's `127.0.0.1`.

```bash
git clone https://github.com/giannbentley2369-gif/WireguardToProxy.git
cd WireguardToProxy
mkdir -p data
docker compose up -d --build
```

Open <http://127.0.0.1:8080>, add configs on **Add configs**, then use any proxy:

```bash
curl -x socks5h://wgproxy:PASSWORD@127.0.0.1:20000 https://api.ipify.org
```

The proxy username and password are generated at first start and shown on the dashboard.

The default upstream is `127.0.0.1:2080` (Throne's default mixed port). If your outer VPN client listens
elsewhere, change **Settings → Upstream proxy**. To run without an outer client, clear the host
(direct mode).

To update: `git pull && docker compose up -d --build`. State in `./data` is kept.

## Architecture

### Request path

```
 application ──► 127.0.0.1:20000   sing-box "mixed" inbound (SOCKS5 + HTTP, username/password)
                   │  route rule: in-US-miami-1 → wg-US-miami-1, nothing else
                   │  destination names resolved through this tunnel (DNS from the .conf)
                   ▼
                WireGuard endpoint wg-US-miami-1   userspace ("system": false), gVisor netstack
                   │  encrypted WireGuard UDP, "detour": "upstream"
                   ▼
                127.0.0.1:2080     outer VPN client (Throne), SOCKS5 UDP ASSOCIATE on loopback
                   ▼
                outer VPN server ──► WireGuard server ──► destination
```

### The upstream proxy, and why the container is userspace-only

An outer VPN client in TUN mode captures whatever the host routing table sends to its TUN interface. If
the WireGuard tunnels sent their UDP the normal way, about a hundred raw UDP flows would be captured,
reclassified and wrapped by the outer VPN's rules, or leak around it. Either way, the home router would
see each of them.

Instead, every WireGuard endpoint in the generated sing-box configuration has `"detour": "upstream"`.
`upstream` is a SOCKS5 outbound pointing at the outer client's local port, so WireGuard's datagrams
travel over SOCKS5 UDP ASSOCIATE on the loopback interface. The TUN never captures loopback traffic, and
the datagrams leave the machine inside the outer client's own connection: the router sees one
connection. The DNS server that resolves endpoint host names (such as `miami-1.sgw.guardianapp.com`) is
wired the same way: it has `"detour": "upstream"` and is referenced by each endpoint's
`domain_resolver`.

Nothing depends on the host's routing table, so the container needs no TUN device, no `NET_ADMIN`, no
routes and no firewall rules. It therefore cannot conflict with the outer VPN's TUN, routes or marks. The
compose file drops every capability except the few the entrypoint uses to fix the ownership of `./data`
before it switches to an unprivileged user.

With an empty upstream host the app uses **direct mode**: tunnels still run in userspace, but their UDP
follows the host routing table (and therefore the outer VPN's TUN, if one is active).

**Compatibility with sing-box 1.14.x.** WireGuard endpoints accept the full set of dial fields,
including `detour` and `domain_resolver`, so no fallback is needed. This was verified with sing-box
1.14.4: WireGuard UDP and the endpoint-hostname DNS queries both arrive at the upstream as SOCKS5 UDP
associations. The legacy `wireguard` outbound type was removed in sing-box 1.13.0, so it is not
available as a fallback in 1.14.x.

The upstream must support UDP (SOCKS5 UDP ASSOCIATE). **Settings → Test upstream** checks TCP, the
SOCKS5 handshake, TCP through the proxy (showing the outer exit IP) and UDP through the proxy.

### What every generated configuration guarantees

- **Inbounds**: `mixed` on `127.0.0.1:PORT` with username/password authentication.
- **Route rules**, in order:
  1. `resolve` destination names with the tunnel's own DNS server: the `.conf`'s `DNS =`, queried
     *through that tunnel* (fallback `1.1.1.1`, also through the tunnel). Names are never resolved via
     the upstream or the host.
  2. `reject` IP families the tunnel cannot carry. IPv6 is rejected unless the `.conf` has an IPv6
     address *and* an IPv6 route.
  3. `inbound → its own endpoint`, one rule per proxy.
  4. A final catch-all `reject`. Traffic can never fall through to a default outbound.
- **Endpoints**: `"system": false`, `workers: 1`, MTU 1280 (a larger MTU in the `.conf` is capped,
  a smaller one is kept), `persistent_keepalive_interval: 25` unless the `.conf` sets
  `PersistentKeepalive`, `detour` to `upstream` (or to an explicit `direct` outbound in direct mode),
  and a `domain_resolver` pointing at the bootstrap DNS server.
- `route.default_domain_resolver` is always set. sing-box 1.14 refuses to *run* without it, even though
  `sing-box check` accepts such a config.
- Every configuration passes `sing-box check` before it replaces a running one. A tunnel that sing-box
  rejects is excluded (status *Error*) instead of blocking the others.

The generated files are `data/engine/shard-NN.json`.

### Engine processes and the staggered start

sing-box starts every endpoint of a process at the same moment, and a reload restarts all of them, so a
single process cannot stagger WireGuard handshakes. Tunnels are therefore packed into batches
("shards") of **10 tunnels** by default. Each batch is its own sing-box process, and batches start
**3 seconds apart**. With 150 configs that is 15 processes started over roughly 45–50 seconds, each
producing at most 10 handshakes at once.

Batching also limits the blast radius of changes. Enabling, disabling, renaming or re-porting a proxy
regenerates and restarts only its batch. Settings that affect every tunnel (upstream, credentials, DNS,
MTU, log level) restart the batches one after another, with the same delay. Set **Tunnels per engine
process** to at least the number of configs to get a single sing-box process; there is then no
staggering.

If the upstream is configured but unreachable when the engine starts (for example, Docker starts at boot
before you log in and start Throne), the engine waits for it and then does the staggered start. Once
running, tunnels reconnect by themselves if the upstream restarts.

**Memory.** With a detour, each WireGuard endpoint costs about 0.4 MiB of Go heap (measured with
sing-box 1.14.4: about 55 MiB for 150 idle endpoints). Without a detour, sing-box uses a 128-packet
batched UDP socket costing about 8 MiB per endpoint. That is why direct mode also routes endpoints
through an explicit `direct` outbound. `GOMEMLIMIT=384MiB` is set on every engine process as a soft
limit.

### Ports

- New proxies get the lowest free port of the range (default 20000–20999), skipping the WebUI port and
  a loopback upstream port.
- Assignments are stored in the database and never change by themselves; restarts and reboots reuse
  them.
- If another program holds a proxy's port when its batch starts, **only that proxy** moves to a new free
  port. The dashboard shows a *moved* marker with the details, and exports always contain the current
  ports.
- Deleting a proxy releases its port. To override a port, use **Edit** on the dashboard or
  **Settings → Per-proxy port overrides**.

### Status values

| Status | Meaning |
| --- | --- |
| OK | The last test fetched the exit IP through the tunnel: handshake done, traffic flows. |
| Dead | The last test failed. Hover for the reason. |
| Unknown | Running, not tested yet. |
| Pending / Starting | Waiting for its batch to start. |
| Restarting / Failed | Its engine process failed; see **Engine & logs**. |
| Error | Excluded by the engine, e.g. rejected by `sing-box check`. Use **Edit → Clear error and retry**. |
| Disabled | Disabled by you: no listener, no tunnel. |

sing-box does not expose WireGuard handshake state, so *OK* and *Dead* come from active tests: **Test
all**, the per-row **Test** button or the optional automatic test interval.

## Usage

### Adding configs

**Add configs** accepts `.conf` files (multi-select or drag and drop), `.zip` archives (`.conf` files in
any folder; other files are ignored) and pasted text. The proxy name is the file name without `.conf`,
reduced to letters, digits, `.`, `_` and `-`. Name clashes get `-2`, `-3`, … suffixes.

The parser understands `[Interface]` `PrivateKey`, `Address`, `DNS`, `MTU` and `[Peer]` `PublicKey`,
`PresharedKey`, `Endpoint` (IP, `[IPv6]` or host name), `AllowedIPs` and `PersistentKeepalive`, including
multiple peers. wg-quick host settings (`PostUp`, `Table`, …) are ignored with a warning.

Duplicates: a config with the same private key **and** the same server (peer public key) as an existing
one is rejected, because two sessions with the same key to one server would knock each other off. The
same private key with a *different* server is accepted with a warning, which is normal for providers
that issue one key per device.

### Testing

For each enabled proxy, 25 at a time, the app requests `https://api.ipify.org` through the proxy's SOCKS5
port and records the exit IP and latency. Latency is the full request time, including the TLS
handshake. The unique exit IPs are then looked up with the `ip-api.com` batch endpoint (free tier: plain
HTTP, 100 addresses per request), by default through the upstream proxy. The URL, timeout, parallelism
and an automatic interval are under **Settings → Testing**.

### Exporting

Use **Export…** on the dashboard, or script it. Scripts authenticate with HTTP Basic auth: any user
name, with the WebUI password, if one is set.

```bash
curl -u ":$WEBUI_PASSWORD" -o proxies.txt "http://127.0.0.1:8080/api/export?country=US&status=ok"
```

Parameters: `scheme=socks5|http`, `enabled_only=true|false`, `status=any|ok`, `country=US,DE`
(country codes or names), `ids=1,2,3`.

### Using the proxies

Every proxy accepts SOCKS5 (TCP and UDP ASSOCIATE) and HTTP (CONNECT and plain requests) on the same
port, with the same credentials. Prefer `socks5h://` in tools that distinguish it, so that host names
are resolved inside the tunnel.

## Configuration reference

### Environment variables

Set these in `docker-compose.yml` or in a `.env` file next to it.

| Variable | Default | Purpose |
| --- | --- | --- |
| `WGPROXY_WEBUI_PORT` | `8080` | WebUI port. It always binds `127.0.0.1`. |
| `PUID` / `PGID` | `1000` | User and group that own `./data` and run the app and sing-box. |
| `WGPROXY_LOG_LEVEL` | `info` | Application log level. |
| `WGPROXY_ALLOWED_HOSTS` | *(empty)* | Extra host names accepted in the `Host` header, e.g. for an SSH-tunnel alias. |
| `WGPROXY_DATA_DIR` | `/data` | Data directory inside the container. |
| `WGPROXY_SING_BOX` | `/usr/local/bin/sing-box` | Engine binary. |

### Settings (WebUI → Settings)

| Setting | Default | Notes |
| --- | --- | --- |
| Upstream host / port | `127.0.0.1` / `2080` | Empty host = direct mode. A host name is resolved with the system resolver. |
| Upstream username / password | empty | Optional SOCKS5 credentials. |
| Proxy username / password | `wgproxy` / random | Required by every local proxy. |
| Port range | `20000`–`20999` | Used for new assignments only. |
| Bootstrap DNS | `1.1.1.1`, UDP | Resolves endpoint host names, through the upstream. Switch to TCP if the upstream's UDP is unreliable. |
| Tunnel DNS fallback | `1.1.1.1` | Used inside tunnels whose `.conf` has no `DNS =`. |
| Default MTU | `1280` | Also the maximum for an MTU from a `.conf`. |
| Default keepalive | `25` s | For peers without `PersistentKeepalive`; `0` disables it. |
| Engine log level | `warn` | sing-box log level. |
| GOMEMLIMIT per process | `384MiB` | Empty disables it. |
| Tunnels per engine process | `10` | Batch size for the staggered start. |
| Delay between batches | `3` s | |
| Exit IP URL / timeout / parallel tests | `https://api.ipify.org` / `15` s / `25` | |
| Automatic test interval | `0` (off) | Minutes. |
| Country lookups through the upstream | on | |

## Data directory and backups

```
data/
├── wgproxy.db        SQLite: configs (original .conf text), port assignments, settings,
│                     credentials, test results
├── secret.key        signs WebUI sessions
└── engine/
    ├── shard-00.json generated sing-box configuration (contains private keys)
    └── shard-00.pid
```

Files are private: mode `0600` in a `0700` directory. They contain WireGuard private keys and passwords.
To back up, copy `./data` while the container is stopped, or download every imported `.conf` from
**Settings → Backup**.

## Security notes

- Every listener binds `127.0.0.1`.
- **WebUI**: a `Host` header allowlist blocks DNS-rebinding attacks. State-changing requests must carry
  `X-Requested-With: wgproxy` and a same-origin `Origin` header, which other websites cannot produce. A
  strict Content-Security-Policy applies.
- **Optional WebUI password**: it is stored as an scrypt hash, and sessions use an HttpOnly,
  SameSite=Strict cookie. Changing the password signs every session out. Scripts can use HTTP Basic auth
  with the same password.
- **Proxies**: they require the proxy credentials, but any local user who knows them can use the
  proxies. Treat `./data` as a secret.
- **Container**: it runs as `PUID:PGID` with no capabilities, `no-new-privileges` and a read-only root
  filesystem.

## Troubleshooting

**The WebUI does not open.** Check `docker compose ps` and `docker compose logs`. If port 8080 is taken,
set `WGPROXY_WEBUI_PORT=8081` (for example in `.env`) and run `docker compose up -d`. Docker Desktop is
not supported (see Quick start).

**Banner: "Waiting for the upstream proxy …".** The outer VPN client is not listening on the configured
host and port. Start it, fix **Settings → Upstream proxy**, or clear the host for direct mode.

**Every proxy is Dead.** Run **Settings → Test upstream**. *UDP through upstream* must pass, because
WireGuard is UDP-only; some outer protocols or routing rules drop UDP. Then check **Engine & logs** for
handshake errors, and test one config with `wg-quick` on another machine to rule out the config itself.
Expired or revoked keys look exactly like a dead server.

**Only configs with a host-name endpoint fail.** Look for `failed to resolve endpoints` in the logs. Set
**Bootstrap DNS protocol** to TCP or try another bootstrap server.

**A proxy shows "moved".** Another program held its port when its batch started, so it got a new one.
Exports always show the current port. To pin a port, set an override on a port that is free.

**Permission denied on `./data`.** The entrypoint fixes ownership when the container starts as root,
which is the compose default. If you run it with `--user`, run `sudo chown -R 1000:1000 data` or set
`PUID`/`PGID`.

**Forgot the WebUI password.**
`docker compose exec wireguard-to-proxy python -m wgproxy reset-ui-password`.

**"N log line(s) … suppressed".** Engine output is rate limited per process (30 lines/s). It mostly
happens while the upstream is down, when every tunnel logs a reconnect error each second.

**Status *Error* on one proxy.** sing-box rejected that tunnel. The reason is in **Edit** and in the
logs. Fix or re-import the config, then click **Clear error and retry**. Restarting the engine also
retries every excluded tunnel.

**Changing the sing-box version.** Set the `SING_BOX_VERSION` build argument and the
`SING_BOX_SHA256_*` checksums in the `Dockerfile` (copy them from the release's asset digests). This
application targets 1.14.x.

## Development

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
python -m pytest
WGPROXY_DATA_DIR=./data python -m wgproxy serve      # needs sing-box on PATH
```

The tests cover:

- the `.conf` parser;
- the generated sing-box configuration: route rules, detour wiring, DNS and IP families;
- the port manager and batch assignment, and the importer;
- the API: auth, CSRF and Host checks, import and export;
- the engine supervisor, against real subprocesses of a fake `sing-box`: staggered start, SIGTERM
  shutdown, port repair, quarantine, waiting for the upstream and crash restarts.

When a real `sing-box` binary is on `PATH` (or in `WGPROXY_SING_BOX`), `tests/test_singbox_integration.py`
also runs `sing-box check` and starts the generated configurations.

```
wgproxy/
├── wgconf.py      .conf parser
├── singbox.py     sing-box configuration generator
├── ports.py       port allocation, repair and batch assignment
├── engine.py      sing-box process supervisor (shards, staggered start, repairs)
├── upstream.py    upstream monitor and SOCKS5 diagnostics
├── tester.py      exit IP, latency and country tests
├── importer.py    uploads, zip archives, duplicate detection
├── db.py          SQLite persistence
├── settings.py    validated settings
├── security.py    WebUI auth, Host/CSRF checks, security headers
├── api.py         JSON API
├── pages.py       HTML pages
├── templates/     Jinja2 page shells
└── static/        CSS and vanilla JavaScript modules
```

## Design choices

- **Python + FastAPI backend.** The heavy lifting (WireGuard, the gVisor stack, proxying) happens
  inside sing-box. The backend parses configs, generates JSON, supervises processes and serves a small
  UI. Python keeps that logic short and easy to audit, asyncio makes subprocess supervision
  straightforward, `httpx` provides SOCKS5-capable test clients and pytest makes the generator and
  supervisor easy to test. A Go backend would save some memory but needs more code for the same
  behaviour.
- **Frontend**: server-rendered HTML shells plus vanilla ES modules. There is no build step and no CDN,
  so it works offline and under a strict CSP.
- **State**: SQLite in WAL mode (Python standard library), giving atomic updates of the port manifest and
  test results without a separate service.

## License

[MIT](LICENSE)
