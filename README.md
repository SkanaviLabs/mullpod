# mullpod

[Mullvad VPN](https://mullvad.net) is a pretty unique service: it lets you to use all of its exit servers via SOCKS5 once you connect to single entry point via Wireguard connection.
This makes it incredibly useful for many agentic and testing scenarios, however the network setup can be complicated. See [Mullvad docs](https://mullvad.net/en/help/socks5-proxy) for details.  

**mullpod** is a single executable that connects to a Mullvad entry point using an internal WireGuard process, hence does not require any additional network setup. It provides local HTTP and SOCKS5 proxies with basic routing, allowing each connection to be routed through any of Mullvad's ~530 servers based on the proxy username.  

**Warning: It's a convenience, not a network isolation tool:** see
[Network isolation](#network-isolation) for details.

## Table of contents

- [Use](#use)
  - [Sessions](#sessions)
  - [Ports](#ports-loopback-by-default-every-port-speaks-http-and-socks5)
  - [Control API](#control-api)
- [What it is](#what-it-is)
- [Use cases](#use-cases)
- [Network isolation](#network-isolation)
- [How it works](#how-it-works)
- [Setup](#setup)
- [Config](#config)
- [Speed](#speed)
- [Caveats](#caveats)
- [Develop](#develop)
- [License](#license)

## Use

```bash
make run                                                                     # start it (first time: see Setup)

curl -x http://de:x@127.0.0.1:8090 https://am.i.mullvad.net/json            # any German server
curl -x http://us-nyc:x@127.0.0.1:8090 https://am.i.mullvad.net/json        # any New York server
curl -x http://se-sto-wg-001:x@127.0.0.1:8090 https://am.i.mullvad.net/json # exactly this server
curl -x http://any:x@127.0.0.1:8090 https://am.i.mullvad.net/json           # any server, new one each time
curl -x http://de_job1:x@127.0.0.1:8090 https://am.i.mullvad.net/json       # German, same IP for session job1
curl -x socks5h://jp:x@127.0.0.1:1080 https://am.i.mullvad.net/json         # SOCKS5 works the same way
curl -x http://127.0.0.1:8083 https://am.i.mullvad.net/json                 # no username: fixed port, Germany

export HTTPS_PROXY=http://any_agent1:x@127.0.0.1:8090                        # agents / SDKs
```

The only required configuration is in `.env` (copy from `.env.example`); everything else
lives in `config.yaml` (see [Setup](#setup) and [Config](#config)):

```bash
# From the Mullvad WireGuard config you downloaded:
WIREGUARD_PRIVATE_KEY=<PrivateKey>
# IPv4 part of the Address line only:
WIREGUARD_ADDRESSES=10.x.x.x/32
# Optional, require every client to send this as the proxy password:
# PROXY_PASSWORD=
```

Both values come from the one `.conf` file you download; the address must match the key, or
the tunnel passes no traffic. Nothing is prefilled for you: a placeholder such as
`10.x.x.x/32` is rejected at startup.

Proxy username = `<exit>[_<session>]`, password = anything (unless `PROXY_PASSWORD` is set).

Exits use Mullvad's own identifiers, the same ones as in the Mullvad app, relay list and
server hostnames:

| exit | example | picks |
|---|---|---|
| country code | `de`, `us`, `gb` | a server in that country |
| city code `<cc>-<city>` | `de-fra`, `us-nyc` | a server in that city |
| server hostname | `de-fra-wg-001` | exactly that server, and the session's server (see [Sessions](#sessions)) |
| `any` | `any` | any server |
| alias | `eu`, `nordic` | any server in the alias (`config.yaml`) |
| `current` | `current` | one hop: leave via the tunnel's entry server |
| `default` | `default_s1` | the default chain (rules → port → `default_exit`) |

Case doesn't matter. `curl -s '127.0.0.1:8088/exits?servers=1'` lists every country code,
city code and hostname.

### Sessions

A session gives a client a stable IP. Sessions are a convenience, not access control: any
client using the same session name shares its server, and nothing stops a client from
redefining a session.

- **Without a session:** each new connection may get a different server.
- **With a session** (`_<anything>`, e.g. `de-fra_job42`): the session has **one current
  server**.
  - **Exit contains it:** a request whose exit contains the current server keeps using it.
  - **Exit doesn't contain it:** the request picks a server in its exit, and that becomes
    the session's server until a later request moves it again.
  - **Exact server name:** always uses that server, and makes it the session's server.

```bash
curl -x http://de-fra-wg-005_job:x@127.0.0.1:8090 …   # session "job" → de-fra-wg-005
curl -x http://de-fra_job:x@127.0.0.1:8090 …          # → de-fra-wg-005 (contains it)
curl -x http://any_job:x@127.0.0.1:8090 …             # → de-fra-wg-005
curl -x http://jp_job:x@127.0.0.1:8090 …              # → jp-tyo-wg-002: session moves to Japan
curl -x http://any_job:x@127.0.0.1:8090 …             # → jp-tyo-wg-002
curl -x http://de_job:x@127.0.0.1:8090 …              # → a German server: session moves to Germany
```

- **Idle timeout:** a session is forgotten after 10 min idle (`sticky.ttl`), or at once with
  `/forget?session=job` (GET or POST).
- **If the current server fails:** the next request with a broad exit moves the session to
  a healthy server. An exact server name always uses its server.
- **Fixed ports** (8081–8084) have a built-in session per port. It's kept separately for
  each exit, so a per-domain rule that sends some sites elsewhere doesn't move the port's
  main IP.


**Playwright:** use HTTP (Chromium can't authenticate to SOCKS5) and always give each
context a session:

```python
browser = p.chromium.launch(proxy={"server": "http://127.0.0.1:8090"},
                            args=["--force-webrtc-ip-handling-policy=disable_non_proxied_udp"])
ctx = browser.new_context(proxy={"server": "http://127.0.0.1:8090",
                                 "username": "de-fra_ctx1", "password": "x"})
```

**Plain Chrome:** `--proxy-server=http://127.0.0.1:8081` (fixed US exit) or
`--proxy-pac-url=http://127.0.0.1:8088/proxy.pac`.

### Ports (loopback by default; every port speaks HTTP and SOCKS5)

| port | |
|---|---|
| 8090 | main; HTTP without credentials gets `407` so browsers send the username |
| 1080 | no credentials needed; default exit, rotates per connection |
| 8081 / 8082 / 8083 / 8084 | fixed `us` / `gb` / `de` / `jp`, sticky per port |
| 8088 | control API |

Ports are set per listener in `config.yaml`, each with an explicit `host:port` address; the
shipped file uses 8090 for the main port (8080 is often already taken) and binds everything
to `127.0.0.1`. IPv4, IPv6 and hostnames work (`192.168.1.20:8091`, `[::1]:8092`); IPv6
literals must be bracketed. Wildcards (`0.0.0.0`, `::`) and hostless addresses (`:8090`)
are rejected, because Mullvad's exit proxies have no auth. Restart after editing.

`make verify` and `make smoke` read the ports from the running instance. Without
`PROXY_PASSWORD`, mullpod warns at startup for every port on a non-loopback address.

### Control API

```bash
curl -s 127.0.0.1:8088/health
curl -s 127.0.0.1:8088/exits                 # ?servers=1 for hostnames
curl -s '127.0.0.1:8088/ip?exit=se-sto'      # which IP/server a selector gets
curl -s '127.0.0.1:8088/forget?session=job42'           # forget a session (GET or POST)
curl -s 127.0.0.1:8088/metrics
curl -s -XPOST 127.0.0.1:8088/tunnel/switch  # move the tunnel to another tunnel.entry server
```

Every response through the HTTP proxy carries `X-Mullvad-Server` (on `CONNECT`, in the
`200` reply). Logs are one JSON line per connection, on stdout.

## What it is

Every Mullvad WireGuard server runs a SOCKS5 proxy, and you can reach all of them through a
single WireGuard connection. With one tunnel to any one server, you can leave the internet
from any of Mullvad's ~530 servers in 50 countries, or from all of them at once, connection
by connection.

Using that directly is tedious. You need to:
- look up each server's internal proxy address;
- keep the tunnel up;
- point every tool at the right `10.124.x.x:1080`.

mullpod is a thin proxy and router that does this for you. You choose the exit with a
proxy username (`de`, `us-nyc`, `se-sto-wg-001`, `any`) on one local port. On top of that it
gives you sticky sessions, failover and a plain HTTP proxy for browsers that can't use SOCKS5
authentication.

It's a single native binary that holds the Mullvad WireGuard tunnel inside its own process.
Your machine does not connect to Mullvad; only traffic you send to these ports does.

## Use cases

- **Agents and LLM tooling.** Point a framework or SDK at
  `HTTPS_PROXY=http://any_agent1:x@127.0.0.1:8090`. Every tool call and page fetch leaves
  from a Mullvad exit, and the `_agent1` session keeps one IP for the whole task, so a run is
  reproducible and easy to follow in the logs.
- **Fan-out work.** Run 30 workers with `any_w1` … `any_w30`: each keeps its own stable
  server, while requests without a session spread over exits and no single IP sees the whole
  burst. Dead servers are benched and retried elsewhere automatically.
- **Geo-specific results.** See what a search page, price, store listing or ad looks like
  from a country (`jp`) or a city (`de-fra`), and move a session between them mid-run.
- **Browser automation.** Playwright selects an exit per context over HTTP, Puppeteer via
  `page.authenticate`; plain Chrome uses a fixed port (`--proxy-server=http://127.0.0.1:8081`)
  or the PAC file (`/proxy.pac`). No SOCKS5 authentication needed.
- **One process tree through Mullvad.** Export `HTTPS_PROXY` in one shell or container and
  only programs started there are affected; the rest of the machine keeps its normal route.
  No root, no TUN device, no system-wide tunnel.
- **Scheduled jobs and CI.** Keep one long-running process and give each job a session name
  instead of shipping a WireGuard config per runner. `POST /tunnel/switch` moves the entry
  server when a network path degrades.
- **Checking your own egress handling.** Verify that a client honours proxy settings, fails
  over, or rotates region — `/ip?exit=...` shows the exact server and IP a selector gets.

Sessions are the natural unit: one per agent, worker, tenant or job. Any request can move a
session to another exit, and later broad requests follow it. See [Caveats](#caveats) for the
limits that matter here (TCP only, shared exit IPs, CAPTCHAs).

## Network isolation

**This is not a network isolation tool.** mullpod only covers traffic that's sent to
it. Anything that ignores the proxy goes out from your real IP with no warning: other code,
tools, DNS lookups, WebRTC. If your application or agent must never touch the internet except through
Mullvad, don't rely on this. Use system mullvad client or run the app itself inside a container whose only route out
is a Mullvad WireGuard tunnel with a kill switch:
- [Gluetun](https://github.com/passteque/gluetun) (`qmcgaw/gluetun`) has the kill switch
  built in. Attach the agent's container with `network_mode: service:gluetun`.
- [linuxserver/wireguard](https://github.com/linuxserver/docker-wireguard) has no kill
  switch until you add one. Without your own firewall rules in `wg0.conf`, traffic leaks
  when the tunnel drops.

## How it works

Every Mullvad WireGuard server runs a SOCKS5 proxy at its own internal address
(`<cc>-<city>-wg-socks5-NNN.relays.mullvad.net` → `10.124.x.x:1080`), and every proxy is
reachable from any Mullvad tunnel. So one tunnel is enough: the proxy picks an exit per
connection by dialing a different `10.124.x.x:1080`.

```
client → 127.0.0.1 → mullpod ─ in-process WireGuard tunnel → entry server → exit's SOCKS5 → internet
```

- **Tunnel:** wireguard-go with a userspace network stack. No root, no TUN device, no Docker.
  The stack exists only inside the process, so nothing else on the machine can use it and the
  proxy has no other route out.
- **Fails closed:** the proxy never dials the internet directly. While the tunnel is down,
  requests fail at once with `503`, and no exit server is blamed.
- **Entry server:** chosen from `tunnel.entry`, a Mullvad code such as `us-mia`, `se` or
  `de-fra-wg-001`. Pick one near you.
- **Tunnel health:** probes `10.64.0.1:1080` (Mullvad's internal DNS/proxy endpoint,
  reachable from any tunnel) every 10 s. After 3 failures in a row it moves to another
  entry server matching `tunnel.entry`. `POST /tunnel/switch` moves it by hand.
- **Relay list:** loaded from the Mullvad API, cached in `data/relays.json`
  (`catalog.cache`; set it to `""` to keep the list in memory only), and refreshed
  through the tunnel every 6 h. The entry server's WireGuard key and IP come from this list,
  so on the very first run (no cache) it's fetched once over the normal network
  (`tunnel.bootstrap_direct`).
- **Ports:** every port speaks HTTP and SOCKS5. Exit hostnames are resolved inside the
  tunnel, via Mullvad DNS `10.64.0.1`.
- **Choosing an exit:** round-robin, or sticky per session.
  - **Breaker:** a dead exit proxy is benched (30 s doubling to 10 min), and the request
    retries once on another server.
  - **Errors:** a SOCKS error reply is the target's fault and is passed through without
    penalty.

## Setup

Needs Go (`brew install go`).

1. On <https://mullvad.net/en/account/wireguard-config>, generate a key for a new device,
   pick any server, and download the config file.
2. `cp .env.example .env`, then set `WIREGUARD_PRIVATE_KEY` and `WIREGUARD_ADDRESSES`
   (IPv4 part only, e.g. `10.66.12.34/32`) from that config.
3. In `config.yaml`, set `tunnel.entry` to a Mullvad code near you (e.g. `us-mia`),
   change any port that's taken on your machine, and replace `127.0.0.1` in each listener
   (and `api`) with the interface your clients use if they aren't on loopback.
4. Run it:

   ```bash
   make run
   ```

   This builds `bin/mullpod` and runs it in the foreground. Logs (one JSON line per
   connection) go to the terminal; Ctrl-C stops it. `./bin/mullpod -version` prints the
   build version and the license notice.
5. In another terminal:

   ```bash
   make verify
   ```

**`.env` vs `config.yaml`:**
- **`.env`** holds only secrets and settings specific to your Mullvad device:
  `WIREGUARD_PRIVATE_KEY`, `WIREGUARD_ADDRESSES`, and the optional `PROXY_PASSWORD`.
- **`config.yaml`** holds every other setting: entry server, listener addresses, exits, aliases,
  timeouts.
- **No overlap:** other keys in `.env` are ignored with a warning at start-up, and the
  environment never overrides `config.yaml`.

Both are read from the current directory; `./bin/mullpod -config path -env path`
points elsewhere. Listener and API addresses must include a host; `":port"` is rejected
because it would bind every interface.

**Outbound firewalls (Little Snitch, LuLu):** allow `bin/mullpod` to connect out:
- UDP port 51820 to Mullvad's servers (the tunnel);
- TCP 443 to `api.mullvad.net` (the first-run relay list).

Until then it can't connect, and `/health` stays `down`. Rebuilding the binary may make the
firewall ask again.

## Config

[config.yaml](config.yaml) sets the listeners (each with its own bind address), default
exit, aliases, per-domain rules, sticky TTL and breaker. It's read at startup, so restart
the process after editing.

## Speed

mullpod runs at about the same speed as a WireGuard Docker container (kernel WireGuard).
Side-by-side tests haven't shown a systematic difference.

The limit is how Mullvad's network routes traffic. For the best results:
- **Entry:** set `tunnel.entry` to the Mullvad location **closest to you**.
- **Exit:** pick an exit **close to that entry**. Speed through an exit's SOCKS proxy falls
  with distance, and `current` (no second hop) is the fastest.

Far exits are slower but fine for agents, page loads and API calls. To measure a path:

```bash
curl -s -o /dev/null -w '%{speed_download}\n' -x http://de-fra_t:x@127.0.0.1:8090 \
  'https://speed.cloudflare.com/__down?bytes=20000000'   # bytes/s
```

## Caveats

- **TCP only:** the exit proxies don't support UDP, so no QUIC or UDP WebRTC. Use the WebRTC
  flag above in browsers.
- **Two hops:** traffic goes entry → exit, about 0.8 s for a US→DE request. Choose the
  entry (`tunnel.entry`) near you; `current` is one hop. All exits share the entry server's
  bandwidth.
- **Throughput drops with distance to the exit.** See [Speed](#speed).
- **Shared VPN IPs:** expect CAPTCHAs on some sites; change the session to get a new server.
- **No auth on Mullvad's proxies:** keep listener addresses on `127.0.0.1`, or set `PROXY_PASSWORD` before
  exposing the ports.
- **One Mullvad device slot:** the stack uses one. Give it its own WireGuard key.
- **Session id for browsers:** without one, the connections of a single page load spread
  across servers.

## Develop

`make build` writes `bin/mullpod`; `go install github.com/SkanaviLabs/mullpod@latest`
installs it into `$GOBIN` instead. The binary still reads `.env` and `config.yaml` from the
working directory.

`make test` checks `gofmt`, runs `go vet`, and runs the tests with `-race` and coverage.
Coverage is about 80% of statements; the uncovered part is mostly `main()` wiring and the
periodic relay-list refresh, which the live checks exercise. CI runs the same target on
Ubuntu (`.github/workflows/test.yml`); the live checks need a real Mullvad account and are
not part of it.

| layer | what | how |
|---|---|---|
| unit | selectors, sessions (one current server, moves), TTL and cap, rotation, breaker backoff, HTTP/SOCKS5 inbound, `PROXY_PASSWORD`, control API, relay-list fetch and cache, DNS caching, config parsing | `make test`, with fake exit proxies |
| tunnel | real WireGuard handshakes against in-process entry servers: traffic, dead-server failover, `Switch`, fail-fast while down | `make test` (`TestEmbeddedTunnelFailover`) |
| live | 25 checks against real Mullvad servers: exits per country, rotation, sticky, session moves, 407 | `make verify` |
| live, tunnel | move to another entry server live; traffic and `current` follow | `make verify` (step 6) |
| browser | Playwright page load stays on one exit | `make smoke` |

Not covered: long-running behaviour (6-hourly relay refresh, many-hour uptime, sustained
load), and a real network outage against live Mullvad. Blocking UDP on macOS needs root, so
the live test switches the entry server instead. The in-process tunnel test does cover
failover.

## License

MIT — see [LICENSE](LICENSE). Free to use, modify and redistribute, including commercially,
provided the copyright notice and license text are kept.

Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi.

