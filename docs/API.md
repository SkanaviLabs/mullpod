# mullpod API reference

mullpod has two interfaces:

- **Proxy ports** (`listeners` in `config.yaml`, `127.0.0.1:8090` by default): HTTP proxy
  and SOCKS5 on the same port. The proxy username picks the exit.
- **Control API** (`api` in `config.yaml`, `127.0.0.1:8088` by default): plain HTTP, JSON
  responses. Read-only `GET` endpoints for status and lookups, and `POST` for anything that
  changes state.

This reference covers version 1.1.0. See [CHANGELOG.md](../CHANGELOG.md) for changes.

- [Proxy ports](#proxy-ports)
  - [Choosing the exit](#choosing-the-exit)
  - [Sessions](#sessions)
  - [Headers](#headers)
  - [Errors](#proxy-errors)
  - [Connection log](#connection-log)
- [Control API](#control-api)
  - [GET /health](#get-health)
  - [GET /exits](#get-exits)
  - [GET /ip](#get-ip)
  - [GET /sessions](#get-sessions)
  - [POST /forget](#post-forget)
  - [POST /tunnel/switch](#post-tunnelswitch)
  - [GET /proxy.pac](#get-proxypac)
  - [GET /metrics](#get-metrics)
  - [GET /](#get-)

---

## Proxy ports

Every port speaks both protocols; mullpod tells them apart by the client's first byte.

| protocol | how | exit chosen by |
|---|---|---|
| HTTP `CONNECT` (HTTPS) | `curl -x http://de_s1:x@127.0.0.1:8090 https://…` | `Proxy-Authorization` username |
| HTTP forward (plain `http://`) | same | `Proxy-Authorization` username |
| SOCKS5 | `curl -x socks5h://de_s1:x@127.0.0.1:8090 https://…` | SOCKS5 username |

The password is ignored unless `PROXY_PASSWORD` is set in `.env`; then it must match.
TCP only: Mullvad's exit proxies don't carry UDP.

### Choosing the exit

The username is `<exit>[_<session>]`. Everything before the first `_` is the exit, and
everything after it is the session (so `us_w1_2` is exit `us`, session `w1_2`). The exit is
case-insensitive.

| exit | example | meaning |
|---|---|---|
| `any` | `any` | any server, round-robin |
| country | `de` | any server in the country (ISO code, as in `/exits`) |
| city | `de-fra` | any server in the city |
| server | `de-fra-wg-001` | exactly that server; also makes it the session's server |
| alias | `eu` | any server in the alias's members (`aliases` in `config.yaml`) |
| `current` | `current` | leave from the tunnel's entry server itself (one hop, fastest) |
| `default` | `default` | the default exit, as if no exit were given |

When no exit is given, mullpod uses, in order: a matching per-domain rule (`rules`), the
listener's `exit`, then `default_exit`.

With `challenge: true` on a listener, a request without credentials gets `407` with
`Proxy-Authenticate: Basic`, so browsers prompt for a username. With `challenge: false` such
a request uses the default route.

### Sessions

A session name gives a client a stable server. The session has one current server:

- a request whose exit contains that server keeps using it;
- a request whose exit doesn't contain it picks a server there, which becomes the session's
  server;
- an exact server name always uses that server and makes it the session's server;
- if the current server fails, the next request moves the session to a healthy one.

A session never expires while it has open connections. Once the last one closes, it's
forgotten after `sticky.ttl` (default 10 min) without a new connection, or at once with
[`POST /forget`](#post-forget). At most `sticky.max` sessions are kept; the least recently
used one without open connections is dropped first.

With `sticky.implicit: true`, a username without `_session` is its own session. A listener
with `session:` set has a built-in session, kept separately for each exit.

Sessions are a convenience, not access control: anyone who uses a session name shares its
server.

### Headers

Request headers (HTTP proxy only; removed before the request goes out):

| header | effect |
|---|---|
| `X-Exit` | overrides the exit from the username |
| `X-Session` | session to use when the username has none |

Response header:

| header | where |
|---|---|
| `X-Mullvad-Server` | the exit server's hostname; on the `200 Connection Established` reply to `CONNECT`, and on every plain-HTTP response |

### Proxy errors

When mullpod can't open the connection, the HTTP proxy answers with a plain-text error
(SOCKS5 replies with a failure code):

| status | cause |
|---|---|
| `400` | unknown exit (see `/exits`), or a plain request sent to a proxy port |
| `407` | missing credentials on a `challenge` listener, or wrong `PROXY_PASSWORD` |
| `502` | the exit server or the target refused or failed the connection |
| `503` | the tunnel isn't up yet, or there is no relay list |
| `504` | timed out reaching the exit server or the target (`dial_timeout`) |

Once a `CONNECT` tunnel is open, mullpod only relays encrypted bytes: it can't see the
target's status codes. A `429` from the target reaches the client unchanged and is logged as
`result="ok"`.

### Connection log

One JSON line per connection on stdout (and in the `-log` file, if set), written when the
connection closes:

```json
{"time":"…","level":"INFO","msg":"conn","listener":"main","proto":"http-connect",
 "client":"127.0.0.1:53412","target":"am.i.mullvad.net:443","exit":"us","session":"w0",
 "server":"us-dal-wg-701","ms":30012,"dial_ms":412,"sent":1834,"recv":9120}
```

`proto` is `http-connect`, `http` or `socks5`. `ms` is how long the connection was open,
not request latency: a keep-alive connection carries many requests and sits idle between
them. `dial_ms` is how long reaching the target through the exit took (the exit's SOCKS
handshake and the TCP connect to the target); a slow exit shows here. On failure the line
has `level` `INFO` with an `err` field, and the connection counts as `result="error"` in
[`/metrics`](#get-metrics). `err: "idle timeout"` means mullpod closed the connection after
`idle_timeout` with no bytes in either direction.

---

## Control API

All endpoints return JSON (`/proxy.pac` and `/metrics` excepted), pretty-printed. A wrong
method returns `405`. The API has no authentication; keep `api` on a loopback address.

### GET /health

Status of the tunnel and relay list. Returns **`200`** when the tunnel is up and the relay
list is loaded, **`503`** otherwise. Use it as the readiness check before sending traffic.

```bash
curl -s 127.0.0.1:8088/health
```

```json
{
  "status": "ok",
  "version": "v1.1.0",
  "tunnel": true,
  "relays": 530,
  "catalog_age_s": 3,
  "unhealthy": 0,
  "active_conns": 0,
  "sessions": 0,
  "tunnel_info": { "entry": "us-mia-wg-002", "entry_since_s": 3, "switches": 0 }
}
```

| field | meaning |
|---|---|
| `status` | `ok` or `down` |
| `version` | build version (`-version` prints the same) |
| `tunnel` | the tunnel passes its health probe |
| `relays` | servers in the relay list |
| `catalog_age_s` | seconds since the relay list was loaded; `-1` if never |
| `unhealthy` | servers currently benched after failures |
| `active_conns` | open client connections on all proxy ports |
| `sessions` | live sessions (see [`/sessions`](#get-sessions)) |
| `tunnel_info.entry` | entry server the tunnel is connected to |
| `tunnel_info.entry_since_s` | seconds on that entry server |
| `tunnel_info.switches` | entry server changes since start |

### GET /exits

The relay list grouped by country and city, plus the routing configuration.

| parameter | meaning |
|---|---|
| `servers` | any value (e.g. `?servers=1`) adds each city's server hostnames |

```bash
curl -s '127.0.0.1:8088/exits?servers=1'
```

```json
{
  "total": 530,
  "default_exit": "any",
  "aliases": { "nordic": ["se", "no", "dk", "fi"] },
  "rules": [],
  "listeners": [
    { "name": "main", "addr": "127.0.0.1:8090", "exit": "", "session": "", "challenge": "true" }
  ],
  "countries": [
    {
      "code": "al", "name": "Albania", "servers": 4,
      "cities": [
        { "code": "al-tia", "name": "Tirana", "servers": 4,
          "hostnames": ["al-tia-wg-001", "…"] }
      ]
    }
  ],
  "grammar": "<exit>[_<session>]; exit = …"
}
```

`countries` is sorted by code. In `listeners`, `challenge` is the string `"true"` or
`"false"`.

### GET /ip

Which server and public IP a selection gets. mullpod makes a real request to
`ip_check_url` (default `https://am.i.mullvad.net/json`) through the exit, so it takes a
second or more.

Read-only: it uses a session's current server if the session exists and the exit contains
it, but never creates, moves or refreshes a session.

| parameter | meaning |
|---|---|
| `exit` | exit selector, as in a username; default: `default_exit` |
| `session` | session name; or a full username (`us_w0`) when `exit` is not given |

```bash
curl -s '127.0.0.1:8088/ip?session=us_w0'
```

```json
{
  "exit": "us",
  "session": "w0",
  "session_live": true,
  "server": "us-dal-wg-701",
  "ms": 1840,
  "check": {
    "ip": "23.234.104.35",
    "country": "USA",
    "city": "Dallas, TX",
    "mullvad_exit_ip": true,
    "mullvad_exit_ip_hostname": "us-dal-wg-socks5-701"
  }
}
```

| field | meaning |
|---|---|
| `exit`, `session` | the selection used, after parsing |
| `session_live` | the session exists (if not, `server` is just a server from `exit`) |
| `server` | the exit server the check went through |
| `ms` | duration of the check |
| `check` | the IP-check response: parsed JSON, or a string if it isn't JSON |

Errors use the [proxy error](#proxy-errors) statuses, with the body
`{"exit", "session", "server", "error"}`; for example `400` for `?exit=zz`.

### GET /sessions

Live sessions, from memory: instant, and sends nothing over the network.

| parameter | meaning |
|---|---|
| `name` | only this session (the session name, not the full username) |

```bash
curl -s 127.0.0.1:8088/sessions
```

```json
{
  "count": 1,
  "ttl_s": 600,
  "sessions": [
    {
      "name": "w0",
      "server": "us-dal-wg-701",
      "open_conns": 1,
      "conns": 1,
      "last_used": "2026-11-16T22:43:59Z",
      "idle_s": 2,
      "ttl_left_s": -1
    }
  ]
}
```

| field | meaning |
|---|---|
| `count` | sessions listed |
| `ttl_s` | `sticky.ttl` in seconds |
| `name` | session name |
| `server` | the session's current server |
| `open_conns` | connections open through the session now |
| `conns` | connections made through the session since it was created |
| `last_used` | when a connection last started or closed (UTC) |
| `idle_s` | seconds since `last_used` |
| `ttl_left_s` | seconds until it's forgotten; `-1` while it has open connections |

Sessions are sorted by name. An unknown `name` returns `200` with `count: 0`.

### POST /forget

Drops a session, so its next connection picks a server anew. Open connections are not
closed.

| parameter | meaning |
|---|---|
| `session` | session name (required) |

```bash
curl -s -XPOST '127.0.0.1:8088/forget?session=w0'
```

```json
{ "session": "w0", "forgot": true }
```

`forgot` is `false` if there was no such session. Without `session`: `400`. `GET` returns
`405`.

### POST /tunnel/switch

Moves the tunnel to another entry server matching `tunnel.entry`. Returns `202` at once; the
switch happens in the background. Open connections through the old entry are dropped.

```bash
curl -s -XPOST 127.0.0.1:8088/tunnel/switch
```

```json
{ "switching_from": "us-mia-wg-002" }
```

Poll `/health` until `tunnel_info.entry` changes and `status` is `ok`.

### GET /proxy.pac

A proxy auto-config file for browsers and OSes: local and private addresses go direct,
everything else through the proxy port. Per-domain `rules` are applied by mullpod, not in
the PAC file.

```js
function FindProxyForURL(url, host) {
  if (isPlainHostName(host) || host == "localhost" || shExpMatch(host, "127.*") ||
      isInNet(host, "10.0.0.0", "255.0.0.0") || isInNet(host, "192.168.0.0", "255.255.0.0"))
    return "DIRECT";
  return "PROXY 127.0.0.1:8090";
}
```

The host is `pac.host` from `config.yaml`, or else the host the request was sent to; the
port is `pac.port`. `Content-Type: application/x-ns-proxy-autoconfig`.

### GET /metrics

Prometheus text format.

```
mullpod_relays 530
mullpod_relays_unhealthy 0
mullpod_sessions 3
mullpod_active_connections 0
mullpod_bytes_sent_total 110192
mullpod_bytes_received_total 335679
mullpod_tunnel_up 1
mullpod_connections_total{listener="main",proto="http-connect",result="ok"} 57
mullpod_connections_total{listener="main",proto="socks5",result="ok"} 1
```

| metric | type | meaning |
|---|---|---|
| `mullpod_relays` | gauge | servers in the relay list |
| `mullpod_relays_unhealthy` | gauge | servers currently benched |
| `mullpod_sessions` | gauge | live sessions |
| `mullpod_active_connections` | gauge | open client connections |
| `mullpod_bytes_sent_total` | counter | bytes from clients to targets |
| `mullpod_bytes_received_total` | counter | bytes from targets to clients |
| `mullpod_tunnel_up` | gauge | `1` if the tunnel is up |
| `mullpod_connections_total` | counter | finished connections by `listener`, `proto` (`http-connect`, `http`, `socks5`) and `result` (`ok`, `error`) |

Byte counters are added when a connection closes. `result` describes the connection through
the tunnel, not the target's response.

### GET /

Lists the endpoints.

```json
{ "endpoints": ["/health", "/exits", "/ip?exit=&session=", "/sessions?name=",
  "POST /forget?session=", "POST /tunnel/switch", "/proxy.pac", "/metrics"] }
```
