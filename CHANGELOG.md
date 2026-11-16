# Changelog

All notable changes to mullpod are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions are git tags
(`vX.Y.Z`); `mullpod -version` and `/health` report the build's version.

Each entry starts with the part of mullpod it changes:

- **Proxy:** the proxy ports (HTTP and SOCKS5), exit selection and sessions.
- **Control API:** the HTTP API on `api` (default `127.0.0.1:8088`); see
  [docs/API.md](docs/API.md).
- **Tunnel:** the WireGuard tunnel, entry servers and the relay list.
- **Logging**, **Build**, **Docs.**

## [Unreleased]

## [1.1.0] - 2026-11-16

### Changed

- **Control API — breaking:** `/forget` only accepts `POST`; `GET /forget` now returns
  405. All `GET` endpoints are read-only.
- **Proxy:** a session with open connections no longer expires and is the last to be
  evicted at the `sticky.max` cap. Its idle time (`sticky.ttl`) now counts from when its
  last connection closes, not from when the connection opened, so long keep-alive
  connections keep their server.
- **Control API:** `GET /ip` is read-only: it uses a session's current server if the
  session exists, but never creates, moves or refreshes it. It accepts a full proxy
  username (`/ip?session=us_w0`) and reports `session_live`.
- **Control API:** the `sessions` count in `/health` and `mullpod_sessions` in `/metrics`
  count only live sessions.

### Added

- **Control API:** `GET /sessions` (and `?name=`): each live session's server, open and
  total connections, last use, idle time and TTL left, without any network traffic.
- **Control API:** `version` in `/health`.
- **Build:** a plain `go build` in a git checkout reports its version as `dev-<commit>`
  instead of `dev` (`-version`, `/health`).
- **Docs:** [API reference](docs/API.md): every endpoint, parameter, field and status code
  of the proxy ports and the control API.
- **Docs:** README recipe for crawlers and parallel workers (readiness, keep-alive, one
  session per worker, rotating on throttling, pacing), and notes on what the control API
  shows.

## [1.0.0] - 2026-11-15

First release.

- **Tunnel:** one binary that holds a Mullvad WireGuard tunnel in its own process (no root,
  no TUN device) and reaches every Mullvad exit server's SOCKS5 proxy through it; switches
  entry server when its health probe fails.
- **Proxy:** HTTP and SOCKS5 on the same port; the proxy username `<exit>[_<session>]`
  selects the exit: `any`, a country, a city, an exact server, an alias, `current` or
  `default`.
- **Proxy:** sticky sessions with one current server that moves when a request names
  another exit, with an idle TTL and a cap.
- **Proxy:** per-domain rules, aliases, per-listener exits and fixed sessions; optional
  `PROXY_PASSWORD`, and `407` challenges for browsers.
- **Proxy:** failover: unreachable exit servers are benched with backoff and the request is
  retried on another one.
- **Tunnel:** relay list fetched from Mullvad, cached and refreshed; exit hostnames and DNS
  for `current` resolved inside the tunnel.
- **Control API:** `/health`, `/exits`, `/ip`, `/forget`, `/tunnel/switch`, `/proxy.pac`
  and Prometheus `/metrics`.
- **Logging:** one JSON log line per connection on stdout.

[Unreleased]: https://github.com/SkanaviLabs/mullpod/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/SkanaviLabs/mullpod/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/SkanaviLabs/mullpod/releases/tag/v1.0.0
