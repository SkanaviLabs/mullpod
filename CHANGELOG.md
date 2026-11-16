# Changelog

All notable changes to mullpod are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions are git tags
(`vX.Y.Z`); `mullpod -version` and `/health` report the build's version.

## [Unreleased]

## [1.1.0] - 2026-11-16

### Changed

- **Breaking:** `/forget` only accepts `POST`; `GET /forget` now returns 405. All `GET`
  endpoints of the control API are read-only.
- A session with open connections no longer expires and is the last to be evicted at the
  `sticky.max` cap. Its idle time (`sticky.ttl`) now counts from when its last connection
  closes, not from when the connection opened, so long keep-alive connections keep their
  server.
- `GET /ip` is read-only: it uses a session's current server if the session exists, but
  never creates, moves or refreshes it. It accepts a full proxy username
  (`/ip?session=us_w0`) and reports `session_live`.
- The `sessions` count in `/health` and `/metrics` counts only live sessions.

### Added

- `GET /sessions` (and `?name=`): each live session's server, open and total connections,
  last use, idle time and TTL left, without any network traffic.
- `version` in `/health`. A plain `go build` in a git checkout reports `dev-<commit>`
  instead of `dev`.
- [API reference](docs/API.md): every proxy and control API endpoint, parameter, field and
  status code.
- README: a recipe for crawlers and parallel workers (readiness, keep-alive, one session per
  worker, rotating on throttling, pacing), and notes on what the control API shows.

## [1.0.0] - 2026-11-15

First release.

- One binary that holds a Mullvad WireGuard tunnel in its own process (no root, no TUN
  device) and reaches every Mullvad exit server's SOCKS5 proxy through it.
- HTTP and SOCKS5 proxy on the same port; the proxy username `<exit>[_<session>]` selects
  the exit: `any`, a country, a city, an exact server, an alias, `current` or `default`.
- Sticky sessions with one current server that moves when a request names another exit,
  with an idle TTL and a cap.
- Per-domain rules, aliases, per-listener exits and fixed sessions; optional
  `PROXY_PASSWORD`, and `407` challenges for browsers.
- Failover: unreachable exit servers are benched with backoff and the request is retried on
  another one; the tunnel switches entry server when its health probe fails.
- Relay list fetched from Mullvad, cached and refreshed; exit hostnames and DNS for `current`
  resolved inside the tunnel.
- Control API: `/health`, `/exits`, `/ip`, `/forget`, `/tunnel/switch`, `/proxy.pac` and
  Prometheus `/metrics`; one JSON log line per connection.

[Unreleased]: https://github.com/SkanaviLabs/mullpod/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/SkanaviLabs/mullpod/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/SkanaviLabs/mullpod/releases/tag/v1.0.0
