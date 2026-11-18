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

### Added

- **Proxy:** `idle_timeout` (default `10m`): a `CONNECT`, SOCKS5 or plain-HTTP connection
  with no bytes in either direction for that long is closed and logged with
  `err: "idle timeout"`. A dead exit or a stalled client no longer keeps a tunnel open
  forever and its session pinned to one server (an open connection keeps a session
  alive). Busy and slow-but-steady transfers are not affected; `0` turns it off.
- **Logging:** `dial_ms` on every connection line: how long reaching the target through
  the exit took, separate from `ms` (how long the connection stayed open).
- **Logging:** `-log <file>` also appends the log to a file. The file keeps the log when
  stdout goes away, and unrecovered panics and fatal runtime errors are written there too.
- **Logging:** `signal received` (with the signal), `shutting down` (with the reason and
  open connections) and `stopped` (with the exit code) lines, and the process ID on
  `starting`, so every exit leaves a record.
- **Build:** service files for running mullpod in the background with automatic restart:
  [dist/mullpod.plist](dist/mullpod.plist) (macOS launchd) and
  [dist/mullpod.service](dist/mullpod.service) (systemd user unit).

### Fixed

- **Logging:** mullpod no longer dies silently when its stdout or stderr is a pipe whose
  reader goes away (a closed terminal, a killed `| tee`): writes fail instead, a warning
  is logged once, and the proxy keeps running. Before, Go's default `SIGPIPE` handling
  ended the process on the next log line with nothing recorded.
- **Proxy:** `SIGHUP` (the terminal closing) now shuts down cleanly and is logged, like
  `SIGINT` and `SIGTERM`.
- **Proxy:** a panic while handling one connection is logged with its stack trace and
  closes only that connection, instead of ending the process.

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
