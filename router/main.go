// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi
// SPDX-License-Identifier: MIT

// Command mullpod is a multi-exit proxy. It holds one Mullvad WireGuard
// tunnel inside its own process and sends each connection out through the
// SOCKS5 proxy of whichever Mullvad server the client selects.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// version is set at build time:
//
//	go build -ldflags "-X main.version=$(git describe --tags --always --dirty)"
var version = "dev"

// Seams for tests: the real implementations bind ports, open the tunnel and
// install signal handlers.
var (
	newTunnel = NewTunnel
	listen    = net.Listen
	newSignal = func() (context.Context, context.CancelFunc) {
		return signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	}
	exit      = os.Exit
	sweepTick = time.Minute
)

func main() { exit(cli(os.Args[1:], os.Stdout, os.Stderr)) }

// cli parses flags and runs the process. It returns the process exit code.
func cli(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("mullpod", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "config.yaml", "config file (all settings)")
	envPath := fs.String("env", ".env", "secrets file: WIREGUARD_PRIVATE_KEY, WIREGUARD_ADDRESSES, PROXY_PASSWORD")
	showVersion := fs.Bool("version", false, "print version, copyright and license, then exit")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if *showVersion {
		fmt.Fprintf(stdout, "mullpod %s\n", version)
		fmt.Fprintln(stdout, "Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi")
		fmt.Fprintln(stdout, "License: MIT (see LICENSE)")
		return 0
	}

	slog.SetDefault(slog.New(slog.NewJSONHandler(stdout, nil)))
	slog.Info("starting", "version", version)
	ctx, stop := newSignal()
	defer stop()
	if err := serve(ctx, *cfgPath, *envPath); err != nil {
		slog.Error("mullpod", "err", err.Error())
		return 1
	}
	return 0
}

// serve loads the configuration and runs until ctx is canceled or a fatal
// error occurs.
func serve(ctx context.Context, cfgPath, envPath string) error {
	if envPath != "" {
		ignored, err := loadDotenv(envPath)
		if err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("env: %w", err)
		}
		for _, k := range ignored {
			slog.Warn(".env: ignoring non-secret key; set it in config.yaml", "key", k)
		}
	}
	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	warnExposed(cfg)
	tun, err := newTunnel(cfg)
	if err != nil {
		return fmt.Errorf("tunnel: %w", err)
	}

	cat := NewCatalog(tun.LookupHost)
	br := NewBreaker(cfg.Breaker.Base.Duration, cfg.Breaker.Max.Duration)
	pk := NewPicker(cat, br, cfg.Aliases, cfg.Sticky.TTL.Duration, cfg.Sticky.Max)
	d := &Dialer{cat: cat, picker: pk, br: br, net: tun, timeout: cfg.DialTimeout.Duration, ready: tun.Ready}
	m := &Metrics{}

	if cfg.Catalog.Cache != "" {
		if n, err := cat.LoadFile(cfg.Catalog.Cache); err == nil {
			slog.Info("catalog loaded from cache", "relays", n)
		}
	}

	// Fatal errors from goroutines are reported here instead of killing the
	// process, so serve can shut down cleanly.
	fatal := make(chan error, 1)
	fail := func(err error) { reportFatal(fatal, err) }

	slog.Info("tunnel: starting", "entry", cfg.Tunnel.Entry)
	go func() {
		// The entry server's key and endpoint come from the relay list, so
		// without a cache it is fetched once over the host network.
		for cat.Len() == 0 && ctx.Err() == nil {
			if !cfg.Tunnel.BootstrapDirect {
				fail(errors.New("no cached relay list and tunnel.bootstrap_direct is off"))
				return
			}
			n, err := cat.Fetch(ctx, &http.Client{Timeout: 30 * time.Second}, cfg.Catalog.URL, cfg.Catalog.Cache)
			if err != nil {
				slog.Warn("catalog bootstrap failed", "err", err.Error())
				sleepCtx(ctx, 5*time.Second)
				continue
			}
			slog.Info("catalog bootstrapped over host network", "relays", n)
		}
		tun.Run(ctx, pk)
	}()
	go catalogLoop(ctx, cat, cfg, tun)
	sweep := sweepTick
	go func() {
		t := time.NewTicker(sweep)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				pk.Sweep()
			}
		}
	}()

	for _, l := range cfg.Listeners {
		ln, err := listen("tcp", l.Addr)
		if err != nil {
			return fmt.Errorf("listen %s: %w", l.Addr, err)
		}
		srv := &Server{cfg: cfg, ln: l, d: d, m: m}
		go srv.Serve(ln)
		slog.Info("listening", "name", l.Name, "addr", l.Addr, "exit", l.Exit, "session", l.Session, "challenge", l.Challenge)
	}
	api := &API{cfg: cfg, cat: cat, picker: pk, br: br, d: d, m: m, tun: tun}
	hs := &http.Server{Addr: cfg.API, Handler: api.Handler(), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		if err := hs.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fail(fmt.Errorf("api: %w", err))
		}
	}()
	slog.Info("api listening", "addr", cfg.API)

	var runErr error
	select {
	case <-ctx.Done():
	case runErr = <-fatal:
	}
	slog.Info("shutting down")
	sctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	hs.Shutdown(sctx)
	return runErr
}

// reportFatal queues err without blocking when one is already queued.
func reportFatal(ch chan<- error, err error) {
	select {
	case ch <- err:
	default:
	}
}

// warnExposed flags ports reachable beyond localhost. Mullvad's exit proxies
// have no auth, and the control API has no auth of its own.
func warnExposed(cfg *Config) {
	if !loopbackAddr(cfg.API) {
		slog.Warn("control API has no auth and is not bound to loopback", "addr", cfg.API)
	}
	if cfg.Password != "" {
		return
	}
	for _, l := range cfg.Listeners {
		if !loopbackAddr(l.Addr) {
			slog.Warn("proxy port reachable without PROXY_PASSWORD", "listener", l.Name, "addr", l.Addr)
		}
	}
}

func loopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// catalogLoop fetches the relay list through the tunnel until it succeeds (the
// tunnel may still be coming up), then refreshes it periodically.
func catalogLoop(ctx context.Context, cat *Catalog, cfg *Config, nd netDialer) {
	client := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{DialContext: nd.DialContext}}
	backoff := 3 * time.Second
	for {
		n, err := cat.Fetch(ctx, client, cfg.Catalog.URL, cfg.Catalog.Cache)
		wait := cfg.Catalog.Refresh.Duration
		if err != nil {
			slog.Warn("catalog fetch failed", "err", err.Error(), "retry_s", int(backoff.Seconds()))
			wait = backoff
			backoff = min(backoff*2, 2*time.Minute)
		} else {
			slog.Info("catalog fetched", "relays", n)
			backoff = 3 * time.Second
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}
