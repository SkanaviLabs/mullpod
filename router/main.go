// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi
// SPDX-License-Identifier: MIT

// Command mullpod is a multi-exit proxy. It holds one Mullvad WireGuard
// tunnel inside its own process and sends each connection out through the
// SOCKS5 proxy of whichever Mullvad server the client selects.
package main

import (
	"context"
	"flag"
	"fmt"
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

func main() {
	cfgPath := flag.String("config", "config.yaml", "config file (all settings)")
	envPath := flag.String("env", ".env", "secrets file: WIREGUARD_PRIVATE_KEY, WIREGUARD_ADDRESSES, PROXY_PASSWORD")
	showVersion := flag.Bool("version", false, "print version, copyright and license, then exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("mullpod %s\n", version)
		fmt.Println("Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi")
		fmt.Println("License: MIT (see LICENSE)")
		return
	}

	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))
	slog.Info("starting", "version", version)
	if *envPath != "" {
		ignored, err := loadDotenv(*envPath)
		if err != nil && !os.IsNotExist(err) {
			slog.Error("env", "err", err.Error())
			os.Exit(1)
		}
		for _, k := range ignored {
			slog.Warn(".env: ignoring non-secret key; set it in config.yaml", "key", k)
		}
	}
	cfg, err := LoadConfig(*cfgPath)
	if err != nil {
		slog.Error("config", "err", err.Error())
		os.Exit(1)
	}
	warnExposed(cfg)
	tun, err := NewTunnel(cfg)
	if err != nil {
		slog.Error("tunnel", "err", err.Error())
		os.Exit(1)
	}

	cat := NewCatalog(tun.LookupHost)
	br := NewBreaker(cfg.Breaker.Base.Duration, cfg.Breaker.Max.Duration)
	pk := NewPicker(cat, br, cfg.Aliases, cfg.Sticky.TTL.Duration, cfg.Sticky.Max)
	d := &Dialer{cat: cat, picker: pk, br: br, net: tun, timeout: cfg.DialTimeout.Duration, ready: tun.Ready}
	m := &Metrics{}

	if n, err := cat.LoadFile(cfg.Catalog.Cache); err == nil {
		slog.Info("catalog loaded from cache", "relays", n)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	slog.Info("tunnel: starting", "entry", cfg.Tunnel.Entry)
	go func() {
		// The entry server's key and endpoint come from the relay list, so
		// without a cache it is fetched once over the host network.
		for cat.Len() == 0 && ctx.Err() == nil {
			if !cfg.Tunnel.BootstrapDirect {
				slog.Error("tunnel: no cached relay list and tunnel.bootstrap_direct is off")
				os.Exit(1)
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
	go func() {
		t := time.NewTicker(time.Minute)
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
		ln, err := net.Listen("tcp", l.Addr)
		if err != nil {
			slog.Error("listen", "addr", l.Addr, "err", err.Error())
			os.Exit(1)
		}
		srv := &Server{cfg: cfg, ln: l, d: d, m: m}
		go srv.Serve(ln)
		slog.Info("listening", "name", l.Name, "addr", l.Addr, "exit", l.Exit, "session", l.Session, "challenge", l.Challenge)
	}
	api := &API{cfg: cfg, cat: cat, picker: pk, br: br, d: d, m: m, tun: tun}
	hs := &http.Server{Addr: cfg.API, Handler: api.Handler(), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		if err := hs.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("api", "err", err.Error())
			os.Exit(1)
		}
	}()
	slog.Info("api listening", "addr", cfg.API)

	<-ctx.Done()
	slog.Info("shutting down")
	sctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	hs.Shutdown(sctx)
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
