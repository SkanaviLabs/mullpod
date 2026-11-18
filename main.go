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
	"path/filepath"
	"runtime/debug"
	"syscall"
	"time"
)

// version is set at build time:
//
//	go build -ldflags "-X main.version=$(git describe --tags --always --dirty)"
var version = "dev"

func init() {
	if version == "dev" {
		version = buildVersion()
	}
}

// buildVersion names a build made without -ldflags from the VCS stamp Go
// embeds (go build in a git checkout): "dev-<rev12>[-dirty]".
func buildVersion() string {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return "dev"
	}
	var rev string
	var dirty bool
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			dirty = s.Value == "true"
		}
	}
	if rev == "" {
		return "dev"
	}
	v := "dev-" + rev[:min(12, len(rev))]
	if dirty {
		v += "-dirty"
	}
	return v
}

// Seams for tests: the real implementations bind ports, open the tunnel and
// install signal handlers.
var (
	newTunnel = NewTunnel
	listen    = net.Listen
	newSignal = func() (context.Context, context.CancelFunc) {
		return notifyContext(syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
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
	showLicenses := fs.Bool("licenses", false, "print copyright and license notices (including third-party), then exit")
	logPath := fs.String("log", "", "also append the JSON log to this file; it keeps logging when stdout goes away, and crash output (panics, fatal runtime errors) is written there too")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if *showLicenses {
		fmt.Fprint(stdout, licenseText)
		fmt.Fprintln(stdout)
		fmt.Fprint(stdout, thirdPartyNotices)
		return 0
	}
	if *showVersion {
		fmt.Fprintf(stdout, "mullpod %s\n", version)
		fmt.Fprintln(stdout, "Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi")
		fmt.Fprintln(stdout, "License: MIT (see LICENSE)")
		fmt.Fprintln(stdout, "Third-party notices: run mullpod -licenses or see THIRD_PARTY_NOTICES.md")
		return 0
	}

	out, closeLog, err := openLog(*logPath, stdout)
	if err != nil {
		fmt.Fprintf(stderr, "mullpod: -log: %v\n", err)
		return 1
	}
	defer closeLog()
	slog.SetDefault(slog.New(slog.NewJSONHandler(out, nil)))
	ignoreSIGPIPE()
	slog.Info("starting", "version", version, "pid", os.Getpid())
	ctx, stop := newSignal()
	defer stop()
	if err := serve(ctx, *cfgPath, *envPath); err != nil {
		slog.Error("mullpod", "err", err.Error())
		slog.Info("stopped", "code", 1)
		return 1
	}
	slog.Info("stopped", "code", 0)
	return 0
}

// openLog returns where the log goes: stdout alone, or with path set, the file
// first and then stdout. Losing stdout (a closed terminal, a dead tee) then
// costs only the copy on stdout. Unrecovered panics and fatal runtime errors are
// also written to the file, since stderr may be gone too.
func openLog(path string, stdout io.Writer) (io.Writer, func(), error) {
	if path == "" {
		return stdout, func() {}, nil
	}
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, nil, err
		}
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return nil, nil, err
	}
	if err := setCrashOutput(f); err != nil {
		f.Close()
		return nil, nil, err
	}
	return &logWriter{file: f, stdout: stdout}, func() { setCrashOutput(nil); f.Close() }, nil
}

var setCrashOutput = func(f *os.File) error { return debug.SetCrashOutput(f, debug.CrashOptions{}) }

// logWriter writes each log line to the file, then to stdout; a stdout error
// is ignored so the file keeps the full log.
type logWriter struct {
	file   io.Writer
	stdout io.Writer
}

func (w *logWriter) Write(p []byte) (int, error) {
	n, err := w.file.Write(p)
	w.stdout.Write(p)
	return n, err
}

// ignoreSIGPIPE stops a write to a broken stdout or stderr pipe from killing
// the process (Go's default for fds 1 and 2): the write fails with EPIPE
// instead, and the first such failure is logged.
func ignoreSIGPIPE() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGPIPE)
	go func() {
		<-ch
		slog.Warn("stdout or stderr is a broken pipe; continuing (use -log to keep a log)")
		for range ch {
		}
	}()
}

// notifyContext is canceled by the first of sigs, and logs which one arrived.
func notifyContext(sigs ...os.Signal) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, sigs...)
	go func() {
		select {
		case s := <-ch:
			slog.Info("signal received", "signal", s.String())
			cancel()
		case <-ctx.Done():
		}
	}()
	return ctx, func() { signal.Stop(ch); cancel() }
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
	if cfg.IdleTimeout.Duration <= 0 {
		slog.Warn("idle_timeout is off: idle tunnels stay open until a side closes them")
	}
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
	reason := "signal"
	select {
	case <-ctx.Done():
	case runErr = <-fatal:
		reason = "fatal error"
	}
	slog.Info("shutting down", "reason", reason, "active_conns", m.active.Load())
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
