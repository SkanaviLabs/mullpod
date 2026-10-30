// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi
// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func withMainVars(t *testing.T) {
	t.Helper()
	oldTunnel, oldSignal, oldListen, oldExit, oldTick := newTunnel, newSignal, listen, exit, sweepTick
	t.Cleanup(func() {
		newTunnel, newSignal, listen, exit, sweepTick = oldTunnel, oldSignal, oldListen, oldExit, oldTick
	})
}

func fakeTunnelFor(c *Config) (*Tunnel, error) {
	return &Tunnel{cfg: c, dev: &fakeDev{}, net: &fakeNet{err: errors.New("no net")},
		switchReq: make(chan struct{}, 1)}, nil
}

func cannedSignal() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx, func() {}
}

func writeMainConfig(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

const servedConfig = `
listeners:
  - { name: main, addr: "127.0.0.1:0" }
api: "127.0.0.1:0"
catalog:
  cache: ""
tunnel:
  entry: any
`

func TestCLI(t *testing.T) {
	withMainVars(t)

	var out, errb bytes.Buffer
	if code := cli([]string{"-version"}, &out, &errb); code != 0 {
		t.Errorf("version exit = %d", code)
	}
	if !strings.Contains(out.String(), "License: MIT") || !strings.Contains(out.String(), version) {
		t.Errorf("version output: %q", out.String())
	}

	out.Reset()
	errb.Reset()
	if code := cli([]string{"-nope"}, &out, &errb); code != 2 {
		t.Errorf("bad flag exit = %d", code)
	}
	if code := cli([]string{"-h"}, &out, &errb); code != 0 {
		t.Errorf("help exit = %d", code)
	}
}

func TestCLIErrors(t *testing.T) {
	withMainVars(t)
	newSignal = cannedSignal

	var out, errb bytes.Buffer
	dir := t.TempDir()
	good := writeMainConfig(t, servedConfig)

	if code := cli([]string{"-env", dir, "-config", good}, &out, &errb); code != 1 {
		t.Errorf("env error exit = %d", code)
	}
	if code := cli([]string{"-env", "", "-config", dir}, &out, &errb); code != 1 {
		t.Errorf("config error exit = %d", code)
	}

	newTunnel = func(*Config) (*Tunnel, error) { return nil, errors.New("tunnel") }
	if code := cli([]string{"-env", "", "-config", good}, &out, &errb); code != 1 {
		t.Errorf("tunnel error exit = %d", code)
	}

	newTunnel = fakeTunnelFor
	if code := cli([]string{"-env", "", "-config", good}, &out, &errb); code != 0 {
		t.Errorf("success exit = %d", code)
	}
}

func TestMainRunsCLI(t *testing.T) {
	withMainVars(t)
	var got int
	exit = func(code int) { got = code }
	oldArgs := os.Args
	os.Args = []string{"mullpod", "-version"}
	t.Cleanup(func() { os.Args = oldArgs })

	main()
	if got != 0 {
		t.Errorf("exit code = %d", got)
	}
}

func TestServeBootstrapOff(t *testing.T) {
	withMainVars(t)
	newTunnel = fakeTunnelFor
	p := writeMainConfig(t, `
listeners:
  - { name: main, addr: "127.0.0.1:0" }
api: "127.0.0.1:0"
catalog:
  cache: ""
  url: "http://127.0.0.1:1/"
tunnel:
  entry: any
  bootstrap_direct: false
`)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := serve(ctx, p, ""); err == nil {
		t.Error("bootstrap_direct off was accepted without a cache")
	}
}

func TestServeListenerError(t *testing.T) {
	withMainVars(t)
	newTunnel = fakeTunnelFor
	listen = func(string, string) (net.Listener, error) { return nil, errors.New("listen") }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := serve(ctx, writeMainConfig(t, servedConfig), ""); err == nil {
		t.Error("listen error ignored")
	}
}

func TestServeAPIError(t *testing.T) {
	withMainVars(t)
	newTunnel = fakeTunnelFor
	cache := filepath.Join(t.TempDir(), "relays.json")
	os.WriteFile(cache, []byte(relayJSON), 0o600)
	p := writeMainConfig(t, `
listeners:
  - { name: main, addr: "127.0.0.1:0" }
api: "127.0.0.1:99999"
catalog:
  cache: "`+cache+`"
tunnel:
  entry: any
`)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := serve(ctx, p, ""); err == nil {
		t.Error("bad api address ignored")
	}
}

func TestServeBootstrapSuccessAndSweep(t *testing.T) {
	withMainVars(t)
	newTunnel = fakeTunnelFor
	sweepTick = time.Millisecond

	hit := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		select {
		case hit <- struct{}{}:
		default:
		}
		io.WriteString(w, relayJSON)
	}))
	defer srv.Close()

	p := writeMainConfig(t, `
listeners:
  - { name: main, addr: "127.0.0.1:0" }
api: "127.0.0.1:0"
catalog:
  cache: ""
  url: "`+srv.URL+`"
tunnel:
  entry: any
`)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		select {
		case <-hit:
			time.Sleep(30 * time.Millisecond)
			cancel()
		case <-time.After(3 * time.Second):
			cancel()
		}
	}()
	if err := serve(ctx, p, ""); err != nil {
		t.Errorf("serve: %v", err)
	}
}

func TestCatalogLoop(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		hit := make(chan struct{}, 1)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			select {
			case hit <- struct{}{}:
			default:
			}
			io.WriteString(w, relayJSON)
		}))
		defer srv.Close()
		cfg := defaultConfig()
		cfg.Catalog.URL = srv.URL
		cfg.Catalog.Cache = ""
		cat := NewCatalog(nil)
		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			<-hit
			cancel()
		}()
		catalogLoop(ctx, cat, cfg, &net.Dialer{})
	})

	t.Run("failure", func(t *testing.T) {
		cfg := defaultConfig()
		cfg.Catalog.URL = "http://127.0.0.1:1/"
		cfg.Catalog.Cache = ""
		cat := NewCatalog(nil)
		ctx, cancel := context.WithCancel(context.Background())
		go func() { time.Sleep(20 * time.Millisecond); cancel() }()
		catalogLoop(ctx, cat, cfg, &net.Dialer{})
	})

	t.Run("refresh", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			io.WriteString(w, relayJSON)
		}))
		defer srv.Close()
		cfg := defaultConfig()
		cfg.Catalog.URL = srv.URL
		cfg.Catalog.Cache = ""
		cfg.Catalog.Refresh = Duration{time.Millisecond}
		cat := NewCatalog(nil)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
		defer cancel()
		catalogLoop(ctx, cat, cfg, &net.Dialer{})
	})
}

func TestWarnExposed(t *testing.T) {
	warnExposed(&Config{API: "0.0.0.0:1", Listeners: []Listener{{Name: "a", Addr: "0.0.0.0:2"}}})
	warnExposed(&Config{API: "127.0.0.1:1", Listeners: []Listener{{Name: "a", Addr: "192.168.1.2:2"}}})
	warnExposed(&Config{API: "127.0.0.1:1", Listeners: []Listener{{Name: "a", Addr: "0.0.0.0:2"}}, Password: "x"})
}

func TestReportFatal(t *testing.T) {
	ch := make(chan error, 1)
	reportFatal(ch, errors.New("first"))
	reportFatal(ch, errors.New("second")) // queue full: default branch
	if err := <-ch; err == nil || err.Error() != "first" {
		t.Errorf("queued error = %v", err)
	}
}

func TestRealSignalContext(t *testing.T) {
	ctx, stop := newSignal()
	stop()
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("signal context was not canceled")
	}
}

func TestServeIgnoredEnvKeys(t *testing.T) {
	withMainVars(t)
	newTunnel = fakeTunnelFor
	env := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(env, []byte("NOT_A_SECRET=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := serve(ctx, writeMainConfig(t, servedConfig), env); err != nil {
		t.Errorf("serve: %v", err)
	}
}

func TestServeBootstrapFetchError(t *testing.T) {
	withMainVars(t)
	newTunnel = fakeTunnelFor
	p := writeMainConfig(t, `
listeners:
  - { name: main, addr: "127.0.0.1:0" }
api: "127.0.0.1:0"
catalog:
  cache: ""
  url: "http://127.0.0.1:1/"
tunnel:
  entry: any
`)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := serve(ctx, p, ""); err != nil {
		t.Errorf("serve: %v", err)
	}
}
