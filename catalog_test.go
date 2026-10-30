// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

func TestCatalogFetchErrors(t *testing.T) {
	ctx := context.Background()
	c := NewCatalog(nil)

	p := filepath.Join(t.TempDir(), "bad.json")
	os.WriteFile(p, []byte("{"), 0o600)
	if _, err := c.LoadFile(p); err == nil {
		t.Error("bad cache accepted")
	}

	if _, err := c.Fetch(ctx, http.DefaultClient, "://bad", ""); err == nil {
		t.Error("bad URL accepted")
	}

	closed := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	u := closed.URL
	closed.Close()
	if _, err := c.Fetch(ctx, http.DefaultClient, u, ""); err == nil {
		t.Error("connection error ignored")
	}

	for name, body := range map[string]string{"parse": "{", "empty": "[]"} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			io.WriteString(w, body)
		}))
		_, err := c.Fetch(ctx, srv.Client(), srv.URL, "")
		srv.Close()
		if err == nil {
			t.Errorf("%s: bad relay list accepted", name)
		}
	}

	truncated := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		conn, _, _ := w.(http.Hijacker).Hijack()
		io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nx")
		conn.Close()
	}))
	defer truncated.Close()
	if _, err := c.Fetch(ctx, truncated.Client(), truncated.URL, ""); err == nil {
		t.Error("truncated body accepted")
	}
}

func TestWriteCacheErrors(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "file")
	os.WriteFile(file, []byte("x"), 0o600)
	if err := writeCache(filepath.Join(file, "relays.json"), []byte("x")); err == nil {
		t.Error("mkdir under a file succeeded")
	}

	tmpDir := filepath.Join(dir, "blocked")
	if err := os.Mkdir(filepath.Join(tmpDir+".tmp"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := writeCache(tmpDir, []byte("x")); err == nil {
		t.Error("write over a directory succeeded")
	}
}

// ---- config ----

const relayJSON = `[
 {"hostname":"se-sto-wg-001","country_code":"se","country_name":"Sweden","city_code":"sto","city_name":"Stockholm","active":true,"socks_name":"se-sto-wg-socks5-001.relays.mullvad.net","socks_port":1080,"pubkey":"k","ipv4_addr_in":"1.1.1.1"},
 {"hostname":"se-sto-wg-002","country_code":"se","city_code":"sto","active":false,"socks_name":"x","socks_port":1080},
 {"hostname":"se-sto-wg-003","country_code":"se","city_code":"sto","active":true,"socks_name":""}
]`

func TestCatalogFetchAndCache(t *testing.T) {
	var fail atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if fail.Load() {
			http.Error(w, "nope", 500)
			return
		}
		io.WriteString(w, relayJSON)
	}))
	defer srv.Close()
	cache := filepath.Join(t.TempDir(), "sub", "relays.json")

	c := NewCatalog(net.DefaultResolver.LookupHost)
	n, err := c.Fetch(context.Background(), srv.Client(), srv.URL, cache)
	if err != nil || n != 1 {
		t.Fatalf("fetch: %d %v (inactive and SOCKS-less relays must be dropped)", n, err)
	}
	if c.LoadedAt().IsZero() || len(c.All()) != 1 || c.All()[0].Pubkey != "k" || c.All()[0].IPv4In != "1.1.1.1" {
		t.Errorf("relay fields: %+v", c.All())
	}
	c2 := NewCatalog(nil)
	if n, err := c2.LoadFile(cache); err != nil || n != 1 {
		t.Errorf("cache reload: %d %v", n, err)
	}
	// An empty cache path disables saving; the fetch still installs the list.
	if n, err := c.Fetch(context.Background(), srv.Client(), srv.URL, ""); err != nil || n != 1 {
		t.Errorf("fetch without cache: %d %v", n, err)
	}
	fail.Store(true)
	if _, err := c.Fetch(context.Background(), srv.Client(), srv.URL, cache); err == nil {
		t.Error("HTTP 500 accepted")
	}
	if c.Len() != 1 {
		t.Error("failed fetch wiped the catalog")
	}
	if _, err := c2.LoadFile(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Error("missing cache accepted")
	}
	if _, err := ParseRelays([]byte("not json")); err == nil {
		t.Error("bad JSON accepted")
	}
}

func TestWriteCache(t *testing.T) {
	dir := t.TempDir()
	if err := writeCache("", []byte("x")); err != nil {
		t.Fatalf("empty cache: %v", err)
	}
	if ents, err := os.ReadDir(dir); err != nil || len(ents) != 0 {
		t.Errorf("empty cache wrote files: %v %v", ents, err)
	}
	p := filepath.Join(dir, "sub", "relays.json")
	if err := writeCache(p, []byte(`[1]`)); err != nil {
		t.Fatalf("write cache: %v", err)
	}
	if b, err := os.ReadFile(p); err != nil || string(b) != `[1]` {
		t.Errorf("cache contents: %q %v", b, err)
	}
	if _, err := os.Stat(p + ".tmp"); !os.IsNotExist(err) {
		t.Errorf("temp file left behind: %v", err)
	}
}

func TestResolveCachesAndPicksIPv4(t *testing.T) {
	var calls atomic.Int32
	c := NewCatalog(func(_ context.Context, host string) ([]string, error) {
		calls.Add(1)
		if host == "v6only" {
			return []string{"fc00::1"}, nil
		}
		if host == "broken" {
			return nil, errors.New("nxdomain")
		}
		return []string{"fc00::1", "10.124.0.5"}, nil
	})
	r := &Relay{SocksName: "se-sto-wg-socks5-001", SocksPort: 1080}
	for i := 0; i < 3; i++ {
		if a, err := c.Resolve(context.Background(), r); err != nil || a != "10.124.0.5:1080" {
			t.Fatalf("resolve: %q %v", a, err)
		}
	}
	if calls.Load() != 1 {
		t.Errorf("lookups: %d, want 1 (cached)", calls.Load())
	}
	if _, err := c.Resolve(context.Background(), &Relay{SocksName: "v6only", SocksPort: 1080}); err == nil {
		t.Error("IPv6-only answer accepted")
	}
	if _, err := c.Resolve(context.Background(), &Relay{SocksName: "broken", SocksPort: 1080}); err == nil {
		t.Error("lookup error swallowed")
	}
}

// ---- config file ----

// TestLoadConfigFixture checks the exact parsed values of testdata/config.yaml.
// It deliberately does not read the user's ../config.yaml: Setup tells users to
// change ports, entry and aliases there, and the test must not depend on that.
