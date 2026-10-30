// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi
// SPDX-License-Identifier: MIT

package main

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestConfigErrorPathsAndRules(t *testing.T) {
	dir := t.TempDir()
	if _, err := loadDotenv(dir); err == nil {
		t.Error("directory accepted as .env")
	}
	if _, err := LoadConfig(dir); err == nil {
		t.Error("directory accepted as config")
	}

	p := filepath.Join(dir, "rules.yaml")
	os.WriteFile(p, []byte("listeners: [{addr: \"127.0.0.1:0\"}]\n"+
		"rules:\n  - {match: \"Example.COM\", exit: DE}\n  - {match: \"*.foo.com\", exit: jp}\n"), 0o600)
	cfg, err := LoadConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Rules[0].Match != "example.com" || cfg.Rules[0].Exit != "de" {
		t.Errorf("rule not normalised: %+v", cfg.Rules)
	}
	if got := cfg.MatchRule("EXAMPLE.com."); got != "de" {
		t.Errorf("exact rule: %q", got)
	}
	if got := cfg.MatchRule("a.foo.com"); got != "jp" {
		t.Errorf("wildcard rule: %q", got)
	}

	empty := filepath.Join(dir, "empty.yaml")
	os.WriteFile(empty, []byte("listeners: []\n"), 0o600)
	if _, err := LoadConfig(empty); err == nil {
		t.Error("config without listeners accepted")
	}
}

// ---- selector ----

func TestLoadConfigFixture(t *testing.T) {
	cfg, err := LoadConfig("testdata/config.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Listeners) != 6 || cfg.Listeners[0].Name != "main" || !cfg.Listeners[0].Challenge || cfg.Listeners[0].Addr != "127.0.0.1:8090" {
		t.Errorf("listeners: %+v", cfg.Listeners)
	}
	if cfg.Listeners[2].Exit != "us" || cfg.Listeners[2].Session == "" {
		t.Errorf("fixed listener: %+v", cfg.Listeners[2])
	}
	if cfg.Sticky.TTL.Duration != 10*time.Minute || cfg.Tunnel.ProbeInterval.Duration != 10*time.Second || cfg.Catalog.Refresh.Duration != 6*time.Hour {
		t.Errorf("durations: %v %v %v", cfg.Sticky.TTL, cfg.Tunnel.ProbeInterval, cfg.Catalog.Refresh)
	}
	if cfg.API != "127.0.0.1:8088" || cfg.Tunnel.Entry != "us-mia" || cfg.Catalog.Cache != "data/relays.json" || cfg.PACPort() != "8081" || len(cfg.Aliases["eu"]) == 0 {
		t.Errorf("api %q cache %q pac %q aliases %v", cfg.API, cfg.Catalog.Cache, cfg.PACPort(), cfg.Aliases)
	}

	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.yaml")
	os.WriteFile(bad, []byte("dial_timeout: 5x\n"), 0o600)
	if _, err := LoadConfig(bad); err == nil {
		t.Error("bad duration accepted")
	}
	os.WriteFile(bad, []byte("listeners: [{addr: nope}]\n"), 0o600)
	if _, err := LoadConfig(bad); err == nil {
		t.Error("bad listener address accepted")
	}
}

// TestShippedConfigParses only checks that the repo's example config stays
// loadable. Users are expected to edit it, so no exact values are asserted.

func TestShippedConfigParses(t *testing.T) {
	cfg, err := LoadConfig("config.yaml")
	if errors.Is(err, os.ErrNotExist) {
		t.Skip("no config.yaml in the repo root")
	}
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Listeners) == 0 {
		t.Error("shipped config has no listeners")
	}
	if cfg.API == "" {
		t.Error("shipped config has no api address")
	}
}

func TestListenerIPv6(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "v6.yaml")
	os.WriteFile(p, []byte(`
listeners:
  - {name: main, addr: "[::1]:8090"}
  - {name: pinned, addr: "10.1.2.3:9000"}
api: "[::1]:8088"
`), 0o600)

	cfg, err := LoadConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listeners[0].Addr != "[::1]:8090" || cfg.API != "[::1]:8088" {
		t.Fatalf("explicit IPv6: %q %q", cfg.Listeners[0].Addr, cfg.API)
	}
	if cfg.Listeners[1].Addr != "10.1.2.3:9000" {
		t.Errorf("explicit IPv4 changed: %q", cfg.Listeners[1].Addr)
	}

	bad := filepath.Join(dir, "bad-api.yaml")
	os.WriteFile(bad, []byte(`api: "::1:8088"`+"\n"), 0o600)
	if _, err := LoadConfig(bad); err == nil {
		t.Error("unbracketed IPv6 api address accepted")
	}
}

func TestRejectWildcardAddress(t *testing.T) {
	dir := t.TempDir()
	for _, c := range []struct{ name, config string }{
		{"listener-any-v4", "listeners: [{addr: \"0.0.0.0:9000\"}]\n"},
		{"listener-any-v6", "listeners: [{addr: \"[::]:9000\"}]\n"},
		{"listener-any-v6-long", "listeners: [{addr: \"[0:0:0:0:0:0:0:0]:9000\"}]\n"},
		{"listener-no-host", "listeners: [{addr: \":9000\"}]\n"},
		{"api-any-v4", "listeners: [{addr: \"127.0.0.1:9000\"}]\napi: \"0.0.0.0:8088\"\n"},
		{"api-no-host", "listeners: [{addr: \"127.0.0.1:9000\"}]\napi: \":8088\"\n"},
	} {
		p := filepath.Join(dir, strings.ReplaceAll(c.name, "-", "_")+".yaml")
		os.WriteFile(p, []byte(c.config), 0o600)
		if _, err := LoadConfig(p); err == nil {
			t.Errorf("%s: wildcard address accepted", c.name)
		} else if !strings.Contains(err.Error(), "every interface") {
			t.Errorf("%s: unexpected error: %v", c.name, err)
		}
	}
}

func TestListenIPv6(t *testing.T) {
	ln, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	defer ln.Close()
	if !strings.HasPrefix(ln.Addr().String(), "[::1]:") {
		t.Errorf("listener address: %s", ln.Addr())
	}
}

func TestPACPortFallbacks(t *testing.T) {
	c := defaultConfig()
	c.Listeners = []Listener{{Addr: ":8080", Challenge: true}, {Addr: ":1080"}, {Addr: ":8085", Session: "s"}}
	if p := c.PACPort(); p != "8085" {
		t.Errorf("prefer sticky credential-free port: %s", p)
	}
	c.Listeners = c.Listeners[:2]
	if p := c.PACPort(); p != "1080" {
		t.Errorf("fallback: %s", p)
	}
	c.PAC.Port = "9000"
	if p := c.PACPort(); p != "9000" {
		t.Errorf("explicit: %s", p)
	}
}

// ---- sessions: TTL, sweep, cap ----
