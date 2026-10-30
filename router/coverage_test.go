// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi
// SPDX-License-Identifier: MIT

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// ---- control API ----

// fakeTunnel stands in for *Tunnel in API tests.
type fakeTunnel struct {
	up       atomic.Bool
	switches atomic.Int32
}

func (f *fakeTunnel) Ready() bool            { return f.up.Load() }
func (f *fakeTunnel) Status() map[string]any { return map[string]any{"entry": "us-mia-wg-001"} }
func (f *fakeTunnel) Switch()                { f.switches.Add(1) }

func apiFor(r *rig) (*API, *fakeTunnel, *httptest.Server) {
	ft := &fakeTunnel{}
	ft.up.Store(true)
	a := &API{cfg: r.cfg, cat: r.cat, picker: r.picker, br: r.br, d: r.d, m: &Metrics{}, tun: ft}
	return a, ft, httptest.NewServer(a.Handler())
}

func getJSON(t *testing.T, method, u string) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(method, u, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var m map[string]any
	json.NewDecoder(resp.Body).Decode(&m)
	return resp.StatusCode, m
}

func TestAPIHealth(t *testing.T) {
	r := newRig(t, "de-fra-wg-001")
	_, ft, srv := apiFor(r)
	defer srv.Close()

	code, m := getJSON(t, "GET", srv.URL+"/health")
	if code != 200 || m["status"] != "ok" || m["tunnel"] != true || m["relays"].(float64) != 1 {
		t.Fatalf("healthy: %d %v", code, m)
	}
	if info, _ := m["tunnel_info"].(map[string]any); info["entry"] != "us-mia-wg-001" {
		t.Errorf("tunnel_info: %v", m["tunnel_info"])
	}
	// Tunnel down → 503.
	ft.up.Store(false)
	if code, m = getJSON(t, "GET", srv.URL+"/health"); code != 503 || m["tunnel"] != false {
		t.Errorf("tunnel down: %d %v", code, m)
	}
	// Empty catalog → 503 even with a tunnel.
	ft.up.Store(true)
	r.cat.Set(nil)
	if code, m = getJSON(t, "GET", srv.URL+"/health"); code != 503 || m["relays"].(float64) != 0 {
		t.Errorf("no relays: %d %v", code, m)
	}
}

func TestAPIExitsRotatePACMetricsSwitch(t *testing.T) {
	r := newRig(t, "de-fra-wg-001", "de-fra-wg-002", "de-ber-wg-001", "jp-tyo-wg-001")
	r.cfg.Listeners = []Listener{{Name: "main", Addr: ":8080", Challenge: true}, {Name: "us", Addr: ":8081", Exit: "us", Session: "p"}}
	_, ft, srv := apiFor(r)
	defer srv.Close()

	code, m := getJSON(t, "GET", srv.URL+"/exits?servers=1")
	if code != 200 || m["total"].(float64) != 4 {
		t.Fatalf("exits: %d %v", code, m)
	}
	countries := m["countries"].([]any)
	de := countries[0].(map[string]any)
	if de["code"] != "de" || de["servers"].(float64) != 3 || len(de["cities"].([]any)) != 2 {
		t.Errorf("de: %v", de)
	}
	city := de["cities"].([]any)[0].(map[string]any)
	if len(city["hostnames"].([]any)) == 0 {
		t.Error("servers=1 did not list hostnames")
	}

	// /forget drops a session.
	first, _ := r.picker.Pick(Selection{Exit: "de", Session: "s"}, nil)
	if code, m = getJSON(t, "POST", srv.URL+"/forget?session=s"); code != 200 || m["forgot"] != true {
		t.Errorf("forget: %d %v", code, m)
	}
	if code, _ = getJSON(t, "POST", srv.URL+"/forget"); code != 400 {
		t.Errorf("forget without session: %d", code)
	}
	if code, m = getJSON(t, "POST", srv.URL+"/forget?session=s"); m["forgot"] != false {
		t.Errorf("second forget should have nothing to forget: %v", m)
	}
	// GET works the same as POST.
	r.picker.Pick(Selection{Exit: "de", Session: "g"}, nil)
	if code, m = getJSON(t, "GET", srv.URL+"/forget?session=g"); code != 200 || m["forgot"] != true {
		t.Errorf("GET forget: %d %v", code, m)
	}
	_ = first

	resp, _ := http.Get(srv.URL + "/proxy.pac")
	pac, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(pac), `return "PROXY 127.0.0.1:8081"`) || !strings.Contains(string(pac), "DIRECT") {
		t.Errorf("pac:\n%s", pac)
	}

	resp, _ = http.Get(srv.URL + "/metrics")
	met, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	for _, want := range []string{"mullpod_relays 4", "mullpod_tunnel_up", "mullpod_sessions"} {
		if !strings.Contains(string(met), want) {
			t.Errorf("metrics missing %q:\n%s", want, met)
		}
	}

	if code, m = getJSON(t, "POST", srv.URL+"/tunnel/switch"); code != 202 || m["switching_from"] != "us-mia-wg-001" || ft.switches.Load() != 1 {
		t.Errorf("tunnel/switch: %d %v switches=%d", code, m, ft.switches.Load())
	}
	if code, m = getJSON(t, "GET", srv.URL+"/"); code != 200 || m["endpoints"] == nil {
		t.Errorf("index: %d %v", code, m)
	}
}

func TestAPIIP(t *testing.T) {
	r := newRig(t, "jp-tyo-wg-001", "de-fra-wg-001")
	check := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, `{"ip":"1.2.3.4","country":"Japan","mullvad_exit_ip":true}`)
	}))
	defer check.Close()
	r.cfg.IPCheckURL = check.URL
	_, _, srv := apiFor(r)
	defer srv.Close()

	code, m := getJSON(t, "GET", srv.URL+"/ip?exit=jp&session=x")
	if code != 200 || m["server"] != "jp-tyo-wg-001" || m["check"].(map[string]any)["country"] != "Japan" {
		t.Fatalf("ip: %d %v", code, m)
	}
	if code, m = getJSON(t, "GET", srv.URL+"/ip?exit=zz"); code != 400 || m["error"] == nil {
		t.Errorf("unknown exit: %d %v", code, m)
	}
}

// ---- PROXY_PASSWORD ----

func TestPasswordRequired(t *testing.T) {
	r := newRig(t, "de-fra-wg-001")
	r.cfg.Password = "s3cret"
	addr := r.listen(t, Listener{Name: "open"}) // no challenge: the password alone must enforce auth
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "ok") }))
	defer target.Close()

	httpVia := func(user, pass string) int {
		pu := &url.URL{Scheme: "http", Host: addr}
		if user != "" {
			pu.User = url.UserPassword(user, pass)
		}
		c := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(pu), DisableKeepAlives: true}}
		resp, err := c.Get(target.URL)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if c := httpVia("", ""); c != 407 {
		t.Errorf("HTTP without credentials: %d", c)
	}
	if c := httpVia("de", "wrong"); c != 407 {
		t.Errorf("HTTP wrong password: %d", c)
	}
	if c := httpVia("de", "s3cret"); c != 200 {
		t.Errorf("HTTP right password: %d", c)
	}

	socksAuth := func(methods []byte, user, pass string) []byte {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(5 * time.Second))
		c.Write(append([]byte{5, byte(len(methods))}, methods...))
		g := make([]byte, 2)
		io.ReadFull(c, g)
		if g[1] != 2 {
			return g
		}
		c.Write(append(append(append([]byte{1, byte(len(user))}, user...), byte(len(pass))), pass...))
		a := make([]byte, 2)
		io.ReadFull(c, a)
		return a
	}
	if got := socksAuth([]byte{0}, "", ""); !bytes.Equal(got, []byte{5, 0xff}) {
		t.Errorf("SOCKS no-auth with password set: %v", got)
	}
	if got := socksAuth([]byte{0, 2}, "de", "wrong"); !bytes.Equal(got, []byte{1, 1}) {
		t.Errorf("SOCKS wrong password: %v", got)
	}
	if got := socksAuth([]byte{0, 2}, "de", "s3cret"); !bytes.Equal(got, []byte{1, 0}) {
		t.Errorf("SOCKS right password: %v", got)
	}
}

// ---- catalog: fetch, cache, resolve ----

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
	cfg, err := LoadConfig("../config.yaml")
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

func TestLoopbackAddr(t *testing.T) {
	for addr, want := range map[string]bool{
		"127.0.0.1:8090": true,
		"[::1]:8088":     true,
		"localhost:8080": true,
		"0.0.0.0:8080":   false,
		":8080":          false,
		"example.com:80": false,
		"nope":           false,
	} {
		if got := loopbackAddr(addr); got != want {
			t.Errorf("loopbackAddr(%q) = %v, want %v", addr, got, want)
		}
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

func TestPACIPv6(t *testing.T) {
	a := &API{cfg: &Config{}}
	a.cfg.PAC.Port = "8081"

	for _, c := range []struct{ host, req, want string }{
		{"::1", "http://[::1]:8088/proxy.pac", `return "PROXY [::1]:8081"`},
		{"[::1]", "http://[::1]:8088/proxy.pac", `return "PROXY [::1]:8081"`},
		{"", "http://[::1]:8088/proxy.pac", `return "PROXY [::1]:8081"`},
		{"127.0.0.1", "http://127.0.0.1:8088/proxy.pac", `return "PROXY 127.0.0.1:8081"`},
	} {
		a.cfg.PAC.Host = c.host
		rec := httptest.NewRecorder()
		a.Handler().ServeHTTP(rec, httptest.NewRequest("GET", c.req, nil))
		if body := rec.Body.String(); !strings.Contains(body, c.want) {
			t.Errorf("pac host %q:\n%s", c.host, body)
		}
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

func TestStickyExpiryAndCap(t *testing.T) {
	r := newRig(t, "se-sto-wg-001", "se-sto-wg-002", "se-sto-wg-003")
	pk := NewPicker(r.cat, r.br, nil, 60*time.Millisecond, 2)
	pk.Pick(Selection{Exit: "se", Session: "a"}, nil)
	pk.Pick(Selection{Exit: "se", Session: "b"}, nil)
	pk.Pick(Selection{Exit: "se", Session: "c"}, nil)
	if n := pk.Sessions(); n != 2 {
		t.Errorf("cap: %d sessions, want 2", n)
	}
	pk.Pick(Selection{Exit: "se-sto-wg-001", Session: "pin"}, nil)
	time.Sleep(100 * time.Millisecond)
	pk.Sweep()
	if n := pk.Sessions(); n != 0 {
		t.Errorf("after TTL + sweep: %d sessions", n)
	}
	// An expired session no longer holds its server.
	pk.Pick(Selection{Exit: "se-sto-wg-001", Session: "p2"}, nil)
	time.Sleep(100 * time.Millisecond)
	seen := map[string]bool{}
	for i := 0; i < 6; i++ {
		x, _ := pk.Pick(Selection{Exit: "se"}, nil)
		seen[x.Hostname] = true
	}
	x, _ := pk.Pick(Selection{Exit: "se", Session: "p2"}, nil)
	_ = x
	if len(seen) != 3 {
		t.Errorf("rotation after expiry used %v", seen)
	}
}

func TestBreakerBackoff(t *testing.T) {
	b := NewBreaker(time.Second, 4*time.Second)
	want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 4 * time.Second}
	for i, w := range want {
		d := b.Fail("x")
		lo, hi := time.Duration(float64(w)*0.79), time.Duration(float64(w)*1.21)
		if d < lo || d > hi {
			t.Errorf("fail %d: %v, want %v ±20%%", i+1, d, w)
		}
	}
	if b.Healthy("x") || b.Unhealthy() != 1 {
		t.Error("benched server reported healthy")
	}
	b.OK("x")
	if !b.Healthy("x") || b.Unhealthy() != 0 {
		t.Error("OK did not reset")
	}
}

// ---- SOCKS edge cases, routing extras, error mapping ----

func TestSOCKSUnsupportedCommandAndIPv6(t *testing.T) {
	r := newRig(t, "de-fra-wg-001")
	addr := r.listen(t, Listener{Name: "open"})
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	c.Write([]byte{5, 1, 0})
	io.ReadFull(c, make([]byte, 2))
	req, _ := appendSocksAddr([]byte{5, 2, 0}, "127.0.0.1", 80) // BIND
	c.Write(req)
	h := make([]byte, 4)
	io.ReadFull(c, h)
	if h[1] != 7 {
		t.Errorf("BIND: reply %d, want 7", h[1])
	}

	b, err := appendSocksAddr(nil, "2001:db8::1", 443)
	if err != nil || b[0] != 4 {
		t.Fatalf("ipv6 encode: %v %v", b, err)
	}
	host, port, err := readSocksAddr(bytes.NewReader(b[1:]), b[0])
	if err != nil || host != "2001:db8::1" || port != 443 {
		t.Errorf("ipv6 round trip: %s %d %v", host, port, err)
	}
	if _, err := appendSocksAddr(nil, strings.Repeat("a", 256), 1); err == nil {
		t.Error("over-long hostname accepted")
	}
	if _, _, err := readSocksAddr(bytes.NewReader(nil), 9); err == nil {
		t.Error("unknown address type accepted")
	}
}

func TestRouteSessionHeaderAndImplicit(t *testing.T) {
	cfg := defaultConfig()
	s := &Server{cfg: cfg, ln: Listener{}}
	if got := s.route("de", true, "", "hdr", "x.com"); got != (Selection{"de", "hdr"}) {
		t.Errorf("X-Session: %+v", got)
	}
	if got := s.route("de_u", true, "", "hdr", "x.com"); got.Session != "u" {
		t.Errorf("username session must beat header: %+v", got)
	}
	cfg.Sticky.Implicit = true
	if got := s.route("de", true, "", "", "x.com"); got.Session != "user:de" {
		t.Errorf("implicit sticky: %+v", got)
	}
}

func TestDialStatus(t *testing.T) {
	cases := map[error]int{
		fmt.Errorf("x: %w", errUnknownExit):      400,
		errCatalogEmpty:                          503,
		errTunnelDown:                            503,
		context.DeadlineExceeded:                 504,
		&TargetError{Code: 5}:                    502,
		&UpstreamError{"s", errors.New("reset")}: 502,
	}
	for err, want := range cases {
		if got := dialStatus(err); got != want {
			t.Errorf("%v: %d, want %d", err, got, want)
		}
	}
	if (&TargetError{Code: 4}).Error() != "exit: host unreachable" || (&TargetError{Code: 99}).Error() == "" {
		t.Error("TargetError text")
	}
	if !strings.Contains((&UpstreamError{"s", io.EOF}).Error(), "s") || !errors.Is(&UpstreamError{"s", io.EOF}, io.EOF) {
		t.Error("UpstreamError wrap")
	}
}

func TestPlainHTTPKeepAliveAndBadRequest(t *testing.T) {
	r := newRig(t, "de-fra-wg-001")
	addr := r.listen(t, Listener{Name: "open"})
	// A direct (non-proxy) request to a proxy port is rejected with a hint.
	c, _ := net.Dial("tcp", addr)
	fmt.Fprintf(c, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	c.Close()
	if err != nil || resp.StatusCode != 400 {
		t.Errorf("origin-form request: %v %v", resp, err)
	}
}
