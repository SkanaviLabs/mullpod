// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi
// SPDX-License-Identifier: MIT

package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// ---- shared fakes ----

type nopConn struct{}

func (nopConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (nopConn) Write(p []byte) (int, error)      { return len(p), nil }
func (nopConn) Close() error                     { return nil }
func (nopConn) LocalAddr() net.Addr              { return dummyAddr{} }
func (nopConn) RemoteAddr() net.Addr             { return dummyAddr{} }
func (nopConn) SetDeadline(time.Time) error      { return nil }
func (nopConn) SetReadDeadline(time.Time) error  { return nil }
func (nopConn) SetWriteDeadline(time.Time) error { return nil }

type dummyAddr struct{}

func (dummyAddr) Network() string { return "tcp" }
func (dummyAddr) String() string  { return "127.0.0.1:0" }

type failConn struct{ nopConn }

func (failConn) Write([]byte) (int, error) { return 0, errors.New("write failed") }

type errDialer struct{ err error }

func (e errDialer) DialContext(context.Context, string, string) (net.Conn, error) { return nil, e.err }

type dialFunc func(context.Context, string, string) (net.Conn, error)

func (f dialFunc) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return f(ctx, network, addr)
}

type scriptedListener struct{ n int }

func (l *scriptedListener) Accept() (net.Conn, error) {
	l.n++
	if l.n == 1 {
		return nil, errors.New("accept failed")
	}
	return nil, net.ErrClosed
}
func (l *scriptedListener) Close() error   { return nil }
func (l *scriptedListener) Addr() net.Addr { return dummyAddr{} }

type timeoutError struct{}

func (timeoutError) Error() string   { return "timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

// ---- control API ----

func TestAPIIPDefaultExitAndNonJSON(t *testing.T) {
	r := newRig(t, "de-fra-wg-001")
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "plain text, not json")
	}))
	defer target.Close()
	r.cfg.IPCheckURL = target.URL
	_, _, srv := apiFor(r)
	defer srv.Close()

	code, m := getJSON(t, "GET", srv.URL+"/ip")
	if code != 200 || m["check"] != "plain text, not json" {
		t.Errorf("ip default exit: %d %v", code, m)
	}
	if m["exit"] != r.cfg.DefaultExit {
		t.Errorf("exit = %v, want %v", m["exit"], r.cfg.DefaultExit)
	}
}

func TestAPIMetricsConnections(t *testing.T) {
	r := newRig(t, "de-fra-wg-001")
	a, _, srv := apiFor(r)
	defer srv.Close()
	a.m.Count("main", "http", "ok")
	a.m.Count("main", "http", "ok")
	a.m.Count("open", "socks5", "error")

	resp, err := http.Get(srv.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(b), `mullpod_connections_total{listener="main",proto="http",result="ok"} 2`) {
		t.Errorf("metrics:\n%s", b)
	}
}

// ---- catalog ----

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

func TestSelectorErrorPaths(t *testing.T) {
	pk := NewPicker(NewCatalog(nil), NewBreaker(time.Minute, time.Hour), nil, time.Minute, 10)
	if _, err := pk.Candidates("any"); !errors.Is(err, errCatalogEmpty) {
		t.Errorf("empty catalog: %v", err)
	}

	r := newRig(t, "de-fra-wg-001", "de-fra-wg-002")
	if _, err := r.picker.Pick(Selection{Exit: "de-fra-wg-001"}, map[string]bool{"de-fra-wg-001": true}); err == nil {
		t.Error("excluded exact server was picked")
	}
	both := map[string]bool{"de-fra-wg-001": true, "de-fra-wg-002": true}
	if _, err := r.picker.Pick(Selection{Exit: "de-fra"}, both); err == nil {
		t.Error("picked with every candidate excluded")
	}

	r.br.Fail("de-fra-wg-001")
	r.br.Fail("de-fra-wg-002")
	got, err := r.picker.Pick(Selection{Exit: "de-fra"}, map[string]bool{"de-fra-wg-001": true})
	if err != nil || got.Hostname != "de-fra-wg-002" {
		t.Errorf("fallback: %v %v", got, err)
	}
}

// ---- dialer ----

func TestDialCurrentAndBadTargets(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			c.Close()
		}
	}()

	d := &Dialer{net: &net.Dialer{Timeout: time.Second}, timeout: time.Second}
	c, server, err := d.Dial(context.Background(), Selection{Exit: exitCurrent}, ln.Addr().String())
	if err != nil || server != exitCurrent {
		t.Fatalf("current: %v %v", server, err)
	}
	c.Close()

	if _, _, err := d.Dial(context.Background(), Selection{Exit: "de"}, "noport"); err == nil {
		t.Error("target without port accepted")
	}
	if _, _, err := d.Dial(context.Background(), Selection{Exit: "de"}, "host:abc"); err == nil {
		t.Error("bad port accepted")
	}
}

func TestDialErrors(t *testing.T) {
	ctx := context.Background()
	br := NewBreaker(time.Second, time.Minute)

	// One dead exit: the second attempt has nothing left, so the first error wins.
	one := NewCatalog(nil)
	one.Set([]*Relay{{Hostname: "de-fra-wg-001", CountryCode: "de", CityCode: "fra", Active: true, Addr: "127.0.0.1:1"}})
	d := &Dialer{cat: one, picker: NewPicker(one, br, nil, time.Minute, 10), br: br,
		net: &net.Dialer{Timeout: 200 * time.Millisecond}, timeout: 200 * time.Millisecond}
	if _, _, err := d.Dial(ctx, Selection{Exit: "de"}, "127.0.0.1:9"); err == nil {
		t.Error("dead exit accepted")
	}

	// Two dead exits: both attempts fail, the last error is returned.
	two := NewCatalog(nil)
	two.Set([]*Relay{
		{Hostname: "de-fra-wg-001", CountryCode: "de", CityCode: "fra", Active: true, Addr: "127.0.0.1:1"},
		{Hostname: "de-fra-wg-002", CountryCode: "de", CityCode: "fra", Active: true, Addr: "127.0.0.1:1"},
	})
	d = &Dialer{cat: two, picker: NewPicker(two, NewBreaker(time.Second, time.Minute), nil, time.Minute, 10),
		br: NewBreaker(time.Second, time.Minute), net: &net.Dialer{Timeout: 200 * time.Millisecond}, timeout: 200 * time.Millisecond}
	if _, _, err := d.Dial(ctx, Selection{Exit: "de"}, "127.0.0.1:9"); err == nil {
		t.Error("two dead exits accepted")
	}

	// Cancel while dialing: the error is the context's, not the exit's.
	cctx, cancel := context.WithCancel(ctx)
	go func() { time.Sleep(10 * time.Millisecond); cancel() }()
	d = &Dialer{cat: two, picker: NewPicker(two, NewBreaker(time.Second, time.Minute), nil, time.Minute, 10),
		br: NewBreaker(time.Second, time.Minute), timeout: 2 * time.Second,
		net: dialFunc(func(ctx context.Context, _, _ string) (net.Conn, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		})}
	if _, _, err := d.Dial(cctx, Selection{Exit: "de"}, "127.0.0.1:9"); !errors.Is(err, context.Canceled) {
		t.Errorf("cancel: %v", err)
	}

	// The tunnel goes down between the ready check and the failed dial.
	var calls atomic.Int32
	d = &Dialer{cat: two, picker: NewPicker(two, NewBreaker(time.Second, time.Minute), nil, time.Minute, 10),
		br: NewBreaker(time.Second, time.Minute), net: &net.Dialer{Timeout: 200 * time.Millisecond}, timeout: 200 * time.Millisecond,
		ready: func() bool { return calls.Add(1) == 1 }}
	if _, _, err := d.Dial(ctx, Selection{Exit: "de"}, "127.0.0.1:9"); !errors.Is(err, errTunnelDown) {
		t.Errorf("tunnel down after failure: %v", err)
	}
}

func TestViaRelayResolveError(t *testing.T) {
	cat := NewCatalog(func(context.Context, string) ([]string, error) { return nil, errors.New("dns") })
	relay := &Relay{Hostname: "de-fra-wg-001", SocksName: "unresolvable"}
	d := &Dialer{cat: cat, net: &net.Dialer{}, timeout: time.Second}
	if _, err := d.viaRelay(context.Background(), relay, "example.com", 80); err == nil {
		t.Error("resolve error ignored")
	}
}

// ---- socks5 helpers ----

func TestSocksConnectErrors(t *testing.T) {
	t.Run("greeting write", func(t *testing.T) {
		c1, c2 := net.Pipe()
		c2.Close()
		if err := socksConnect(c1, "h", 80); err == nil {
			t.Error("write to closed peer succeeded")
		}
		c1.Close()
	})

	t.Run("greeting read", func(t *testing.T) {
		c1, c2 := net.Pipe()
		go func() {
			io.ReadFull(c2, make([]byte, 3))
			c2.Close()
		}()
		if err := socksConnect(c1, "h", 80); err == nil {
			t.Error("missing greeting accepted")
		}
		c1.Close()
	})

	t.Run("greeting rejected", func(t *testing.T) {
		c1, c2 := net.Pipe()
		go func() {
			io.ReadFull(c2, make([]byte, 3))
			c2.Write([]byte{5, 1})
		}()
		if err := socksConnect(c1, "h", 80); err == nil {
			t.Error("rejected greeting accepted")
		}
		c1.Close()
		c2.Close()
	})

	t.Run("bad host", func(t *testing.T) {
		c1, c2 := net.Pipe()
		go func() {
			io.ReadFull(c2, make([]byte, 3))
			c2.Write([]byte{5, 0})
		}()
		if err := socksConnect(c1, strings.Repeat("a", 300), 80); err == nil {
			t.Error("overlong host accepted")
		}
		c1.Close()
		c2.Close()
	})

	t.Run("request write", func(t *testing.T) {
		c1, c2 := net.Pipe()
		go func() {
			io.ReadFull(c2, make([]byte, 3))
			c2.Write([]byte{5, 0})
			c2.Close()
		}()
		if err := socksConnect(c1, "h", 80); err == nil {
			t.Error("request write to closed peer succeeded")
		}
		c1.Close()
	})

	t.Run("reply read", func(t *testing.T) {
		c1, c2 := net.Pipe()
		go func() {
			io.ReadFull(c2, make([]byte, 3))
			c2.Write([]byte{5, 0})
			var h [4]byte
			io.ReadFull(c2, h[:])
			readSocksAddr(c2, h[3])
			c2.Close()
		}()
		if err := socksConnect(c1, "h", 80); err == nil {
			t.Error("missing reply accepted")
		}
		c1.Close()
	})

	t.Run("bad reply version", func(t *testing.T) {
		c1, c2 := net.Pipe()
		go func() {
			io.ReadFull(c2, make([]byte, 3))
			c2.Write([]byte{5, 0})
			var h [4]byte
			io.ReadFull(c2, h[:])
			readSocksAddr(c2, h[3])
			c2.Write([]byte{4, 0, 0, 1, 0, 0, 0, 0, 0, 0})
		}()
		if err := socksConnect(c1, "h", 80); err == nil {
			t.Error("bad reply version accepted")
		}
		c1.Close()
		c2.Close()
	})
}

func TestReadSocksAddrErrors(t *testing.T) {
	for _, atyp := range []byte{1, 3, 4} {
		if _, _, err := readSocksAddr(bytes.NewReader(nil), atyp); err == nil {
			t.Errorf("atyp %d: short address accepted", atyp)
		}
	}
	if _, _, err := readSocksAddr(bytes.NewReader([]byte{5}), 3); err == nil {
		t.Error("short hostname accepted")
	}
	if _, _, err := readSocksAddr(bytes.NewReader([]byte{1, 2, 3, 4}), 1); err == nil {
		t.Error("missing port accepted")
	}
	if _, _, err := readSocksAddr(bytes.NewReader(nil), 9); err == nil {
		t.Error("unknown atyp accepted")
	}
}

func TestReadUserPassErrors(t *testing.T) {
	for name, in := range map[string][]byte{
		"header":   nil,
		"version":  {2, 0},
		"username": {1, 5, 'a'},
		"plen":     {1, 0},
		"password": {1, 1, 'a', 3, 'b'},
	} {
		if _, _, err := readUserPass(bytes.NewReader(in)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	u, p, err := readUserPass(bytes.NewReader([]byte{1, 1, 'a', 1, 'b'}))
	if err != nil || u != "a" || p != "b" {
		t.Errorf("valid credentials: %q %q %v", u, p, err)
	}
}

// ---- proxy ----

func TestServeAcceptError(t *testing.T) {
	s := &Server{cfg: &Config{}, m: &Metrics{}}
	if err := s.Serve(&scriptedListener{}); !errors.Is(err, net.ErrClosed) {
		t.Errorf("serve: %v", err)
	}
}

func TestHandlePeekError(t *testing.T) {
	c1, c2 := net.Pipe()
	c2.Close()
	(&Server{cfg: &Config{}, m: &Metrics{}}).handle(c1)
}

func TestServeHTTPChallengeContinues(t *testing.T) {
	c1, c2 := net.Pipe()
	s := &Server{cfg: &Config{}, ln: Listener{Challenge: true}, m: &Metrics{}}
	go s.serveHTTP(c2, bufio.NewReader(c2))

	req := "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n"
	io.WriteString(c1, req+req)
	br := bufio.NewReader(c1)
	for i := 0; i < 2; i++ {
		resp, err := http.ReadResponse(br, nil)
		if err != nil || resp.StatusCode != 407 {
			t.Fatalf("response %d: %v", i, err)
		}
		resp.Body.Close()
	}
	c1.Close()
}

func TestServeHTTPBadRequest(t *testing.T) {
	c1, c2 := net.Pipe()
	go func() {
		io.WriteString(c1, "not http\r\n\r\n")
		c1.Close()
	}()
	(&Server{cfg: &Config{}, m: &Metrics{}}).serveHTTP(c2, bufio.NewReader(c2))
}

func TestConnectWithoutPortUses443(t *testing.T) {
	cat := NewCatalog(nil)
	cat.Set([]*Relay{{Hostname: "de-fra-wg-001", Active: true, Addr: "exit"}})
	br := NewBreaker(time.Minute, time.Hour)
	pk := NewPicker(cat, br, nil, time.Minute, 10)

	exitSide, exitPeer := net.Pipe()
	got := make(chan string, 1)
	go func() {
		r := bufio.NewReader(exitPeer)
		var g [2]byte
		io.ReadFull(r, g[:])
		io.ReadFull(r, make([]byte, g[1]))
		exitPeer.Write([]byte{5, 0})
		var h [4]byte
		io.ReadFull(r, h[:])
		host, port, err := readSocksAddr(r, h[3])
		if err == nil {
			got <- net.JoinHostPort(host, fmt.Sprint(port))
			socksReply(exitPeer, 0)
		}
	}()

	d := &Dialer{cat: cat, picker: pk, br: br, timeout: time.Second,
		net: dialFunc(func(context.Context, string, string) (net.Conn, error) { return exitSide, nil })}
	s := &Server{cfg: &Config{DefaultExit: "any"}, d: d, m: &Metrics{}}

	client, server := net.Pipe()
	go s.serveHTTP(server, bufio.NewReader(server))
	io.WriteString(client, "CONNECT example.com HTTP/1.1\r\nHost: example.com\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("connect: %v", err)
	}
	client.Close()
	select {
	case addr := <-got:
		if addr != "example.com:443" {
			t.Errorf("target = %q, want example.com:443", addr)
		}
	case <-time.After(time.Second):
		t.Error("exit never saw the target")
	}
}

func echoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
	return ln.Addr().String()
}

func TestConnectReplyWriteError(t *testing.T) {
	r := newRig(t, "de-fra-wg-001")
	s := &Server{cfg: r.cfg, ln: Listener{}, d: r.d, m: &Metrics{}}
	s.connect(failConn{}, bufio.NewReader(strings.NewReader("")), echoServer(t), Selection{Exit: "de"})
}

func TestForwardDialError(t *testing.T) {
	d := &Dialer{cat: NewCatalog(nil), picker: NewPicker(NewCatalog(nil), NewBreaker(time.Second, time.Minute), nil, time.Minute, 10),
		br: NewBreaker(time.Second, time.Minute), net: errDialer{errors.New("down")}, timeout: time.Second}
	s := &Server{cfg: &Config{}, ln: Listener{Name: "t"}, d: d, m: &Metrics{}}
	req := httptest.NewRequest("GET", "http://example.com/", nil)
	if s.forward(nopConn{}, req, Selection{Exit: "any"}) {
		t.Error("forward succeeded with a dead dialer")
	}
}

func TestDialStatusTimeoutAndAuth(t *testing.T) {
	if got := dialStatus(timeoutError{}); got != http.StatusGatewayTimeout {
		t.Errorf("timeout status = %d", got)
	}
	if _, _, ok := proxyAuth("Bearer x"); ok {
		t.Error("non-basic auth accepted")
	}
	if _, _, ok := proxyAuth("Basic !!!"); ok {
		t.Error("undecodable credentials accepted")
	}
	if got := hostOnly("example.com"); got != "example.com" {
		t.Errorf("hostOnly = %q", got)
	}
}

func TestServeSOCKSReadErrors(t *testing.T) {
	s := &Server{cfg: &Config{}, m: &Metrics{}}
	cases := [][]byte{
		nil,                      // no header
		{5, 2},                   // methods truncated
		{5, 1, 2, 2, 0},          // user/pass with bad auth version
		{5, 1, 0, 5, 1, 0, 3, 5}, // request address truncated
	}
	for i, in := range cases {
		s.serveSOCKS(nopConn{}, bufio.NewReader(bytes.NewReader(in)))
		_ = i
	}
}

func TestServeSOCKSTargetError(t *testing.T) {
	r := newRig(t, "de-fra-wg-001")
	r.exits["de-fra-wg-001"].reply = 5
	addr := r.listen(t, Listener{Name: "s"})

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write([]byte{5, 1, 0})
	if _, err := io.ReadFull(c, make([]byte, 2)); err != nil {
		t.Fatal(err)
	}
	c.Write([]byte{5, 1, 0, 1, 127, 0, 0, 1, 0, 80})
	reply := make([]byte, 10)
	if _, err := io.ReadFull(c, reply); err != nil {
		t.Fatal(err)
	}
	if reply[1] != 5 {
		t.Errorf("SOCKS reply = %d, want the exit's code", reply[1])
	}
}

func TestServeSOCKSReplyWriteError(t *testing.T) {
	exitSide, peer := net.Pipe()
	go func() {
		r := bufio.NewReader(peer)
		var g [2]byte
		io.ReadFull(r, g[:])
		io.ReadFull(r, make([]byte, g[1]))
		peer.Write([]byte{5, 0})
		var h [4]byte
		io.ReadFull(r, h[:])
		readSocksAddr(r, h[3])
		peer.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	}()
	defer peer.Close()

	cat := NewCatalog(nil)
	cat.Set([]*Relay{{Hostname: "de-fra-wg-001", Active: true, Addr: "exit"}})
	br := NewBreaker(time.Minute, time.Hour)
	d := &Dialer{cat: cat, picker: NewPicker(cat, br, nil, time.Minute, 10), br: br, timeout: time.Second,
		net: dialFunc(func(context.Context, string, string) (net.Conn, error) { return exitSide, nil })}
	req, err := appendSocksAddr([]byte{5, 1, 0}, "127.0.0.1", 80)
	if err != nil {
		t.Fatal(err)
	}
	buf := append([]byte{5, 1, 0}, req...) // greeting, then request
	(&Server{cfg: &Config{DefaultExit: "any"}, d: d, m: &Metrics{}}).
		serveSOCKS(failConn{}, bufio.NewReader(bytes.NewReader(buf)))
}

func TestSpliceWithoutCloseWrite(t *testing.T) {
	sent, recv := splice(nopConn{}, nopConn{}, nopConn{})
	if sent != 0 || recv != 0 {
		t.Errorf("splice copied %d/%d", sent, recv)
	}
}
