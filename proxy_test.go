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
	"net/url"
	"strings"
	"testing"
	"time"
)

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
