// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi
// SPDX-License-Identifier: MIT

package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeExit is a minimal no-auth SOCKS5 server standing in for a Mullvad exit.
// It stamps responses so tests can tell which exit carried a request.
type fakeExit struct {
	ln    net.Listener
	conns atomic.Int64
	reply byte // non-zero: answer every CONNECT with this SOCKS error
}

func startExit(t *testing.T) *fakeExit {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeExit{ln: ln}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(c)
		}
	}()
	return f
}

func (f *fakeExit) serve(c net.Conn) {
	defer c.Close()
	f.conns.Add(1)
	var g [2]byte
	io.ReadFull(c, g[:])
	io.ReadFull(c, make([]byte, g[1]))
	c.Write([]byte{5, 0})
	var h [4]byte
	if _, err := io.ReadFull(c, h[:]); err != nil {
		return
	}
	host, port, err := readSocksAddr(c, h[3])
	if err != nil {
		return
	}
	if f.reply != 0 {
		socksReply(c, f.reply)
		return
	}
	up, err := net.Dial("tcp", net.JoinHostPort(host, fmt.Sprint(port)))
	if err != nil {
		socksReply(c, 5)
		return
	}
	socksReply(c, 0)
	splice(c, c, up)
}

func (f *fakeExit) addr() string { return f.ln.Addr().String() }

var testNames = map[string]string{
	"se": "Sweden", "se-sto": "Stockholm", "se-got": "Gothenburg",
	"no": "Norway", "no-osl": "Oslo",
	"de": "Germany", "de-fra": "Frankfurt", "de-ber": "Berlin",
	"us": "USA", "us-nyc": "New York, NY", "us-mia": "Miami, FL",
	"gb": "UK", "gb-lon": "London", "jp": "Japan", "jp-tyo": "Tokyo",
	"br": "Brazil", "br-sao": "São Paulo",
}

type rig struct {
	cfg    *Config
	cat    *Catalog
	picker *Picker
	br     *Breaker
	d      *Dialer
	exits  map[string]*fakeExit
}

func newRig(t *testing.T, hosts ...string) *rig {
	t.Helper()
	cfg := defaultConfig()
	cat := NewCatalog(net.DefaultResolver.LookupHost)
	exits := map[string]*fakeExit{}
	var relays []*Relay
	for _, h := range hosts {
		parts := strings.Split(h, "-")
		f := startExit(t)
		exits[h] = f
		relays = append(relays, &Relay{Hostname: h, CountryCode: parts[0], CityCode: parts[1],
			CountryName: testNames[parts[0]], CityName: testNames[parts[0]+"-"+parts[1]], Active: true, Addr: f.addr()})
	}
	cat.Set(relays)
	br := NewBreaker(time.Minute, time.Hour)
	pk := NewPicker(cat, br, map[string][]string{"nordic": {"se", "no"}}, time.Minute, 100)
	d := &Dialer{cat: cat, picker: pk, br: br, net: &net.Dialer{Timeout: 2 * time.Second}, timeout: 2 * time.Second}
	return &rig{cfg: cfg, cat: cat, picker: pk, br: br, d: d, exits: exits}
}

func (r *rig) listen(t *testing.T, l Listener) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	s := &Server{cfg: r.cfg, ln: l, d: r.d, m: &Metrics{}}
	go s.Serve(ln)
	return ln.Addr().String()
}

func TestParseUser(t *testing.T) {
	cases := map[string]Selection{
		"de":              {Exit: "de"},
		"DE-Fra_s1":       {Exit: "de-fra", Session: "s1"},
		"se-sto-wg-001_a": {Exit: "se-sto-wg-001", Session: "a"},
		"us_a_b":          {Exit: "us", Session: "a_b"},
		"":                {},
	}
	for in, want := range cases {
		if got := ParseUser(in); got != want {
			t.Errorf("ParseUser(%q) = %+v, want %+v", in, got, want)
		}
	}
}

func TestCandidates(t *testing.T) {
	r := newRig(t, "se-sto-wg-001", "se-got-wg-002", "no-osl-wg-001", "de-fra-wg-001")
	for sel, want := range map[string]int{"any": 4, "se": 2, "se-sto": 1, "se-sto-wg-001": 1,
		"nordic": 3} {
		c, err := r.picker.Candidates(sel)
		if err != nil || len(c) != want {
			t.Errorf("%s: got %d (%v), want %d", sel, len(c), err, want)
		}
	}
	for _, bad := range []string{"xx", "rotate", "random"} {
		if _, err := r.picker.Candidates(bad); !errors.Is(err, errUnknownExit) {
			t.Errorf("%q should be unknown: %v", bad, err)
		}
	}
}

func TestMullvadCodesAsUsername(t *testing.T) {
	r := newRig(t, "de-fra-wg-001", "de-fra-wg-002", "de-ber-wg-001", "us-nyc-wg-001", "us-mia-wg-001", "br-sao-wg-001")
	cases := map[string][]string{
		"de":            {"de-ber-wg-001", "de-fra-wg-001", "de-fra-wg-002"},
		"DE":            {"de-ber-wg-001", "de-fra-wg-001", "de-fra-wg-002"},
		"us":            {"us-mia-wg-001", "us-nyc-wg-001"},
		"de-fra":        {"de-fra-wg-001", "de-fra-wg-002"},
		"us-nyc":        {"us-nyc-wg-001"},
		"br-sao":        {"br-sao-wg-001"},
		"de-fra-wg-002": {"de-fra-wg-002"},
		"DE-FRA-WG-002": {"de-fra-wg-002"},
	}
	for user, want := range cases {
		sel := ParseUser(user)
		got := map[string]bool{}
		for i := 0; i < 20; i++ {
			x, err := r.picker.Pick(sel, nil)
			if err != nil {
				t.Fatalf("%s: %v", user, err)
			}
			got[x.Hostname] = true
		}
		if len(got) != len(want) {
			t.Errorf("%s: picked %v, want %v", user, got, want)
		}
		for _, h := range want {
			if !got[h] {
				t.Errorf("%s: never picked %s (got %v)", user, h, got)
			}
		}
	}
	// Only Mullvad's identifiers: no names, no shortened hostnames.
	for _, bad := range []string{"germany", "frankfurt", "usa", "de-fra-002", "de-frankfurt"} {
		if _, err := r.picker.Candidates(bad); !errors.Is(err, errUnknownExit) {
			t.Errorf("%q should be unknown, got %v", bad, err)
		}
	}
}

func TestSessionHasOneCurrentServer(t *testing.T) {
	r := newRig(t, "de-fra-wg-001", "de-fra-wg-002", "de-fra-wg-003", "de-ber-wg-001", "jp-tyo-wg-001", "jp-tyo-wg-002")
	pick := func(user string) string {
		t.Helper()
		sel := ParseUser(user)
		if sel.Exit == "default" {
			sel.Exit = "any"
		}
		x, err := r.picker.Pick(sel, nil)
		if err != nil {
			t.Fatalf("%s: %v", user, err)
		}
		return x.Hostname
	}
	country := func(h string) string { return h[:2] }

	// Exact server, with or without a session, is always that server.
	for i := 0; i < 5; i++ {
		if h := pick("de-fra-wg-002"); h != "de-fra-wg-002" {
			t.Fatalf("exact server without session gave %s", h)
		}
	}
	// An exact name sets the session's server; broader exits that contain it keep it.
	if h := pick("de-fra-wg-002_job"); h != "de-fra-wg-002" {
		t.Fatalf("exact server gave %s", h)
	}
	for _, user := range []string{"de-fra_job", "de_job", "any_job", "any_job", "default_job"} {
		for i := 0; i < 3; i++ {
			if h := pick(user); h != "de-fra-wg-002" {
				t.Errorf("%s: got %s, want de-fra-wg-002", user, h)
			}
		}
	}
	// An exit that doesn't contain it moves the session there, until changed again.
	jp := pick("jp_job")
	if country(jp) != "jp" {
		t.Fatalf("jp_job: %s", jp)
	}
	for _, user := range []string{"any_job", "jp_job", "jp-tyo_job", "default_job"} {
		if h := pick(user); h != jp {
			t.Errorf("%s after moving to Japan: got %s, want %s", user, h, jp)
		}
	}
	de := pick("de_job")
	if country(de) != "de" {
		t.Fatalf("de_job after jp: %s", de)
	}
	if h := pick("any_job"); h != de {
		t.Errorf("any_job after moving back to Germany: got %s, want %s", h, de)
	}
	// Narrowing within the current country moves too if the server isn't in the narrower exit.
	if h := pick("de-ber_job"); h != "de-ber-wg-001" {
		t.Errorf("de-ber_job: %s", h)
	}
	if h := pick("de_job"); h != "de-ber-wg-001" {
		t.Errorf("de_job should stay on the Berlin server: %s", h)
	}

	// Other sessions and session-less requests are unaffected.
	seen := map[string]bool{}
	for i := 0; i < 10; i++ {
		seen[pick("de-fra")] = true
	}
	if len(seen) != 3 {
		t.Errorf("de-fra without session used %v", seen)
	}
	if h := pick("jp_other"); country(h) != "jp" {
		t.Errorf("jp_other: %s", h)
	}

	// Forget clears the session.
	if !r.picker.Forget("job") || r.picker.Forget("job") {
		t.Error("Forget")
	}

	// A benched current server: broad exits move the session, the exact name still uses it.
	pick("de-fra-wg-001_b")
	r.br.Fail("de-fra-wg-001")
	moved := pick("de_b")
	if moved == "de-fra-wg-001" || country(moved) != "de" {
		t.Errorf("broad exit used a benched server: %s", moved)
	}
	if h := pick("de_b"); h != moved {
		t.Errorf("session should now stay on %s, got %s", moved, h)
	}
	if h := pick("de-fra-wg-001_b"); h != "de-fra-wg-001" {
		t.Errorf("exact name must still use its server, got %s", h)
	}
}

func TestSessionServerOverProxy(t *testing.T) {
	r := newRig(t, "se-sto-wg-001", "se-sto-wg-002", "se-got-wg-001")
	addr := r.listen(t, Listener{Name: "main", Challenge: true})
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "ok") }))
	defer target.Close()
	via := func(user string) string {
		pu := &url.URL{Scheme: "http", Host: addr, User: url.UserPassword(user, "x")}
		c := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(pu), DisableKeepAlives: true}}
		resp, err := c.Get(target.URL)
		if err != nil {
			t.Fatalf("%s: %v", user, err)
		}
		resp.Body.Close()
		return resp.Header.Get("X-Mullvad-Server")
	}
	if s := via("se-sto-wg-002_agent"); s != "se-sto-wg-002" {
		t.Fatalf("exact: %s", s)
	}
	for _, u := range []string{"se_agent", "any_agent", "se-sto_agent"} {
		if s := via(u); s != "se-sto-wg-002" {
			t.Errorf("%s: %s", u, s)
		}
	}
	if s := via("se-got_agent"); s != "se-got-wg-001" {
		t.Errorf("se-got_agent: %s", s)
	}
}

func TestStickyAndRotation(t *testing.T) {
	r := newRig(t, "se-sto-wg-001", "se-sto-wg-002", "se-sto-wg-003")
	seen := map[string]bool{}
	for i := 0; i < 3; i++ {
		x, _ := r.picker.Pick(Selection{Exit: "se"}, nil)
		seen[x.Hostname] = true
	}
	if len(seen) != 3 {
		t.Errorf("rotation used %d servers, want 3", len(seen))
	}
	first, _ := r.picker.Pick(Selection{Exit: "se", Session: "s"}, nil)
	for i := 0; i < 10; i++ {
		x, _ := r.picker.Pick(Selection{Exit: "se", Session: "s"}, nil)
		if x != first {
			t.Fatal("sticky session changed server")
		}
	}
	r.br.Fail(first.Hostname)
	x, _ := r.picker.Pick(Selection{Exit: "se", Session: "s"}, nil)
	if x == first {
		t.Error("sticky session kept an unhealthy server")
	}
}

func TestFailoverToHealthyExit(t *testing.T) {
	r := newRig(t, "se-sto-wg-001", "se-sto-wg-002")
	dead := r.exits["se-sto-wg-001"]
	dead.ln.Close()
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "hi") }))
	defer target.Close()
	for i := 0; i < 4; i++ {
		c, srv, err := r.d.Dial(context.Background(), Selection{Exit: "se"}, target.Listener.Addr().String())
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		c.Close()
		if srv != "se-sto-wg-002" {
			t.Errorf("dial %d used %s", i, srv)
		}
	}
	if r.br.Healthy("se-sto-wg-001") {
		t.Error("dead exit not benched")
	}
}

func TestTargetErrorDoesNotBench(t *testing.T) {
	r := newRig(t, "se-sto-wg-001")
	r.exits["se-sto-wg-001"].reply = 4
	_, _, err := r.d.Dial(context.Background(), Selection{Exit: "se"}, "example.invalid:443")
	var te *TargetError
	if !errors.As(err, &te) || te.Code != 4 {
		t.Fatalf("want host-unreachable TargetError, got %v", err)
	}
	if !r.br.Healthy("se-sto-wg-001") {
		t.Error("target error benched the exit")
	}
}

func TestHTTPConnectAndPlain(t *testing.T) {
	r := newRig(t, "de-fra-wg-001", "jp-tyo-wg-001")
	addr := r.listen(t, Listener{Name: "main", Challenge: true})
	tlsTarget := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "secure") }))
	defer tlsTarget.Close()
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Header.Get("Proxy-Authorization") != "" || req.Header.Get("X-Exit") != "" {
			w.WriteHeader(500)
		}
		io.WriteString(w, "plain")
	}))
	defer plain.Close()

	client := func(user string) *http.Client {
		pu := &url.URL{Scheme: "http", Host: addr}
		if user != "" {
			pu.User = url.UserPassword(user, "x")
		}
		return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
			Proxy: http.ProxyURL(pu), TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, DisableKeepAlives: true}}
	}

	// No credentials on a challenge listener → 407 with Proxy-Authenticate.
	resp, err := client("").Get(plain.URL)
	if err != nil || resp.StatusCode != 407 || resp.Header.Get("Proxy-Authenticate") == "" {
		t.Fatalf("want 407, got %v %v", resp, err)
	}
	resp.Body.Close()

	before := r.exits["jp-tyo-wg-001"].conns.Load()
	resp, err = client("jp_s1").Get(tlsTarget.URL)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(b) != "secure" || r.exits["jp-tyo-wg-001"].conns.Load() != before+1 {
		t.Errorf("CONNECT via jp: body %q", b)
	}

	resp, err = client("de").Get(plain.URL)
	if err != nil {
		t.Fatal(err)
	}
	b, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(b) != "plain" || resp.Header.Get("X-Mullvad-Server") != "de-fra-wg-001" {
		t.Errorf("plain via de: %d %q %q", resp.StatusCode, b, resp.Header.Get("X-Mullvad-Server"))
	}

	resp, err = client("zz").Get(tlsTarget.URL)
	if err == nil {
		resp.Body.Close()
		t.Error("unknown exit should fail CONNECT")
	}
}

func TestSOCKS5Inbound(t *testing.T) {
	r := newRig(t, "us-nyc-wg-001", "gb-lon-wg-001")
	addr := r.listen(t, Listener{Name: "open"})
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "ok") }))
	defer target.Close()
	host, port, _ := net.SplitHostPort(target.Listener.Addr().String())

	get := func(user string) string {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		if user != "" {
			c.Write([]byte{5, 2, 0, 2})
		} else {
			c.Write([]byte{5, 1, 0})
		}
		var g [2]byte
		io.ReadFull(c, g[:])
		if g[1] == 2 {
			c.Write(append(append([]byte{1, byte(len(user))}, user...), 1, 'x'))
			io.ReadFull(c, g[:])
		}
		var p int
		fmt.Sscan(port, &p)
		req, _ := appendSocksAddr([]byte{5, 1, 0}, host, p)
		c.Write(req)
		var h [4]byte
		io.ReadFull(c, h[:])
		if h[1] != 0 {
			return fmt.Sprintf("reply %d", h[1])
		}
		readSocksAddr(c, h[3])
		fmt.Fprintf(c, "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
		resp, err := http.ReadResponse(bufio.NewReader(c), nil)
		if err != nil {
			return err.Error()
		}
		b, _ := io.ReadAll(resp.Body)
		return string(b)
	}

	before := r.exits["gb-lon-wg-001"].conns.Load()
	if got := get("gb_x"); got != "ok" || r.exits["gb-lon-wg-001"].conns.Load() != before+1 {
		t.Errorf("socks via gb: %q", got)
	}
	if got := get(""); got != "ok" {
		t.Errorf("socks no-auth default: %q", got)
	}
	if got := get("xx"); got != "reply 2" {
		t.Errorf("unknown exit: %q", got)
	}
}

func TestRouteOrder(t *testing.T) {
	cfg := defaultConfig()
	cfg.Rules = []Rule{{Match: "*.example.co.uk", Exit: "gb"}}
	s := &Server{cfg: cfg, ln: Listener{Exit: "us", Session: "port"}}
	cases := []struct {
		user, hdr, host string
		want            Selection
	}{
		{"de_s", "", "a.example.co.uk", Selection{"de", "s"}},
		{"de", "jp", "x.com", Selection{"jp", "port|jp"}},
		{"", "", "www.example.co.uk", Selection{"gb", "port|gb"}},
		{"default_z", "", "x.com", Selection{"us", "z"}},
		{"", "", "x.com", Selection{"us", "port|us"}},
	}
	for _, c := range cases {
		if got := s.route(c.user, c.user != "", c.hdr, "", c.host); got != c.want {
			t.Errorf("route(%q,%q,%q) = %+v, want %+v", c.user, c.hdr, c.host, got, c.want)
		}
	}
	s.ln = Listener{}
	if got := s.route("", false, "", "", "x.com"); got.Exit != "any" {
		t.Errorf("global default: %+v", got)
	}
}

func TestConcurrentSticky(t *testing.T) {
	r := newRig(t, "se-sto-wg-001", "se-sto-wg-002", "se-sto-wg-003", "se-sto-wg-004")
	var wg sync.WaitGroup
	var mu sync.Mutex
	got := map[string]bool{}
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			x, err := r.picker.Pick(Selection{Exit: "se", Session: "same"}, nil)
			if err == nil {
				mu.Lock()
				got[x.Hostname] = true
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if len(got) != 1 {
		t.Errorf("concurrent sticky picks used %d servers", len(got))
	}
}
