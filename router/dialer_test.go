// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

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
