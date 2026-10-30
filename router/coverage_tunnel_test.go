// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"encoding/base64"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

type fakeDev struct {
	ipcErr, upErr error
	closed        bool
}

func (f *fakeDev) IpcSet(string) error { return f.ipcErr }
func (f *fakeDev) Up() error           { return f.upErr }
func (f *fakeDev) Close()              { f.closed = true }

type fakeNet struct {
	conn      net.Conn
	err       error
	dial      func(context.Context) (net.Conn, error)
	lookup    []string
	lookupErr error
}

func (f *fakeNet) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	if f.dial != nil {
		return f.dial(ctx)
	}
	if f.err != nil {
		return nil, f.err
	}
	return f.conn, nil
}

func (f *fakeNet) LookupContextHost(context.Context, string) ([]string, error) {
	return f.lookup, f.lookupErr
}

func testKey() string { return base64.StdEncoding.EncodeToString(make([]byte, 32)) }

func tunnelConfig() *Config {
	c := defaultConfig()
	c.Tunnel.PrivateKey = testKey()
	c.Tunnel.Address = "10.0.0.2/32"
	return c
}

func withTunnelVars(t *testing.T, netTUN func([]netip.Addr, []netip.Addr, int) (tun.Device, *netstack.Net, error), dev func(tun.Device) wgDevice) {
	t.Helper()
	oldNet, oldDev := createNetTUN, newWGDevice
	if netTUN != nil {
		createNetTUN = netTUN
	}
	if dev != nil {
		newWGDevice = dev
	}
	t.Cleanup(func() { createNetTUN, newWGDevice = oldNet, oldDev })
}

func TestNewTunnelErrorPaths(t *testing.T) {
	t.Run("address", func(t *testing.T) {
		c := tunnelConfig()
		c.Tunnel.Address = "fc00::1/128"
		if _, err := NewTunnel(c); err == nil {
			t.Error("address without IPv4 accepted")
		}
	})

	t.Run("dns", func(t *testing.T) {
		c := tunnelConfig()
		c.Tunnel.DNS = "nope"
		if _, err := NewTunnel(c); err == nil {
			t.Error("bad DNS accepted")
		}
	})

	t.Run("nettun", func(t *testing.T) {
		withTunnelVars(t, func([]netip.Addr, []netip.Addr, int) (tun.Device, *netstack.Net, error) {
			return nil, nil, errors.New("nettun")
		}, nil)
		if _, err := NewTunnel(tunnelConfig()); err == nil {
			t.Error("netTUN error ignored")
		}
	})

	t.Run("ipcset", func(t *testing.T) {
		dev := &fakeDev{ipcErr: errors.New("ipc")}
		withTunnelVars(t, func([]netip.Addr, []netip.Addr, int) (tun.Device, *netstack.Net, error) {
			return nil, nil, nil
		}, func(tun.Device) wgDevice { return dev })
		if _, err := NewTunnel(tunnelConfig()); err == nil {
			t.Error("IpcSet error ignored")
		}
		if !dev.closed {
			t.Error("device not closed after IpcSet failure")
		}
	})

	t.Run("up", func(t *testing.T) {
		dev := &fakeDev{upErr: errors.New("up")}
		withTunnelVars(t, func([]netip.Addr, []netip.Addr, int) (tun.Device, *netstack.Net, error) {
			return nil, nil, nil
		}, func(tun.Device) wgDevice { return dev })
		if _, err := NewTunnel(tunnelConfig()); err == nil {
			t.Error("Up error ignored")
		}
		if !dev.closed {
			t.Error("device not closed after Up failure")
		}
	})
}

func TestParseTunnelAddrVariants(t *testing.T) {
	if a, err := parseTunnelAddr("10.0.0.2"); err != nil || a.String() != "10.0.0.2" {
		t.Errorf("bare address: %v %v", a, err)
	}
	if a, err := parseTunnelAddr("fc00::1, 10.0.0.2/32"); err != nil || a.String() != "10.0.0.2" {
		t.Errorf("IPv4 after IPv6: %v %v", a, err)
	}
	if _, err := parseTunnelAddr("fc00::1"); err == nil {
		t.Error("IPv6-only address accepted")
	}
}

func TestSwitchNonBlocking(t *testing.T) {
	tun := &Tunnel{switchReq: make(chan struct{}, 1)}
	tun.Switch()
	tun.Switch() // buffer full: default branch
}

func TestTunnelLookupAndSleep(t *testing.T) {
	tun := &Tunnel{net: &fakeNet{lookup: []string{"1.2.3.4"}}}
	got, err := tun.LookupHost(context.Background(), "example.com")
	if err != nil || len(got) != 1 || got[0] != "1.2.3.4" {
		t.Errorf("lookup: %v %v", got, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	sleepCtx(ctx, time.Hour) // canceled: returns at once
	sleepCtx(context.Background(), time.Millisecond)
}

func TestPickEntryErrors(t *testing.T) {
	tun := &Tunnel{cfg: defaultConfig()}
	empty := NewPicker(NewCatalog(nil), NewBreaker(time.Second, time.Minute), nil, time.Minute, 10)
	if _, err := tun.pickEntry(empty, nil); !errors.Is(err, errCatalogEmpty) {
		t.Errorf("empty catalog: %v", err)
	}

	cat := NewCatalog(nil)
	cat.Set([]*Relay{{Hostname: "a", Pubkey: "k", IPv4In: "1.1.1.1", Addr: "10.124.0.1:1080", Active: true}})
	p := NewPicker(cat, NewBreaker(time.Second, time.Minute), nil, time.Minute, 10)
	if _, err := tun.pickEntry(p, map[string]bool{"a": true}); err == nil {
		t.Error("all-tried returned a server")
	}
}

func TestConnectErrors(t *testing.T) {
	ctx := context.Background()
	c := defaultConfig()
	c.Tunnel.ConnectTimeout = Duration{50 * time.Millisecond}
	tun := &Tunnel{cfg: c, dev: &fakeDev{}, net: &fakeNet{conn: nopConn{}}, switchReq: make(chan struct{}, 1)}
	relay := &Relay{Hostname: "de-fra-wg-001", Pubkey: "not-base64", IPv4In: "1.1.1.1"}
	if err := tun.connect(ctx, relay); err == nil {
		t.Error("bad relay key accepted")
	}

	relay.Pubkey = testKey()
	tun.dev = &fakeDev{ipcErr: errors.New("ipc")}
	if err := tun.connect(ctx, relay); err == nil {
		t.Error("IpcSet error ignored")
	}

	tun.dev = &fakeDev{}
	if err := tun.connect(ctx, relay); err != nil {
		t.Fatalf("connect: %v", err)
	}
	if !tun.Ready() || tun.Status()["entry"] != relay.Hostname {
		t.Errorf("tunnel not up: %v", tun.Status())
	}

	// No traffic before the deadline, and the context dies during the sleep.
	c2 := defaultConfig()
	c2.Tunnel.ConnectTimeout = Duration{time.Second}
	cctx, cancel := context.WithCancel(context.Background())
	tun2 := &Tunnel{cfg: c2, dev: &fakeDev{}, switchReq: make(chan struct{}, 1),
		net: &fakeNet{dial: func(context.Context) (net.Conn, error) { cancel(); return nil, errors.New("no") }}}
	if err := tun2.connect(cctx, relay); err == nil {
		t.Error("connect without traffic succeeded")
	}
}

func TestWatch(t *testing.T) {
	c := defaultConfig()
	c.Tunnel.ProbeInterval = Duration{time.Millisecond}
	c.Tunnel.FailThreshold = 2

	// Successful probes keep the tunnel up until the context ends.
	ctx, cancel := context.WithCancel(context.Background())
	tun := &Tunnel{cfg: c, net: &fakeNet{conn: nopConn{}}, switchReq: make(chan struct{}, 1)}
	go func() { time.Sleep(20 * time.Millisecond); cancel() }()
	tun.watch(ctx)

	// Failed probes return after fail_threshold.
	c.Tunnel.FailThreshold = 1
	ctx2, cancel2 := context.WithTimeout(context.Background(), time.Second)
	defer cancel2()
	tun2 := &Tunnel{cfg: c, net: &fakeNet{err: errors.New("no")}, switchReq: make(chan struct{}, 1)}
	tun2.watch(ctx2)

	// An explicit switch ends the watch loop.
	ctx3, cancel3 := context.WithCancel(context.Background())
	defer cancel3()
	tun3 := &Tunnel{cfg: c, net: &fakeNet{conn: nopConn{}}, switchReq: make(chan struct{}, 1)}
	tun3.Switch()
	tun3.watch(ctx3)
}

func TestRunPaths(t *testing.T) {
	c := defaultConfig()
	c.Tunnel.Entry = "any"
	c.Tunnel.ConnectTimeout = Duration{20 * time.Millisecond}
	c.Tunnel.ProbeInterval = Duration{time.Millisecond}
	c.Tunnel.FailThreshold = 1

	// No candidates: log, reset, wait for the context.
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(10 * time.Millisecond); cancel() }()
	empty := NewPicker(NewCatalog(nil), NewBreaker(time.Second, time.Minute), nil, time.Minute, 10)
	tun := &Tunnel{cfg: c, dev: &fakeDev{}, net: &fakeNet{conn: nopConn{}}, switchReq: make(chan struct{}, 1)}
	tun.Run(ctx, empty)

	// Candidates exist but every connect fails.
	cat := NewCatalog(nil)
	cat.Set([]*Relay{{Hostname: "de-fra-wg-001", Pubkey: testKey(), IPv4In: "1.1.1.1", Addr: "10.124.0.1:1080", Active: true}})
	p := NewPicker(cat, NewBreaker(time.Second, time.Minute), nil, time.Minute, 10)
	ctx2, cancel2 := context.WithCancel(context.Background())
	go func() { time.Sleep(10 * time.Millisecond); cancel2() }()
	tun2 := &Tunnel{cfg: c, dev: &fakeDev{ipcErr: errors.New("ipc")}, net: &fakeNet{conn: nopConn{}}, switchReq: make(chan struct{}, 1)}
	tun2.Run(ctx2, p)

	// Up, an explicit switch, then every server tried.
	ctx3, cancel3 := context.WithCancel(context.Background())
	tun3 := &Tunnel{cfg: c, dev: &fakeDev{}, net: &fakeNet{conn: nopConn{}}, switchReq: make(chan struct{}, 1)}
	go func() { time.Sleep(5 * time.Millisecond); tun3.Switch(); time.Sleep(10 * time.Millisecond); cancel3() }()
	tun3.Run(ctx3, p)
}
