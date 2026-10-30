// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

var errTunnelDown = errors.New("tunnel down (reconnecting)")

// Tunnel is a userspace WireGuard tunnel to one Mullvad entry server. Its
// network stack lives inside this process, so nothing else on the host can use
// it, and the router has no other route out: it fails closed by construction.
type Tunnel struct {
	cfg       *Config
	dev       *device.Device
	tnet      *netstack.Net
	up        atomic.Bool
	switchReq chan struct{}

	mu       sync.Mutex
	entry    *Relay
	since    time.Time
	switches int
}

func NewTunnel(cfg *Config) (*Tunnel, error) {
	key, err := decodeKey(cfg.Tunnel.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("WIREGUARD_PRIVATE_KEY: %w", err)
	}
	addr, err := parseTunnelAddr(cfg.Tunnel.Address)
	if err != nil {
		return nil, err
	}
	dns, err := netip.ParseAddr(cfg.Tunnel.DNS)
	if err != nil {
		return nil, fmt.Errorf("tunnel.dns: %w", err)
	}
	tdev, tnet, err := netstack.CreateNetTUN([]netip.Addr{addr}, []netip.Addr{dns}, cfg.Tunnel.MTU)
	if err != nil {
		return nil, err
	}
	dev := device.NewDevice(tdev, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "wireguard: "))
	if err := dev.IpcSet("private_key=" + key + "\n"); err != nil {
		dev.Close()
		return nil, err
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, err
	}
	return &Tunnel{cfg: cfg, dev: dev, tnet: tnet, switchReq: make(chan struct{}, 1)}, nil
}

// Switch asks the tunnel to move to another entry server.
func (t *Tunnel) Switch() {
	select {
	case t.switchReq <- struct{}{}:
	default:
	}
}

func decodeKey(b64 string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil || len(b) != 32 {
		return "", errors.New("not a base64 WireGuard key")
	}
	return hex.EncodeToString(b), nil
}

// parseTunnelAddr takes the IPv4 address out of "10.x.x.x/32,fc00::.../128".
func parseTunnelAddr(s string) (netip.Addr, error) {
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if p, err := netip.ParsePrefix(part); err == nil && p.Addr().Is4() {
			return p.Addr(), nil
		}
		if a, err := netip.ParseAddr(part); err == nil && a.Is4() {
			return a, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("WIREGUARD_ADDRESSES: no IPv4 address in %q", s)
}

func (t *Tunnel) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return t.tnet.DialContext(ctx, network, addr)
}

func (t *Tunnel) LookupHost(ctx context.Context, host string) ([]string, error) {
	return t.tnet.LookupContextHost(ctx, host)
}

func (t *Tunnel) Ready() bool { return t.up.Load() }

func (t *Tunnel) Status() map[string]any {
	t.mu.Lock()
	defer t.mu.Unlock()
	st := map[string]any{"switches": t.switches}
	if t.entry != nil {
		st["entry"] = t.entry.Hostname
		st["entry_since_s"] = int(time.Since(t.since).Seconds())
	}
	return st
}

// Run keeps the tunnel connected: it picks an entry server matching
// tunnel.entry, checks that traffic flows, and moves to another server after
// tunnel.fail_threshold failed probes in a row.
func (t *Tunnel) Run(ctx context.Context, p *Picker) {
	tried := map[string]bool{}
	for ctx.Err() == nil {
		r, err := t.pickEntry(p, tried)
		if err != nil {
			slog.Warn("tunnel: no entry server", "err", err.Error())
			tried = map[string]bool{}
			sleepCtx(ctx, 5*time.Second)
			continue
		}
		tried[r.Hostname] = true
		slog.Info("tunnel: connecting", "entry", r.Hostname, "endpoint", r.IPv4In)
		if err := t.connect(ctx, r); err != nil {
			slog.Warn("tunnel: entry server failed", "entry", r.Hostname, "err", err.Error())
			continue
		}
		slog.Info("tunnel: up", "entry", r.Hostname, "city", r.CityName)
		tried = map[string]bool{r.Hostname: true}
		t.watch(ctx)
		if ctx.Err() == nil {
			slog.Warn("tunnel: leaving entry server", "entry", r.Hostname)
		}
	}
}

func (t *Tunnel) pickEntry(p *Picker, tried map[string]bool) (*Relay, error) {
	cands, err := p.Candidates(t.cfg.Tunnel.Entry)
	if err != nil {
		return nil, err
	}
	var ok []*Relay
	for _, r := range cands {
		if !tried[r.Hostname] && r.Pubkey != "" && r.IPv4In != "" {
			ok = append(ok, r)
		}
	}
	if len(ok) == 0 {
		return nil, fmt.Errorf("all %d entry servers for %q failed; retrying", len(cands), t.cfg.Tunnel.Entry)
	}
	return ok[rand.IntN(len(ok))], nil
}

// connect points the tunnel at entry server r and waits until traffic flows.
func (t *Tunnel) connect(ctx context.Context, r *Relay) error {
	t.up.Store(false)
	pub, err := decodeKey(r.Pubkey)
	if err != nil {
		return fmt.Errorf("relay pubkey: %w", err)
	}
	port := 51820
	if r.WGPort != 0 {
		port = r.WGPort
	}
	uapi := fmt.Sprintf("replace_peers=true\npublic_key=%s\nendpoint=%s\npersistent_keepalive_interval=25\nreplace_allowed_ips=true\nallowed_ip=0.0.0.0/0\n",
		pub, net.JoinHostPort(r.IPv4In, fmt.Sprint(port)))
	if err := t.dev.IpcSet(uapi); err != nil {
		return err
	}
	t.mu.Lock()
	if t.entry != nil {
		t.switches++
	}
	t.entry, t.since = r, time.Now()
	t.mu.Unlock()

	deadline := time.Now().Add(t.cfg.Tunnel.ConnectTimeout.Duration)
	for time.Now().Before(deadline) && ctx.Err() == nil {
		if t.probe(ctx) {
			t.up.Store(true)
			return nil
		}
		sleepCtx(ctx, time.Second)
	}
	return errors.New("no traffic through entry server")
}

// watch probes the tunnel until it fails fail_threshold times in a row.
func (t *Tunnel) watch(ctx context.Context) {
	tick := time.NewTicker(t.cfg.Tunnel.ProbeInterval.Duration)
	defer tick.Stop()
	fails := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.switchReq:
			slog.Info("tunnel: switch requested")
			return
		case <-tick.C:
		}
		if t.probe(ctx) {
			fails = 0
			t.up.Store(true)
			continue
		}
		fails++
		t.up.Store(false)
		slog.Warn("tunnel: probe failed", "fails", fails)
		if fails >= t.cfg.Tunnel.FailThreshold {
			return
		}
	}
}

// probe checks that the entry server's own SOCKS proxy (10.64.0.1:1080) answers.
func (t *Tunnel) probe(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	c, err := t.tnet.DialContext(ctx, "tcp", t.cfg.TunnelProbe)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

func sleepCtx(ctx context.Context, d time.Duration) {
	select {
	case <-ctx.Done():
	case <-time.After(d):
	}
}
