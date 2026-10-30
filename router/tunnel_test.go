// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

func genKey(t *testing.T) (priv, pub []byte) {
	t.Helper()
	priv = make([]byte, 32)
	rand.Read(priv)
	priv[0] &= 248
	priv[31] = priv[31]&127 | 64
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	return priv, pub
}

// wgServer is an in-process WireGuard peer standing in for a Mullvad entry
// server: it answers on 10.64.0.1:1080 inside its tunnel, like Mullvad does.
type wgServer struct {
	dev  *device.Device
	pub  []byte
	port int
}

func startWGServer(t *testing.T, clientPub []byte) *wgServer {
	t.Helper()
	priv, pub := genKey(t)
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := pc.LocalAddr().(*net.UDPAddr).Port
	pc.Close()

	tdev, tnet, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.64.0.1")}, nil, 1420)
	if err != nil {
		t.Fatal(err)
	}
	dev := device.NewDevice(tdev, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	uapi := "private_key=" + hex.EncodeToString(priv) + "\nlisten_port=" + strconv.Itoa(port) +
		"\npublic_key=" + hex.EncodeToString(clientPub) + "\nallowed_ip=10.74.0.2/32\n"
	if err := dev.IpcSet(uapi); err != nil {
		t.Fatal(err)
	}
	if err := dev.Up(); err != nil {
		t.Fatal(err)
	}
	ln, err := tnet.ListenTCP(&net.TCPAddr{IP: net.ParseIP("10.64.0.1"), Port: 1080})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { io.WriteString(c, "pong"); c.Close() }()
		}
	}()
	s := &wgServer{dev: dev, pub: pub, port: port}
	t.Cleanup(func() { ln.Close(); dev.Close() })
	return s
}

func waitFor(t *testing.T, d time.Duration, cond func() bool) bool {
	t.Helper()
	end := time.Now().Add(d)
	for time.Now().Before(end) {
		if cond() {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

func TestEmbeddedTunnelFailover(t *testing.T) {
	cpriv, cpub := genKey(t)
	s1, s2, s3 := startWGServer(t, cpub), startWGServer(t, cpub), startWGServer(t, cpub)

	cfg := defaultConfig()
	cfg.Tunnel.PrivateKey = base64.StdEncoding.EncodeToString(cpriv)
	cfg.Tunnel.Address = "10.74.0.2/32,fc00:bbbb::1/128"
	cfg.Tunnel.Entry = "se"
	cfg.Tunnel.ProbeInterval = Duration{150 * time.Millisecond}
	cfg.Tunnel.FailThreshold = 2
	cfg.Tunnel.ConnectTimeout = Duration{5 * time.Second}
	tun, err := NewTunnel(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer tun.dev.Close()

	cat := NewCatalog(tun.LookupHost)
	servers := map[string]*wgServer{"se-sto-wg-001": s1, "se-sto-wg-002": s2, "se-sto-wg-003": s3}
	var relays []*Relay
	for h, s := range servers {
		relays = append(relays, &Relay{Hostname: h, CountryCode: "se", CityCode: "sto", Active: true,
			Addr: "unused:1080", Pubkey: base64.StdEncoding.EncodeToString(s.pub), IPv4In: "127.0.0.1", WGPort: s.port})
	}
	cat.Set(relays)
	pk := NewPicker(cat, NewBreaker(time.Minute, time.Hour), nil, time.Minute, 100)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go tun.Run(ctx, pk)

	if !waitFor(t, 8*time.Second, tun.Ready) {
		t.Fatal("tunnel never came up")
	}
	first := tun.Status()["entry"].(string)

	// Traffic flows through the tunnel to the entry server.
	c, err := tun.DialContext(ctx, "tcp", "10.64.0.1:1080")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(c)
	c.Close()
	if string(b) != "pong" {
		t.Fatalf("through tunnel: %q", b)
	}

	// Kill the active entry server: the tunnel must go down, then move to the other one.
	servers[first].dev.Close()
	if !waitFor(t, 5*time.Second, func() bool { return !tun.Ready() }) {
		t.Fatal("tunnel did not notice the dead entry server")
	}
	d := &Dialer{cat: cat, picker: pk, br: NewBreaker(time.Minute, time.Hour), net: tun, timeout: time.Second, ready: tun.Ready}
	if _, _, err := d.Dial(ctx, Selection{Exit: "se"}, "example.com:443"); !errors.Is(err, errTunnelDown) {
		t.Errorf("dial while down: want errTunnelDown, got %v", err)
	}
	if d.br.Unhealthy() != 0 {
		t.Error("tunnel outage benched exits")
	}
	if !waitFor(t, 10*time.Second, func() bool { return tun.Ready() && tun.Status()["entry"] != first }) {
		t.Fatalf("no failover: %v ready=%v", tun.Status(), tun.Ready())
	}
	if tun.Status()["switches"].(int) < 1 {
		t.Error("switch not counted")
	}

	// A requested switch moves to another live entry server and traffic resumes.
	second := tun.Status()["entry"]
	tun.Switch()
	if !waitFor(t, 15*time.Second, func() bool { e := tun.Status()["entry"]; return tun.Ready() && e != second && e != first }) {
		t.Fatalf("Switch did not move to the remaining live server: %v ready=%v", tun.Status(), tun.Ready())
	}
	c, err = tun.DialContext(ctx, "tcp", "10.64.0.1:1080")
	if err != nil {
		t.Fatalf("after switch: %v", err)
	}
	c.Close()
}

func TestTunnelConfigParsing(t *testing.T) {
	a, err := parseTunnelAddr("10.74.137.79/32,fc00:bbbb:bbbb:bb01::b:894e/128")
	if err != nil || a.String() != "10.74.137.79" {
		t.Errorf("addr: %v %v", a, err)
	}
	if _, err := parseTunnelAddr("fc00::1/128"); err == nil {
		t.Error("IPv6-only address accepted")
	}
	if _, err := decodeKey("not-a-key"); err == nil {
		t.Error("bad key accepted")
	}
	if _, err := NewTunnel(defaultConfig()); err == nil {
		t.Error("tunnel without key accepted")
	}
}

func TestDotenvHoldsOnlySecrets(t *testing.T) {
	dir := t.TempDir()
	env := filepath.Join(dir, ".env")
	os.WriteFile(env, []byte("# comment\n\nWIREGUARD_PRIVATE_KEY=\"abc=\"\nWIREGUARD_ADDRESSES=10.74.0.2/32\n"+
		"PROXY_PASSWORD='pw'\nENTRY=us-mia\nMAIN_PORT=8090\nBIND=0.0.0.0\n"), 0o600)
	for _, k := range []string{"WIREGUARD_PRIVATE_KEY", "WIREGUARD_ADDRESSES", "PROXY_PASSWORD", "ENTRY", "MAIN_PORT", "BIND"} {
		t.Setenv(k, "")
		os.Unsetenv(k)
	}
	t.Setenv("WIREGUARD_ADDRESSES", "10.9.9.9/32") // already set: dotenv must not override

	ignored, err := loadDotenv(env)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(ignored, ",") != "ENTRY,MAIN_PORT,BIND" {
		t.Errorf("ignored keys: %v", ignored)
	}
	if os.Getenv("WIREGUARD_PRIVATE_KEY") != "abc=" || os.Getenv("PROXY_PASSWORD") != "pw" || os.Getenv("WIREGUARD_ADDRESSES") != "10.9.9.9/32" {
		t.Errorf("secrets: %q %q %q", os.Getenv("WIREGUARD_PRIVATE_KEY"), os.Getenv("PROXY_PASSWORD"), os.Getenv("WIREGUARD_ADDRESSES"))
	}
	for _, k := range []string{"ENTRY", "MAIN_PORT", "BIND"} {
		if _, set := os.LookupEnv(k); set {
			t.Errorf("non-secret %s was exported from .env", k)
		}
	}

	// Even when set in the real environment, non-secret settings never override config.
	t.Setenv("ENTRY", "jp")
	t.Setenv("MAIN_PORT", "9999")
	t.Setenv("BIND", "0.0.0.0")
	cfg, err := LoadConfig("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listeners[0].Addr != "127.0.0.1:8080" || cfg.API != "127.0.0.1:8088" || cfg.Tunnel.Entry != "any" {
		t.Errorf("env leaked into config: %s %s %s", cfg.Listeners[0].Addr, cfg.API, cfg.Tunnel.Entry)
	}
	if cfg.Password != "pw" || cfg.Tunnel.PrivateKey != "abc=" || cfg.Tunnel.Address != "10.9.9.9/32" {
		t.Errorf("secrets not applied: %+v", cfg.Tunnel)
	}

	// Every listener must name its host; ":port" would bind every interface.
	cfgFile := filepath.Join(dir, "c.yaml")
	os.WriteFile(cfgFile, []byte("listeners: [{name: a, addr: \":7000\"}]\n"), 0o600)
	if _, err := LoadConfig(cfgFile); err == nil {
		t.Error("hostless listener accepted")
	}
}

func mustRead(t *testing.T, p string) []byte {
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
