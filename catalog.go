// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Relay is one Mullvad WireGuard server as published by the relay API.
type Relay struct {
	Hostname    string `json:"hostname"`
	CountryCode string `json:"country_code"`
	CountryName string `json:"country_name"`
	CityCode    string `json:"city_code"`
	CityName    string `json:"city_name"`
	Active      bool   `json:"active"`
	Owned       bool   `json:"owned"`
	Provider    string `json:"provider"`
	SocksName   string `json:"socks_name"`
	SocksPort   int    `json:"socks_port"`
	Pubkey      string `json:"pubkey"`       // WireGuard key, for using it as the entry server
	IPv4In      string `json:"ipv4_addr_in"` // WireGuard endpoint

	// Addr, when set, is used instead of resolving SocksName (tests, overrides).
	Addr string `json:"-"`
	// WGPort overrides Mullvad's WireGuard port 51820 (tests).
	WGPort int `json:"-"`
}

func (r *Relay) City() string { return r.CountryCode + "-" + r.CityCode }

var errCatalogEmpty = errors.New("relay list not loaded yet (is the tunnel up?)")

// LookupFunc resolves a hostname to addresses (the tunnel's DNS or a resolver's).
type LookupFunc func(ctx context.Context, host string) ([]string, error)

type Catalog struct {
	lookup LookupFunc

	mu       sync.RWMutex
	relays   []*Relay
	index    map[string][]*Relay
	servers  map[string]*Relay // by hostname
	loadedAt time.Time

	addrMu sync.Mutex
	addrs  map[string]cachedAddr
}

type cachedAddr struct {
	addr string
	exp  time.Time
}

func NewCatalog(lookup LookupFunc) *Catalog {
	return &Catalog{lookup: lookup, index: map[string][]*Relay{}, addrs: map[string]cachedAddr{}}
}

func ParseRelays(b []byte) ([]*Relay, error) {
	var rs []*Relay
	if err := json.Unmarshal(b, &rs); err != nil {
		return nil, err
	}
	return rs, nil
}

// Set replaces the catalog with the active relays that expose a SOCKS5 proxy.
func (c *Catalog) Set(all []*Relay) int {
	var relays []*Relay
	for _, r := range all {
		if !r.Active || (r.SocksName == "" && r.Addr == "") {
			continue
		}
		r.Hostname = strings.ToLower(r.Hostname)
		r.CountryCode = strings.ToLower(r.CountryCode)
		r.CityCode = strings.ToLower(r.CityCode)
		if r.SocksPort == 0 {
			r.SocksPort = 1080
		}
		relays = append(relays, r)
	}
	sort.Slice(relays, func(i, j int) bool { return relays[i].Hostname < relays[j].Hostname })

	idx := map[string][]*Relay{}
	servers := map[string]*Relay{}
	add := func(k string, r *Relay) { idx[k] = append(idx[k], r) }
	for _, r := range relays {
		add("any", r)
		add(r.CountryCode, r)
		add(r.City(), r)
		add(r.Hostname, r)
		servers[r.Hostname] = r
	}

	c.mu.Lock()
	c.relays, c.index, c.servers, c.loadedAt = relays, idx, servers, time.Now()
	c.mu.Unlock()
	return len(relays)
}

// Server returns the relay if key is a server hostname.
func (c *Catalog) Server(key string) *Relay {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.servers[key]
}

func (c *Catalog) Lookup(key string) []*Relay {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.index[key]
}

func (c *Catalog) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.relays)
}

func (c *Catalog) LoadedAt() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.loadedAt
}

func (c *Catalog) All() []*Relay {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.relays
}

func (c *Catalog) LoadFile(path string) (int, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	rs, err := ParseRelays(b)
	if err != nil {
		return 0, err
	}
	return c.Set(rs), nil
}

// Fetch downloads the relay list, installs it and, when cache is not empty,
// writes it to the cache file. cache == "" keeps the list in memory only.
func (c *Catalog) Fetch(ctx context.Context, client *http.Client, url, cache string) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("relay api: %s", resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return 0, err
	}
	rs, err := ParseRelays(b)
	if err != nil {
		return 0, err
	}
	n := c.Set(rs)
	if n == 0 {
		return 0, errors.New("relay api returned no usable relays")
	}
	if cache != "" {
		_ = writeCache(cache, b)
	}
	return n, nil
}

// writeCache atomically writes b to path. An empty path disables caching.
func writeCache(path string, b []byte) error {
	if path == "" {
		return nil
	}
	tmp := path + ".tmp"
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Resolve returns the ip:port of a relay's SOCKS5 proxy (an internal 10.124.x.x address).
func (c *Catalog) Resolve(ctx context.Context, r *Relay) (string, error) {
	if r.Addr != "" {
		return r.Addr, nil
	}
	c.addrMu.Lock()
	ca, ok := c.addrs[r.SocksName]
	c.addrMu.Unlock()
	if ok && time.Now().Before(ca.exp) {
		return ca.addr, nil
	}
	hosts, err := c.lookup(ctx, r.SocksName)
	if err != nil {
		return "", err
	}
	var ip net.IP
	for _, h := range hosts {
		if p := net.ParseIP(h); p != nil && p.To4() != nil {
			ip = p
			break
		}
	}
	if ip == nil {
		return "", fmt.Errorf("%s: no IPv4 address", r.SocksName)
	}
	addr := net.JoinHostPort(ip.String(), strconv.Itoa(r.SocksPort))
	c.addrMu.Lock()
	c.addrs[r.SocksName] = cachedAddr{addr, time.Now().Add(time.Hour)}
	c.addrMu.Unlock()
	return addr, nil
}
