// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi
// SPDX-License-Identifier: MIT

package main

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Duration accepts Go duration strings ("30s", "6h") in YAML.
type Duration struct{ time.Duration }

func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	v, err := time.ParseDuration(n.Value)
	if err != nil {
		return fmt.Errorf("duration %q: %w", n.Value, err)
	}
	d.Duration = v
	return nil
}

type Listener struct {
	Name      string `yaml:"name"`
	Addr      string `yaml:"addr"`
	Exit      string `yaml:"exit"`      // fixed exit for this port ("" = global default)
	Session   string `yaml:"session"`   // fixed sticky id for this port ("" = new server per connection)
	Challenge bool   `yaml:"challenge"` // answer 407 to HTTP clients that send no credentials
}

type Rule struct {
	Match string `yaml:"match"` // "example.com" or "*.example.com" (also matches example.com)
	Exit  string `yaml:"exit"`
}

type Config struct {
	Listeners   []Listener `yaml:"listeners"`
	API         string     `yaml:"api"`
	DefaultExit string     `yaml:"default_exit"`
	Password    string     `yaml:"-"` // PROXY_PASSWORD (.env)
	TunnelProbe string     `yaml:"tunnel_probe"`
	IPCheckURL  string     `yaml:"ip_check_url"`
	DialTimeout Duration   `yaml:"dial_timeout"`

	Sticky struct {
		TTL      Duration `yaml:"ttl"`
		Max      int      `yaml:"max"`
		Implicit bool     `yaml:"implicit"` // a username without "_session" is its own session
	} `yaml:"sticky"`

	Catalog struct {
		URL     string   `yaml:"url"`
		Refresh Duration `yaml:"refresh"`
		Cache   string   `yaml:"cache"`
	} `yaml:"catalog"`

	Breaker struct {
		Base Duration `yaml:"base"`
		Max  Duration `yaml:"max"`
	} `yaml:"breaker"`

	PAC struct {
		Host string `yaml:"host"`
		Port string `yaml:"port"`
	} `yaml:"pac"`

	Tunnel struct {
		Entry          string   `yaml:"entry"` // entry server selector, Mullvad codes (us-mia, se, ...)
		MTU            int      `yaml:"mtu"`
		DNS            string   `yaml:"dns"`
		ProbeInterval  Duration `yaml:"probe_interval"`
		FailThreshold  int      `yaml:"fail_threshold"`
		ConnectTimeout Duration `yaml:"connect_timeout"`
		// Fetch the relay list over the host network when there is no cache yet:
		// the entry server's key and IP come from that list.
		BootstrapDirect bool   `yaml:"bootstrap_direct"`
		PrivateKey      string `yaml:"-"` // WIREGUARD_PRIVATE_KEY
		Address         string `yaml:"-"` // WIREGUARD_ADDRESSES
	} `yaml:"tunnel"`

	Aliases map[string][]string `yaml:"aliases"`
	Rules   []Rule              `yaml:"rules"`
}

func defaultConfig() *Config {
	c := &Config{
		Listeners: []Listener{
			{Name: "main", Addr: "127.0.0.1:8080", Challenge: true},
			{Name: "open", Addr: "127.0.0.1:1080"},
		},
		API:         "127.0.0.1:8088",
		DefaultExit: "any",
		TunnelProbe: "10.64.0.1:1080",
		IPCheckURL:  "https://am.i.mullvad.net/json",
		DialTimeout: Duration{15 * time.Second},
	}
	c.Sticky.TTL = Duration{10 * time.Minute}
	c.Sticky.Max = 10000
	c.Catalog.URL = "https://api.mullvad.net/www/relays/wireguard/"
	c.Catalog.Refresh = Duration{6 * time.Hour}
	c.Catalog.Cache = "data/relays.json"
	c.Breaker.Base = Duration{30 * time.Second}
	c.Breaker.Max = Duration{10 * time.Minute}
	c.Tunnel.Entry = "any"
	c.Tunnel.MTU = 1420
	c.Tunnel.DNS = "10.64.0.1"
	c.Tunnel.ProbeInterval = Duration{10 * time.Second}
	c.Tunnel.FailThreshold = 3
	c.Tunnel.ConnectTimeout = Duration{15 * time.Second}
	c.Tunnel.BootstrapDirect = true
	return c
}

// secretKeys are the only settings read from .env / the environment.
var secretKeys = map[string]bool{"WIREGUARD_PRIVATE_KEY": true, "WIREGUARD_ADDRESSES": true, "PROXY_PASSWORD": true}

// loadDotenv sets the secret KEY=VALUE pairs from path for variables not
// already set, and returns the other keys it found so they can be flagged.
func loadDotenv(path string) (ignored []string, err error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		k, v, ok := strings.Cut(line, "=")
		if !ok || line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
			v = v[1 : len(v)-1]
		}
		if !secretKeys[k] {
			ignored = append(ignored, k)
			continue
		}
		if _, set := os.LookupEnv(k); !set {
			os.Setenv(k, v)
		}
	}
	return ignored, nil
}

func LoadConfig(path string) (*Config, error) {
	cfg := defaultConfig()
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		if err := yaml.Unmarshal(b, cfg); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
	}
	for i := range cfg.Listeners {
		if cfg.Listeners[i].Name == "" {
			cfg.Listeners[i].Name = cfg.Listeners[i].Addr
		}
	}
	// Only secrets come from the environment (.env); everything else is config.yaml.
	cfg.Password = os.Getenv("PROXY_PASSWORD")
	cfg.Tunnel.PrivateKey = os.Getenv("WIREGUARD_PRIVATE_KEY")
	cfg.Tunnel.Address = os.Getenv("WIREGUARD_ADDRESSES")
	cfg.Tunnel.Entry = strings.ToLower(cfg.Tunnel.Entry)

	cfg.DefaultExit = strings.ToLower(cfg.DefaultExit)
	aliases := make(map[string][]string, len(cfg.Aliases))
	for k, v := range cfg.Aliases {
		for i := range v {
			v[i] = strings.ToLower(v[i])
		}
		aliases[strings.ToLower(k)] = v
	}
	cfg.Aliases = aliases
	for i := range cfg.Listeners {
		l := &cfg.Listeners[i]
		l.Exit = strings.ToLower(l.Exit)
		host, _, err := net.SplitHostPort(l.Addr)
		if err != nil {
			return nil, fmt.Errorf("listener %q: %w", l.Name, err)
		}
		if err := validateHost(host); err != nil {
			return nil, fmt.Errorf("listener %q: %w", l.Name, err)
		}
	}
	apiHost, _, err := net.SplitHostPort(cfg.API)
	if err != nil {
		return nil, fmt.Errorf("api %q: %w", cfg.API, err)
	}
	if err := validateHost(apiHost); err != nil {
		return nil, fmt.Errorf("api %q: %w", cfg.API, err)
	}
	for i := range cfg.Rules {
		cfg.Rules[i].Match = strings.ToLower(cfg.Rules[i].Match)
		cfg.Rules[i].Exit = strings.ToLower(cfg.Rules[i].Exit)
	}
	if len(cfg.Listeners) == 0 {
		return nil, fmt.Errorf("no listeners configured")
	}
	return cfg, nil
}

// validateHost rejects addresses that would make net.Listen bind every
// interface: an empty host, 0.0.0.0, and any spelling of the IPv6 unspecified
// address. Listeners and the API must name their interface explicitly.
func validateHost(host string) error {
	host = normalizeHost(host)
	if host == "" {
		return errors.New("no host (binds every interface); name a specific address")
	}
	if ip, err := netip.ParseAddr(host); err == nil && ip.Unmap().IsUnspecified() {
		return fmt.Errorf("%s binds every interface; name a specific address", host)
	}
	return nil
}

// normalizeHost trims spaces and one pair of brackets around an IPv6 literal.
func normalizeHost(host string) string {
	host = strings.TrimSpace(host)
	if len(host) > 1 && host[0] == '[' && host[len(host)-1] == ']' {
		return host[1 : len(host)-1]
	}
	return host
}

// MatchRule returns the exit of the first per-domain rule matching host, or "".
func (c *Config) MatchRule(host string) string {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, r := range c.Rules {
		if suffix, ok := strings.CutPrefix(r.Match, "*."); ok {
			if host == suffix || strings.HasSuffix(host, "."+suffix) {
				return r.Exit
			}
		} else if host == r.Match {
			return r.Exit
		}
	}
	return ""
}

// PACPort is the port browsers using the PAC file are sent to: pac.port if set,
// otherwise the first listener that needs no credentials and has a fixed session.
func (c *Config) PACPort() string {
	if c.PAC.Port != "" {
		return c.PAC.Port
	}
	var fallback string
	for _, l := range c.Listeners {
		if l.Challenge {
			continue
		}
		_, port, _ := net.SplitHostPort(l.Addr)
		if l.Session != "" {
			return port
		}
		if fallback == "" {
			fallback = port
		}
	}
	return fallback
}
