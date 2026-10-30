// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Metrics struct {
	active     atomic.Int64
	sent, recv atomic.Int64

	mu    sync.Mutex
	conns map[[3]string]int64
}

func (m *Metrics) Count(listener, proto, result string) {
	m.mu.Lock()
	if m.conns == nil {
		m.conns = map[[3]string]int64{}
	}
	m.conns[[3]string{listener, proto, result}]++
	m.mu.Unlock()
}

func (m *Metrics) AddBytes(sent, recv int64) {
	m.sent.Add(sent)
	m.recv.Add(recv)
}

type API struct {
	cfg    *Config
	cat    *Catalog
	picker *Picker
	br     *Breaker
	d      *Dialer
	m      *Metrics
	tun    tunnelControl
}

// tunnelControl is the part of *Tunnel the API uses (faked in tests).
type tunnelControl interface {
	Ready() bool
	Status() map[string]any
	Switch()
}

func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", a.health)
	mux.HandleFunc("GET /exits", a.exits)
	mux.HandleFunc("GET /ip", a.ip)
	mux.HandleFunc("GET /forget", a.forget)
	mux.HandleFunc("POST /forget", a.forget)
	mux.HandleFunc("POST /tunnel/switch", func(w http.ResponseWriter, r *http.Request) {
		from := a.tun.Status()["entry"]
		a.tun.Switch()
		writeJSON(w, 202, map[string]any{"switching_from": from})
	})
	mux.HandleFunc("GET /proxy.pac", a.pac)
	mux.HandleFunc("GET /metrics", a.metrics)
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"endpoints": []string{"/health", "/exits", "/ip?exit=&session=",
			"GET|POST /forget?session=", "POST /tunnel/switch", "/proxy.pac", "/metrics"}})
	})
	return mux
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}

func (a *API) health(w http.ResponseWriter, r *http.Request) {
	tunnel := a.tun.Ready()
	n := a.cat.Len()
	status, code := "ok", 200
	if !tunnel || n == 0 {
		status, code = "down", 503
	}
	age := -1
	if t := a.cat.LoadedAt(); !t.IsZero() {
		age = int(time.Since(t).Seconds())
	}
	out := map[string]any{
		"status": status, "tunnel": tunnel, "relays": n, "catalog_age_s": age,
		"unhealthy": a.br.Unhealthy(), "active_conns": a.m.active.Load(), "sessions": a.picker.Sessions(),
		"tunnel_info": a.tun.Status(),
	}
	writeJSON(w, code, out)
}

func (a *API) exits(w http.ResponseWriter, r *http.Request) {
	type city struct {
		Code    string   `json:"code"`
		Name    string   `json:"name"`
		Count   int      `json:"servers"`
		Servers []string `json:"hostnames,omitempty"`
	}
	type country struct {
		Code   string  `json:"code"`
		Name   string  `json:"name"`
		Count  int     `json:"servers"`
		Cities []*city `json:"cities"`
	}
	full := r.URL.Query().Get("servers") != ""
	byCC := map[string]*country{}
	byCity := map[string]*city{}
	for _, rl := range a.cat.All() {
		co := byCC[rl.CountryCode]
		if co == nil {
			co = &country{Code: rl.CountryCode, Name: rl.CountryName}
			byCC[rl.CountryCode] = co
		}
		ci := byCity[rl.City()]
		if ci == nil {
			ci = &city{Code: rl.City(), Name: rl.CityName}
			byCity[rl.City()] = ci
			co.Cities = append(co.Cities, ci)
		}
		co.Count++
		ci.Count++
		if full {
			ci.Servers = append(ci.Servers, rl.Hostname)
		}
	}
	list := make([]*country, 0, len(byCC))
	for _, c := range byCC {
		list = append(list, c)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Code < list[j].Code })

	var ports []map[string]string
	for _, l := range a.cfg.Listeners {
		ports = append(ports, map[string]string{"name": l.Name, "addr": l.Addr, "exit": l.Exit,
			"session": l.Session, "challenge": fmt.Sprint(l.Challenge)})
	}
	writeJSON(w, 200, map[string]any{
		"total": a.cat.Len(), "default_exit": a.cfg.DefaultExit, "aliases": a.cfg.Aliases,
		"rules": a.cfg.Rules, "listeners": ports, "countries": list,
		"grammar": "<exit>[_<session>]; exit = <cc> | <cc>-<city> | <cc>-<city>-wg-NNN (sets the session's server) | any | <alias> | current | default",
	})
}

func (a *API) ip(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	sel := Selection{Exit: strings.ToLower(q.Get("exit")), Session: q.Get("session")}
	if sel.Exit == "" || sel.Exit == "default" {
		sel.Exit = a.cfg.DefaultExit
	}
	var server string
	tr := &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			c, srv, err := a.d.Dial(ctx, sel, addr)
			server = srv
			return c, err
		},
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 25 * time.Second}
	start := time.Now()
	resp, err := client.Get(a.cfg.IPCheckURL)
	if err != nil {
		writeJSON(w, dialStatus(err), map[string]any{"exit": sel.Exit, "session": sel.Session, "server": server, "error": err.Error()})
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var check any
	if json.Unmarshal(body, &check) != nil {
		check = string(body)
	}
	writeJSON(w, 200, map[string]any{"exit": sel.Exit, "session": sel.Session, "server": server,
		"ms": time.Since(start).Milliseconds(), "check": check})
}

func (a *API) forget(w http.ResponseWriter, r *http.Request) {
	session := r.URL.Query().Get("session")
	if session == "" {
		writeJSON(w, 400, map[string]string{"error": "session is required"})
		return
	}
	writeJSON(w, 200, map[string]any{"session": session, "forgot": a.picker.Forget(session)})
}

func (a *API) pac(w http.ResponseWriter, r *http.Request) {
	host := a.cfg.PAC.Host
	if host == "" {
		host = hostOnly(r.Host)
	}
	host = normalizeHost(host)
	if strings.Contains(host, ":") {
		host = "[" + host + "]" // PAC proxy strings take IPv6 literals in brackets
	}
	w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
	fmt.Fprintf(w, `// mullpod PAC: per-domain rules are applied server-side.
function FindProxyForURL(url, host) {
  if (isPlainHostName(host) || host == "localhost" || shExpMatch(host, "127.*") ||
      isInNet(host, "10.0.0.0", "255.0.0.0") || isInNet(host, "192.168.0.0", "255.255.0.0"))
    return "DIRECT";
  return "PROXY %s:%s";
}
`, host, a.cfg.PACPort())
}

func (a *API) metrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	fmt.Fprintf(w, "mullpod_relays %d\n", a.cat.Len())
	fmt.Fprintf(w, "mullpod_relays_unhealthy %d\n", a.br.Unhealthy())
	fmt.Fprintf(w, "mullpod_sessions %d\n", a.picker.Sessions())
	fmt.Fprintf(w, "mullpod_active_connections %d\n", a.m.active.Load())
	fmt.Fprintf(w, "mullpod_bytes_sent_total %d\n", a.m.sent.Load())
	fmt.Fprintf(w, "mullpod_bytes_received_total %d\n", a.m.recv.Load())
	up := 0
	if a.tun.Ready() {
		up = 1
	}
	fmt.Fprintf(w, "mullpod_tunnel_up %d\n", up)
	a.m.mu.Lock()
	keys := make([][3]string, 0, len(a.m.conns))
	for k := range a.m.conns {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return strings.Join(keys[i][:], ",") < strings.Join(keys[j][:], ",") })
	for _, k := range keys {
		fmt.Fprintf(w, "mullpod_connections_total{listener=%q,proto=%q,result=%q} %d\n", k[0], k[1], k[2], a.m.conns[k])
	}
	a.m.mu.Unlock()
}
