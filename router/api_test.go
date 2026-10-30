// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi
// SPDX-License-Identifier: MIT

package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

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

type fakeTunnel struct {
	up       atomic.Bool
	switches atomic.Int32
}

func (f *fakeTunnel) Ready() bool            { return f.up.Load() }
func (f *fakeTunnel) Status() map[string]any { return map[string]any{"entry": "us-mia-wg-001"} }
func (f *fakeTunnel) Switch()                { f.switches.Add(1) }

func apiFor(r *rig) (*API, *fakeTunnel, *httptest.Server) {
	ft := &fakeTunnel{}
	ft.up.Store(true)
	a := &API{cfg: r.cfg, cat: r.cat, picker: r.picker, br: r.br, d: r.d, m: &Metrics{}, tun: ft}
	return a, ft, httptest.NewServer(a.Handler())
}

func getJSON(t *testing.T, method, u string) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(method, u, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var m map[string]any
	json.NewDecoder(resp.Body).Decode(&m)
	return resp.StatusCode, m
}

func TestAPIHealth(t *testing.T) {
	r := newRig(t, "de-fra-wg-001")
	_, ft, srv := apiFor(r)
	defer srv.Close()

	code, m := getJSON(t, "GET", srv.URL+"/health")
	if code != 200 || m["status"] != "ok" || m["tunnel"] != true || m["relays"].(float64) != 1 {
		t.Fatalf("healthy: %d %v", code, m)
	}
	if info, _ := m["tunnel_info"].(map[string]any); info["entry"] != "us-mia-wg-001" {
		t.Errorf("tunnel_info: %v", m["tunnel_info"])
	}
	// Tunnel down → 503.
	ft.up.Store(false)
	if code, m = getJSON(t, "GET", srv.URL+"/health"); code != 503 || m["tunnel"] != false {
		t.Errorf("tunnel down: %d %v", code, m)
	}
	// Empty catalog → 503 even with a tunnel.
	ft.up.Store(true)
	r.cat.Set(nil)
	if code, m = getJSON(t, "GET", srv.URL+"/health"); code != 503 || m["relays"].(float64) != 0 {
		t.Errorf("no relays: %d %v", code, m)
	}
}

func TestAPIExitsRotatePACMetricsSwitch(t *testing.T) {
	r := newRig(t, "de-fra-wg-001", "de-fra-wg-002", "de-ber-wg-001", "jp-tyo-wg-001")
	r.cfg.Listeners = []Listener{{Name: "main", Addr: ":8080", Challenge: true}, {Name: "us", Addr: ":8081", Exit: "us", Session: "p"}}
	_, ft, srv := apiFor(r)
	defer srv.Close()

	code, m := getJSON(t, "GET", srv.URL+"/exits?servers=1")
	if code != 200 || m["total"].(float64) != 4 {
		t.Fatalf("exits: %d %v", code, m)
	}
	countries := m["countries"].([]any)
	de := countries[0].(map[string]any)
	if de["code"] != "de" || de["servers"].(float64) != 3 || len(de["cities"].([]any)) != 2 {
		t.Errorf("de: %v", de)
	}
	city := de["cities"].([]any)[0].(map[string]any)
	if len(city["hostnames"].([]any)) == 0 {
		t.Error("servers=1 did not list hostnames")
	}

	// /forget drops a session.
	first, _ := r.picker.Pick(Selection{Exit: "de", Session: "s"}, nil)
	if code, m = getJSON(t, "POST", srv.URL+"/forget?session=s"); code != 200 || m["forgot"] != true {
		t.Errorf("forget: %d %v", code, m)
	}
	if code, _ = getJSON(t, "POST", srv.URL+"/forget"); code != 400 {
		t.Errorf("forget without session: %d", code)
	}
	if code, m = getJSON(t, "POST", srv.URL+"/forget?session=s"); m["forgot"] != false {
		t.Errorf("second forget should have nothing to forget: %v", m)
	}
	// GET works the same as POST.
	r.picker.Pick(Selection{Exit: "de", Session: "g"}, nil)
	if code, m = getJSON(t, "GET", srv.URL+"/forget?session=g"); code != 200 || m["forgot"] != true {
		t.Errorf("GET forget: %d %v", code, m)
	}
	_ = first

	resp, _ := http.Get(srv.URL + "/proxy.pac")
	pac, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(pac), `return "PROXY 127.0.0.1:8081"`) || !strings.Contains(string(pac), "DIRECT") {
		t.Errorf("pac:\n%s", pac)
	}

	resp, _ = http.Get(srv.URL + "/metrics")
	met, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	for _, want := range []string{"mullpod_relays 4", "mullpod_tunnel_up", "mullpod_sessions"} {
		if !strings.Contains(string(met), want) {
			t.Errorf("metrics missing %q:\n%s", want, met)
		}
	}

	if code, m = getJSON(t, "POST", srv.URL+"/tunnel/switch"); code != 202 || m["switching_from"] != "us-mia-wg-001" || ft.switches.Load() != 1 {
		t.Errorf("tunnel/switch: %d %v switches=%d", code, m, ft.switches.Load())
	}
	if code, m = getJSON(t, "GET", srv.URL+"/"); code != 200 || m["endpoints"] == nil {
		t.Errorf("index: %d %v", code, m)
	}
}

func TestAPIIP(t *testing.T) {
	r := newRig(t, "jp-tyo-wg-001", "de-fra-wg-001")
	check := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, `{"ip":"1.2.3.4","country":"Japan","mullvad_exit_ip":true}`)
	}))
	defer check.Close()
	r.cfg.IPCheckURL = check.URL
	_, _, srv := apiFor(r)
	defer srv.Close()

	code, m := getJSON(t, "GET", srv.URL+"/ip?exit=jp&session=x")
	if code != 200 || m["server"] != "jp-tyo-wg-001" || m["check"].(map[string]any)["country"] != "Japan" {
		t.Fatalf("ip: %d %v", code, m)
	}
	if code, m = getJSON(t, "GET", srv.URL+"/ip?exit=zz"); code != 400 || m["error"] == nil {
		t.Errorf("unknown exit: %d %v", code, m)
	}
}

// ---- PROXY_PASSWORD ----

func TestPACIPv6(t *testing.T) {
	a := &API{cfg: &Config{}}
	a.cfg.PAC.Port = "8081"

	for _, c := range []struct{ host, req, want string }{
		{"::1", "http://[::1]:8088/proxy.pac", `return "PROXY [::1]:8081"`},
		{"[::1]", "http://[::1]:8088/proxy.pac", `return "PROXY [::1]:8081"`},
		{"", "http://[::1]:8088/proxy.pac", `return "PROXY [::1]:8081"`},
		{"127.0.0.1", "http://127.0.0.1:8088/proxy.pac", `return "PROXY 127.0.0.1:8081"`},
	} {
		a.cfg.PAC.Host = c.host
		rec := httptest.NewRecorder()
		a.Handler().ServeHTTP(rec, httptest.NewRequest("GET", c.req, nil))
		if body := rec.Body.String(); !strings.Contains(body, c.want) {
			t.Errorf("pac host %q:\n%s", c.host, body)
		}
	}
}
