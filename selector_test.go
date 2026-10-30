// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi
// SPDX-License-Identifier: MIT

package main

import (
	"errors"
	"testing"
	"time"
)

func TestSelectorErrorPaths(t *testing.T) {
	pk := NewPicker(NewCatalog(nil), NewBreaker(time.Minute, time.Hour), nil, time.Minute, 10)
	if _, err := pk.Candidates("any"); !errors.Is(err, errCatalogEmpty) {
		t.Errorf("empty catalog: %v", err)
	}

	r := newRig(t, "de-fra-wg-001", "de-fra-wg-002")
	if _, err := r.picker.Pick(Selection{Exit: "de-fra-wg-001"}, map[string]bool{"de-fra-wg-001": true}); err == nil {
		t.Error("excluded exact server was picked")
	}
	both := map[string]bool{"de-fra-wg-001": true, "de-fra-wg-002": true}
	if _, err := r.picker.Pick(Selection{Exit: "de-fra"}, both); err == nil {
		t.Error("picked with every candidate excluded")
	}

	r.br.Fail("de-fra-wg-001")
	r.br.Fail("de-fra-wg-002")
	got, err := r.picker.Pick(Selection{Exit: "de-fra"}, map[string]bool{"de-fra-wg-001": true})
	if err != nil || got.Hostname != "de-fra-wg-002" {
		t.Errorf("fallback: %v %v", got, err)
	}
}

// ---- dialer ----

func TestStickyExpiryAndCap(t *testing.T) {
	r := newRig(t, "se-sto-wg-001", "se-sto-wg-002", "se-sto-wg-003")
	pk := NewPicker(r.cat, r.br, nil, 60*time.Millisecond, 2)
	pk.Pick(Selection{Exit: "se", Session: "a"}, nil)
	pk.Pick(Selection{Exit: "se", Session: "b"}, nil)
	pk.Pick(Selection{Exit: "se", Session: "c"}, nil)
	if n := pk.Sessions(); n != 2 {
		t.Errorf("cap: %d sessions, want 2", n)
	}
	pk.Pick(Selection{Exit: "se-sto-wg-001", Session: "pin"}, nil)
	time.Sleep(100 * time.Millisecond)
	pk.Sweep()
	if n := pk.Sessions(); n != 0 {
		t.Errorf("after TTL + sweep: %d sessions", n)
	}
	// An expired session no longer holds its server.
	pk.Pick(Selection{Exit: "se-sto-wg-001", Session: "p2"}, nil)
	time.Sleep(100 * time.Millisecond)
	seen := map[string]bool{}
	for i := 0; i < 6; i++ {
		x, _ := pk.Pick(Selection{Exit: "se"}, nil)
		seen[x.Hostname] = true
	}
	x, _ := pk.Pick(Selection{Exit: "se", Session: "p2"}, nil)
	_ = x
	if len(seen) != 3 {
		t.Errorf("rotation after expiry used %v", seen)
	}
}
