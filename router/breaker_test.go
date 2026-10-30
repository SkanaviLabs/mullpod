// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi
// SPDX-License-Identifier: MIT

package main

import (
	"testing"
	"time"
)

func TestBreakerBackoff(t *testing.T) {
	b := NewBreaker(time.Second, 4*time.Second)
	want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 4 * time.Second}
	for i, w := range want {
		d := b.Fail("x")
		lo, hi := time.Duration(float64(w)*0.79), time.Duration(float64(w)*1.21)
		if d < lo || d > hi {
			t.Errorf("fail %d: %v, want %v ±20%%", i+1, d, w)
		}
	}
	if b.Healthy("x") || b.Unhealthy() != 1 {
		t.Error("benched server reported healthy")
	}
	b.OK("x")
	if !b.Healthy("x") || b.Unhealthy() != 0 {
		t.Error("OK did not reset")
	}
}

// ---- SOCKS edge cases, routing extras, error mapping ----
