// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi
// SPDX-License-Identifier: MIT

package main

import (
	"math/rand/v2"
	"sync"
	"time"
)

// Breaker keeps servers whose SOCKS proxy failed out of rotation for a while,
// doubling the penalty on repeated failures.
type Breaker struct {
	base, max time.Duration

	mu sync.Mutex
	st map[string]*breakerState
}

type breakerState struct {
	fails int
	until time.Time
}

func NewBreaker(base, max time.Duration) *Breaker {
	return &Breaker{base: base, max: max, st: map[string]*breakerState{}}
}

func (b *Breaker) Healthy(host string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	s := b.st[host]
	return s == nil || time.Now().After(s.until)
}

func (b *Breaker) Fail(host string) time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()
	s := b.st[host]
	if s == nil {
		s = &breakerState{}
		b.st[host] = s
	}
	s.fails++
	d := b.base
	for i := 1; i < s.fails && d < b.max; i++ {
		d *= 2
	}
	d = min(d, b.max)
	d = time.Duration(float64(d) * (0.8 + 0.4*rand.Float64()))
	s.until = time.Now().Add(d)
	return d
}

func (b *Breaker) OK(host string) {
	b.mu.Lock()
	delete(b.st, host)
	b.mu.Unlock()
}

func (b *Breaker) Unhealthy() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	n, now := 0, time.Now()
	for _, s := range b.st {
		if now.Before(s.until) {
			n++
		}
	}
	return n
}
