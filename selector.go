// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi
// SPDX-License-Identifier: MIT

package main

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"strings"
	"sync"
	"time"
)

// Selection says where a connection should exit: Exit is a selector
// (any, country, city, server, alias or "current"); Session makes it sticky.
type Selection struct {
	Exit    string
	Session string
}

const exitCurrent = "current"

var (
	errUnknownExit = errors.New("unknown exit")
	errNoExit      = errors.New("no usable server for exit")
)

// ParseUser splits a proxy username "<exit>[_<session>]".
func ParseUser(u string) Selection {
	exit, sess, _ := strings.Cut(strings.TrimSpace(u), "_")
	return Selection{Exit: strings.ToLower(exit), Session: sess}
}

type Picker struct {
	cat     *Catalog
	br      *Breaker
	aliases map[string][]string
	ttl     time.Duration
	max     int

	mu       sync.Mutex
	rr       map[string]int
	sessions map[string]*stickyEntry // session → its current server
}

type stickyEntry struct {
	host string
	last time.Time
}

func NewPicker(cat *Catalog, br *Breaker, aliases map[string][]string, ttl time.Duration, max int) *Picker {
	return &Picker{cat: cat, br: br, aliases: aliases, ttl: ttl, max: max,
		rr: map[string]int{}, sessions: map[string]*stickyEntry{}}
}

// Candidates expands an exit selector (including aliases) into relays.
func (p *Picker) Candidates(exit string) ([]*Relay, error) {
	if p.cat.Len() == 0 {
		return nil, errCatalogEmpty
	}
	seen := map[string]bool{}
	var out []*Relay
	var expand func(string, int)
	expand = func(sel string, depth int) {
		if members, ok := p.aliases[sel]; ok && depth < 5 {
			for _, m := range members {
				expand(m, depth+1)
			}
			return
		}
		for _, r := range p.cat.Lookup(sel) {
			if !seen[r.Hostname] {
				seen[r.Hostname] = true
				out = append(out, r)
			}
		}
	}
	expand(exit, 0)
	if len(out) == 0 {
		return nil, fmt.Errorf("%w %q (see /exits)", errUnknownExit, exit)
	}
	return out, nil
}

// Pick chooses a relay for sel, never returning one in exclude.
//
// A session has one current server. A request whose exit contains it keeps
// using it ("de-fra-wg-001", then "de-fra", "de", "any"); a request whose
// exit doesn't ("jp") picks a server there, and that becomes the session's
// server. An exact server name always uses that server. Sessions are a
// convenience for stable IPs, not an access control.
//
// Exits use Mullvad's identifiers only: country code, <cc>-<city>, hostname.
func (p *Picker) Pick(sel Selection, exclude map[string]bool) (*Relay, error) {
	cands, err := p.Candidates(sel.Exit)
	if err != nil {
		return nil, err
	}
	now := time.Now()

	p.mu.Lock()
	defer p.mu.Unlock()
	var r *Relay
	if exact := p.cat.Server(sel.Exit); exact != nil {
		if exclude[exact.Hostname] {
			return nil, fmt.Errorf("%w %q", errNoExit, sel.Exit)
		}
		r = exact
	} else if e := p.sessions[sel.Session]; sel.Session != "" && e != nil &&
		now.Sub(e.last) < p.ttl && !exclude[e.host] && p.br.Healthy(e.host) {
		for _, c := range cands {
			if c.Hostname == e.host {
				r = c
				break
			}
		}
	}
	if r == nil {
		if r = p.roundRobin(sel.Exit, cands, exclude); r == nil {
			return nil, fmt.Errorf("%w %q", errNoExit, sel.Exit)
		}
	}
	if sel.Session != "" {
		p.sessions[sel.Session] = &stickyEntry{host: r.Hostname, last: now}
		if len(p.sessions) > p.max {
			p.evictOldest()
		}
	}
	return r, nil
}

// roundRobin walks the candidates round-robin from a per-selector cursor. If every
// non-excluded candidate is in the breaker, the first of them is still returned.
func (p *Picker) roundRobin(exit string, cands []*Relay, exclude map[string]bool) *Relay {
	n := len(cands)
	start, ok := p.rr[exit]
	if !ok {
		start = rand.IntN(n)
	}
	var fallback *Relay
	for i := 0; i < n; i++ {
		r := cands[(start+i)%n]
		if exclude[r.Hostname] {
			continue
		}
		if !p.br.Healthy(r.Hostname) {
			if fallback == nil {
				fallback = r
			}
			continue
		}
		p.rr[exit] = (start + i + 1) % n
		return r
	}
	return fallback
}

func (p *Picker) evictOldest() {
	var oldK string
	var oldT time.Time
	for k, e := range p.sessions {
		if oldK == "" || e.last.Before(oldT) {
			oldK, oldT = k, e.last
		}
	}
	delete(p.sessions, oldK)
}

// Forget drops a session's current server, so its next request picks anew.
func (p *Picker) Forget(session string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	_, ok := p.sessions[session]
	delete(p.sessions, session)
	return ok
}

func (p *Picker) Sweep() {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	for k, e := range p.sessions {
		if now.Sub(e.last) >= p.ttl {
			delete(p.sessions, k)
		}
	}
}

func (p *Picker) Sessions() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.sessions)
}
