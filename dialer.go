// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"time"
)

// netDialer is the network the router dials through: the tunnel (a plain
// net.Dialer in tests).
type netDialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

// Dialer opens a TCP connection to a target through the exit chosen by a Selection.
type Dialer struct {
	cat     *Catalog
	picker  *Picker
	br      *Breaker
	net     netDialer
	timeout time.Duration
	ready   func() bool // nil = always; false fails fast instead of benching exits
}

// UpstreamError means the exit's SOCKS proxy itself could not be used.
type UpstreamError struct {
	Server string
	Err    error
}

func (e *UpstreamError) Error() string { return fmt.Sprintf("upstream %s: %v", e.Server, e.Err) }
func (e *UpstreamError) Unwrap() error { return e.Err }

// Dial returns the connection and the server it exits from.
func (d *Dialer) Dial(ctx context.Context, sel Selection, target string) (net.Conn, string, error) {
	if d.ready != nil && !d.ready() {
		return nil, "", errTunnelDown
	}
	if sel.Exit == exitCurrent {
		ctx, cancel := context.WithTimeout(ctx, d.timeout)
		defer cancel()
		c, err := d.net.DialContext(ctx, "tcp", target)
		return c, exitCurrent, err
	}
	host, ps, err := net.SplitHostPort(target)
	if err != nil {
		return nil, "", err
	}
	port, err := strconv.Atoi(ps)
	if err != nil || port <= 0 || port > 65535 {
		return nil, "", fmt.Errorf("bad port %q", ps)
	}

	tried := map[string]bool{}
	var last error
	for attempt := 0; attempt < 2; attempt++ {
		r, err := d.picker.Pick(sel, tried)
		if err != nil {
			if last != nil {
				return nil, "", last
			}
			return nil, "", err
		}
		tried[r.Hostname] = true
		c, err := d.viaRelay(ctx, r, host, port)
		if err == nil {
			d.br.OK(r.Hostname)
			return c, r.Hostname, nil
		}
		var te *TargetError
		if errors.As(err, &te) {
			d.br.OK(r.Hostname)
			return nil, r.Hostname, err
		}
		if ctx.Err() != nil {
			return nil, r.Hostname, ctx.Err()
		}
		if d.ready != nil && !d.ready() {
			return nil, r.Hostname, errTunnelDown // not the exit's fault
		}
		pen := d.br.Fail(r.Hostname)
		slog.Warn("upstream failed", "server", r.Hostname, "err", err.Error(), "benched_s", int(pen.Seconds()))
		last = &UpstreamError{Server: r.Hostname, Err: err}
	}
	return nil, "", last
}

func (d *Dialer) viaRelay(ctx context.Context, r *Relay, host string, port int) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()
	addr, err := d.cat.Resolve(ctx, r)
	if err != nil {
		return nil, err
	}
	// Reaching an exit's proxy inside the tunnel is fast; a slow TCP connect means it's dead.
	cctx, ccancel := context.WithTimeout(ctx, min(5*time.Second, d.timeout))
	c, err := d.net.DialContext(cctx, "tcp", addr)
	ccancel()
	if err != nil {
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		c.SetDeadline(dl)
	}
	if err := socksConnect(c, host, port); err != nil {
		c.Close()
		return nil, err
	}
	c.SetDeadline(time.Time{})
	return c, nil
}
