// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"errors"
	"io"
	"net"
	"time"
)

type nopConn struct{}

func (nopConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (nopConn) Write(p []byte) (int, error)      { return len(p), nil }
func (nopConn) Close() error                     { return nil }
func (nopConn) LocalAddr() net.Addr              { return dummyAddr{} }
func (nopConn) RemoteAddr() net.Addr             { return dummyAddr{} }
func (nopConn) SetDeadline(time.Time) error      { return nil }
func (nopConn) SetReadDeadline(time.Time) error  { return nil }
func (nopConn) SetWriteDeadline(time.Time) error { return nil }

type dummyAddr struct{}

func (dummyAddr) Network() string { return "tcp" }
func (dummyAddr) String() string  { return "127.0.0.1:0" }

type failConn struct{ nopConn }

func (failConn) Write([]byte) (int, error) { return 0, errors.New("write failed") }

type errDialer struct{ err error }

func (e errDialer) DialContext(context.Context, string, string) (net.Conn, error) { return nil, e.err }

type dialFunc func(context.Context, string, string) (net.Conn, error)

func (f dialFunc) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return f(ctx, network, addr)
}

type scriptedListener struct{ n int }

func (l *scriptedListener) Accept() (net.Conn, error) {
	l.n++
	if l.n == 1 {
		return nil, errors.New("accept failed")
	}
	return nil, net.ErrClosed
}
func (l *scriptedListener) Close() error   { return nil }
func (l *scriptedListener) Addr() net.Addr { return dummyAddr{} }

type timeoutError struct{}

func (timeoutError) Error() string   { return "timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

// ---- control API ----
