// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi
// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"io"
	"net"
	"strings"
	"testing"
)

func TestSocksConnectErrors(t *testing.T) {
	t.Run("greeting write", func(t *testing.T) {
		c1, c2 := net.Pipe()
		c2.Close()
		if err := socksConnect(c1, "h", 80); err == nil {
			t.Error("write to closed peer succeeded")
		}
		c1.Close()
	})

	t.Run("greeting read", func(t *testing.T) {
		c1, c2 := net.Pipe()
		go func() {
			io.ReadFull(c2, make([]byte, 3))
			c2.Close()
		}()
		if err := socksConnect(c1, "h", 80); err == nil {
			t.Error("missing greeting accepted")
		}
		c1.Close()
	})

	t.Run("greeting rejected", func(t *testing.T) {
		c1, c2 := net.Pipe()
		go func() {
			io.ReadFull(c2, make([]byte, 3))
			c2.Write([]byte{5, 1})
		}()
		if err := socksConnect(c1, "h", 80); err == nil {
			t.Error("rejected greeting accepted")
		}
		c1.Close()
		c2.Close()
	})

	t.Run("bad host", func(t *testing.T) {
		c1, c2 := net.Pipe()
		go func() {
			io.ReadFull(c2, make([]byte, 3))
			c2.Write([]byte{5, 0})
		}()
		if err := socksConnect(c1, strings.Repeat("a", 300), 80); err == nil {
			t.Error("overlong host accepted")
		}
		c1.Close()
		c2.Close()
	})

	t.Run("request write", func(t *testing.T) {
		c1, c2 := net.Pipe()
		go func() {
			io.ReadFull(c2, make([]byte, 3))
			c2.Write([]byte{5, 0})
			c2.Close()
		}()
		if err := socksConnect(c1, "h", 80); err == nil {
			t.Error("request write to closed peer succeeded")
		}
		c1.Close()
	})

	t.Run("reply read", func(t *testing.T) {
		c1, c2 := net.Pipe()
		go func() {
			io.ReadFull(c2, make([]byte, 3))
			c2.Write([]byte{5, 0})
			var h [4]byte
			io.ReadFull(c2, h[:])
			readSocksAddr(c2, h[3])
			c2.Close()
		}()
		if err := socksConnect(c1, "h", 80); err == nil {
			t.Error("missing reply accepted")
		}
		c1.Close()
	})

	t.Run("bad reply version", func(t *testing.T) {
		c1, c2 := net.Pipe()
		go func() {
			io.ReadFull(c2, make([]byte, 3))
			c2.Write([]byte{5, 0})
			var h [4]byte
			io.ReadFull(c2, h[:])
			readSocksAddr(c2, h[3])
			c2.Write([]byte{4, 0, 0, 1, 0, 0, 0, 0, 0, 0})
		}()
		if err := socksConnect(c1, "h", 80); err == nil {
			t.Error("bad reply version accepted")
		}
		c1.Close()
		c2.Close()
	})
}

func TestReadSocksAddrErrors(t *testing.T) {
	for _, atyp := range []byte{1, 3, 4} {
		if _, _, err := readSocksAddr(bytes.NewReader(nil), atyp); err == nil {
			t.Errorf("atyp %d: short address accepted", atyp)
		}
	}
	if _, _, err := readSocksAddr(bytes.NewReader([]byte{5}), 3); err == nil {
		t.Error("short hostname accepted")
	}
	if _, _, err := readSocksAddr(bytes.NewReader([]byte{1, 2, 3, 4}), 1); err == nil {
		t.Error("missing port accepted")
	}
	if _, _, err := readSocksAddr(bytes.NewReader(nil), 9); err == nil {
		t.Error("unknown atyp accepted")
	}
}

func TestReadUserPassErrors(t *testing.T) {
	for name, in := range map[string][]byte{
		"header":   nil,
		"version":  {2, 0},
		"username": {1, 5, 'a'},
		"plen":     {1, 0},
		"password": {1, 1, 'a', 3, 'b'},
	} {
		if _, _, err := readUserPass(bytes.NewReader(in)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	u, p, err := readUserPass(bytes.NewReader([]byte{1, 1, 'a', 1, 'b'}))
	if err != nil || u != "a" || p != "b" {
		t.Errorf("valid credentials: %q %q %v", u, p, err)
	}
}

// ---- proxy ----
