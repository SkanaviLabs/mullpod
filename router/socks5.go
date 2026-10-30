// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi
// SPDX-License-Identifier: MIT

package main

import (
	"errors"
	"fmt"
	"io"
	"net"
)

// TargetError is a SOCKS5 error reply from an exit proxy: the proxy is alive,
// but it could not reach the target.
type TargetError struct{ Code byte }

var socksReplies = map[byte]string{
	1: "general failure",
	2: "connection not allowed by ruleset",
	3: "network unreachable",
	4: "host unreachable",
	5: "connection refused",
	6: "TTL expired",
	7: "command not supported",
	8: "address type not supported",
}

func (e *TargetError) Error() string {
	if s, ok := socksReplies[e.Code]; ok {
		return "exit: " + s
	}
	return fmt.Sprintf("exit: socks reply %d", e.Code)
}

// socksConnect performs an unauthenticated SOCKS5 CONNECT on c.
func socksConnect(c net.Conn, host string, port int) error {
	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		return err
	}
	var g [2]byte
	if _, err := io.ReadFull(c, g[:]); err != nil {
		return err
	}
	if g[0] != 5 || g[1] != 0 {
		return fmt.Errorf("socks greeting rejected (%x)", g)
	}
	req, err := appendSocksAddr([]byte{5, 1, 0}, host, port)
	if err != nil {
		return err
	}
	if _, err := c.Write(req); err != nil {
		return err
	}
	var h [4]byte
	if _, err := io.ReadFull(c, h[:]); err != nil {
		return err
	}
	if h[0] != 5 {
		return fmt.Errorf("bad socks reply version %d", h[0])
	}
	if h[1] != 0 {
		return &TargetError{Code: h[1]}
	}
	_, _, err = readSocksAddr(c, h[3])
	return err
}

func appendSocksAddr(b []byte, host string, port int) ([]byte, error) {
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			b = append(append(b, 1), ip4...)
		} else {
			b = append(append(b, 4), ip.To16()...)
		}
	} else {
		if len(host) == 0 || len(host) > 255 {
			return nil, errors.New("bad target host")
		}
		b = append(append(b, 3, byte(len(host))), host...)
	}
	return append(b, byte(port>>8), byte(port)), nil
}

func readSocksAddr(r io.Reader, atyp byte) (string, int, error) {
	var host string
	switch atyp {
	case 1, 4:
		ip := make([]byte, map[byte]int{1: 4, 4: 16}[atyp])
		if _, err := io.ReadFull(r, ip); err != nil {
			return "", 0, err
		}
		host = net.IP(ip).String()
	case 3:
		var l [1]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return "", 0, err
		}
		name := make([]byte, l[0])
		if _, err := io.ReadFull(r, name); err != nil {
			return "", 0, err
		}
		host = string(name)
	default:
		return "", 0, &TargetError{Code: 8}
	}
	var p [2]byte
	if _, err := io.ReadFull(r, p[:]); err != nil {
		return "", 0, err
	}
	return host, int(p[0])<<8 | int(p[1]), nil
}
