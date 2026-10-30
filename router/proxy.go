// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi
// SPDX-License-Identifier: MIT

package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const idleTimeout = 2 * time.Minute

// Server is one listener. Every listener speaks both HTTP proxy and SOCKS5,
// told apart by the first byte the client sends.
type Server struct {
	cfg *Config
	ln  Listener
	d   *Dialer
	m   *Metrics
}

func (s *Server) Serve(l net.Listener) error {
	for {
		c, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return err
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}
		go s.handle(c)
	}
}

func (s *Server) handle(c net.Conn) {
	defer c.Close()
	s.m.active.Add(1)
	defer s.m.active.Add(-1)
	c.SetReadDeadline(time.Now().Add(30 * time.Second))
	br := bufio.NewReader(c)
	b, err := br.Peek(1)
	if err != nil {
		return
	}
	if b[0] == 5 {
		s.serveSOCKS(c, br)
	} else {
		s.serveHTTP(c, br)
	}
}

// route applies the selection order: header → username → domain rule →
// listener exit → default exit; session: username → header → listener.
func (s *Server) route(user string, hasUser bool, hdrExit, hdrSession, host string) Selection {
	var sel Selection
	if hasUser && user != "" {
		sel = ParseUser(user)
		if sel.Session == "" && s.cfg.Sticky.Implicit {
			sel.Session = "user:" + user
		}
	}
	if hdrExit != "" {
		sel.Exit = strings.ToLower(strings.TrimSpace(hdrExit))
	}
	if sel.Exit == "default" {
		sel.Exit = ""
	}
	if hdrSession != "" && sel.Session == "" {
		sel.Session = hdrSession
	}
	if sel.Exit == "" {
		sel.Exit = s.cfg.MatchRule(host)
	}
	if sel.Exit == "" {
		sel.Exit = s.ln.Exit
	}
	if sel.Exit == "" {
		sel.Exit = s.cfg.DefaultExit
	}
	if sel.Session == "" && s.ln.Session != "" {
		// A port's built-in session is kept per exit, so per-domain rules that
		// send some sites elsewhere don't move the port's main IP.
		sel.Session = s.ln.Session + "|" + sel.Exit
	}
	return sel
}

func (s *Server) log(proto, client, target string, sel Selection, server string, start time.Time, sent, recv int64, err error) {
	result := "ok"
	attrs := []any{"listener", s.ln.Name, "proto", proto, "client", client, "target", target,
		"exit", sel.Exit, "session", sel.Session, "server", server,
		"ms", time.Since(start).Milliseconds(), "sent", sent, "recv", recv}
	if err != nil {
		result = "error"
		attrs = append(attrs, "err", err.Error())
	}
	s.m.Count(s.ln.Name, proto, result)
	s.m.AddBytes(sent, recv)
	slog.Info("conn", attrs...)
}

// ---- HTTP proxy ----

func (s *Server) serveHTTP(c net.Conn, br *bufio.Reader) {
	for {
		c.SetReadDeadline(time.Now().Add(idleTimeout))
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		c.SetReadDeadline(time.Time{})

		user, pass, hasCreds := proxyAuth(req.Header.Get("Proxy-Authorization"))
		if (s.cfg.Password != "" && (!hasCreds || pass != s.cfg.Password)) || (!hasCreds && s.ln.Challenge) {
			io.Copy(io.Discard, req.Body)
			req.Body.Close()
			writeStatus(c, http.StatusProxyAuthRequired,
				"Proxy username selects the exit: http://<exit>[_<session>]:x@host:port (e.g. de-fra_s1). "+
					"Ports without credentials: see /exits on the control API.",
				"Proxy-Authenticate", `Basic realm="mullpod"`)
			if req.Close {
				return
			}
			continue
		}

		if req.Method == http.MethodConnect {
			target := req.Host
			if _, _, err := net.SplitHostPort(target); err != nil {
				target = net.JoinHostPort(target, "443")
			}
			sel := s.route(user, hasCreds, req.Header.Get("X-Exit"), req.Header.Get("X-Session"), hostOnly(target))
			s.connect(c, br, target, sel)
			return
		}
		if req.URL.Host == "" {
			writeStatus(c, http.StatusBadRequest, "this is a proxy port; the control API is on "+s.cfg.API)
			return
		}
		sel := s.route(user, hasCreds, req.Header.Get("X-Exit"), req.Header.Get("X-Session"), req.URL.Hostname())
		if !s.forward(c, req, sel) {
			return
		}
	}
}

func (s *Server) connect(c net.Conn, br *bufio.Reader, target string, sel Selection) {
	start := time.Now()
	up, server, err := s.d.Dial(context.Background(), sel, target)
	if err != nil {
		writeStatus(c, dialStatus(err), err.Error(), "Connection", "close")
		s.log("http-connect", c.RemoteAddr().String(), target, sel, server, start, 0, 0, err)
		return
	}
	if _, err := io.WriteString(c, "HTTP/1.1 200 Connection Established\r\nX-Mullvad-Server: "+server+"\r\n\r\n"); err != nil {
		up.Close()
		return
	}
	sent, recv := splice(c, br, up)
	s.log("http-connect", c.RemoteAddr().String(), target, sel, server, start, sent, recv, nil)
}

var hopHeaders = []string{"Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization",
	"Proxy-Connection", "Te", "Trailer", "Transfer-Encoding", "Upgrade", "X-Exit", "X-Session"}

func stripHop(h http.Header) {
	for _, f := range h.Values("Connection") {
		for _, k := range strings.Split(f, ",") {
			h.Del(strings.TrimSpace(k))
		}
	}
	for _, k := range hopHeaders {
		h.Del(k)
	}
}

// forward relays one plain-HTTP request over a fresh upstream connection, so a
// pooled connection can never carry a request out of the wrong exit.
func (s *Server) forward(c net.Conn, req *http.Request, sel Selection) bool {
	start := time.Now()
	target := req.URL.Host
	stripHop(req.Header)
	req.RequestURI = ""
	var server string
	tr := &http.Transport{
		Proxy:                 nil,
		DisableKeepAlives:     true,
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			uc, srv, err := s.d.Dial(ctx, sel, addr)
			server = srv
			return uc, err
		},
	}
	defer tr.CloseIdleConnections()
	resp, err := tr.RoundTrip(req)
	if err != nil {
		writeStatus(c, dialStatus(err), err.Error(), "Connection", "close")
		s.log("http", c.RemoteAddr().String(), target, sel, server, start, 0, 0, err)
		return false
	}
	defer resp.Body.Close()
	stripHop(resp.Header)
	resp.Header.Set("X-Mullvad-Server", server)
	cw := &countWriter{w: c}
	err = resp.Write(cw)
	s.log("http", c.RemoteAddr().String(), target, sel, server, start, max(req.ContentLength, 0), cw.n, err)
	return err == nil && !req.Close && !resp.Close
}

func dialStatus(err error) int {
	switch {
	case errors.Is(err, errUnknownExit):
		return http.StatusBadRequest
	case errors.Is(err, errCatalogEmpty), errors.Is(err, errTunnelDown):
		return http.StatusServiceUnavailable
	case errors.Is(err, context.DeadlineExceeded):
		return http.StatusGatewayTimeout
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return http.StatusGatewayTimeout
	}
	return http.StatusBadGateway
}

func writeStatus(w io.Writer, code int, msg string, kv ...string) {
	var b strings.Builder
	fmt.Fprintf(&b, "HTTP/1.1 %d %s\r\n", code, http.StatusText(code))
	for i := 0; i+1 < len(kv); i += 2 {
		fmt.Fprintf(&b, "%s: %s\r\n", kv[i], kv[i+1])
	}
	body := msg + "\n"
	fmt.Fprintf(&b, "Content-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
	io.WriteString(w, b.String())
}

func proxyAuth(h string) (user, pass string, ok bool) {
	enc, found := strings.CutPrefix(h, "Basic ")
	if !found {
		return "", "", false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(enc))
	if err != nil {
		return "", "", false
	}
	user, pass, ok = strings.Cut(string(raw), ":")
	return user, pass, ok
}

func hostOnly(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return hostport
}

// ---- SOCKS5 inbound ----

func (s *Server) serveSOCKS(c net.Conn, br *bufio.Reader) {
	start := time.Now()
	var hdr [2]byte
	if _, err := io.ReadFull(br, hdr[:]); err != nil {
		return
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(br, methods); err != nil {
		return
	}
	var noAuth, userPass bool
	for _, m := range methods {
		noAuth = noAuth || m == 0
		userPass = userPass || m == 2
	}

	var user string
	var hasUser bool
	switch {
	case userPass:
		c.Write([]byte{5, 2})
		u, p, err := readUserPass(br)
		if err != nil {
			return
		}
		if s.cfg.Password != "" && p != s.cfg.Password {
			c.Write([]byte{1, 1})
			return
		}
		c.Write([]byte{1, 0})
		user, hasUser = u, true
	case noAuth && s.cfg.Password == "":
		c.Write([]byte{5, 0})
	default:
		c.Write([]byte{5, 0xff})
		return
	}

	var rq [4]byte
	if _, err := io.ReadFull(br, rq[:]); err != nil || rq[0] != 5 {
		return
	}
	host, port, err := readSocksAddr(br, rq[3])
	if err != nil {
		socksReply(c, 8)
		return
	}
	if rq[1] != 1 {
		socksReply(c, 7)
		return
	}
	c.SetReadDeadline(time.Time{})
	target := net.JoinHostPort(host, fmt.Sprint(port))
	sel := s.route(user, hasUser, "", "", host)

	up, server, err := s.d.Dial(context.Background(), sel, target)
	if err != nil {
		var te *TargetError
		code := byte(1)
		switch {
		case errors.As(err, &te):
			code = te.Code
		case errors.Is(err, errUnknownExit):
			code = 2
		}
		socksReply(c, code)
		s.log("socks5", c.RemoteAddr().String(), target, sel, server, start, 0, 0, err)
		return
	}
	if socksReply(c, 0) != nil {
		up.Close()
		return
	}
	sent, recv := splice(c, br, up)
	s.log("socks5", c.RemoteAddr().String(), target, sel, server, start, sent, recv, nil)
}

func readUserPass(r io.Reader) (string, string, error) {
	var v [2]byte
	if _, err := io.ReadFull(r, v[:]); err != nil {
		return "", "", err
	}
	if v[0] != 1 {
		return "", "", errors.New("bad auth version")
	}
	u := make([]byte, v[1])
	if _, err := io.ReadFull(r, u); err != nil {
		return "", "", err
	}
	var pl [1]byte
	if _, err := io.ReadFull(r, pl[:]); err != nil {
		return "", "", err
	}
	p := make([]byte, pl[0])
	if _, err := io.ReadFull(r, p); err != nil {
		return "", "", err
	}
	return string(u), string(p), nil
}

func socksReply(c net.Conn, code byte) error {
	_, err := c.Write([]byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0})
	return err
}

// ---- plumbing ----

type closeWriter interface{ CloseWrite() error }

// splice copies both directions until both are done, propagating half-closes.
func splice(client net.Conn, clientR io.Reader, up net.Conn) (sent, recv int64) {
	defer up.Close()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		sent, _ = io.Copy(up, clientR)
		if cw, ok := up.(closeWriter); ok {
			cw.CloseWrite()
		} else {
			up.Close()
		}
	}()
	recv, _ = io.Copy(client, up)
	if cw, ok := client.(closeWriter); ok {
		cw.CloseWrite()
	}
	// The exit is done; give the client a moment to finish, then tear down.
	client.SetReadDeadline(time.Now().Add(5 * time.Second))
	wg.Wait()
	return sent, recv
}

type countWriter struct {
	w io.Writer
	n int64
}

func (c *countWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}
