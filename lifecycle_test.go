// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi
// SPDX-License-Identifier: MIT

package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// syncBuf is a log sink safe for concurrent writers.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// captureLog sends slog output to a buffer for the rest of the test.
func captureLog(t *testing.T) *syncBuf {
	t.Helper()
	buf := &syncBuf{}
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(buf, nil)))
	t.Cleanup(func() { slog.SetDefault(old) })
	return buf
}

// connLines returns the "conn" log lines in buf, decoded.
func connLines(t *testing.T, buf *syncBuf) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(l), &m) == nil && m["msg"] == "conn" {
			out = append(out, m)
		}
	}
	return out
}

// await fails the test unless cond holds within 3 seconds.
func await(t *testing.T, what string, cond func() bool) {
	t.Helper()
	if !waitFor(t, 3*time.Second, cond) {
		t.Fatalf("timed out waiting for %s", what)
	}
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// silentServer accepts connections, optionally writes greeting, then never
// sends anything else.
func silentServer(t *testing.T, greeting string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { c.Close() })
			go func() {
				if greeting != "" {
					bufio.NewReader(c).ReadString('\n') // wait for the request line
					io.WriteString(c, greeting)
				}
			}()
		}
	}()
	return ln.Addr().String()
}

// ---- idle timeout ----

func TestSpliceIdleTimeout(t *testing.T) {
	client, clientPeer := net.Pipe()
	up, upPeer := net.Pipe()
	defer clientPeer.Close()
	defer upPeer.Close()

	done := make(chan error, 1)
	go func() {
		_, _, err := splice(client, client, up, 50*time.Millisecond)
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, errIdle) {
			t.Errorf("err = %v, want errIdle", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("splice did not end an idle tunnel")
	}
}

func TestSpliceIdleStalledClient(t *testing.T) {
	// The exit keeps sending, but the client never reads: nothing moves.
	client, clientPeer := net.Pipe()
	up, upPeer := net.Pipe()
	defer clientPeer.Close()
	defer upPeer.Close()
	go func() {
		for {
			if _, err := upPeer.Write([]byte("x")); err != nil {
				return
			}
		}
	}()

	done := make(chan error, 1)
	go func() {
		_, _, err := splice(client, client, up, 50*time.Millisecond)
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, errIdle) {
			t.Errorf("err = %v, want errIdle", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("splice did not end a stalled tunnel")
	}
}

func TestSpliceIdleKeepsSlowSteadyStream(t *testing.T) {
	client, clientPeer := net.Pipe()
	up, upPeer := net.Pipe()
	defer clientPeer.Close()
	go io.Copy(io.Discard, clientPeer)
	go func() {
		// One byte every 15ms for 300ms: always within the 80ms idle window,
		// though the whole stream takes far longer than it.
		for range 20 {
			upPeer.Write([]byte("x"))
			time.Sleep(15 * time.Millisecond)
		}
		upPeer.Close()
	}()

	sent, recv, err := splice(client, client, up, 80*time.Millisecond)
	if err != nil {
		t.Errorf("err = %v, want nil", err)
	}
	if recv != 20 || sent != 0 {
		t.Errorf("sent/recv = %d/%d, want 0/20", sent, recv)
	}
}

func TestIdleWatchDisabled(t *testing.T) {
	fired := false
	w := watchIdle(0, func() { fired = true })
	time.Sleep(20 * time.Millisecond)
	w.stop()
	w.stop() // idempotent
	if fired || w.expired() {
		t.Error("a zero idle timeout fired")
	}
}

func TestConnectIdleTimeoutReleasesSession(t *testing.T) {
	logs := captureLog(t)
	r := newRig(t, "se-sto-wg-001")
	r.cfg.IdleTimeout = Duration{100 * time.Millisecond}
	proxy := r.listen(t, Listener{Name: "main"})
	target := silentServer(t, "")

	c, err := net.Dial("tcp", proxy)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	io.WriteString(c, "CONNECT "+target+" HTTP/1.1\r\nHost: "+target+"\r\n"+
		"Proxy-Authorization: Basic "+b64("se_idle:x")+"\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("CONNECT: %v %v", resp, err)
	}
	if got := r.picker.SessionList("idle"); len(got) != 1 || got[0].Open != 1 {
		t.Fatalf("session while open: %+v", got)
	}

	// The tunnel is idle: mullpod closes it, logs why, and lets the session go.
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("read on an idle tunnel returned data")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("mullpod did not close the idle tunnel")
	}
	await(t, "conn log line", func() bool { return len(connLines(t, logs)) == 1 })
	line := connLines(t, logs)[0]
	if line["err"] != "idle timeout" {
		t.Errorf("err = %v, want idle timeout", line["err"])
	}
	if _, ok := line["dial_ms"]; !ok {
		t.Errorf("conn line has no dial_ms: %v", line)
	}
	if got := r.picker.SessionList("idle"); len(got) != 1 || got[0].Open != 0 {
		t.Errorf("session after idle close: %+v", got)
	}
}

func TestForwardIdleTimeout(t *testing.T) {
	logs := captureLog(t)
	r := newRig(t, "se-sto-wg-001")
	r.cfg.IdleTimeout = Duration{100 * time.Millisecond}
	proxy := r.listen(t, Listener{Name: "main"})
	// Headers and part of the body, then nothing.
	target := silentServer(t, "HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\npartial")

	c, err := net.Dial("tcp", proxy)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	io.WriteString(c, "GET http://"+target+"/ HTTP/1.1\r\nHost: "+target+"\r\n"+
		"Proxy-Authorization: Basic "+b64("se:x")+"\r\n\r\n")
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	got, err := io.ReadAll(c)
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("mullpod did not close a stalled response")
	}
	if !strings.Contains(string(got), "partial") {
		t.Errorf("client got %q", got)
	}
	await(t, "conn log line", func() bool { return len(connLines(t, logs)) == 1 })
	if line := connLines(t, logs)[0]; line["err"] != "idle timeout" {
		t.Errorf("err = %v, want idle timeout", line["err"])
	}
}

func TestDialMsLoggedOnSuccessAndFailure(t *testing.T) {
	logs := captureLog(t)
	r := newRig(t, "se-sto-wg-001")
	proxy := r.listen(t, Listener{Name: "main"})
	origin := echoServer(t)

	for _, user := range []string{"se:x", "nowhere:x"} {
		c, err := net.Dial("tcp", proxy)
		if err != nil {
			t.Fatal(err)
		}
		io.WriteString(c, "CONNECT "+origin+" HTTP/1.1\r\nHost: "+origin+"\r\n"+
			"Proxy-Authorization: Basic "+b64(user)+"\r\n\r\n")
		http.ReadResponse(bufio.NewReader(c), nil)
		c.Close()
	}
	await(t, "two conn lines", func() bool { return len(connLines(t, logs)) == 2 })
	for _, line := range connLines(t, logs) {
		if _, ok := line["dial_ms"].(float64); !ok {
			t.Errorf("no numeric dial_ms: %v", line)
		}
	}
}

func TestShippedIdleTimeoutDefault(t *testing.T) {
	cfg, err := LoadConfig("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.IdleTimeout.Duration != 10*time.Minute {
		t.Errorf("default idle_timeout = %v", cfg.IdleTimeout)
	}
	p := writeMainConfig(t, "idle_timeout: 0s\n")
	if cfg, err = LoadConfig(p); err != nil || cfg.IdleTimeout.Duration != 0 {
		t.Errorf("idle_timeout: 0s → %v, %v", cfg.IdleTimeout, err)
	}
}

// ---- crash safety ----

func TestHandleRecoversPanic(t *testing.T) {
	logs := captureLog(t)
	// A nil dialer panics on the first dial.
	s := &Server{cfg: defaultConfig(), ln: Listener{Name: "main"}, m: &Metrics{}}
	c, peer := net.Pipe()
	defer peer.Close()
	done := make(chan struct{})
	go func() { s.handle(c); close(done) }()
	go io.Copy(io.Discard, peer)
	io.WriteString(peer, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("handle did not return")
	}
	if !strings.Contains(logs.String(), "panic in connection handler") || !strings.Contains(logs.String(), "goroutine") {
		t.Errorf("panic not logged with a stack: %s", logs.String())
	}
	if n := s.m.active.Load(); n != 0 {
		t.Errorf("active = %d after panic", n)
	}
}

// ---- logging and signals ----

type brokenWriter struct{}

func (brokenWriter) Write([]byte) (int, error) { return 0, syscall.EPIPE }

func TestOpenLogKeepsFileWhenStdoutBreaks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "mullpod.log")
	var crash *os.File
	old := setCrashOutput
	setCrashOutput = func(f *os.File) error { crash = f; return nil }
	t.Cleanup(func() { setCrashOutput = old })

	w, closeLog, err := openLog(path, brokenWriter{})
	if err != nil {
		t.Fatal(err)
	}
	if crash == nil || crash.Name() != path {
		t.Errorf("crash output not sent to the log file: %v", crash)
	}
	if n, err := io.WriteString(w, "line 1\n"); err != nil || n != 7 {
		t.Errorf("write with broken stdout: %d, %v", n, err)
	}
	closeLog()
	if crash != nil {
		t.Error("crash output not reset on close")
	}
	w2, closeLog2, err := openLog(path, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(w2, "line 2\n")
	closeLog2()
	b, _ := os.ReadFile(path)
	if string(b) != "line 1\nline 2\n" {
		t.Errorf("log file = %q, want both lines appended", b)
	}

	if w, _, err := openLog("", io.Discard); err != nil || w != io.Discard {
		t.Errorf("no -log: %v, %v", w, err)
	}
	blocker := filepath.Join(t.TempDir(), "file")
	os.WriteFile(blocker, nil, 0o600)
	if _, _, err := openLog(filepath.Join(blocker, "x.log"), io.Discard); err == nil {
		t.Error("expected an error when the log directory can't be made")
	}
	if _, _, err := openLog(t.TempDir(), io.Discard); err == nil {
		t.Error("expected an error opening a directory as the log")
	}
	setCrashOutput = func(*os.File) error { return errors.New("no") }
	if _, _, err := openLog(filepath.Join(t.TempDir(), "x.log"), io.Discard); err == nil {
		t.Error("expected the crash-output error")
	}
}

func TestCLIWritesLogFile(t *testing.T) {
	withMainVars(t)
	old := slog.Default()
	t.Cleanup(func() { slog.SetDefault(old) })
	newSignal = cannedSignal
	newTunnel = fakeTunnelFor
	logPath := filepath.Join(t.TempDir(), "logs", "mullpod.log")

	var out, errb bytes.Buffer
	if code := cli([]string{"-env", "", "-config", writeMainConfig(t, servedConfig), "-log", logPath}, &out, &errb); code != 0 {
		t.Fatalf("exit = %d: %s", code, errb.String())
	}
	b, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"msg":"starting"`, `"pid":`, `"msg":"shutting down","reason":"signal"`, `"msg":"stopped","code":0`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("log file lacks %s:\n%s", want, b)
		}
	}
	if !strings.Contains(out.String(), `"msg":"starting"`) {
		t.Error("stdout no longer carries the log")
	}

	if code := cli([]string{"-log", t.TempDir()}, &out, &errb); code != 1 {
		t.Errorf("bad -log exit = %d", code)
	}
}

func TestNotifyContextLogsSignal(t *testing.T) {
	logs := captureLog(t)
	ctx, stop := notifyContext(syscall.SIGHUP)
	defer stop()
	if err := syscall.Kill(os.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ctx.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("SIGHUP did not cancel the context")
	}
	await(t, "signal log line", func() bool { return strings.Contains(logs.String(), `"signal":"hangup"`) })

	// stop without a signal ends the goroutine.
	_, stop2 := notifyContext(syscall.SIGHUP)
	stop2()
}
