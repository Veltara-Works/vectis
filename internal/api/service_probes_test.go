package api

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fakeServer accepts connections on a loopback port and hands each to serve.
func fakeServer(t *testing.T, serve func(net.Conn)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); serve(c) }()
		}
	}()
	return ln.Addr().String()
}

func probeCtx(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	t.Cleanup(cancel)
	return ctx
}

func TestProbeGreeting(t *testing.T) {
	ok := fakeServer(t, func(c net.Conn) { io.WriteString(c, "220 mail.example ESMTP\r\n"); io.ReadAll(c) })
	if err := probeGreeting(probeCtx(t), ok, "220", "QUIT\r\n"); err != nil {
		t.Errorf("good banner: %v", err)
	}
	wrong := fakeServer(t, func(c net.Conn) { io.WriteString(c, "554 go away\r\n") })
	if err := probeGreeting(probeCtx(t), wrong, "220", "QUIT\r\n"); err == nil || !strings.Contains(err.Error(), "unexpected greeting") {
		t.Errorf("wrong banner = %v, want an unexpected-greeting error", err)
	}
	silent := fakeServer(t, func(c net.Conn) { time.Sleep(2 * time.Second) })
	start := time.Now()
	if err := probeGreeting(probeCtx(t), silent, "220", "QUIT\r\n"); err == nil {
		t.Error("silent server = nil error, want a timeout")
	}
	if took := time.Since(start); took > time.Second {
		t.Errorf("silent server took %v, want the probe deadline", took)
	}
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	closed := ln.Addr().String()
	ln.Close()
	if err := probeGreeting(probeCtx(t), closed, "220", "QUIT\r\n"); err == nil {
		t.Error("refused connection = nil error")
	}
}

func TestProbeMilter(t *testing.T) {
	ok := fakeServer(t, func(c net.Conn) {
		buf := make([]byte, 17)
		if _, err := io.ReadFull(c, buf); err != nil || buf[4] != 'O' {
			return
		}
		c.Write([]byte{0, 0, 0, 13, 'O', 0, 0, 0, 6, 0, 0, 1, 0xff, 0, 0, 0, 0})
		io.ReadAll(c)
	})
	if err := probeMilter(probeCtx(t), ok); err != nil {
		t.Errorf("milter OPTNEG: %v", err)
	}
	bad := fakeServer(t, func(c net.Conn) {
		io.ReadFull(c, make([]byte, 17))
		c.Write([]byte{0, 0, 0, 1, 't'}) // tempfail, not OPTNEG
	})
	if err := probeMilter(probeCtx(t), bad); err == nil {
		t.Error("non-OPTNEG reply = nil error")
	}
	// Copilot #289: a reply cut short after the header must not pass.
	truncated := fakeServer(t, func(c net.Conn) {
		io.ReadFull(c, make([]byte, 17))
		c.Write([]byte{0, 0, 0, 13, 'O'}) // header only, then close
	})
	if err := probeMilter(probeCtx(t), truncated); err == nil {
		t.Error("truncated OPTNEG = nil error")
	}
	stalled := fakeServer(t, func(c net.Conn) {
		io.ReadFull(c, make([]byte, 17))
		c.Write([]byte{0, 0, 0, 13, 'O', 0, 0}) // part of the body, then silence
		time.Sleep(2 * time.Second)
	})
	if err := probeMilter(probeCtx(t), stalled); err == nil {
		t.Error("stalled OPTNEG = nil error")
	}
	tooShort := fakeServer(t, func(c net.Conn) {
		io.ReadFull(c, make([]byte, 17))
		c.Write([]byte{0, 0, 0, 1, 'O'}) // claims a 1-byte frame
	})
	if err := probeMilter(probeCtx(t), tooShort); err == nil {
		t.Error("1-byte OPTNEG frame = nil error")
	}
}

func TestProbeHTTPPing(t *testing.T) {
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "OK") }))
	defer ok.Close()
	if err := probeHTTPPing(probeCtx(t), ok.URL); err != nil {
		t.Errorf("ping OK: %v", err)
	}
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) }))
	defer bad.Close()
	if err := probeHTTPPing(probeCtx(t), bad.URL); err == nil {
		t.Error("ping 503 = nil error")
	}
	// Copilot #289: a body cut short (declared longer than sent) or stalled
	// must not pass.
	truncated := fakeServer(t, func(c net.Conn) {
		io.ReadAll(io.LimitReader(c, 1)) // wait for the request to start
		io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nOK")
	})
	if err := probeHTTPPing(probeCtx(t), "http://"+truncated); err == nil {
		t.Error("truncated ping body = nil error")
	}
	stalled := fakeServer(t, func(c net.Conn) {
		io.ReadAll(io.LimitReader(c, 1))
		io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nOK")
		time.Sleep(2 * time.Second)
	})
	if err := probeHTTPPing(probeCtx(t), "http://"+stalled); err == nil {
		t.Error("stalled ping body = nil error")
	}
}

func TestServiceProberResultsAndCache(t *testing.T) {
	var calls atomic.Int32
	p := newServiceProber([]serviceProbe{
		{"up", func(context.Context) error { calls.Add(1); return nil }},
		{"down", func(context.Context) error { calls.Add(1); return io.ErrUnexpectedEOF }},
	})
	now := time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC)
	p.now = func() time.Time { return now }

	r := p.Results(context.Background())
	if r["up"].Status != "healthy" || r["down"].Status != "unhealthy" || r["down"].Error == "" {
		t.Fatalf("results = %+v, want up healthy, down unhealthy with its error", r)
	}
	p.Results(context.Background())
	if calls.Load() != 2 {
		t.Errorf("probes ran %d times within the cache window, want 2 (once each)", calls.Load())
	}
	now = now.Add(probeCacheTTL + time.Second)
	p.Results(context.Background())
	if calls.Load() != 4 {
		t.Errorf("probes ran %d times after the cache expired, want 4", calls.Load())
	}
}

// The default probe set covers exactly the four services the dashboard used
// to show as "unchecked".
func TestDefaultServiceProbes(t *testing.T) {
	var names []string
	for _, p := range defaultServiceProbes() {
		names = append(names, p.name)
	}
	if got := strings.Join(names, ","); got != "postfix,dovecot,rspamd,traefik" {
		t.Errorf("probes = %s", got)
	}
}

// TestServiceProbesLive runs the real probes against the stack's services. It
// only runs inside a Vectis api container (VECTIS_LIVE_PROBES=1); use it to
// check the probes against a live box before a release.
func TestServiceProbesLive(t *testing.T) {
	if os.Getenv("VECTIS_LIVE_PROBES") != "1" {
		t.Skip("set VECTIS_LIVE_PROBES=1 inside an api container")
	}
	for name, h := range newServiceProber(defaultServiceProbes()).Results(context.Background()) {
		t.Logf("%s: %s %dms %s", name, h.Status, h.ResponseMs, h.Error)
		if h.Status != "healthy" {
			t.Errorf("%s unhealthy: %s", name, h.Error)
		}
	}
}
