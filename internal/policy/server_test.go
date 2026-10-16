package policy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"
)

// fakeBackend is a programmable Backend for decision tests.
type fakeBackend struct {
	resolveID, resolveDom string
	resolveFound          bool
	resolveErr            error

	suspended     bool
	suspendReason string
	suspendErr    error

	rateAllowed bool
	rateReason  string
	rateHourly  int64
	rateErr     error

	autoSuspendCalled  bool
	autoSuspendReason  string
	autoSuspendMailbox string
}

func (f *fakeBackend) ResolveLogin(_ context.Context, _ string) (string, string, bool, error) {
	return f.resolveID, f.resolveDom, f.resolveFound, f.resolveErr
}

func (f *fakeBackend) IsMailboxSuspended(_ context.Context, _ string) (bool, string, error) {
	return f.suspended, f.suspendReason, f.suspendErr
}

func (f *fakeBackend) CheckAndRecord(_ context.Context, _, _ string) (bool, string, int64, error) {
	return f.rateAllowed, f.rateReason, f.rateHourly, f.rateErr
}

func (f *fakeBackend) AutoSuspend(_ context.Context, mailboxID, _, reason string, _ int64) {
	f.autoSuspendCalled = true
	f.autoSuspendMailbox = mailboxID
	f.autoSuspendReason = reason
}

func testServer(b Backend, cfg Config) *Server {
	if cfg.Hostname == "" {
		cfg.Hostname = "mail.example.com"
	}
	return New(b, cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func TestEvaluate(t *testing.T) {
	tests := []struct {
		name        string
		attrs       map[string]string
		backend     *fakeBackend
		cfg         Config
		wantPrefix  string // expected action prefix
		wantSuspend bool   // expect AutoSuspend to have been called
		wantReject  string // expected OnReject label, "" for none
	}{
		{
			name:       "no sasl_username is not governed",
			attrs:      map[string]string{"protocol_state": "DATA"},
			backend:    &fakeBackend{},
			wantPrefix: "DUNNO",
		},
		{
			name:       "unknown login passes through",
			attrs:      map[string]string{"sasl_username": "ghost@example.com"},
			backend:    &fakeBackend{resolveFound: false},
			wantPrefix: "DUNNO",
		},
		{
			name:       "suspended mailbox is rejected",
			attrs:      map[string]string{"sasl_username": "alice@example.com"},
			backend:    &fakeBackend{resolveFound: true, resolveID: "mb-1", suspended: true, suspendReason: "manual"},
			wantPrefix: "554 5.7.1 Sending from this mailbox is suspended: manual",
			wantReject: "suspended",
		},
		{
			name:       "healthy mailbox under rate limit passes",
			attrs:      map[string]string{"sasl_username": "alice@example.com"},
			backend:    &fakeBackend{resolveFound: true, resolveID: "mb-1", rateAllowed: true},
			cfg:        Config{RateLimit: true},
			wantPrefix: "DUNNO",
		},
		{
			name:        "rate limit breach auto-suspends and rejects",
			attrs:       map[string]string{"sasl_username": "alice@example.com"},
			backend:     &fakeBackend{resolveFound: true, resolveID: "mb-1", resolveDom: "dom-1", rateAllowed: false, rateReason: "550 this hour", rateHourly: 551},
			cfg:         Config{RateLimit: true},
			wantPrefix:  "554 5.7.1 Sending from this mailbox is suspended: 550 this hour",
			wantSuspend: true,
			wantReject:  "rate_limit",
		},
		{
			name:       "rate limit disabled skips counter, suspend still enforced",
			attrs:      map[string]string{"sasl_username": "alice@example.com"},
			backend:    &fakeBackend{resolveFound: true, resolveID: "mb-1", rateAllowed: false, rateErr: errBoom},
			cfg:        Config{RateLimit: false},
			wantPrefix: "DUNNO", // not suspended + rate disabled => allowed, and CheckAndRecord never consulted
		},
		{
			name:       "resolve error fails open when FailOpen",
			attrs:      map[string]string{"sasl_username": "alice@example.com"},
			backend:    &fakeBackend{resolveErr: errBoom},
			cfg:        Config{FailOpen: true},
			wantPrefix: "DUNNO",
		},
		{
			name:       "resolve error tempfails when not FailOpen",
			attrs:      map[string]string{"sasl_username": "alice@example.com"},
			backend:    &fakeBackend{resolveErr: errBoom},
			cfg:        Config{FailOpen: false},
			wantPrefix: "451 4.7.0",
		},
		{
			name:       "rate check error always fails open",
			attrs:      map[string]string{"sasl_username": "alice@example.com"},
			backend:    &fakeBackend{resolveFound: true, resolveID: "mb-1", rateErr: errBoom},
			cfg:        Config{RateLimit: true, FailOpen: false}, // strict, but rate errors must not block
			wantPrefix: "DUNNO",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var rejected string
			tt.cfg.OnReject = func(reason string) { rejected = reason }
			s := testServer(tt.backend, tt.cfg)
			got := s.evaluate(context.Background(), tt.attrs, &messageState{})
			if !strings.HasPrefix(got, tt.wantPrefix) {
				t.Fatalf("action = %q, want prefix %q", got, tt.wantPrefix)
			}
			if tt.backend.autoSuspendCalled != tt.wantSuspend {
				t.Errorf("autoSuspendCalled = %v, want %v", tt.backend.autoSuspendCalled, tt.wantSuspend)
			}
			if rejected != tt.wantReject {
				t.Errorf("OnReject label = %q, want %q", rejected, tt.wantReject)
			}
		})
	}
}

func TestReadRequest(t *testing.T) {
	// Two back-to-back requests on one connection, CRLF on the first.
	raw := "request=smtpd_access_policy\r\nsasl_username=alice@example.com\r\n\r\n" +
		"sasl_username=bob@example.com\nprotocol_state=DATA\n\n"
	r := bufio.NewReader(strings.NewReader(raw))

	first, err := readRequest(r)
	if err != nil {
		t.Fatalf("first readRequest: %v", err)
	}
	if first["sasl_username"] != "alice@example.com" || first["request"] != "smtpd_access_policy" {
		t.Fatalf("first request attrs = %v", first)
	}

	second, err := readRequest(r)
	if err != nil {
		t.Fatalf("second readRequest: %v", err)
	}
	if second["sasl_username"] != "bob@example.com" || second["protocol_state"] != "DATA" {
		t.Fatalf("second request attrs = %v", second)
	}

	if _, err := readRequest(r); err != io.EOF {
		t.Fatalf("third readRequest err = %v, want io.EOF", err)
	}
}

func TestReadRequestLimits(t *testing.T) {
	// A single line longer than maxRequestLineBytes with no newline must error
	// rather than grow unbounded (G-L1).
	t.Run("line too long", func(t *testing.T) {
		raw := "k=" + strings.Repeat("v", maxRequestLineBytes+10) // never terminated
		if _, err := readRequest(bufio.NewReader(strings.NewReader(raw))); err == nil {
			t.Fatal("want error on over-long line, got nil")
		}
	})

	// More attribute lines than maxRequestAttrs, never reaching the blank
	// terminator, must error (POL-2).
	t.Run("too many attrs", func(t *testing.T) {
		var sb strings.Builder
		for i := 0; i < maxRequestAttrs+5; i++ {
			fmt.Fprintf(&sb, "k%d=v\n", i)
		}
		if _, err := readRequest(bufio.NewReader(strings.NewReader(sb.String()))); err == nil {
			t.Fatal("want error on too many attrs, got nil")
		}
	})

	// Cumulative bytes past maxRequestBytes without a terminator must error
	// even when individual lines are within the per-line cap (POL-2).
	t.Run("total bytes exceeded", func(t *testing.T) {
		line := "k=" + strings.Repeat("v", 1000) + "\n" // ~1KB per line, under line cap
		var sb strings.Builder
		for sb.Len() <= maxRequestBytes+2000 {
			sb.WriteString(line)
		}
		if _, err := readRequest(bufio.NewReader(strings.NewReader(sb.String()))); err == nil {
			t.Fatal("want error on total bytes exceeded, got nil")
		}
	})

	// A normal request just under the caps still parses.
	t.Run("normal request ok", func(t *testing.T) {
		attrs, err := readRequest(bufio.NewReader(strings.NewReader("sasl_username=alice@example.com\n\n")))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if attrs["sasl_username"] != "alice@example.com" {
			t.Fatalf("attrs = %v", attrs)
		}
	})
}

func TestNormalizeLogin(t *testing.T) {
	cases := []struct{ in, host, want string }{
		{"alice@example.com", "mail.example.com", "alice@example.com"},
		{"Alice@Example.COM", "mail.example.com", "alice@example.com"},
		{"  alice@example.com  ", "mail.example.com", "alice@example.com"},
		{"alice@example.com@mail.example.com", "mail.example.com", "alice@example.com"}, // appended realm stripped
		{"alice@example.com", "", "alice@example.com"},                                  // no hostname configured
		{"", "mail.example.com", ""},
	}
	for _, c := range cases {
		if got := normalizeLogin(c.in, c.host); got != c.want {
			t.Errorf("normalizeLogin(%q, %q) = %q, want %q", c.in, c.host, got, c.want)
		}
	}
}

func TestSanitizeText(t *testing.T) {
	if got := sanitizeText("hello\r\nworld\ninjected=DUNNO"); got != "hello world injected=DUNNO" {
		t.Errorf("sanitizeText newline flatten = %q", got)
	}
	long := strings.Repeat("a", 500)
	if got := sanitizeText(long); len(got) > 200 {
		t.Errorf("sanitizeText length = %d, want <=200", len(got))
	}
}

// TestServeWire exercises the real socket path end-to-end with actual
// on-the-wire bytes (per the real-envelope test rule): a suspended mailbox must
// produce a 554 reject, and the connection must be reusable for a second
// request.
func TestServeWire(t *testing.T) {
	fb := &fakeBackend{resolveFound: true, resolveID: "mb-1", suspended: true, suspendReason: "compromised"}
	var rejects int
	s := testServer(fb, Config{ListenAddr: "127.0.0.1:0", OnReject: func(string) { rejects++ }})
	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer s.Stop()

	s.mu.Lock()
	addr := s.ln.Addr().String()
	s.mu.Unlock()

	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	br := bufio.NewReader(conn)

	send := func() string {
		t.Helper()
		req := "request=smtpd_access_policy\nprotocol_state=DATA\nsasl_username=alice@example.com\n\n"
		if _, err := conn.Write([]byte(req)); err != nil {
			t.Fatalf("write: %v", err)
		}
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read action: %v", err)
		}
		blank, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read terminator: %v", err)
		}
		if strings.TrimRight(blank, "\r\n") != "" {
			t.Fatalf("response not terminated by blank line, got %q", blank)
		}
		return strings.TrimRight(line, "\r\n")
	}

	if got := send(); got != "action=554 5.7.1 Sending from this mailbox is suspended: compromised" {
		t.Fatalf("first response = %q", got)
	}
	// Connection reuse: second request on the same conn.
	if got := send(); !strings.HasPrefix(got, "action=554") {
		t.Fatalf("second response = %q", got)
	}
	if rejects != 2 {
		t.Errorf("OnReject called %d times, want 2", rejects)
	}
}

// TestStopClosesIdleConnections guards the shutdown path: a handler parked in
// readRequest on a persistent connection (Postfix keeps these open) must be
// unblocked by Stop closing the connection, so shutdown never hangs.
func TestStopClosesIdleConnections(t *testing.T) {
	s := testServer(&fakeBackend{resolveFound: false}, Config{ListenAddr: "127.0.0.1:0"})
	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	s.mu.Lock()
	addr := s.ln.Addr().String()
	s.mu.Unlock()

	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Send one request and read its reply; the handler then parks in readRequest
	// awaiting a next request that never arrives — the exact persistent-conn case.
	if _, err := conn.Write([]byte("sasl_username=x@example.com\n\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := bufio.NewReader(conn).ReadString('\n'); err != nil {
		t.Fatalf("read: %v", err)
	}

	done := make(chan struct{})
	go func() { s.Stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Stop() hung on a live idle connection — handler never unblocked")
	}
}

var errBoom = &boomError{}

type boomError struct{}

func (*boomError) Error() string { return "boom" }

// fakeWarmup hosts example.com locally and allows up to remaining external
// recipients in total.
type fakeWarmup struct {
	remaining int
	err       error
	reserved  []int
}

func (f *fakeWarmup) IsLocalDomain(_ context.Context, domain string) (bool, error) {
	if domain == "broken.example" {
		return false, fmt.Errorf("db down")
	}
	return domain == "example.com", nil
}

func (f *fakeWarmup) ReserveWarmup(_ context.Context, n int) (bool, string, error) {
	if f.err != nil {
		return false, "", f.err
	}
	f.reserved = append(f.reserved, n)
	if n > f.remaining {
		return false, "IP warmup daily limit reached\nfor 203.0.113.7", nil
	}
	f.remaining -= n
	return true, "", nil
}

func rcpt(instance, recipient string) map[string]string {
	return map[string]string{"protocol_state": "RCPT", "instance": instance,
		"sasl_username": "alice@example.com", "recipient": recipient}
}

func data(instance string, count int) map[string]string {
	return map[string]string{"protocol_state": "DATA", "instance": instance,
		"sasl_username": "alice@example.com", "recipient_count": fmt.Sprint(count)}
}

func TestWarmupCountsExternalRecipientsAndReservesAtData(t *testing.T) {
	fb := &fakeBackend{resolveFound: true, resolveID: "mb-1", rateAllowed: true}
	fw := &fakeWarmup{remaining: 3}
	var rejects []string
	s := testServer(fb, Config{RateLimit: true, Warmup: fw, OnReject: func(r string) { rejects = append(rejects, r) }})
	ctx := context.Background()
	var msg messageState

	// Message 1: two external recipients, one local, one bare local name.
	for _, r := range []string{"bob@gmail.com", "carol@example.com", "Dave@Outlook.COM", "postmaster"} {
		if got := s.evaluate(ctx, rcpt("1.1", r), &msg); got != "DUNNO" {
			t.Fatalf("RCPT %s = %q, want DUNNO", r, got)
		}
	}
	if got := s.evaluate(ctx, data("1.1", 4), &msg); got != "DUNNO" {
		t.Fatalf("DATA within the limit = %q, want DUNNO", got)
	}

	// Message 2: an aborted message's recipients must not carry over.
	s.evaluate(ctx, rcpt("1.2", "x@gmail.com"), &msg)
	s.evaluate(ctx, rcpt("1.3", "y@gmail.com"), &msg)
	s.evaluate(ctx, rcpt("1.3", "z@gmail.com"), &msg)
	got := s.evaluate(ctx, data("1.3", 2), &msg)
	if !strings.HasPrefix(got, "452 4.5.3 ") || strings.ContainsAny(got, "\n\r") {
		t.Fatalf("DATA over the limit = %q, want a single-line 452 4.5.3 deferral", got)
	}
	if want := []int{2, 2}; fmt.Sprint(fw.reserved) != fmt.Sprint(want) {
		t.Errorf("reserved %v, want %v", fw.reserved, want)
	}
	if fmt.Sprint(rejects) != "[warmup_limit]" {
		t.Errorf("OnReject labels = %v, want [warmup_limit]", rejects)
	}

	// Message 3: only local recipients reserve nothing.
	s.evaluate(ctx, rcpt("1.4", "carol@example.com"), &msg)
	if got := s.evaluate(ctx, data("1.4", 1), &msg); got != "DUNNO" || len(fw.reserved) != 2 {
		t.Errorf("local-only DATA = %q with %v reserved, want DUNNO and no reservation", got, fw.reserved)
	}
}

func TestWarmupEdgeCases(t *testing.T) {
	ctx := context.Background()
	newServer := func(fw *fakeWarmup, fb *fakeBackend) *Server {
		return testServer(fb, Config{RateLimit: true, Warmup: fw})
	}
	ok := func() *fakeBackend { return &fakeBackend{resolveFound: true, resolveID: "mb-1", rateAllowed: true} }

	t.Run("lookup error counts as external", func(t *testing.T) {
		fw := &fakeWarmup{remaining: 10}
		s, msg := newServer(fw, ok()), &messageState{}
		s.evaluate(ctx, rcpt("2.1", "a@broken.example"), msg)
		s.evaluate(ctx, data("2.1", 1), msg)
		if fmt.Sprint(fw.reserved) != "[1]" {
			t.Errorf("reserved %v, want [1]", fw.reserved)
		}
	})
	t.Run("reserve error fails open", func(t *testing.T) {
		s, msg := newServer(&fakeWarmup{err: fmt.Errorf("db down")}, ok()), &messageState{}
		s.evaluate(ctx, rcpt("2.2", "a@gmail.com"), msg)
		if got := s.evaluate(ctx, data("2.2", 1), msg); got != "DUNNO" {
			t.Errorf("DATA on a reserve error = %q, want DUNNO", got)
		}
	})
	t.Run("never more than Postfix accepted", func(t *testing.T) {
		fw := &fakeWarmup{remaining: 10}
		s, msg := newServer(fw, ok()), &messageState{}
		for _, r := range []string{"a@gmail.com", "b@gmail.com", "c@gmail.com"} {
			s.evaluate(ctx, rcpt("2.3", r), msg)
		}
		s.evaluate(ctx, data("2.3", 2), msg)
		if fmt.Sprint(fw.reserved) != "[2]" {
			t.Errorf("reserved %v, want [2] (recipient_count)", fw.reserved)
		}
	})
	t.Run("unauthenticated requests are not counted", func(t *testing.T) {
		fw := &fakeWarmup{remaining: 10}
		s, msg := newServer(fw, ok()), &messageState{}
		r := rcpt("2.4", "a@gmail.com")
		delete(r, "sasl_username")
		s.evaluate(ctx, r, msg)
		s.evaluate(ctx, data("2.4", 1), msg)
		if len(fw.reserved) != 0 {
			t.Errorf("reserved %v for an unauthenticated recipient, want none", fw.reserved)
		}
	})
	t.Run("a suspended mailbox is rejected before warmup counts", func(t *testing.T) {
		fw := &fakeWarmup{remaining: 10}
		fb := ok()
		fb.suspended = true
		s, msg := newServer(fw, fb), &messageState{}
		s.evaluate(ctx, rcpt("2.5", "a@gmail.com"), msg)
		if got := s.evaluate(ctx, data("2.5", 1), msg); !strings.HasPrefix(got, "554 5.7.1") || len(fw.reserved) != 0 {
			t.Errorf("suspended DATA = %q with %v reserved, want 554 and no reservation", got, fw.reserved)
		}
	})
	t.Run("RCPT never runs the suspend or rate checks", func(t *testing.T) {
		fb := ok()
		fb.suspended = true
		s, msg := newServer(&fakeWarmup{remaining: 10}, fb), &messageState{}
		if got := s.evaluate(ctx, rcpt("2.6", "a@gmail.com"), msg); got != "DUNNO" {
			t.Errorf("RCPT for a suspended mailbox = %q, want DUNNO (DATA decides)", got)
		}
	})
}

// The per-message count lives on the policy connection, as Postfix sends a
// message's RCPT and DATA requests over the same one.
func TestWarmupOverTheWire(t *testing.T) {
	fb := &fakeBackend{resolveFound: true, resolveID: "mb-1", rateAllowed: true}
	s := testServer(fb, Config{ListenAddr: "127.0.0.1:0", RateLimit: true, Warmup: &fakeWarmup{remaining: 1}})
	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer s.Stop()
	s.mu.Lock()
	addr := s.ln.Addr().String()
	s.mu.Unlock()

	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	br := bufio.NewReader(conn)
	send := func(attrs map[string]string) string {
		t.Helper()
		var b strings.Builder
		b.WriteString("request=smtpd_access_policy\n")
		for k, v := range attrs {
			b.WriteString(k + "=" + v + "\n")
		}
		b.WriteString("\n")
		if _, err := conn.Write([]byte(b.String())); err != nil {
			t.Fatalf("write: %v", err)
		}
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read action: %v", err)
		}
		if _, err := br.ReadString('\n'); err != nil {
			t.Fatalf("read terminator: %v", err)
		}
		return strings.TrimRight(line, "\r\n")
	}

	send(rcpt("3.1", "a@gmail.com"))
	if got := send(data("3.1", 1)); got != "action=DUNNO" {
		t.Fatalf("first message = %q, want DUNNO", got)
	}
	send(rcpt("3.2", "b@gmail.com"))
	if got := send(data("3.2", 1)); !strings.HasPrefix(got, "action=452 4.5.3 ") {
		t.Fatalf("second message = %q, want a 452 deferral", got)
	}
}
