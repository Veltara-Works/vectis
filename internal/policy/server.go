// Package policy implements a Postfix SMTP access policy delegation server that
// enforces per-mailbox send suspension and the outbound abuse rate-limit on the
// authenticated submission path (ports 587/465).
//
// Background: Vectis already has a complete send-suspend subsystem
// (mailboxes.send_suspended, AbuseDetector, the /abuse admin API), but it was
// only enforced on the HTTP send API. Mail submitted via authenticated SMTP
// (Thunderbird/Outlook/Roundcube webmail) bypassed it entirely, so the admin
// "suspend" action and the abuse auto-suspend were ineffective on the path real
// clients use — a compromised mailbox could keep blasting via SMTP-AUTH. This
// server closes that gap: Postfix calls it as a check_policy_service from the
// submission/smtps services, and it applies exactly the same suspend + rate
// checks the HTTP path applies. See vectis-private issue #5.
//
// The package is deliberately free of app-specific dependencies (no repos, no
// Postgres, no Valkey, no Prometheus) — it talks to a small Backend interface so
// the wire protocol and the decision logic are unit-testable with fakes.
package policy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"
)

// Backend resolves SASL logins to mailboxes and applies the suspend / rate
// checks. It is satisfied by an adapter over the API server's repositories and
// abuse detector.
type Backend interface {
	// ResolveLogin maps a SASL username (normally a full email address) to its
	// mailbox and domain IDs. found is false (with no error) when the login
	// matches no managed mailbox.
	ResolveLogin(ctx context.Context, login string) (mailboxID, domainID string, found bool, err error)

	// IsMailboxSuspended reports whether the mailbox is currently suspended from
	// sending, and the operator/auto-suspend reason.
	IsMailboxSuspended(ctx context.Context, mailboxID string) (suspended bool, reason string, err error)

	// CheckAndRecord increments the outbound rate counters for the mailbox and
	// reports whether the send is within limits. allowed is false once the
	// auto-suspend threshold is crossed; reason/hourlyCount describe the breach.
	CheckAndRecord(ctx context.Context, mailboxID, domainID string) (allowed bool, reason string, hourlyCount int64, err error)

	// AutoSuspend records the abuse event and sets send_suspended. Best-effort:
	// the implementation logs its own errors and never returns one (a failed
	// suspend must not turn into a tempfail for the triggering message).
	AutoSuspend(ctx context.Context, mailboxID, domainID, reason string, hourlyCount int64)
}

// Config tunes the policy server.
type Config struct {
	// ListenAddr is the TCP address Postfix connects to (e.g. ":10099"). Empty
	// disables the server.
	ListenAddr string
	// Hostname is the server hostname, used to strip a SASL realm that Postfix
	// may append when smtpd_sasl_local_domain is set.
	Hostname string
	// RateLimit mirrors the abuse rate-limit / auto-suspend on the submission
	// path. When false, only the explicit send-suspend flag is enforced.
	RateLimit bool
	// FailOpen controls behaviour when a backend lookup errors: true returns
	// DUNNO (continue, do not block legitimate mail); false returns a 451
	// tempfail so the client retries. Rate-check errors always fail open,
	// matching the HTTP send path.
	FailOpen bool
	// Timeout bounds each backend evaluation. Defaults to 5s.
	Timeout time.Duration
	// OnReject, when set, is called once per rejected message with the reason
	// label ("suspended" or "rate_limit"). Used for metrics; optional.
	OnReject func(reason string)
}

// Server is the policy delegation server.
type Server struct {
	cfg     Config
	backend Backend
	logger  *slog.Logger

	mu     sync.Mutex
	ln     net.Listener
	conns  map[net.Conn]struct{} // live client connections, closed on Stop
	closed bool
	wg     sync.WaitGroup
}

// New builds a policy server. It does not bind a listener until Start.
func New(backend Backend, cfg Config, logger *slog.Logger) *Server {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}
	return &Server{cfg: cfg, backend: backend, logger: logger, conns: make(map[net.Conn]struct{})}
}

// Start binds the listener and serves connections in the background. It returns
// once the listener is open (or immediately, as a no-op, when ListenAddr is
// empty). Accept/handler errors after start are logged, not returned.
func (s *Server) Start() error {
	if s.cfg.ListenAddr == "" {
		s.logger.Info("submission policy server disabled (no listen address)")
		return nil
	}
	ln, err := net.Listen("tcp", s.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("policy listen %s: %w", s.cfg.ListenAddr, err)
	}
	s.mu.Lock()
	s.ln = ln
	s.mu.Unlock()
	s.logger.Info("submission policy server listening",
		"addr", s.cfg.ListenAddr, "rate_limit", s.cfg.RateLimit, "fail_open", s.cfg.FailOpen)
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.serve(ln)
	}()
	return nil
}

// Stop closes the listener AND any live client connections, then waits for the
// handler goroutines to drain. Postfix keeps policy connections open and
// persistent, so a handler blocked in conn.Read would never return on its own —
// closing the connections unblocks those reads so shutdown can't hang.
func (s *Server) Stop() {
	s.mu.Lock()
	s.closed = true
	ln := s.ln
	conns := make([]net.Conn, 0, len(s.conns))
	for c := range s.conns {
		conns = append(conns, c)
	}
	s.mu.Unlock()

	if ln != nil {
		_ = ln.Close()
	}
	for _, c := range conns {
		_ = c.Close()
	}
	s.wg.Wait()
}

func (s *Server) serve(ln net.Listener) {
	// POL-3: cap concurrent handler goroutines. Postfix opens very few policy
	// connections, so reaching this ceiling means something abnormal (or hostile
	// on the internal net) — refuse rather than fork goroutines unboundedly.
	sem := make(chan struct{}, maxConcurrentConns)
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			s.logger.Error("policy accept failed", "error", err)
			continue
		}
		if !s.trackConn(conn) {
			// Stop() raced ahead of this Accept — refuse the connection.
			_ = conn.Close()
			continue
		}
		select {
		case sem <- struct{}{}:
		default:
			s.logger.Warn("policy: refusing connection, at concurrency cap", "cap", maxConcurrentConns)
			s.untrackConn(conn)
			_ = conn.Close()
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() { <-sem }()
			defer s.untrackConn(conn)
			s.handleConn(conn)
		}()
	}
}

// trackConn registers a live connection so Stop can close it. It returns false
// if the server is already shutting down, in which case the caller must close
// the connection itself.
func (s *Server) trackConn(c net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	s.conns[c] = struct{}{}
	return true
}

func (s *Server) untrackConn(c net.Conn) {
	s.mu.Lock()
	delete(s.conns, c)
	s.mu.Unlock()
}

// Request/connection bounds. A Postfix policy request is a handful of short
// key=value lines terminated by a blank line, so these ceilings are far above
// anything legitimate while stopping a misbehaving or hostile client (internal
// net, but defence in depth) from consuming memory or handler goroutines.
const (
	maxRequestLineBytes = 4096      // one attribute line (G-L1: cap a single unterminated line)
	maxRequestAttrs     = 64        // Postfix sends ~20; generous ceiling (POL-2)
	maxRequestBytes     = 64 * 1024 // whole request, blank-line terminated (POL-2)
	// idleReadTimeout reaps a connection that goes silent mid-request, or sits
	// idle far longer than Postfix's own connection cache would (default 300s),
	// so a stuck/slow reader can't park a handler goroutine forever (G-L1). A
	// healthy cached connection is reused well within this and resets it each
	// request; a reaped idle connection is transparently re-established.
	idleReadTimeout = 10 * time.Minute
	// writeTimeout bounds our response write (POL-1): a peer that stops reading
	// must not park the handler on a full TCP send buffer indefinitely.
	writeTimeout = 30 * time.Second
	// maxConcurrentConns caps live handler goroutines (POL-3).
	maxConcurrentConns = 256
)

// handleConn services a single Postfix connection. Postfix keeps the connection
// open and reuses it for many requests, so we loop until EOF/error.
func (s *Server) handleConn(conn net.Conn) {
	defer conn.Close()
	r := bufio.NewReader(conn)
	for {
		// Bound each request read (G-L1): the whole request — first line to the
		// blank terminator — must arrive within idleReadTimeout, else reap the
		// connection. Reset per request so a cached connection's idle gap
		// between requests doesn't accumulate against a single deadline.
		_ = conn.SetReadDeadline(time.Now().Add(idleReadTimeout))
		attrs, err := readRequest(r)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				s.logger.Debug("policy connection closed", "error", err)
			}
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), s.cfg.Timeout)
		action := s.evaluate(ctx, attrs)
		cancel()
		// Bound the response write (POL-1).
		_ = conn.SetWriteDeadline(time.Now().Add(writeTimeout))
		if _, err := conn.Write([]byte("action=" + action + "\n\n")); err != nil {
			s.logger.Debug("policy write failed", "error", err)
			return
		}
	}
}

const actionOK = "DUNNO"

// evaluate runs the suspend + rate checks for one policy request and returns the
// Postfix action string. It is the unit-tested core of the server.
func (s *Server) evaluate(ctx context.Context, attrs map[string]string) string {
	login := normalizeLogin(attrs["sasl_username"], s.cfg.Hostname)
	if login == "" {
		// No authenticated user. This server is only attached to the
		// submission/smtps services, but never interfere with anything that
		// isn't an authenticated send (defence in depth for inbound on :25).
		return actionOK
	}

	mailboxID, domainID, found, err := s.backend.ResolveLogin(ctx, login)
	if err != nil {
		s.logger.Error("policy: resolve login failed", "login", login, "error", err)
		return s.failAction()
	}
	if !found {
		// Authenticated as something with no matching mailbox (alias-only login,
		// Dovecot master user, or a race with deletion). Don't block.
		s.logger.Debug("policy: login resolved to no mailbox", "login", login)
		return actionOK
	}

	suspended, reason, err := s.backend.IsMailboxSuspended(ctx, mailboxID)
	if err != nil {
		s.logger.Error("policy: suspension check failed", "mailbox_id", mailboxID, "error", err)
		return s.failAction()
	}
	if suspended {
		s.logger.Warn("policy: rejecting send from suspended mailbox", "mailbox_id", mailboxID, "login", login)
		s.onReject("suspended")
		return rejectAction("Sending from this mailbox is suspended" + reasonSuffix(reason))
	}

	if s.cfg.RateLimit {
		allowed, rlReason, hourly, err := s.backend.CheckAndRecord(ctx, mailboxID, domainID)
		if err != nil {
			// Mirror the HTTP send path: never block legitimate mail on a
			// rate-counter (Valkey) error.
			s.logger.Error("policy: rate check failed, failing open", "mailbox_id", mailboxID, "error", err)
			return actionOK
		}
		if !allowed {
			s.logger.Warn("policy: auto-suspending mailbox over rate limit",
				"mailbox_id", mailboxID, "login", login, "hourly_count", hourly)
			s.backend.AutoSuspend(ctx, mailboxID, domainID, rlReason, hourly)
			s.onReject("rate_limit")
			return rejectAction("Sending from this mailbox is suspended: " + rlReason)
		}
	}

	return actionOK
}

func (s *Server) onReject(reason string) {
	if s.cfg.OnReject != nil {
		s.cfg.OnReject(reason)
	}
}

// failAction is the response when a backend lookup errors.
func (s *Server) failAction() string {
	if s.cfg.FailOpen {
		return actionOK
	}
	return "451 4.7.0 Mailbox sending policy temporarily unavailable, try again later"
}

// rejectAction wraps a sanitized message in a permanent 5.7.1 reject.
func rejectAction(msg string) string {
	return "554 5.7.1 " + sanitizeText(msg)
}

func reasonSuffix(reason string) string {
	reason = sanitizeText(reason)
	if reason == "" {
		return ""
	}
	return ": " + reason
}

// readRequest reads one Postfix policy request: a series of "key=value" lines
// terminated by a blank line. It returns io.EOF when the connection closes
// between requests.
func readRequest(r *bufio.Reader) (map[string]string, error) {
	attrs := make(map[string]string, 16)
	total := 0
	for {
		line, err := readLimitedLine(r, maxRequestLineBytes)
		if err != nil {
			return nil, err
		}
		total += len(line)
		if total > maxRequestBytes {
			return nil, fmt.Errorf("policy request exceeds %d bytes without terminator", maxRequestBytes)
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			return attrs, nil
		}
		if len(attrs) >= maxRequestAttrs {
			return nil, fmt.Errorf("policy request exceeds %d attributes", maxRequestAttrs)
		}
		if k, v, ok := strings.Cut(line, "="); ok {
			attrs[strings.TrimSpace(k)] = v
		}
	}
}

// readLimitedLine reads a single '\n'-terminated line but fails once it exceeds
// max bytes without a newline, so one unterminated line can't grow memory
// unbounded — the bufio.ReadString it replaces read to EOF with no cap (G-L1).
// On a clean connection close between requests it returns io.EOF, which the
// caller treats as a normal shutdown.
func readLimitedLine(r *bufio.Reader, max int) (string, error) {
	var sb strings.Builder
	for {
		b, err := r.ReadByte()
		if err != nil {
			return sb.String(), err
		}
		if b == '\n' {
			sb.WriteByte(b)
			return sb.String(), nil
		}
		if sb.Len() >= max {
			return "", fmt.Errorf("policy request line exceeds %d bytes", max)
		}
		sb.WriteByte(b)
	}
}

// normalizeLogin lower-cases the SASL username and strips a trailing "@hostname"
// realm that Postfix appends when smtpd_sasl_local_domain is set, so a full
// email login arriving as "user@example.com@mail.host" still resolves.
func normalizeLogin(login, hostname string) string {
	login = strings.ToLower(strings.TrimSpace(login))
	if login == "" {
		return ""
	}
	if h := strings.ToLower(strings.TrimSpace(hostname)); h != "" {
		realm := "@" + h
		if strings.HasSuffix(login, realm) && strings.Count(login, "@") > 1 {
			login = strings.TrimSuffix(login, realm)
		}
	}
	return login
}

// sanitizeText flattens control characters (so a DB-sourced reason can't break
// the single-line policy protocol) and caps the length.
func sanitizeText(s string) string {
	s = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r < 0x20 {
			return ' '
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 200 {
		s = strings.TrimSpace(s[:200])
	}
	return s
}
