// Package policy implements a Postfix SMTP access policy delegation server that
// enforces per-mailbox send suspension, the outbound abuse rate-limit and the
// IP warmup daily limit on the authenticated submission path (ports 587/465).
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
	"strconv"
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

// Warmup applies the IP warmup daily limit. Only recipients outside this
// server count: local deliveries never touch the sending IP's reputation.
type Warmup interface {
	// Active reports whether a warmup is running (cheaply, from a cache).
	// When none is, recipients aren't classified at RCPT; DATA still asks
	// ReserveWarmup, which counts every accepted recipient for a message with
	// nothing recorded, so a warmup started mid-transaction is still applied.
	Active(ctx context.Context) bool
	// IsLocalDomain reports whether mail to domain is delivered on this server.
	IsLocalDomain(ctx context.Context, domain string) (bool, error)
	// ReserveWarmup counts n external recipients against today's limit, all
	// or none. allowed false means defer the message; message says why. When
	// allowed, release gives the reservation back (the message was then
	// refused for another reason); it is never nil.
	ReserveWarmup(ctx context.Context, n int) (allowed bool, message string, release func(), err error)
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
	// OnReject, when set, is called once per rejected or deferred message with
	// the reason label ("suspended", "rate_limit" or "warmup_limit"). Used for
	// metrics; optional.
	OnReject func(reason string)
	// Warmup, when set, enforces the IP warmup daily limit: external
	// recipients are counted at RCPT and reserved at DATA, and a message over
	// the limit gets a 452 deferral. This needs the policy attached at the RCPT
	// stage as well as DATA (see master.cf). Nil disables it.
	Warmup Warmup
}

// pendingMessage is what the server remembers between a message's RCPT
// requests and its DATA request: how many recipients are outside this server.
// It is shared across connections, not kept per connection, because Postfix
// reconnects when a policy connection is closed (idle timeout, max TTL), and
// that can fall between a message's RCPT and DATA.
type pendingMessage struct {
	external int // recipients outside this server
	rcpts    int // RCPT requests seen, to tell a complete history from part of one
	seen     time.Time
}

// Bounds on the pending-message table. An entry normally lives for one SMTP
// transaction; one that is never completed expires after pendingTTL. Over
// maxPending entries, new messages aren't tracked and are counted
// conservatively at DATA (all accepted recipients as external).
const (
	pendingTTL = time.Hour
	maxPending = 10000
)

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

	pendingMu  sync.Mutex
	pending    map[string]*pendingMessage // keyed by pendingKey
	maxPending int
	now        func() time.Time
}

// New builds a policy server. It does not bind a listener until Start.
func New(backend Backend, cfg Config, logger *slog.Logger) *Server {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}
	return &Server{cfg: cfg, backend: backend, logger: logger, conns: make(map[net.Conn]struct{}),
		pending: make(map[string]*pendingMessage), maxPending: maxPending, now: time.Now}
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

// evaluate handles one policy request and returns the Postfix action string.
// At RCPT it only counts external recipients for the warmup limit; at DATA it
// runs the suspend, rate and warmup checks. It is the unit-tested core of the
// server.
func (s *Server) evaluate(ctx context.Context, attrs map[string]string) string {
	login := normalizeLogin(attrs["sasl_username"], s.cfg.Hostname)
	if login == "" {
		// No authenticated user. This server is only attached to the
		// submission/smtps services, but never interfere with anything that
		// isn't an authenticated send (defence in depth for inbound on :25).
		return actionOK
	}
	key := pendingKey(attrs, login)
	if attrs["protocol_state"] == "RCPT" {
		s.countRecipient(ctx, key, attrs["recipient"])
		return actionOK
	}

	mailboxID, domainID, found, err := s.backend.ResolveLogin(ctx, login)
	if err != nil {
		s.logger.Error("policy: resolve login failed", "login", login, "error", err)
		return s.failAction()
	}
	if !found {
		// Authenticated as something with no matching mailbox (alias-only login,
		// Dovecot master user, or a race with deletion). There's no mailbox to
		// suspend or rate-limit, but the warmup limit is server-wide and still
		// applies.
		s.logger.Debug("policy: login resolved to no mailbox", "login", login)
		action, _ := s.reserveWarmup(ctx, attrs, key)
		return action
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

	// The warmup limit comes before the rate check, so a message deferred for
	// warmup isn't charged to the mailbox's hourly rate: a client retrying
	// after each 452 could otherwise get the mailbox auto-suspended.
	action, release := s.reserveWarmup(ctx, attrs, key)
	if action != actionOK {
		return action
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
			release() // not sent: give the warmup reservation back
			s.logger.Warn("policy: auto-suspending mailbox over rate limit",
				"mailbox_id", mailboxID, "login", login, "hourly_count", hourly)
			s.backend.AutoSuspend(ctx, mailboxID, domainID, rlReason, hourly)
			s.onReject("rate_limit")
			return rejectAction("Sending from this mailbox is suspended: " + rlReason)
		}
	}

	return actionOK
}

// pendingKey identifies a message across policy requests: Postfix's
// per-message "instance" attribute, qualified by client and login. Empty when
// Postfix sent no instance.
func pendingKey(attrs map[string]string, login string) string {
	if attrs["instance"] == "" {
		return ""
	}
	return attrs["instance"] + "|" + attrs["client_address"] + "|" + login
}

// countRecipient adds an RCPT-stage recipient to the message's external count
// when its domain isn't hosted here. A lookup error counts it as external, so
// warmup errs towards limiting.
// Every RCPT records the message, even with a local recipient, so DATA can
// tell "no external recipients" from "nothing recorded".
func (s *Server) countRecipient(ctx context.Context, key, recipient string) {
	if s.cfg.Warmup == nil || key == "" || !s.cfg.Warmup.Active(ctx) {
		return
	}
	external := false
	addr := strings.ToLower(strings.TrimSpace(recipient))
	if i := strings.LastIndex(addr, "@"); i >= 0 && i < len(addr)-1 {
		domain := addr[i+1:]
		local, err := s.cfg.Warmup.IsLocalDomain(ctx, domain)
		if err != nil {
			s.logger.Warn("policy: recipient domain lookup failed, counting as external", "domain", domain, "error", err)
		}
		external = err != nil || !local
	} // else a bare local name (e.g. "postmaster"), delivered here

	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()
	p := s.pending[key]
	if p == nil {
		if len(s.pending) >= s.maxPending {
			s.prunePendingLocked()
		}
		if len(s.pending) >= s.maxPending {
			return // full: DATA will count this message conservatively
		}
		p = &pendingMessage{}
		s.pending[key] = p
	}
	p.seen = s.now()
	p.rcpts++
	if external {
		p.external++
	}
}

// prunePendingLocked drops entries older than pendingTTL. s.pendingMu must be
// held.
func (s *Server) prunePendingLocked() {
	cutoff := s.now().Add(-pendingTTL)
	for k, p := range s.pending {
		if p.seen.Before(cutoff) {
			delete(s.pending, k)
		}
	}
}

// reserveWarmup reserves the message's external recipients at DATA. Over the
// limit, the message is deferred with 452 4.5.3, so it is retried rather than
// bounced, and its count is kept: Postfix keeps the envelope after a DATA
// deferral, so the client can send DATA again for the same message, and that
// must be checked again. With nothing recorded for the message, or only part
// of its recipients (the policy server restarted mid-transaction, the table
// was full for some RCPTs, or the RCPT hook isn't configured), every
// recipient Postfix accepted counts as external. Errors fail open, like the
// rate check.
func (s *Server) reserveWarmup(ctx context.Context, attrs map[string]string, key string) (string, func()) {
	noop := func() {}
	if s.cfg.Warmup == nil {
		return actionOK, noop
	}
	accepted, _ := strconv.Atoi(attrs["recipient_count"])

	s.pendingMu.Lock()
	p, found := s.pending[key]
	n := accepted
	complete := found && p.rcpts >= accepted
	if complete {
		n = p.external
		// Never count more recipients than Postfix accepted for the message.
		if accepted > 0 && accepted < n {
			n = accepted
		}
	}
	s.pendingMu.Unlock()
	if !complete && key != "" {
		s.logger.Debug("policy: recipients not fully recorded for message, counting all as external",
			"instance", attrs["instance"], "recipients", n)
	}

	done := func() {
		if found {
			s.pendingMu.Lock()
			delete(s.pending, key)
			s.pendingMu.Unlock()
		}
	}
	if n <= 0 {
		done()
		return actionOK, noop
	}
	allowed, why, release, err := s.cfg.Warmup.ReserveWarmup(ctx, n)
	if err != nil {
		done()
		s.logger.Error("policy: warmup reserve failed, failing open", "error", err)
		return actionOK, noop
	}
	if !allowed {
		s.logger.Warn("policy: deferring message over the IP warmup daily limit", "external_recipients", n)
		s.onReject("warmup_limit")
		return "452 4.5.3 " + sanitizeText(why), noop
	}
	done()
	if release == nil {
		release = noop
	}
	return actionOK, release
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
