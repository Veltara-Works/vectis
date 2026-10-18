package api

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Network probes for the mail services the api can't inspect as containers
// (it has no Docker socket, ADR-017). Each probe checks that the service's
// port answers with the right protocol greeting, which is what matters to an
// operator, and which a process-level healthcheck doesn't prove (postfix and
// doveadm status pass on empty configs). See #264.

// probeTimeout bounds one probe; probes run concurrently.
const probeTimeout = time.Second

// probeCacheTTL is how long probe results are reused, so a dashboard refresh
// loop can't hammer the mail services.
const probeCacheTTL = 15 * time.Second

// serviceProbe checks one service; nil error means healthy.
type serviceProbe struct {
	name  string
	check func(ctx context.Context) error
}

// internalSubmissionAddr is Postfix's internal-only listener that the send API
// submits on (#227). It is probed with :25 so that a missing listener, which
// the sender silently survives by falling back to :25, still shows up.
const internalSubmissionAddr = "vectis-postfix:10587"

// defaultServiceProbes probes the stack's mail services over the networks the
// api already shares with them (vectis-data, vectis-frontend).
func defaultServiceProbes() []serviceProbe {
	return []serviceProbe{
		{"postfix", allProbes(
			greetingProbe("vectis-postfix:25", "220", "QUIT\r\n"),
			labelProbe("internal submission listener", greetingProbe(internalSubmissionAddr, "220", "QUIT\r\n")),
		)},
		{"dovecot", greetingProbe("vectis-dovecot:143", "* OK", "a LOGOUT\r\n")},
		{"rspamd", milterProbe("vectis-rspamd:11332")},
		{"traefik", pingProbe("http://vectis-traefik:8080/ping")},
	}
}

func greetingProbe(addr, want, bye string) func(context.Context) error {
	return func(ctx context.Context) error { return probeGreeting(ctx, addr, want, bye) }
}

// allProbes passes only when every check passes, and returns the first failure.
func allProbes(checks ...func(context.Context) error) func(context.Context) error {
	return func(ctx context.Context) error {
		for _, check := range checks {
			if err := check(ctx); err != nil {
				return err
			}
		}
		return nil
	}
}

// labelProbe prefixes check's failure with label, so a service with several
// checks reports which one failed.
func labelProbe(label string, check func(context.Context) error) func(context.Context) error {
	return func(ctx context.Context) error {
		if err := check(ctx); err != nil {
			return fmt.Errorf("%s: %w", label, err)
		}
		return nil
	}
}

func milterProbe(addr string) func(context.Context) error {
	return func(ctx context.Context) error { return probeMilter(ctx, addr) }
}

func pingProbe(url string) func(context.Context) error {
	return func(ctx context.Context) error { return probeHTTPPing(ctx, url) }
}

// serviceProber runs the probes concurrently and caches the results.
type serviceProber struct {
	probes []serviceProbe
	ttl    time.Duration
	now    func() time.Time

	mu      sync.Mutex
	results map[string]serviceHealth
	at      time.Time
}

func newServiceProber(probes []serviceProbe) *serviceProber {
	return &serviceProber{probes: probes, ttl: probeCacheTTL, now: time.Now}
}

// Results returns each service's health, from the cache when it is fresh. A
// caller that finds the cache stale runs the probes; concurrent callers wait
// for that run rather than starting their own.
func (p *serviceProber) Results(ctx context.Context) map[string]serviceHealth {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.results != nil && p.now().Sub(p.at) < p.ttl {
		return p.results
	}
	out := make(map[string]serviceHealth, len(p.probes))
	var outMu sync.Mutex
	var wg sync.WaitGroup
	for _, pr := range p.probes {
		wg.Add(1)
		go func(pr serviceProbe) {
			defer wg.Done()
			pctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), probeTimeout)
			defer cancel()
			start := time.Now()
			err := pr.check(pctx)
			h := serviceHealth{Status: "healthy", ResponseMs: time.Since(start).Milliseconds()}
			if err != nil {
				h.Status = "unhealthy"
				h.Error = err.Error()
			}
			outMu.Lock()
			out[pr.name] = h
			outMu.Unlock()
		}(pr)
	}
	wg.Wait()
	p.results, p.at = out, p.now()
	return out
}

func dialProbe(ctx context.Context, addr string) (net.Conn, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	return conn, nil
}

// probeGreeting connects, expects the first line to start with want (an SMTP
// "220" or IMAP "* OK" greeting), then sends bye to close politely.
func probeGreeting(ctx context.Context, addr, want, bye string) error {
	conn, err := dialProbe(ctx, addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return fmt.Errorf("no greeting: %w", err)
	}
	line = strings.TrimRight(line, "\r\n")
	if !strings.HasPrefix(line, want) {
		return fmt.Errorf("unexpected greeting %q", truncate(line, 80))
	}
	_, _ = conn.Write([]byte(bye))
	return nil
}

// probeMilter performs a milter option negotiation (SMFIC_OPTNEG), which is
// how Postfix opens every connection to rspamd's proxy worker, and expects an
// OPTNEG reply. rspamd's HTTP workers listen on loopback only, so this is the
// protocol it serves to the rest of the stack.
func probeMilter(ctx context.Context, addr string) error {
	conn, err := dialProbe(ctx, addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	// length(4) | 'O' | version(4) | actions(4) | protocol(4)
	pkt := make([]byte, 17)
	binary.BigEndian.PutUint32(pkt[0:4], 13)
	pkt[4] = 'O'
	binary.BigEndian.PutUint32(pkt[5:9], 6)      // milter protocol version 6
	binary.BigEndian.PutUint32(pkt[9:13], 0x1FF) // actions we'd allow
	binary.BigEndian.PutUint32(pkt[13:17], 0)    // protocol flags
	if _, err := conn.Write(pkt); err != nil {
		return err
	}
	// Reply: length(4) | 'O' | version(4) | actions(4) | protocol(4) [| macros].
	// Read the whole frame, so a truncated or stalled negotiation fails.
	var lenBuf [4]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return fmt.Errorf("no milter reply: %w", err)
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	if n < 13 || n > 4096 {
		return fmt.Errorf("milter reply length %d, want an OPTNEG frame", n)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(conn, body); err != nil {
		return fmt.Errorf("incomplete milter reply: %w", err)
	}
	if body[0] != 'O' {
		return fmt.Errorf("unexpected milter reply %q", body[0])
	}
	// Close the session cleanly: SMFIC_QUIT.
	_, _ = conn.Write([]byte{0, 0, 0, 1, 'Q'})
	return nil
}

// probeHTTPPing expects 200 "OK" from a ping endpoint.
func probeHTTPPing(ctx context.Context, url string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64))
	if err != nil {
		return fmt.Errorf("ping response: %w", err) // truncated or stalled
	}
	if resp.StatusCode != http.StatusOK || strings.TrimSpace(string(body)) != "OK" {
		return fmt.Errorf("ping answered %d %q", resp.StatusCode, truncate(string(body), 40))
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
