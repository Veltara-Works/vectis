// Package mailimport implements the native "import from external IMAP" feature:
// an admin-triggered background sync that pulls all mail from an external IMAP
// account into a Vectis mailbox, preserving folders, flags, and dates, and
// re-runnable for cutover deltas. See vectis-private #4.
//
// This file is the SOURCE side: a thin streaming wrapper over an external IMAP
// server. Two deliberate properties:
//
//   - It is split into a cheap per-folder "overview" pass (UID + Message-ID +
//     flags + date + size, no bodies) used for idempotent de-duplication, and a
//     per-message body fetch — so a multi-GB mailbox is never held in memory.
//   - Its PUBLIC types use plain Go types only (string flags, uint32 UIDs); the
//     go-imap library is never exposed past this file. The rest of the feature
//     imports `mailimport`, never go-imap, so swapping the IMAP library (e.g.
//     v1 → a future stable v2) is contained to this wrapper.
package mailimport

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/emersion/go-imap"
	"github.com/emersion/go-imap/client"
)

const (
	// dialTimeout bounds the TCP connect to a source server. Without it, a
	// black-holed host hangs the dial indefinitely and wedges an import slot.
	dialTimeout = 30 * time.Second
	// commandTimeout is the per-IMAP-command deadline. Generous enough for a
	// large folder's metadata fetch, but bounds a server that stalls mid-stream
	// so a hung source is eventually abandoned rather than wedging a slot forever.
	commandTimeout = 10 * time.Minute
)

// SourceConfig describes the external account to read from.
type SourceConfig struct {
	Host string
	Port int
	TLS  bool // true = implicit TLS (993); false = plaintext + STARTTLS (143)
	User string
	Pass string
}

// effectivePort returns the dial port, defaulting from the TLS mode.
func (c SourceConfig) effectivePort() int {
	if c.Port != 0 {
		return c.Port
	}
	if c.TLS {
		return 993
	}
	return 143
}

// Addr returns host:port, defaulting the port from the TLS mode.
// net.JoinHostPort (not fmt.Sprintf) so IPv6 literal hosts are bracketed
// correctly, e.g. "[::1]:993".
func (c SourceConfig) Addr() string {
	return net.JoinHostPort(c.Host, strconv.Itoa(c.effectivePort()))
}

// validate enforces the SSRF guard's static checks: a non-empty host and a
// port restricted to the IMAP ports. The dynamic IP check happens in the dialer
// Control hook (rebinding-proof). Restricting the port prevents the import
// feature from being used to reach arbitrary internal services (Redis, HTTP,
// etc.) on a co-located network.
func (c SourceConfig) validate() error {
	if strings.TrimSpace(c.Host) == "" {
		return fmt.Errorf("source host is empty")
	}
	if p := c.effectivePort(); p != 143 && p != 993 {
		return fmt.Errorf("source port %d not allowed (only IMAP 143 or 993)", p)
	}
	return nil
}

// disallowedDialTarget reports whether an IP literal must not be dialed by the
// import feature — loopback, link-local (incl. cloud metadata 169.254.169.254),
// private (RFC 1918 + IPv6 ULA), CGNAT, unspecified, or multicast. This is the
// core SSRF defence: the source server is operator/admin-supplied and dialed
// server-side, so without it an attacker who reaches the import API could probe
// internal infrastructure.
func disallowedDialTarget(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() ||
		ip.IsPrivate() {
		return true
	}
	// 100.64.0.0/10 — CGNAT (RFC 6598), not covered by IsPrivate.
	if ip4 := ip.To4(); ip4 != nil && ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127 {
		return true
	}
	return false
}

// ssrfControl is a net.Dialer Control hook that rejects connections to
// disallowed addresses. It runs after DNS resolution with the concrete IP about
// to be connected, so it defeats DNS-rebinding (TOCTOU) attacks that a
// resolve-then-dial-by-name check would miss.
func ssrfControl(network, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("ssrf guard: parse %q: %w", address, err)
	}
	ip := net.ParseIP(host)
	if disallowedDialTarget(ip) {
		return fmt.Errorf("ssrf guard: refusing to dial disallowed address %s", address)
	}
	return nil
}

// Folder is a source mailbox (folder) and its raw IMAP attributes (e.g.
// "\Noselect", "\Sent"). Attrs are kept as plain strings to avoid leaking
// library types.
type Folder struct {
	Name  string
	Delim string
	Attrs []string
}

// IsNoSelect reports a container-only folder that holds no messages.
func (f Folder) IsNoSelect() bool {
	for _, a := range f.Attrs {
		if strings.EqualFold(a, imap.NoSelectAttr) || strings.EqualFold(a, `\NonExistent`) {
			return true
		}
	}
	return false
}

// Overview is cheap per-message metadata for de-duplication and to drive the
// body fetch. No body is loaded. Flags are raw IMAP flag strings (e.g. "\Seen").
type Overview struct {
	UID          uint32
	MessageID    string // normalized RFC 5322 Message-ID (may be empty)
	Flags        []string
	InternalDate time.Time
	Size         uint32
}

// SourceClient is a connected IMAP reader.
type SourceClient struct {
	c *client.Client
}

// Dial connects and logs in.
func Dial(cfg SourceConfig) (*SourceClient, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}

	// Guarded dialer: bounded connect timeout + an SSRF Control hook that
	// validates the concrete resolved IP at connect time (rebinding-proof).
	dialer := &net.Dialer{Timeout: dialTimeout, Control: ssrfControl}

	var (
		c   *client.Client
		err error
	)
	if cfg.TLS {
		c, err = client.DialWithDialerTLS(dialer, cfg.Addr(), &tls.Config{ServerName: cfg.Host})
		if err != nil {
			return nil, fmt.Errorf("dial tls %s: %w", cfg.Addr(), err)
		}
		c.Timeout = commandTimeout
	} else {
		c, err = client.DialWithDialer(dialer, cfg.Addr())
		if err != nil {
			return nil, fmt.Errorf("dial %s: %w", cfg.Addr(), err)
		}
		c.Timeout = commandTimeout
		// Non-TLS mode is "plaintext + STARTTLS": REQUIRE the upgrade before
		// sending credentials. If the server doesn't advertise STARTTLS we refuse
		// rather than silently transmit the password in cleartext (a downgrade an
		// attacker or a misconfigured server could force).
		ok, serr := c.SupportStartTLS()
		if serr != nil {
			c.Logout()
			return nil, fmt.Errorf("check starttls support on %s: %w", cfg.Addr(), serr)
		}
		if !ok {
			c.Logout()
			return nil, fmt.Errorf("source %s does not advertise STARTTLS; refusing to send credentials in plaintext (use implicit TLS on 993 instead)", cfg.Addr())
		}
		if err := c.StartTLS(&tls.Config{ServerName: cfg.Host}); err != nil {
			c.Logout()
			return nil, fmt.Errorf("starttls %s: %w", cfg.Addr(), err)
		}
	}

	if err := c.Login(cfg.User, cfg.Pass); err != nil {
		c.Logout()
		return nil, fmt.Errorf("login as %s: %w", cfg.User, err)
	}
	return &SourceClient{c: c}, nil
}

// Close logs out and closes the connection.
func (s *SourceClient) Close() {
	if s.c != nil {
		_ = s.c.Logout()
	}
}

// Folders lists all folders on the source.
func (s *SourceClient) Folders() ([]Folder, error) {
	ch := make(chan *imap.MailboxInfo, 32)
	done := make(chan error, 1)
	go func() { done <- s.c.List("", "*", ch) }()

	var out []Folder
	for m := range ch {
		out = append(out, Folder{Name: m.Name, Delim: m.Delimiter, Attrs: m.Attributes})
	}
	if err := <-done; err != nil {
		return nil, fmt.Errorf("list folders: %w", err)
	}
	return out, nil
}

// SelectFolder opens a folder read-only and returns its message count.
func (s *SourceClient) SelectFolder(name string) (uint32, error) {
	mbox, err := s.c.Select(name, true)
	if err != nil {
		return 0, fmt.Errorf("select %q: %w", name, err)
	}
	return mbox.Messages, nil
}

// Overviews fetches cheap metadata for every message in the currently selected
// folder. count is the value returned by SelectFolder.
func (s *SourceClient) Overviews(count uint32) ([]Overview, error) {
	if count == 0 {
		return nil, nil
	}
	seq := new(imap.SeqSet)
	seq.AddRange(1, count)
	items := []imap.FetchItem{
		imap.FetchUid, imap.FetchFlags, imap.FetchInternalDate,
		imap.FetchRFC822Size, imap.FetchEnvelope,
	}

	ch := make(chan *imap.Message, 32)
	done := make(chan error, 1)
	go func() { done <- s.c.Fetch(seq, items, ch) }()

	var out []Overview
	for m := range ch {
		ov := Overview{
			UID:          m.Uid,
			Flags:        m.Flags,
			InternalDate: m.InternalDate,
			Size:         m.Size,
		}
		if m.Envelope != nil {
			ov.MessageID = NormalizeMessageID(m.Envelope.MessageId)
		}
		out = append(out, ov)
	}
	if err := <-done; err != nil {
		return nil, fmt.Errorf("fetch overview: %w", err)
	}
	return out, nil
}

// FetchBody returns the full RFC 822 bytes for one message by UID.
func (s *SourceClient) FetchBody(uid uint32) ([]byte, error) {
	seq := new(imap.SeqSet)
	seq.AddNum(uid)
	section := &imap.BodySectionName{} // empty section = whole message
	items := []imap.FetchItem{section.FetchItem()}

	ch := make(chan *imap.Message, 1)
	done := make(chan error, 1)
	go func() { done <- s.c.UidFetch(seq, items, ch) }()

	var (
		body []byte
		ferr error
	)
	for m := range ch {
		r := m.GetBody(section)
		if r == nil {
			ferr = fmt.Errorf("empty body section")
			continue
		}
		b, err := io.ReadAll(r)
		if err != nil {
			ferr = err
			continue
		}
		body = b
	}
	if err := <-done; err != nil {
		return nil, fmt.Errorf("fetch body uid %d: %w", uid, err)
	}
	if ferr != nil {
		return nil, fmt.Errorf("fetch body uid %d: %w", uid, ferr)
	}
	if body == nil {
		return nil, fmt.Errorf("fetch body uid %d: no message returned", uid)
	}
	return body, nil
}

// NormalizeMessageID trims angle brackets and surrounding whitespace so the same
// message compares equal across servers.
func NormalizeMessageID(id string) string {
	id = strings.TrimSpace(id)
	id = strings.TrimPrefix(id, "<")
	id = strings.TrimSuffix(id, ">")
	return strings.TrimSpace(id)
}
