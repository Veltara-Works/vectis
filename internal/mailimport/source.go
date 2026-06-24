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
	"strings"
	"time"

	"github.com/emersion/go-imap"
	"github.com/emersion/go-imap/client"
)

// SourceConfig describes the external account to read from.
type SourceConfig struct {
	Host string
	Port int
	TLS  bool // true = implicit TLS (993); false = plaintext + STARTTLS (143)
	User string
	Pass string
}

// Addr returns host:port, defaulting the port from the TLS mode.
func (c SourceConfig) Addr() string {
	port := c.Port
	if port == 0 {
		if c.TLS {
			port = 993
		} else {
			port = 143
		}
	}
	return fmt.Sprintf("%s:%d", c.Host, port)
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
	var (
		c   *client.Client
		err error
	)
	if cfg.TLS {
		c, err = client.DialTLS(cfg.Addr(), &tls.Config{ServerName: cfg.Host})
		if err != nil {
			return nil, fmt.Errorf("dial tls %s: %w", cfg.Addr(), err)
		}
	} else {
		c, err = client.Dial(cfg.Addr())
		if err != nil {
			return nil, fmt.Errorf("dial %s: %w", cfg.Addr(), err)
		}
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
