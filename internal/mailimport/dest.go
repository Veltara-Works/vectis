package mailimport

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/emersion/go-imap"
	"github.com/emersion/go-imap/client"
)

// This file is the DESTINATION side: an IMAP wrapper that writes imported
// messages into a Vectis mailbox via the local Dovecot, authenticated with a
// short-lived auth token (see internal/repository/dovecot_auth_token.go) so the
// importer can act AS the target user without their real password. Like the
// source wrapper, the go-imap library is confined to this file; public types
// are plain Go types.

// DestConfig describes the local Dovecot endpoint and the target login.
type DestConfig struct {
	Host        string // e.g. "vectis-dovecot"
	Port        int    // e.g. 993
	User        string // target mailbox email (the login we act as)
	Pass        string // short-lived auth-token password
	TLSInsecure bool   // true for the internal Dovecot (own service, shared cert, private net)
}

// Addr returns host:port (defaulting 993).
func (c DestConfig) Addr() string {
	port := c.Port
	if port == 0 {
		port = 993
	}
	return fmt.Sprintf("%s:%d", c.Host, port)
}

// DestClient is a connected IMAP writer for one target mailbox.
type DestClient struct {
	c *client.Client
}

// DialDest connects to Dovecot over implicit TLS and logs in as the target.
func DialDest(cfg DestConfig) (*DestClient, error) {
	tlsCfg := &tls.Config{ServerName: cfg.Host, InsecureSkipVerify: cfg.TLSInsecure} //nolint:gosec // internal Dovecot, own shared cert on a private network
	c, err := client.DialTLS(cfg.Addr(), tlsCfg)
	if err != nil {
		return nil, fmt.Errorf("dial dest %s: %w", cfg.Addr(), err)
	}
	if err := c.Login(cfg.User, cfg.Pass); err != nil {
		c.Logout()
		return nil, fmt.Errorf("dest login as %s: %w", cfg.User, err)
	}
	return &DestClient{c: c}, nil
}

// Close logs out.
func (d *DestClient) Close() {
	if d.c != nil {
		_ = d.c.Logout()
	}
}

// EnsureFolder creates the folder if it doesn't exist and subscribes to it.
// Idempotent: an "already exists" CREATE is not an error.
func (d *DestClient) EnsureFolder(name string) error {
	if name == "" || name == "INBOX" {
		return nil // INBOX always exists
	}
	// CREATE is the cheapest existence-or-create; ignore the already-exists error.
	if err := d.c.Create(name); err != nil && !isAlreadyExists(err) {
		return fmt.Errorf("create folder %q: %w", name, err)
	}
	if err := d.c.Subscribe(name); err != nil {
		// Subscription is cosmetic; don't fail the import over it.
		return nil
	}
	return nil
}

// ExistingIndex captures what a destination folder already holds — the basis for
// idempotent re-runs (cutover deltas). Messages are de-duplicated by Message-ID;
// messages that lack one (which can't be matched that way) are additionally
// indexed by a content hash so they don't re-append on every run.
type ExistingIndex struct {
	MessageIDs    map[string]struct{} // normalized Message-IDs present
	ContentHashes map[string]struct{} // contentHash() of header-less messages present
}

// Existing selects the folder and scans what's already present. The importer
// always calls EnsureFolder first, so the folder exists by the time we get here;
// a SELECT error therefore signals a real auth/connection problem and is
// returned, not swallowed (swallowing it would silently disable de-dupe and let
// a re-run double-import).
//
// It is a two-pass scan: a cheap envelope pass collects Message-IDs and flags
// the (rare) messages that lack one; a second pass fetches the bodies of only
// those header-less messages to hash them. The body fetch is bounded by the
// header-less count, so large folders stay cheap.
func (d *DestClient) Existing(folder string) (*ExistingIndex, error) {
	mbox, err := d.c.Select(folder, true)
	if err != nil {
		return nil, fmt.Errorf("select %q to scan existing messages: %w", folder, err)
	}
	idx := &ExistingIndex{MessageIDs: map[string]struct{}{}, ContentHashes: map[string]struct{}{}}
	if mbox.Messages == 0 {
		return idx, nil
	}

	// Pass 1: envelope-only scan → Message-IDs, plus the sequence numbers of any
	// messages with no Message-ID (which need a body hash instead).
	seq := new(imap.SeqSet)
	seq.AddRange(1, mbox.Messages)
	ch := make(chan *imap.Message, 64)
	done := make(chan error, 1)
	go func() { done <- d.c.Fetch(seq, []imap.FetchItem{imap.FetchEnvelope}, ch) }()
	headerless := new(imap.SeqSet)
	var headerlessCount int
	for m := range ch {
		id := ""
		if m.Envelope != nil {
			id = NormalizeMessageID(m.Envelope.MessageId)
		}
		if id != "" {
			idx.MessageIDs[id] = struct{}{}
		} else {
			headerless.AddNum(m.SeqNum)
			headerlessCount++
		}
	}
	if err := <-done; err != nil {
		return nil, fmt.Errorf("scan existing messages in %q: %w", folder, err)
	}
	if headerlessCount == 0 {
		return idx, nil
	}

	// Pass 2: hash the bodies of the header-less messages so a re-run recognises
	// an identical message already present.
	section := &imap.BodySectionName{}
	ch2 := make(chan *imap.Message, 16)
	done2 := make(chan error, 1)
	go func() { done2 <- d.c.Fetch(headerless, []imap.FetchItem{section.FetchItem()}, ch2) }()
	for m := range ch2 {
		r := m.GetBody(section)
		if r == nil {
			continue
		}
		b, err := io.ReadAll(r)
		if err != nil {
			return nil, fmt.Errorf("read existing header-less body in %q: %w", folder, err)
		}
		idx.ContentHashes[contentHash(b)] = struct{}{}
	}
	if err := <-done2; err != nil {
		return nil, fmt.Errorf("scan existing header-less bodies in %q: %w", folder, err)
	}
	return idx, nil
}

// Append writes one message into folder, preserving its flags and original
// internal date.
func (d *DestClient) Append(folder string, body []byte, flags []string, date time.Time) error {
	buf := bytes.NewBuffer(body) // *bytes.Buffer satisfies imap.Literal (Read + Len)
	if err := d.c.Append(folder, flags, date, buf); err != nil {
		return fmt.Errorf("append to %q: %w", folder, err)
	}
	return nil
}

// isAlreadyExists reports a benign "mailbox already exists" CREATE error.
// go-imap surfaces the server's text; Dovecot says "Mailbox already exists".
func isAlreadyExists(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "already exists")
}
