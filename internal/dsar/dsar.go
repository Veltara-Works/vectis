// Package dsar implements GDPR data-subject access (Art.15) and erasure
// (Art.17) for a single mail subject. It is Enterprise-gated and super-admin
// only at the API/CLI boundary.
//
// Export assembles a signed-by-the-operator zip: the subject's full message
// bodies (read straight from the Maildir the api container mounts RW) plus an
// account.json carrying the Art.15 metadata record. Erasure hard-deletes the
// live mailbox, its on-disk mail, its message metadata and its aliases, then
// writes a minimal erasure_tombstone so a later backup restore can re-apply the
// erasure (the EDPB Feb-2026 top finding: erasure must survive a restore). It
// deliberately does NOT touch the audit trail or billing records — Art.17(3)
// exemptions — and it never edits backups (ICO "beyond use + overwrite on
// schedule").
package dsar

import (
	"archive/zip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Veltara-Works/vectis/internal/repository"
)

// ErrSubjectNotFound is returned when no mailbox exists for the requested
// subject. Erasure and export are mailbox-centric: the data subject is the
// mailbox owner. (An operator admin account that merely shares the address is
// not auto-erased — see Erase.)
var ErrSubjectNotFound = errors.New("dsar: no mailbox found for subject")

// FormatVersion is stamped into account.json so downstream tooling can detect
// the export schema.
const FormatVersion = "1.0"

// Service performs DSAR export and erasure. It is cheap to construct (a bag of
// repo pointers) so handlers/CLI can build one per call.
type Service struct {
	domains    *repository.DomainRepo
	mailboxes  *repository.MailboxRepo
	aliases    *repository.AliasRepo
	admins     *repository.AdminRepo
	messages   *repository.MessageRepo
	audit      *repository.AuditRepo
	tombstones *repository.ErasureTombstoneRepo
	mailRoot   string // base of the Maildir tree, e.g. /var/vectis/mail
	logger     *slog.Logger
}

// NewService builds a DSAR service. mailRoot is the on-disk base of the Maildir
// tree (see MailRootFromLocation).
func NewService(domains *repository.DomainRepo, mailboxes *repository.MailboxRepo,
	aliases *repository.AliasRepo, admins *repository.AdminRepo, messages *repository.MessageRepo,
	audit *repository.AuditRepo, tombstones *repository.ErasureTombstoneRepo,
	mailRoot string, logger *slog.Logger) *Service {
	if mailRoot == "" {
		mailRoot = "/var/vectis/mail"
	}
	return &Service{
		domains: domains, mailboxes: mailboxes, aliases: aliases, admins: admins,
		messages: messages, audit: audit, tombstones: tombstones,
		mailRoot: mailRoot, logger: logger,
	}
}

// MailRootFromLocation extracts the Maildir base directory from a Dovecot
// mail_location string such as "maildir:/var/vectis/mail/%d/%n/Maildir". It
// returns the path up to the first template token; on anything unexpected it
// falls back to the shipped default so callers always get a usable root.
func MailRootFromLocation(loc string) string {
	const def = "/var/vectis/mail"
	if loc == "" {
		return def
	}
	// Drop a leading driver prefix ("maildir:").
	if i := strings.IndexByte(loc, ':'); i >= 0 && !strings.HasPrefix(loc, "/") {
		loc = loc[i+1:]
	}
	// Cut at the first template token (%d / %n / %u).
	if i := strings.IndexByte(loc, '%'); i >= 0 {
		loc = loc[:i]
	}
	loc = strings.TrimRight(loc, "/")
	if loc == "" || !strings.HasPrefix(loc, "/") {
		return def
	}
	return loc
}

// splitSubject splits a subject email into (localPart, domain). The domain is
// lower-cased to match how domains are stored; the local part is preserved.
func splitSubject(email string) (local, domain string, ok bool) {
	at := strings.LastIndexByte(email, '@')
	if at <= 0 || at == len(email)-1 {
		return "", "", false
	}
	return email[:at], strings.ToLower(email[at+1:]), true
}

// resolved holds the live rows a subject email maps to.
type resolved struct {
	email     string
	localPart string
	domain    *repository.Domain  // nil if the domain row is gone
	mailbox   *repository.Mailbox // nil if no mailbox
	admin     *repository.Admin   // nil if no admin shares the address
}

func (s *Service) resolve(ctx context.Context, email string) (*resolved, error) {
	local, domainName, ok := splitSubject(email)
	if !ok {
		return nil, fmt.Errorf("dsar: %q is not a valid email address", email)
	}
	r := &resolved{email: email, localPart: local}

	domain, err := s.domains.GetByName(ctx, domainName)
	if err != nil {
		return nil, fmt.Errorf("resolve domain: %w", err)
	}
	r.domain = domain
	if domain != nil {
		mb, err := s.mailboxes.GetByEmail(ctx, domain.ID, local)
		if err != nil {
			return nil, fmt.Errorf("resolve mailbox: %w", err)
		}
		r.mailbox = mb
	}
	admin, err := s.admins.GetByEmail(ctx, email)
	if err != nil {
		return nil, fmt.Errorf("resolve admin: %w", err)
	}
	r.admin = admin
	return r, nil
}

// maildirPath returns the absolute Maildir path for a resolved subject, or ""
// when the domain row is unknown.
func (s *Service) maildirPath(r *resolved) string {
	if r.domain == nil {
		return ""
	}
	return filepath.Join(s.mailRoot, r.domain.Name, r.localPart, "Maildir")
}

// ---------------------------------------------------------------------------
// Export (Art.15)
// ---------------------------------------------------------------------------

// ExportSummary reports what an export produced.
type ExportSummary struct {
	SubjectEmail string `json:"subject_email"`
	Messages     int    `json:"messages"`
	MailFiles    int    `json:"mail_files"`
	Aliases      int    `json:"aliases"`
	Bytes        int64  `json:"bytes"`
}

// SubjectHasMailbox reports whether a live mailbox exists for subject. Handlers
// call it before setting download headers so a missing subject yields a clean
// 404 instead of a half-streamed zip. Returns the validation error for a
// malformed address.
func (s *Service) SubjectHasMailbox(ctx context.Context, subject string) (bool, error) {
	r, err := s.resolve(ctx, subject)
	if err != nil {
		return false, err
	}
	return r.mailbox != nil, nil
}

// Export writes a DSAR access package (zip) for subject to w. The zip contains
// account.json (Art.15 metadata) and the subject's raw message files under
// messages/. Returns ErrSubjectNotFound if the subject has no mailbox.
// requestedBy is the super-admin's UUID (API) or nil (operator CLI).
func (s *Service) Export(ctx context.Context, subject string, requestedBy *string, w io.Writer) (ExportSummary, error) {
	var sum ExportSummary
	r, err := s.resolve(ctx, subject)
	if err != nil {
		return sum, err
	}
	if r.mailbox == nil {
		return sum, ErrSubjectNotFound
	}
	sum.SubjectEmail = subject

	msgs, err := s.messages.ListBySubject(ctx, r.mailbox.ID, subject)
	if err != nil {
		return sum, err
	}
	aliases, err := s.aliases.ListBySubject(ctx, r.domain.ID, r.localPart, subject)
	if err != nil {
		return sum, err
	}

	zw := zip.NewWriter(w)

	account := s.buildAccount(r, msgs, aliases)
	if err := writeJSONEntry(zw, "account.json", account); err != nil {
		_ = zw.Close()
		return sum, err
	}

	mailFiles, mailBytes, err := s.addMaildir(zw, s.maildirPath(r))
	if err != nil {
		_ = zw.Close()
		return sum, err
	}

	if err := zw.Close(); err != nil {
		return sum, fmt.Errorf("finalize export zip: %w", err)
	}

	sum.Messages = len(msgs)
	sum.Aliases = len(aliases)
	sum.MailFiles = mailFiles
	sum.Bytes = mailBytes

	// Record the access request itself against the requesting actor (a valid
	// admin UUID from the API, or nil for an operator CLI run — never a sentinel
	// string, which would fail the audit_log.admin_id UUID FK).
	if s.audit != nil {
		resID := subject
		if err := s.audit.Log(ctx, requestedBy, "dsar.export", "data_subject", &resID, map[string]any{
			"messages": sum.Messages, "mail_files": sum.MailFiles, "aliases": sum.Aliases,
		}, nil); err != nil {
			s.logger.Warn("dsar: failed to audit export", "error", err)
		}
	}
	return sum, nil
}

// buildAccount assembles the Art.15 metadata record.
func (s *Service) buildAccount(r *resolved, msgs []repository.Message, aliases []repository.Alias) map[string]any {
	identity := map[string]any{
		"mailbox": map[string]any{
			"id":           r.mailbox.ID,
			"email":        r.email,
			"local_part":   r.mailbox.LocalPart,
			"display_name": r.mailbox.DisplayName,
			"quota_mb":     r.mailbox.QuotaMB,
			"active":       r.mailbox.Active,
			"created_at":   r.mailbox.CreatedAt,
		},
	}
	// An admin account that shares the address is also the subject's personal
	// data — include the identity fields (never the password hash / TOTP /
	// federated subject identifiers).
	if r.admin != nil {
		identity["admin_account"] = map[string]any{
			"id":            r.admin.ID,
			"email":         r.admin.Email,
			"role":          r.admin.Role,
			"oidc_provider": r.admin.OIDCProvider,
			"saml_provider": r.admin.SAMLProvider,
			"created_at":    r.admin.CreatedAt,
			"last_login_at": r.admin.LastLoginAt,
		}
	}

	exportMsgs := make([]map[string]any, 0, len(msgs))
	for _, m := range msgs {
		exportMsgs = append(exportMsgs, map[string]any{
			"id":          m.ID,
			"message_id":  m.MessageID,
			"direction":   m.Direction,
			"sender":      m.Sender,
			"recipients":  m.Recipients,
			"subject":     m.Subject,
			"size_bytes":  m.SizeBytes,
			"status":      m.Status,
			"spam_score":  m.SpamScore,
			"spam_action": m.SpamAction,
			"created_at":  m.CreatedAt,
		})
	}

	exportAliases := make([]map[string]any, 0, len(aliases))
	for _, a := range aliases {
		exportAliases = append(exportAliases, map[string]any{
			"id":                a.ID,
			"source_local_part": a.SourceLocalPart,
			"destination":       a.Destination,
			"active":            a.Active,
			"created_at":        a.CreatedAt,
		})
	}

	return map[string]any{
		"export": map[string]any{
			"format_version": FormatVersion,
			"subject_email":  r.email,
			"generated_by":   "Vectis Mail Server",
			"article":        "GDPR Article 15 — Right of access",
		},
		"disclosure":       disclosure(),
		"identity":         identity,
		"message_metadata": exportMsgs,
		"aliases":          exportAliases,
		"counts": map[string]any{
			"message_metadata": len(exportMsgs),
			"aliases":          len(exportAliases),
		},
		"notes": []string{
			"Full message bodies for this subject are included as raw RFC 5322 files under messages/.",
			"Engagement tracking events are excluded: their IP/user-agent rows are personal data of the message recipients, not of this subject.",
			"Password hashes, TOTP secrets and federated subject identifiers are withheld as they are credentials, not subject-access data.",
		},
	}
}

// disclosure is the static Art.15(1) processing disclosure for a self-hosted
// Vectis install. The operator is the controller; this describes what the
// software processes so the operator can hand it to the data subject.
func disclosure() map[string]any {
	return map[string]any{
		"controller":  "The operator of this Vectis Mail installation (self-hosted).",
		"purposes":    "Operating an email service: message transport, delivery, storage, spam filtering and deliverability.",
		"legal_basis": "Determined by the operator (controller); typically contract or legitimate interest for running the mailbox.",
		"categories": []string{
			"Account identity (email address, display name, role)",
			"Message metadata (sender, recipients, subject, size, status, timestamps)",
			"Message content (the mailbox's stored mail)",
			"Aliases that forward to or from the subject",
		},
		"recipients": "Message recipients and their mail providers; spam/deliverability services configured by the operator.",
		"retention":  "Governed by the operator's retention configuration (see the data-retention sweeper) and the mailbox's own lifecycle.",
		"rights":     "Access, rectification, erasure, restriction, portability and objection, exercised against the operator (controller).",
		"source":     "Provided by the subject or generated by their use of the mail service.",
	}
}

// addMaildir walks a Maildir's cur/ and new/ subdirectories and copies each
// stored message into the zip under messages/<sub>/<name>.eml. A missing
// Maildir (subject never received mail) is not an error.
func (s *Service) addMaildir(zw *zip.Writer, maildir string) (files int, bytes int64, err error) {
	if maildir == "" {
		return 0, 0, nil
	}
	for _, sub := range []string{"cur", "new"} {
		dir := filepath.Join(maildir, sub)
		entries, derr := os.ReadDir(dir)
		if derr != nil {
			if os.IsNotExist(derr) {
				continue
			}
			return files, bytes, fmt.Errorf("read maildir %s: %w", sub, derr)
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			n, werr := copyFileToZip(zw, filepath.Join(dir, e.Name()),
				"messages/"+sub+"/"+e.Name()+".eml")
			if werr != nil {
				return files, bytes, werr
			}
			files++
			bytes += n
		}
	}
	return files, bytes, nil
}

func copyFileToZip(zw *zip.Writer, src, zipName string) (int64, error) {
	f, err := os.Open(src)
	if err != nil {
		return 0, fmt.Errorf("open mail file: %w", err)
	}
	defer f.Close()
	w, err := zw.Create(zipName)
	if err != nil {
		return 0, fmt.Errorf("create zip entry: %w", err)
	}
	n, err := io.Copy(w, f)
	if err != nil {
		return n, fmt.Errorf("copy mail file into zip: %w", err)
	}
	return n, nil
}

func writeJSONEntry(zw *zip.Writer, name string, v any) error {
	w, err := zw.Create(name)
	if err != nil {
		return fmt.Errorf("create %s: %w", name, err)
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return fmt.Errorf("encode %s: %w", name, err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Erasure (Art.17)
// ---------------------------------------------------------------------------

// EraseResult reports what an erasure removed.
type EraseResult struct {
	SubjectEmail    string `json:"subject_email"`
	MessageMetadata int64  `json:"message_metadata_deleted"`
	Aliases         int64  `json:"aliases_deleted"`
	MailboxDeleted  bool   `json:"mailbox_deleted"`
	MaildirRemoved  bool   `json:"maildir_removed"`
	AdminRetained   bool   `json:"admin_account_retained"` // a same-address operator account was left in place
	TombstoneID     string `json:"tombstone_id"`
}

// Erase hard-deletes a subject's live personal data and records a tombstone so
// the erasure survives a backup restore. erasedBy is the super-admin's UUID
// (API) or nil (operator CLI). Returns ErrSubjectNotFound if no mailbox exists.
//
// Scope: mailbox, its on-disk mail, its message metadata and its aliases. A
// separate admin/operator account that happens to share the address is NOT
// auto-deleted (that could lock the operator out of their own install); it is
// reported via AdminRetained for manual review. The audit trail and billing
// records are retained under Art.17(3).
func (s *Service) Erase(ctx context.Context, subject string, erasedBy *string) (EraseResult, error) {
	var res EraseResult
	r, err := s.resolve(ctx, subject)
	if err != nil {
		return res, err
	}
	if r.mailbox == nil {
		return res, ErrSubjectNotFound
	}
	res.SubjectEmail = subject
	res.AdminRetained = r.admin != nil

	counts, err := s.purge(ctx, r)
	if err != nil {
		return res, err
	}
	res.MessageMetadata = counts.messages
	res.Aliases = counts.aliases
	res.MailboxDeleted = counts.mailboxDeleted
	res.MaildirRemoved = counts.maildirRemoved

	tomb, err := s.tombstones.Upsert(ctx, subject, strings.ToLower(domainOf(r)), r.localPart, erasedBy)
	if err != nil {
		return res, err
	}
	res.TombstoneID = tomb.ID

	if s.audit != nil {
		resID := subject
		if err := s.audit.Log(ctx, erasedBy, "dsar.erase", "data_subject", &resID, map[string]any{
			"message_metadata_deleted": res.MessageMetadata,
			"aliases_deleted":          res.Aliases,
			"mailbox_deleted":          res.MailboxDeleted,
			"maildir_removed":          res.MaildirRemoved,
			"admin_account_retained":   res.AdminRetained,
			"tombstone_id":             res.TombstoneID,
		}, nil); err != nil {
			s.logger.Warn("dsar: failed to audit erasure", "error", err)
		}
	}
	s.logger.Info("dsar: erased subject",
		"subject", subject, "messages", res.MessageMetadata, "aliases", res.Aliases,
		"mailbox_deleted", res.MailboxDeleted, "maildir_removed", res.MaildirRemoved,
		"admin_retained", res.AdminRetained)
	return res, nil
}

func domainOf(r *resolved) string {
	if r.domain != nil {
		return r.domain.Name
	}
	_, d, _ := splitSubject(r.email)
	return d
}

type purgeCounts struct {
	messages       int64
	aliases        int64
	mailboxDeleted bool
	maildirRemoved bool
}

// purge removes the live personal data for a resolved subject. It is shared by
// Erase and the tombstone reconciler, and is safe to run when some rows are
// already gone (idempotent). Message metadata is deleted BEFORE the mailbox so
// the mailbox_id link is still intact for the inbound filter.
func (s *Service) purge(ctx context.Context, r *resolved) (purgeCounts, error) {
	var c purgeCounts

	mailboxID := ""
	if r.mailbox != nil {
		mailboxID = r.mailbox.ID
	}
	n, err := s.messages.DeleteBySubject(ctx, mailboxID, r.email)
	if err != nil {
		return c, err
	}
	c.messages = n

	domainID := ""
	if r.domain != nil {
		domainID = r.domain.ID
	}
	na, err := s.aliases.DeleteBySubject(ctx, domainID, r.localPart, r.email)
	if err != nil {
		return c, err
	}
	c.aliases = na

	if path := s.maildirPath(r); path != "" {
		if _, statErr := os.Stat(path); statErr == nil {
			if rmErr := os.RemoveAll(path); rmErr != nil {
				return c, fmt.Errorf("remove maildir: %w", rmErr)
			}
			c.maildirRemoved = true
		}
	}

	if r.mailbox != nil {
		deleted, err := s.mailboxes.Delete(ctx, r.mailbox.ID)
		if err != nil {
			return c, err
		}
		c.mailboxDeleted = deleted
	}
	return c, nil
}

// ---------------------------------------------------------------------------
// Tombstone reconciliation (restore survival)
// ---------------------------------------------------------------------------

// ReconcileSummary reports a reconcile pass.
type ReconcileSummary struct {
	Tombstones     int   `json:"tombstones"`
	Resurrected    int   `json:"resurrected_subjects"`
	MessagesPurged int64 `json:"message_metadata_purged"`
	AliasesPurged  int64 `json:"aliases_purged"`
	MaildirsPurged int   `json:"maildirs_purged"`
}

// ReconcileTombstones re-applies every recorded erasure against current live
// data. Run on startup (a restore that resurrected an erased subject is undone
// the moment the server comes back) and available on demand. It is idempotent:
// on a healthy system every tombstone re-purges nothing.
func (s *Service) ReconcileTombstones(ctx context.Context) (ReconcileSummary, error) {
	var sum ReconcileSummary
	tombs, err := s.tombstones.List(ctx)
	if err != nil {
		return sum, err
	}
	sum.Tombstones = len(tombs)

	for i := range tombs {
		t := tombs[i]
		r, err := s.resolve(ctx, t.SubjectEmail)
		if err != nil {
			s.logger.Warn("dsar: reconcile resolve failed", "subject", t.SubjectEmail, "error", err)
			continue
		}
		c, err := s.purge(ctx, r)
		if err != nil {
			s.logger.Error("dsar: reconcile purge failed", "subject", t.SubjectEmail, "error", err)
			continue
		}
		resurrected := c.messages > 0 || c.aliases > 0 || c.mailboxDeleted || c.maildirRemoved
		if resurrected {
			sum.Resurrected++
			sum.MessagesPurged += c.messages
			sum.AliasesPurged += c.aliases
			if c.maildirRemoved {
				sum.MaildirsPurged++
			}
			s.logger.Warn("dsar: re-applied erasure after data resurfaced (likely a restore)",
				"subject", t.SubjectEmail, "messages", c.messages, "aliases", c.aliases,
				"mailbox_deleted", c.mailboxDeleted, "maildir_removed", c.maildirRemoved)
			if s.audit != nil {
				resID := t.SubjectEmail
				if err := s.audit.Log(ctx, nil, "dsar.reconcile", "data_subject", &resID, map[string]any{
					"message_metadata_purged": c.messages,
					"aliases_purged":          c.aliases,
					"mailbox_deleted":         c.mailboxDeleted,
					"maildir_removed":         c.maildirRemoved,
				}, nil); err != nil {
					s.logger.Warn("dsar: failed to audit reconcile", "error", err)
				}
			}
		}
		if err := s.tombstones.MarkReconciled(ctx, t.ID); err != nil {
			s.logger.Warn("dsar: failed to mark tombstone reconciled", "subject", t.SubjectEmail, "error", err)
		}
	}

	if sum.Resurrected > 0 {
		s.logger.Info("dsar: tombstone reconcile re-applied erasures",
			"tombstones", sum.Tombstones, "resurrected", sum.Resurrected,
			"messages_purged", sum.MessagesPurged, "maildirs_purged", sum.MaildirsPurged)
	}
	return sum, nil
}

// ListErasures returns the recorded erasure tombstones (the suppression list).
func (s *Service) ListErasures(ctx context.Context) ([]repository.ErasureTombstone, error) {
	return s.tombstones.List(ctx)
}

// ExportFilename returns a safe download filename for a subject's export zip.
func ExportFilename(subject string, now time.Time) string {
	safe := strings.Map(func(rn rune) rune {
		switch {
		case rn >= 'a' && rn <= 'z', rn >= 'A' && rn <= 'Z', rn >= '0' && rn <= '9', rn == '-', rn == '.':
			return rn
		default:
			return '_'
		}
	}, subject)
	return fmt.Sprintf("vectis-dsar-%s-%s.zip", safe, now.UTC().Format("20060102"))
}
