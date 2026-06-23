package api

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/Veltara-Works/vectis/internal/auth"
	"github.com/Veltara-Works/vectis/internal/repository"
	"github.com/Veltara-Works/vectis/internal/validonx"
)

var validLocalPartRe = regexp.MustCompile(`^[a-zA-Z0-9.!#$%&'*+/=?^_` + "`" + `{|}~-]+$`)

type createMailboxRequest struct {
	DomainID    string  `json:"domain_id"`
	LocalPart   string  `json:"local_part"`
	Password    string  `json:"password"`
	DisplayName *string `json:"display_name,omitempty"`
	QuotaMB     *int    `json:"quota_mb,omitempty"`
}

type updateMailboxRequest struct {
	Password    *string `json:"password,omitempty"`
	DisplayName *string `json:"display_name,omitempty"`
	QuotaMB     *int    `json:"quota_mb,omitempty"`
	Active      *bool   `json:"active,omitempty"`
}

func (s *Server) handleListMailboxes(w http.ResponseWriter, r *http.Request) {
	domainID := r.URL.Query().Get("domain_id")
	if domainID == "" {
		respondError(w, r, http.StatusBadRequest, "MISSING_FIELDS", "domain_id query parameter is required")
		return
	}
	if !s.canAccessDomain(r.Context(), domainID) {
		respondError(w, r, http.StatusForbidden, "FORBIDDEN", "You do not have access to this domain")
		return
	}

	page, err := parsePagination(r)
	if err != nil {
		respondError(w, r, http.StatusBadRequest, "INVALID_PAGINATION", err.Error())
		return
	}

	mailboxes, err := s.mailboxes.ListByDomainPaginated(r.Context(), domainID, repository.PaginationParams{
		Cursor: page.Cursor,
		Limit:  page.Limit,
	})
	if err != nil {
		s.logger.Error("list mailboxes failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list mailboxes")
		return
	}

	hasMore := len(mailboxes) > page.Limit
	var nextCursor string
	if hasMore {
		mailboxes = mailboxes[:page.Limit]
		nextCursor = encodeCursor(mailboxes[page.Limit-1].CreatedAt)
	}

	respondPaginated(w, r, http.StatusOK, mailboxes, nextCursor, hasMore)
}

// provisionMaildir creates the Maildir cur/new/tmp tree for a mailbox and chowns
// the domain tree to vmail (uid/gid 5000). Failures are logged, not fatal —
// Dovecot also creates the Maildir on first delivery. Returns the Maildir base
// path. Shared by the admin create handler and SCIM provisioning so both lay
// down identical on-disk storage.
func (s *Server) provisionMaildir(domainName, localPart string) string {
	domainDir := filepath.Join("/var/vectis/mail", domainName)
	maildirBase := filepath.Join(domainDir, localPart, "Maildir")
	for _, sub := range []string{"cur", "new", "tmp"} {
		if err := os.MkdirAll(filepath.Join(maildirBase, sub), 0700); err != nil {
			s.logger.Warn("failed to create Maildir", "path", maildirBase, "error", err)
		}
	}
	// Ownership to vmail (5000:5000) from the domain dir down.
	_ = filepath.Walk(domainDir, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr == nil {
			os.Chown(path, 5000, 5000)
		}
		return nil
	})
	return maildirBase
}

func (s *Server) handleCreateMailbox(w http.ResponseWriter, r *http.Request) {
	var req createMailboxRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, r, http.StatusBadRequest, "INVALID_JSON", "Invalid JSON request body")
		return
	}

	if req.DomainID == "" || req.LocalPart == "" || req.Password == "" {
		respondError(w, r, http.StatusBadRequest, "MISSING_FIELDS", "domain_id, local_part, and password are required")
		return
	}
	if !s.canAccessDomain(r.Context(), req.DomainID) {
		respondError(w, r, http.StatusForbidden, "FORBIDDEN", "You do not have access to this domain")
		return
	}
	if !validLocalPartRe.MatchString(req.LocalPart) {
		respondError(w, r, http.StatusBadRequest, "INVALID_LOCAL_PART", "Invalid local part format")
		return
	}
	if len(req.LocalPart) > 64 {
		respondError(w, r, http.StatusBadRequest, "INVALID_LOCAL_PART", "Local part must be 64 characters or fewer")
		return
	}
	if err := auth.ValidatePasswordStrength(req.Password); err != nil {
		respondError(w, r, http.StatusBadRequest, "WEAK_PASSWORD", err.Error())
		return
	}

	// Check domain exists and is active.
	domain, err := s.domains.GetByID(r.Context(), req.DomainID)
	if err != nil {
		s.logger.Error("get domain failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to verify domain")
		return
	}
	if domain == nil {
		respondError(w, r, http.StatusBadRequest, "DOMAIN_NOT_FOUND", "Domain does not exist")
		return
	}
	if !domain.Active {
		respondError(w, r, http.StatusBadRequest, "DOMAIN_INACTIVE", "Domain is not active")
		return
	}

	// Mailbox cap enforcement.
	// Pro/Enterprise: respects domain.MaxMailboxes if set, else unlimited.
	// Free: hard cap of 25 per domain regardless of domain.MaxMailboxes,
	// to handle Pro→Free downgrades on domains created with unlimited quota.
	// Existing 26+ mailboxes are not retroactively suspended; only NEW
	// creations past the cap are blocked.
	tier, _ := s.featureGate.ResolveTier(r.Context())
	effectiveCap := -1 // -1 = unlimited
	if domain.MaxMailboxes != nil {
		effectiveCap = *domain.MaxMailboxes
	}
	if tier == validonx.TierFree {
		if effectiveCap < 0 || effectiveCap > 25 {
			effectiveCap = 25
		}
	}
	if effectiveCap >= 0 {
		count, _ := s.domains.CountMailboxes(r.Context(), req.DomainID)
		if count >= effectiveCap {
			code := "MAILBOX_LIMIT_REACHED"
			msg := fmt.Sprintf("Domain has reached its mailbox limit of %d", effectiveCap)
			if tier == validonx.TierFree {
				code = "LIMIT_EXCEEDED"
				msg = fmt.Sprintf("Starter plan allows up to %d mailboxes per domain. Upgrade to Pro for unlimited mailboxes.", effectiveCap)
			}
			respondError(w, r, http.StatusForbidden, code, msg)
			return
		}
	}

	// Check uniqueness.
	existing, _ := s.mailboxes.GetByEmail(r.Context(), req.DomainID, req.LocalPart)
	if existing != nil {
		respondError(w, r, http.StatusConflict, "MAILBOX_EXISTS",
			fmt.Sprintf("Mailbox %s@%s already exists", req.LocalPart, domain.Name))
		return
	}

	// Hash password.
	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		s.logger.Error("hash password failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to hash password")
		return
	}

	mailbox, err := s.mailboxes.Create(r.Context(), repository.MailboxCreate{
		DomainID:     req.DomainID,
		LocalPart:    req.LocalPart,
		PasswordHash: hash,
		DisplayName:  req.DisplayName,
		QuotaMB:      req.QuotaMB,
	})
	if err != nil {
		s.logger.Error("create mailbox failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to create mailbox")
		return
	}

	// Create Maildir structure on disk + set vmail ownership (Spec A.4 step 6).
	maildirBase := s.provisionMaildir(domain.Name, req.LocalPart)

	// Deliver a welcome email directly to the new Maildir.
	email := fmt.Sprintf("%s@%s", req.LocalPart, domain.Name)
	if err := s.deliverWelcomeEmail(maildirBase, email, domain.Name); err != nil {
		s.logger.Warn("failed to deliver welcome email", "mailbox", email, "error", err)
	}

	adminID := getAdminID(r.Context())
	ip := clientIP(r)
	s.audit.Log(r.Context(), &adminID, "mailbox.create", "mailbox", &mailbox.ID,
		map[string]string{"local_part": req.LocalPart, "domain": domain.Name}, &ip)

	respond(w, r, http.StatusCreated, mailbox)
}

// requireMailboxAccess fetches the mailbox by ID and verifies the caller may
// access its domain. On any failure it writes the error response and returns
// ok=false. Guards the by-ID handlers against cross-domain IDOR (audit P3-M1):
// the List/Create paths already gate on canAccessDomain, but Get/Update/Delete
// acted on a caller-supplied UUID without checking domain ownership.
func (s *Server) requireMailboxAccess(w http.ResponseWriter, r *http.Request, mailboxID string) (*repository.Mailbox, bool) {
	mailbox, err := s.mailboxes.GetByID(r.Context(), mailboxID)
	if err != nil {
		s.logger.Error("get mailbox failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to get mailbox")
		return nil, false
	}
	if mailbox == nil {
		respondError(w, r, http.StatusNotFound, "NOT_FOUND", "Mailbox not found")
		return nil, false
	}
	if !s.canAccessDomain(r.Context(), mailbox.DomainID) {
		respondError(w, r, http.StatusForbidden, "FORBIDDEN", "You do not have access to this mailbox")
		return nil, false
	}
	return mailbox, true
}

func (s *Server) handleGetMailbox(w http.ResponseWriter, r *http.Request) {
	mailboxID := chi.URLParam(r, "mailboxID")
	mailbox, ok := s.requireMailboxAccess(w, r, mailboxID)
	if !ok {
		return
	}
	respond(w, r, http.StatusOK, mailbox)
}

func (s *Server) handleUpdateMailbox(w http.ResponseWriter, r *http.Request) {
	mailboxID := chi.URLParam(r, "mailboxID")

	if _, ok := s.requireMailboxAccess(w, r, mailboxID); !ok {
		return
	}

	var req updateMailboxRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, r, http.StatusBadRequest, "INVALID_JSON", "Invalid JSON request body")
		return
	}

	update := repository.MailboxUpdate{
		DisplayName: req.DisplayName,
		QuotaMB:     req.QuotaMB,
		Active:      req.Active,
	}

	// Hash new password if provided.
	if req.Password != nil {
		hash, err := auth.HashPassword(*req.Password)
		if err != nil {
			s.logger.Error("hash password failed", "error", err)
			respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to hash password")
			return
		}
		update.PasswordHash = &hash
	}

	mailbox, err := s.mailboxes.Update(r.Context(), mailboxID, update)
	if err != nil {
		s.logger.Error("update mailbox failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to update mailbox")
		return
	}
	if mailbox == nil {
		respondError(w, r, http.StatusNotFound, "NOT_FOUND", "Mailbox not found")
		return
	}

	adminID := getAdminID(r.Context())
	ip := clientIP(r)
	s.audit.Log(r.Context(), &adminID, "mailbox.update", "mailbox", &mailboxID, nil, &ip)

	respond(w, r, http.StatusOK, mailbox)
}

func (s *Server) handleDeleteMailbox(w http.ResponseWriter, r *http.Request) {
	mailboxID := chi.URLParam(r, "mailboxID")

	// Require confirmation header (Spec A.4).
	if r.Header.Get("X-Confirm-Delete") != "true" {
		respondError(w, r, http.StatusBadRequest, "CONFIRMATION_REQUIRED",
			"Set X-Confirm-Delete: true header to confirm deletion")
		return
	}

	mb, ok := s.requireMailboxAccess(w, r, mailboxID)
	if !ok {
		return
	}

	deleted, err := s.mailboxes.Delete(r.Context(), mailboxID)
	if err != nil {
		s.logger.Error("delete mailbox failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to delete mailbox")
		return
	}
	if !deleted {
		respondError(w, r, http.StatusNotFound, "NOT_FOUND", "Mailbox not found")
		return
	}

	// Purge the on-disk Maildir so a delete is a complete erasure (P5-H1).
	// The DB row is gone, but mail content + sieve under
	// /var/vectis/mail/{domain}/{local_part} would otherwise survive.
	maildirPurged := false
	if domain, derr := s.domains.GetByID(r.Context(), mb.DomainID); derr == nil && domain != nil {
		userDir := filepath.Join("/var/vectis/mail", domain.Name, mb.LocalPart)
		if rmErr := os.RemoveAll(userDir); rmErr != nil {
			s.logger.Warn("maildir purge failed after mailbox delete", "path", userDir, "error", rmErr)
		} else {
			maildirPurged = true
		}
	} else {
		s.logger.Warn("maildir purge skipped: domain lookup failed", "domain_id", mb.DomainID, "error", derr)
	}

	adminID := getAdminID(r.Context())
	ip := clientIP(r)
	s.audit.Log(r.Context(), &adminID, "mailbox.delete", "mailbox", &mailboxID,
		map[string]any{"maildir_purged": maildirPurged}, &ip)

	respond(w, r, http.StatusOK, map[string]string{"message": "Mailbox deleted"})
}

// deliverWelcomeEmail writes a welcome message directly into the Maildir/new/
// directory so the user sees it on first login.
func (s *Server) deliverWelcomeEmail(maildirBase, email, domainName string) error {
	now := time.Now().UTC()
	msgID := randHex(16) + "@" + s.hostname

	body := fmt.Sprintf(`From: "Vectis Mail" <postmaster@%s>
To: <%s>
Subject: Welcome to your new mailbox
Date: %s
Message-ID: <%s>
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8

Welcome to your new mailbox on %s!

Your account has been created and is ready to use.

=== Connection Details ===

Email Address : %s

IMAP (incoming mail):
  Server : %s
  Port   : 993
  Security: SSL/TLS

SMTP (outgoing mail):
  Server : %s
  Port   : 587
  Security: STARTTLS

Username: %s
Password: the password set by your administrator

Webmail: https://%s/webmail/

If you have any questions, contact your mail administrator.
`,
		domainName,
		email,
		now.Format(time.RFC1123Z),
		msgID,
		s.hostname,
		email,
		s.hostname,
		s.hostname,
		email,
		s.hostname,
	)

	filename := fmt.Sprintf("%d.%s.%s", now.UnixNano(), randHex(16), s.hostname)
	path := filepath.Join(maildirBase, "new", filename)

	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		return fmt.Errorf("write welcome email: %w", err)
	}
	// Ensure vmail ownership.
	os.Chown(path, 5000, 5000)
	return nil
}

func randHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}
