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

	// Check max_mailboxes limit.
	if domain.MaxMailboxes != nil {
		count, _ := s.domains.CountMailboxes(r.Context(), req.DomainID)
		if count >= *domain.MaxMailboxes {
			respondError(w, r, http.StatusConflict, "MAILBOX_LIMIT_REACHED",
				fmt.Sprintf("Domain has reached its mailbox limit of %d", *domain.MaxMailboxes))
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

	// Create Maildir structure on disk (Spec A.4 step 6).
	// Walk starts from the domain directory to ensure correct ownership throughout.
	domainDir := filepath.Join("/var/vectis/mail", domain.Name)
	maildirBase := filepath.Join(domainDir, req.LocalPart, "Maildir")
	for _, sub := range []string{"cur", "new", "tmp"} {
		if mkdirErr := os.MkdirAll(filepath.Join(maildirBase, sub), 0700); mkdirErr != nil {
			s.logger.Warn("failed to create Maildir", "path", maildirBase, "error", mkdirErr)
		}
	}
	// Set ownership to vmail (uid/gid 5000) from domain dir down.
	_ = filepath.Walk(domainDir, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr == nil {
			os.Chown(path, 5000, 5000)
		}
		return nil
	})

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

func (s *Server) handleGetMailbox(w http.ResponseWriter, r *http.Request) {
	mailboxID := chi.URLParam(r, "mailboxID")
	mailbox, err := s.mailboxes.GetByID(r.Context(), mailboxID)
	if err != nil {
		s.logger.Error("get mailbox failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to get mailbox")
		return
	}
	if mailbox == nil {
		respondError(w, r, http.StatusNotFound, "NOT_FOUND", "Mailbox not found")
		return
	}
	respond(w, r, http.StatusOK, mailbox)
}

func (s *Server) handleUpdateMailbox(w http.ResponseWriter, r *http.Request) {
	mailboxID := chi.URLParam(r, "mailboxID")

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

	adminID := getAdminID(r.Context())
	ip := clientIP(r)
	s.audit.Log(r.Context(), &adminID, "mailbox.delete", "mailbox", &mailboxID, nil, &ip)

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
